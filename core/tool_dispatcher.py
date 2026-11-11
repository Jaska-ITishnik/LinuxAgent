"""Secure dispatch for explicitly registered tools."""
from __future__ import annotations

import asyncio
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import inspect
import json
import threading
import time
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

from core.errors import ApprovalInterfaceError, AuthorizationCancelled, ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry, UnknownToolError, DisabledToolError
from security.audit_logger import AuditLogError, AuditLogger


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any]


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    tool_name: str
    status: Literal["success", "error", "denied", "timeout"]
    result_data: Any = None
    error_code: str | None = None
    safe_error_message: str | None = None
    execution_duration: float = Field(ge=0)


class Authorizer(Protocol):
    def authorize(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool: ...


class RevalidatingAuthorizer(Authorizer, Protocol):
    def revalidate(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool: ...


class DenyByDefaultAuthorizer:
    """Deny every action unless an explicit allow decision is configured."""

    def authorize(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool:
        return False


@dataclass(frozen=True)
class AllowListAuthorizer:
    """Small explicit authorizer useful for configured applications and tests."""

    allowed_tool_names: frozenset[str]

    def authorize(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool:
        return tool.name in self.allowed_tool_names


def _type_for_schema(schema: dict[str, Any], name: str) -> Any:
    schema_type = schema.get("type")
    if "enum" in schema:
        enum_values = tuple(schema["enum"])
        return Literal.__getitem__(enum_values)
    if schema_type == "object":
        if not schema.get("properties") and isinstance(schema.get("additionalProperties"), dict):
            return dict[str, _type_for_schema(schema["additionalProperties"], f"{name}Value")]
        return _model_for_schema(schema, name)
    if schema_type == "array":
        from typing import List
        return List[_type_for_schema(schema["items"], f"{name}Item")]
    types: dict[str, Any] = {
        "string": str, "integer": int, "number": float,
        "boolean": bool, "null": type(None),
    }
    try:
        return types[schema_type]
    except KeyError:
        raise ValueError("Unsupported argument schema type") from None


def _model_for_schema(schema: dict[str, Any], name: str) -> type[BaseModel]:
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    fields: dict[str, tuple[Any, Any]] = {}
    for field_name, field_schema in properties.items():
        annotation = _type_for_schema(field_schema, f"{name}_{field_name}")
        constraints: dict[str, Any] = {}
        for key in ("minLength", "maxLength", "pattern", "minimum", "maximum", "minItems", "maxItems"):
            if key in field_schema:
                target = {
                    "minLength": "min_length",
                    "maxLength": "max_length",
                    "minItems": "min_length",
                    "maxItems": "max_length",
                    "minimum": "ge",
                    "maximum": "le",
                }.get(key, key)
                constraints[target] = field_schema[key]
        default = ... if field_name in required else field_schema.get("default", None)
        fields[field_name] = (annotation, Field(default, **constraints))
    extra = "forbid" if schema.get("additionalProperties", False) is False else "allow"
    model = create_model(name, __config__=ConfigDict(extra=extra, strict=True), **fields)
    return model


def _validate_arguments(definition: ToolDefinition, arguments: dict[str, Any]) -> dict[str, Any]:
    schema = definition.argument_schema
    model = _model_for_schema(schema, f"{definition.name.title().replace('_', '')}Arguments")
    validated = model.model_validate(arguments)
    result = validated.model_dump()
    additional = schema.get("additionalProperties", False)
    if isinstance(additional, dict):
        known = schema.get("properties", {})
        for key in arguments.keys() - known.keys():
            _validate_additional(arguments[key], additional)
            result[key] = arguments[key]
    return result


def _validate_additional(value: Any, schema: dict[str, Any]) -> None:
    # Validate schema-valued additionalProperties through a one-field Pydantic model.
    model = _model_for_schema({"type": "object", "properties": {"value": schema}, "required": ["value"], "additionalProperties": False}, "AdditionalArguments")
    model.model_validate({"value": value})


class ToolDispatcher:
    """Validates, authorizes, and runs tools from an explicit ToolRegistry."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        authorizer: Authorizer | None = None,
        audit_logger: AuditLogger | None = None,
        max_result_bytes: int = 64_000,
        max_sync_workers: int = 4,
    ) -> None:
        if max_result_bytes < 1 or max_sync_workers < 1:
            raise ValueError("result limit and worker count must be positive")
        self._registry = registry
        self._authorizer = authorizer or DenyByDefaultAuthorizer()
        self._audit_logger = audit_logger
        self._max_result_bytes = max_result_bytes
        self._executor = ThreadPoolExecutor(max_workers=max_sync_workers, thread_name_prefix="agent-tool")
        self._worker_slots = threading.BoundedSemaphore(max_sync_workers)
        self._closed = False

    async def dispatch(
        self,
        request: ToolCallRequest | dict[str, Any],
        *,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> ToolResult:
        started = time.monotonic()
        raw_name = request.tool_name if isinstance(request, ToolCallRequest) else str(request.get("tool_name", "")) if isinstance(request, dict) else ""
        raw_arguments = request.arguments if isinstance(request, ToolCallRequest) else request.get("arguments", {}) if isinstance(request, dict) else {}
        context = self._audit_logger.context(session_id, task_id) if self._audit_logger else nullcontext()
        with context:
            result = await self._dispatch(request, started)
        if self._audit_logger:
            preauthorization_errors = {
                "INVALID_REQUEST",
                "UNKNOWN_TOOL",
                "TOOL_DISABLED",
                "INVALID_ARGUMENTS",
                "DISPATCHER_CLOSED",
            }
            permission = (
                "denied" if result.status == "denied" or result.safe_error_message == "The approval audit event could not be saved"
                else "not_evaluated" if result.error_code in preauthorization_errors
                else "allowed"
            )
            try:
                self._audit_logger.record(
                    tool_name=raw_name,
                    arguments=raw_arguments,
                    permission_decision=permission,
                    execution_status=result.status,
                    duration=result.execution_duration,
                    session_id=session_id,
                    task_id=task_id,
                )
            except AuditLogError:
                return self._result(
                    raw_name,
                    "error",
                    started,
                    error_code="AUDIT_LOG_FAILED",
                    message="The audit event could not be saved; inspect the operation state before retrying",
                )
        return result

    async def _dispatch(self, request: ToolCallRequest | dict[str, Any], started: float) -> ToolResult:
        name = request.tool_name if isinstance(request, ToolCallRequest) else str(request.get("tool_name", "")) if isinstance(request, dict) else ""
        try:
            call = request if isinstance(request, ToolCallRequest) else ToolCallRequest.model_validate(request)
        except ValidationError:
            return self._result(name, "error", started, error_code="INVALID_REQUEST", message="Tool request is invalid")
        try:
            definition = self._registry.get(call.tool_name)
        except UnknownToolError:
            return self._result(call.tool_name, "error", started, error_code="UNKNOWN_TOOL", message="Tool is not registered")
        except DisabledToolError:
            return self._result(call.tool_name, "error", started, error_code="TOOL_DISABLED", message="Tool is disabled")
        try:
            arguments = _validate_arguments(definition, call.arguments)
        except (ValidationError, ValueError, TypeError):
            return self._result(call.tool_name, "error", started, error_code="INVALID_ARGUMENTS", message="Tool arguments do not match the registered schema")
        if self._closed:
            return self._result(call.tool_name, "error", started, error_code="DISPATCHER_CLOSED", message="Tool dispatcher is closed")
        try:
            authorized = self._authorizer.authorize(definition, arguments)
            revalidate = getattr(self._authorizer, "revalidate", None)
            if authorized and callable(revalidate):
                authorized = revalidate(definition, arguments)
        except AuthorizationCancelled as exc:
            return self._result(
                call.tool_name,
                "denied",
                started,
                error_code=exc.code,
                message=exc.safe_message,
            )
        except ApprovalInterfaceError as exc:
            return self._result(
                call.tool_name,
                "denied",
                started,
                error_code=exc.code,
                message=exc.safe_message,
            )
        except AuditLogError:
            return self._result(call.tool_name, "error", started, error_code="AUDIT_LOG_FAILED", message="The approval audit event could not be saved")
        except Exception:
            authorized = False
        if not authorized:
            return self._result(call.tool_name, "denied", started, error_code="AUTHORIZATION_DENIED", message="This action is not authorized")
        try:
            if inspect.iscoroutinefunction(definition.implementation):
                raw = await asyncio.wait_for(definition.implementation(**arguments), timeout=definition.execution_timeout)
            else:
                raw = await self._run_sync(definition, arguments)
                if inspect.isawaitable(raw):
                    raw = await asyncio.wait_for(raw, timeout=definition.execution_timeout)
            data = self._bounded_json_result(raw)
            return self._result(call.tool_name, "success", started, data=data)
        except (asyncio.TimeoutError, TimeoutError):
            return self._result(call.tool_name, "timeout", started, error_code="EXECUTION_TIMEOUT", message="Tool exceeded its execution time limit")
        except _WorkerCapacityError:
            return self._result(call.tool_name, "error", started, error_code="WORKER_CAPACITY", message="Tool execution capacity is full")
        except _OversizedResultError:
            return self._result(call.tool_name, "error", started, error_code="RESULT_TOO_LARGE", message="Tool result exceeded the size limit")
        except ToolExecutionError as exc:
            return self._result(
                call.tool_name,
                "error",
                started,
                error_code=exc.code,
                message=exc.safe_message,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._result(call.tool_name, "error", started, error_code="TOOL_EXECUTION_FAILED", message="Tool execution failed")

    async def _run_sync(self, definition: ToolDefinition, arguments: dict[str, Any]) -> Any:
        if not self._worker_slots.acquire(blocking=False):
            raise _WorkerCapacityError
        loop = asyncio.get_running_loop()
        concurrent_future = self._executor.submit(lambda: definition.implementation(**arguments))
        concurrent_future.add_done_callback(lambda _: self._worker_slots.release())
        future = asyncio.wrap_future(concurrent_future, loop=loop)
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=definition.execution_timeout)
        except asyncio.TimeoutError:
            future.cancel()  # Effective only if the work has not started; running Python threads cannot be killed.
            raise

    def _bounded_json_result(self, value: Any) -> Any:
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            normalized = json.loads(encoded)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("Tool result must be finite JSON data") from exc
        if len(encoded) > self._max_result_bytes:
            raise _OversizedResultError
        return normalized

    @staticmethod
    def _result(name: str, status: str, started: float, *, data: Any = None, error_code: str | None = None, message: str | None = None) -> ToolResult:
        return ToolResult(
            tool_name=name,
            status=status,
            result_data=data,
            error_code=error_code,
            safe_error_message=message,
            execution_duration=max(0.0, time.monotonic() - started),
        )

    def close(self) -> None:
        """Stop accepting work and cancel queued calls; running sync calls may finish in the background."""
        self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)


class _WorkerCapacityError(Exception):
    pass


class _OversizedResultError(Exception):
    pass
