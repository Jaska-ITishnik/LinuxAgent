"""Ollama-backed language model adapter with bounded transport retries."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Any, Protocol, Sequence

import httpx
from ollama import Client, ResponseError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.config import OllamaConfig


class ToolCall(BaseModel):
    """A validated tool proposal returned by a language model."""

    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]


class ToolCallEnvelope(BaseModel):
    """Schema used when a model uses JSON output instead of native tools."""

    model_config = ConfigDict(extra="forbid", strict=True)
    tool_calls: list[ToolCall] = Field(max_length=32)


class LLMResponse(BaseModel):
    """Normalized model response independent of the Ollama SDK types."""

    model_config = ConfigDict(frozen=True)
    model: str
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


@dataclass(frozen=True)
class ModelCapabilities:
    native_tool_calling: bool
    structured_json: bool


class LLMClient(Protocol):
    """Provider-neutral interface consumed by a future agent service."""

    def chat(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        system_prompt: str | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        response_schema: dict[str, Any] | None = None,
        model: str | None = None,
    ) -> LLMResponse: ...

    def detect_capabilities(self, model: str | None = None) -> ModelCapabilities: ...


class LLMError(RuntimeError):
    """Base class for adapter failures, distinct from agent/planning errors."""


class LLMTransportError(LLMError):
    """A request could not be transported to Ollama."""


class LLMTimeoutError(LLMTransportError):
    """Ollama did not respond before the configured request timeout."""


class LLMConnectionError(LLMTransportError):
    """Ollama is unavailable or cannot be reached."""


class LLMResponseError(LLMError):
    """Ollama returned a response that is invalid or incomplete."""


class ModelUnavailableError(LLMError):
    """The configured model is not available; no fallback model is selected."""


class UnsupportedToolCallingError(LLMError):
    """The model/server cannot use native tools or structured JSON fallback."""


def _fallback_tool_schema(tools: Sequence[dict[str, Any]]) -> dict[str, Any]:
    choices = []
    for tool in tools:
        function = tool.get("function", {})
        name = function.get("name")
        parameters = function.get("parameters")
        if not isinstance(name, str) or not name or not isinstance(parameters, dict):
            raise UnsupportedToolCallingError("Tool fallback requires named tools with JSON object parameter schemas")
        choices.append({
            "type": "object",
            "properties": {
                "name": {"const": name},
                "arguments": parameters,
            },
            "required": ["name", "arguments"],
            "additionalProperties": False,
        })
    return {
        "type": "object",
        "properties": {
            "tool_calls": {"type": "array", "items": {"anyOf": choices}, "maxItems": 32},
        },
        "required": ["tool_calls"],
        "additionalProperties": False,
    }


def _validate_json_schema(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    """Validate common JSON Schema constraints used in tool parameter schemas."""
    expected = schema.get("type")
    type_checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if expected not in type_checks:
        raise ValueError(f"unsupported JSON Schema type at {path}")
    if not type_checks[expected](value):
        raise ValueError(f"wrong JSON type at {path}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"value outside enum at {path}")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"value does not match const at {path}")
    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if any(key not in value for key in required):
            raise ValueError(f"missing required property at {path}")
        if schema.get("additionalProperties") is False and any(key not in properties for key in value):
            raise ValueError(f"unexpected property at {path}")
        for key, child in value.items():
            if key in properties:
                _validate_json_schema(child, properties[key], f"{path}.{key}")
    elif expected == "array":
        items = schema.get("items")
        if items:
            for index, child in enumerate(value):
                _validate_json_schema(child, items, f"{path}[{index}]")
    elif expected == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            raise ValueError(f"string length invalid at {path}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValueError(f"string pattern mismatch at {path}")
    elif expected in {"integer", "number"}:
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            raise ValueError(f"number outside bounds at {path}")


class OllamaClient:
    """Reusable synchronous Ollama client; accepts an SDK-compatible client for tests."""

    def __init__(
        self,
        config: OllamaConfig,
        *,
        retries: int = 2,
        retry_delay: float = 0.2,
        client: Any | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        if not 0 <= retries <= 5:
            raise ValueError("retries must be between 0 and 5")
        if retry_delay < 0 or retry_delay > 5:
            raise ValueError("retry_delay must be between 0 and 5 seconds")
        self._config = config
        self._retries = retries
        self._retry_delay = retry_delay
        self._sleep = sleep
        self._client = client or Client(host=config.host, timeout=config.timeout)
        self._capabilities: dict[str, ModelCapabilities] = {}

    def _request(self, callback: Any) -> Any:
        for attempt in range(self._retries + 1):
            try:
                return callback()
            except (httpx.TimeoutException, TimeoutError) as exc:
                if attempt >= self._retries:
                    raise LLMTimeoutError("Ollama request timed out") from exc
            except (httpx.ConnectError, httpx.NetworkError, ConnectionError) as exc:
                if attempt >= self._retries:
                    raise LLMConnectionError("Cannot connect to Ollama; verify the local service is running") from exc
            except ResponseError as exc:
                if getattr(exc, "status_code", None) == 404:
                    raise ModelUnavailableError(f"Configured Ollama model '{self._config.model}' is unavailable") from None
                raise LLMTransportError(f"Ollama request failed (HTTP {getattr(exc, 'status_code', 'unknown')})") from None
            if self._retry_delay:
                self._sleep(self._retry_delay * (attempt + 1))
        raise LLMConnectionError("Cannot connect to Ollama")

    def detect_capabilities(self, model: str | None = None) -> ModelCapabilities:
        selected_model = model or self._config.model
        if selected_model in self._capabilities:
            return self._capabilities[selected_model]
        try:
            result = self._request(lambda: self._client.show(selected_model))
        except ModelUnavailableError:
            raise
        except LLMError:
            raise
        except Exception as exc:
            raise LLMTransportError("Could not inspect Ollama model capabilities") from exc
        capabilities = result.get("capabilities") if isinstance(result, dict) else getattr(result, "capabilities", None)
        if capabilities is None:
            raise LLMResponseError("Ollama model metadata did not include capabilities")
        normalized = {str(item).lower() for item in capabilities}
        detected = ModelCapabilities(native_tool_calling="tools" in normalized, structured_json=True)
        self._capabilities[selected_model] = detected
        return detected

    def chat(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        system_prompt: str | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        response_schema: dict[str, Any] | None = None,
        model: str | None = None,
    ) -> LLMResponse:
        selected_model = model or self._config.model
        if not selected_model.strip():
            raise ValueError("model must not be empty")
        prepared = [dict(message) for message in messages]
        if system_prompt:
            prepared.insert(0, {"role": "system", "content": system_prompt})
        if not prepared or any(message.get("role") not in {"system", "user", "assistant", "tool"} for message in prepared):
            raise LLMResponseError("Chat messages must include supported conversation roles")

        native_tools: Sequence[dict[str, Any]] | None = None
        structured_format: dict[str, Any] | None = None
        using_fallback = False
        if tools:
            capability = self.detect_capabilities(selected_model)
            if capability.native_tool_calling:
                native_tools = tools
            elif capability.structured_json:
                using_fallback = True
                structured_format = _fallback_tool_schema(tools)
                prepared.insert(0, {
                    "role": "system",
                    "content": "Return only JSON matching the supplied schema. Select tool names only from this list and place arguments in the arguments object: "
                    + json.dumps([tool.get("function", {}).get("name") for tool in tools]),
                })
            else:
                raise UnsupportedToolCallingError(f"Model '{selected_model}' does not support tool calling or structured JSON")
        elif response_schema is not None:
            structured_format = response_schema

        try:
            response = self._request(lambda: self._client.chat(
                model=selected_model,
                messages=prepared,
                tools=native_tools,
                format=structured_format,
                stream=False,
            ))
        except LLMTransportError as exc:
            if using_fallback and "HTTP 400" in str(exc):
                raise UnsupportedToolCallingError("Ollama does not support the requested structured JSON schema") from None
            raise
        except LLMError:
            raise
        except Exception as exc:
            raise LLMTransportError("Ollama chat request failed") from exc

        message = response.get("message") if isinstance(response, dict) else getattr(response, "message", None)
        if message is None:
            raise LLMResponseError("Ollama returned an incomplete response without a message")
        content = message.get("content", "") if isinstance(message, dict) else getattr(message, "content", "")
        raw_calls = message.get("tool_calls", []) if isinstance(message, dict) else getattr(message, "tool_calls", [])
        try:
            if using_fallback:
                payload = json.loads(content)
                envelope = ToolCallEnvelope.model_validate(payload)
                allowed_names = {tool.get("function", {}).get("name") for tool in tools or ()}
                if any(call.name not in allowed_names for call in envelope.tool_calls):
                    raise ValueError("structured response selected an unknown tool")
                schema_by_name = {
                    tool["function"]["name"]: tool["function"]["parameters"]
                    for tool in tools or ()
                }
                for call in envelope.tool_calls:
                    _validate_json_schema(call.arguments, schema_by_name[call.name])
                calls = tuple(envelope.tool_calls)
                content = ""
            else:
                calls = self._normalize_native_calls(raw_calls)
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
            raise LLMResponseError("Ollama returned an invalid structured tool response") from exc
        if not isinstance(content, str) or (not content.strip() and not calls):
            raise LLMResponseError("Ollama returned an empty or incomplete response")
        response_model = response.get("model", selected_model) if isinstance(response, dict) else getattr(response, "model", selected_model)
        if response_model and response_model != selected_model:
            raise LLMResponseError("Ollama response model did not match the requested model")
        return LLMResponse(model=str(response_model or selected_model), content=content, tool_calls=calls)

    @staticmethod
    def _normalize_native_calls(raw_calls: Any) -> tuple[ToolCall, ...]:
        normalized: list[ToolCall] = []
        for item in raw_calls or ():
            function = item.get("function", {}) if isinstance(item, dict) else getattr(item, "function", None)
            if function is None:
                raise ValueError("native tool call missing function")
            if isinstance(function, dict):
                name, arguments = function.get("name"), function.get("arguments")
            else:
                name, arguments = getattr(function, "name", None), getattr(function, "arguments", None)
            if not isinstance(arguments, dict):
                raise ValueError("native tool arguments must be an object")
            normalized.append(ToolCall(name=name, arguments=arguments))
        return tuple(normalized)
