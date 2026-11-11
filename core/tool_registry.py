"""Explicit, allowlisted registry for callable agent tools."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


PermissionLevel = Literal["read", "write", "external", "destructive"]
ToolImplementation = Callable[..., Any]


def _validate_schema_definition(schema: Any, location: str = "argument_schema") -> None:
    """Fail closed on malformed JSON Schema structures used for tool arguments."""
    if not isinstance(schema, dict):
        raise ValueError(f"{location} must be a JSON object schema")
    supported_types = {"object", "array", "string", "integer", "number", "boolean", "null"}
    schema_type = schema.get("type")
    if schema_type not in supported_types:
        raise ValueError(f"{location}.type must be a supported JSON Schema type")
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not all(isinstance(key, str) for key in properties):
            raise ValueError(f"{location}.properties must be an object")
        if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
            raise ValueError(f"{location}.required must be a list of property names")
        if not set(required).issubset(properties):
            raise ValueError(f"{location}.required contains an unknown property")
        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, (bool, dict)):
            raise ValueError(f"{location}.additionalProperties must be boolean or a schema")
        for key, child in properties.items():
            _validate_schema_definition(child, f"{location}.properties.{key}")
        if isinstance(additional, dict):
            _validate_schema_definition(additional, f"{location}.additionalProperties")
    elif schema_type == "array":
        if "items" not in schema:
            raise ValueError(f"{location}.items is required for array schemas")
        _validate_schema_definition(schema["items"], f"{location}.items")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise ValueError(f"{location}.enum must be a non-empty list")
    for key in ("minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"):
        if key in schema and (isinstance(schema[key], bool) or not isinstance(schema[key], (int, float)) or schema[key] < 0):
            raise ValueError(f"{location}.{key} must be a non-negative number")


class ToolDefinition(BaseModel):
    """Validated metadata and an explicit Python callable for one tool."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True, frozen=True)

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    description: str = Field(min_length=1, max_length=1000)
    category: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    argument_schema: dict[str, Any]
    permission_level: PermissionLevel
    execution_timeout: float = Field(gt=0, le=300)
    implementation: ToolImplementation = Field(exclude=True, repr=False)

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("description must not be empty")
        return value

    @field_validator("argument_schema")
    @classmethod
    def validate_argument_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_schema_definition(value)
        if value.get("type") != "object":
            raise ValueError("tool arguments must use a top-level object schema")
        return value

    @field_validator("implementation")
    @classmethod
    def validate_implementation(cls, value: ToolImplementation) -> ToolImplementation:
        if not callable(value):
            raise ValueError("implementation must be a callable registered explicitly")
        return value

    def model_schema(self) -> dict[str, Any]:
        """Return the Ollama/OpenAI compatible function schema (no implementation)."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.argument_schema,
            },
        }


class ToolRegistryError(ValueError):
    """Base exception for registry lookup and registration failures."""


class DuplicateToolError(ToolRegistryError):
    """Raised when a tool name is registered more than once."""


class UnknownToolError(ToolRegistryError):
    """Raised when a requested tool is not explicitly registered."""


class DisabledToolError(ToolRegistryError):
    """Raised when a registered tool is disabled."""


class ToolRegistry:
    """Registry whose only executable references are explicitly registered callables."""

    def __init__(self, definitions: Iterable[ToolDefinition] = ()) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        self._enabled: set[str] = set()
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ToolDefinition, *, enabled: bool = True) -> None:
        if definition.name in self._definitions:
            raise DuplicateToolError(f"Tool '{definition.name}' is already registered")
        self._definitions[definition.name] = definition
        if enabled:
            self._enabled.add(definition.name)

    def enable(self, name: str) -> None:
        self._require_registered(name)
        self._enabled.add(name)

    def disable(self, name: str) -> None:
        self._require_registered(name)
        self._enabled.discard(name)

    def get(self, name: str) -> ToolDefinition:
        definition = self._require_registered(name)
        if name not in self._enabled:
            raise DisabledToolError(f"Tool '{name}' is disabled")
        return definition

    def list_tools(self, *, category: str | None = None, include_disabled: bool = False) -> tuple[ToolDefinition, ...]:
        return tuple(
            definition
            for name, definition in self._definitions.items()
            if (category is None or definition.category == category)
            and (include_disabled or name in self._enabled)
        )

    def list_by_category(self, category: str, *, include_disabled: bool = False) -> tuple[ToolDefinition, ...]:
        return self.list_tools(category=category, include_disabled=include_disabled)

    def model_schemas(self, *, category: str | None = None) -> list[dict[str, Any]]:
        """Generate function schemas only for enabled tools registered in this instance."""
        return [definition.model_schema() for definition in self.list_tools(category=category)]

    def _require_registered(self, name: str) -> ToolDefinition:
        try:
            return self._definitions[name]
        except KeyError:
            raise UnknownToolError(f"Tool '{name}' is not registered") from None
