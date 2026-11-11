"""Registry tests use simple inert callables; no local tools are invoked."""
from __future__ import annotations

import unittest

from pydantic import ValidationError

from core.tool_registry import (
    DisabledToolError,
    DuplicateToolError,
    ToolDefinition,
    ToolRegistry,
    UnknownToolError,
)


def mock_lookup(query: str) -> dict[str, str]:
    return {"query": query}


def make_tool(name: str = "lookup", *, category: str = "filesystem") -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="Look up a mock item",
        category=category,
        argument_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1}},
            "required": ["query"],
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=2,
        implementation=mock_lookup,
    )


class ToolRegistryTests(unittest.TestCase):
    def test_register_and_generate_model_schema(self):
        registry = ToolRegistry()
        registry.register(make_tool())
        self.assertIs(registry.get("lookup").implementation, mock_lookup)
        self.assertEqual(registry.list_by_category("filesystem")[0].name, "lookup")
        schema = registry.model_schemas()[0]
        self.assertEqual(schema["function"]["name"], "lookup")
        self.assertNotIn("implementation", str(schema))

    def test_duplicate_registration_rejected(self):
        registry = ToolRegistry([make_tool()])
        with self.assertRaises(DuplicateToolError):
            registry.register(make_tool())

    def test_invalid_schema_rejected(self):
        with self.assertRaises(ValidationError):
            ToolDefinition(
                name="bad",
                description="Bad schema",
                category="system",
                argument_schema={"type": "object", "required": ["missing"], "properties": {}},
                permission_level="read",
                execution_timeout=1,
                implementation=mock_lookup,
            )

    def test_disabled_tool_cannot_be_selected_or_exposed(self):
        registry = ToolRegistry([make_tool()])
        registry.disable("lookup")
        with self.assertRaises(DisabledToolError):
            registry.get("lookup")
        self.assertEqual(registry.model_schemas(), [])
        self.assertEqual(registry.list_tools(include_disabled=True)[0].name, "lookup")
        registry.enable("lookup")
        self.assertEqual(registry.get("lookup").name, "lookup")

    def test_unknown_tool_rejected(self):
        registry = ToolRegistry()
        with self.assertRaises(UnknownToolError):
            registry.get("model_supplied_name")
        with self.assertRaises(UnknownToolError):
            registry.disable("model_supplied_name")


if __name__ == "__main__":
    unittest.main()
