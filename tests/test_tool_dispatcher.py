"""Secure dispatcher tests with inert in-process mock tools."""
from __future__ import annotations

import asyncio
import time
import unittest

from core.tool_dispatcher import AllowListAuthorizer, ToolCallRequest, ToolDispatcher
from core.tool_registry import ToolDefinition, ToolRegistry


ARGUMENT_SCHEMA = {
    "type": "object",
    "properties": {"value": {"type": "integer", "minimum": 0}},
    "required": ["value"],
    "additionalProperties": False,
}


def echo(value: int) -> dict[str, int]:
    return {"value": value}


def explode(value: int):
    raise RuntimeError("private stack detail")


def slow(value: int):
    time.sleep(0.15)
    return {"value": value}


async def async_echo(value: int):
    await asyncio.sleep(0)
    return {"value": value}


def make_definition(name="echo", implementation=echo, timeout=1):
    return ToolDefinition(
        name=name,
        description="Mock dispatcher tool",
        category="test",
        argument_schema=ARGUMENT_SCHEMA,
        permission_level="read",
        execution_timeout=timeout,
        implementation=implementation,
    )


class ToolDispatcherTests(unittest.IsolatedAsyncioTestCase):
    def dispatcher(self, definition=None, *, authorizer=None, max_bytes=1000):
        registry = ToolRegistry([definition or make_definition()])
        return ToolDispatcher(
            registry,
            authorizer=authorizer or AllowListAuthorizer(frozenset({(definition or make_definition()).name})),
            max_result_bytes=max_bytes,
        )

    async def test_valid_sync_execution(self):
        dispatcher = self.dispatcher()
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": 4}})
        self.assertEqual(result.status, "success")
        self.assertEqual(result.result_data, {"value": 4})
        self.assertIsNone(result.error_code)
        self.assertGreaterEqual(result.execution_duration, 0)

    async def test_valid_async_execution(self):
        dispatcher = self.dispatcher(make_definition("echo", async_echo))
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch(ToolCallRequest(tool_name="echo", arguments={"value": 2}))
        self.assertEqual(result.result_data, {"value": 2})

    async def test_invalid_arguments_rejected(self):
        dispatcher = self.dispatcher()
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": "4", "extra": True}})
        self.assertEqual(result.error_code, "INVALID_ARGUMENTS")

    async def test_numeric_schema_bounds_are_enforced(self):
        dispatcher = self.dispatcher()
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": -1}})
        self.assertEqual(result.error_code, "INVALID_ARGUMENTS")

    async def test_unknown_tool_rejected(self):
        dispatcher = self.dispatcher()
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "unknown", "arguments": {}})
        self.assertEqual(result.error_code, "UNKNOWN_TOOL")

    async def test_tool_exception_is_sanitized(self):
        dispatcher = self.dispatcher(make_definition("echo", explode))
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": 1}})
        self.assertEqual(result.error_code, "TOOL_EXECUTION_FAILED")
        self.assertNotIn("private stack detail", result.safe_error_message or "")

    async def test_sync_timeout_is_reported_and_worker_remains_bounded(self):
        dispatcher = self.dispatcher(make_definition("echo", slow, timeout=0.02))
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": 1}})
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.error_code, "EXECUTION_TIMEOUT")

    async def test_oversized_result_rejected(self):
        dispatcher = self.dispatcher(max_bytes=5)
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": 123456}})
        self.assertEqual(result.error_code, "RESULT_TOO_LARGE")

    async def test_default_authorizer_denies(self):
        dispatcher = ToolDispatcher(ToolRegistry([make_definition()]))
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "echo", "arguments": {"value": 1}})
        self.assertEqual(result.status, "denied")


if __name__ == "__main__":
    unittest.main()
