"""Unit tests for OllamaClient with a deterministic SDK double."""
from __future__ import annotations

import unittest
import httpx

from core.config import OllamaConfig
from core.llm_client import (
    LLMConnectionError,
    LLMResponseError,
    LLMTimeoutError,
    ModelCapabilities,
    OllamaClient,
    UnsupportedToolCallingError,
)


TOOLS = [{"type": "function", "function": {"name": "status", "parameters": {"type": "object", "properties": {}}}}]


class FakeOllama:
    def __init__(self, *, capabilities=None, response=None, error=None):
        self.capabilities = capabilities or ["completion", "tools"]
        self.response = response or {"model": "test-model", "message": {"content": "hello", "tool_calls": []}}
        self.error = error
        self.chat_calls = []
        self.show_calls = []

    def show(self, model):
        self.show_calls.append(model)
        return {"capabilities": self.capabilities}

    def chat(self, **kwargs):
        self.chat_calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class OllamaClientTests(unittest.TestCase):
    def make_adapter(self, fake, *, retries=0):
        return OllamaClient(OllamaConfig(model="test-model"), client=fake, retries=retries, retry_delay=0)

    def test_successful_native_tool_response_and_prompt_history(self):
        fake = FakeOllama(response={
            "model": "test-model",
            "message": {"content": "", "tool_calls": [{"function": {"name": "status", "arguments": {"verbose": True}}}]},
        })
        result = self.make_adapter(fake).chat(
            [{"role": "user", "content": "status"}],
            system_prompt="System rules",
            tools=TOOLS,
        )
        self.assertEqual(result.tool_calls[0].name, "status")
        self.assertEqual(result.tool_calls[0].arguments, {"verbose": True})
        self.assertEqual(fake.chat_calls[0]["messages"][0]["content"], "System rules")
        self.assertEqual(fake.chat_calls[0]["messages"][1]["content"], "status")
        self.assertEqual(fake.chat_calls[0]["tools"], TOOLS)

    def test_timeout_is_classified_after_bounded_retries(self):
        fake = FakeOllama(error=httpx.ReadTimeout("slow"))
        with self.assertRaises(LLMTimeoutError):
            self.make_adapter(fake, retries=2).chat([{"role": "user", "content": "hi"}])
        self.assertEqual(len(fake.chat_calls), 3)

    def test_connection_failure_is_classified_after_retries(self):
        fake = FakeOllama(error=httpx.ConnectError("offline"))
        with self.assertRaises(LLMConnectionError):
            self.make_adapter(fake, retries=1).chat([{"role": "user", "content": "hi"}])
        self.assertEqual(len(fake.chat_calls), 2)

    def test_invalid_structured_fallback_response_rejected(self):
        fake = FakeOllama(
            capabilities=["completion"],
            response={"model": "test-model", "message": {"content": '{"tool_calls":[{"name":"other","arguments":{}}]}'}},
        )
        with self.assertRaises(LLMResponseError):
            self.make_adapter(fake).chat([{"role": "user", "content": "run"}], tools=TOOLS)
        self.assertIsNotNone(fake.chat_calls[0]["format"])
        self.assertIsNone(fake.chat_calls[0]["tools"])

    def test_structured_fallback_validates_tool_arguments(self):
        constrained_tools = [{"type": "function", "function": {
            "name": "lookup",
            "parameters": {
                "type": "object", "properties": {"limit": {"type": "integer"}},
                "required": ["limit"], "additionalProperties": False,
            },
        }}]
        fake = FakeOllama(
            capabilities=["completion"],
            response={"model": "test-model", "message": {"content": '{"tool_calls":[{"name":"lookup","arguments":{"limit":"all"}}]}'}},
        )
        with self.assertRaises(LLMResponseError):
            self.make_adapter(fake).chat([{"role": "user", "content": "lookup"}], tools=constrained_tools)

    def test_unsupported_tool_capability_rejected(self):
        fake = FakeOllama(capabilities=[])
        adapter = self.make_adapter(fake)
        adapter._capabilities["test-model"] = ModelCapabilities(False, False)
        with self.assertRaises(UnsupportedToolCallingError):
            adapter.chat([{"role": "user", "content": "run"}], tools=TOOLS)
        self.assertEqual(fake.chat_calls, [])

    def test_incomplete_model_response_rejected(self):
        fake = FakeOllama(response={"model": "test-model", "message": {"content": "", "tool_calls": []}})
        with self.assertRaises(LLMResponseError):
            self.make_adapter(fake).chat([{"role": "user", "content": "hi"}])

    def test_unexpected_response_model_is_rejected(self):
        fake = FakeOllama(response={"model": "different-model", "message": {"content": "hello"}})
        with self.assertRaisesRegex(LLMResponseError, "did not match"):
            self.make_adapter(fake).chat([{"role": "user", "content": "hi"}])


if __name__ == "__main__":
    unittest.main()
