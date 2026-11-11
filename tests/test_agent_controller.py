"""Execution-loop tests with mock model clients and inert tools."""
from __future__ import annotations

import asyncio
import unittest

from core.agent_controller import AgentController
from core.config import AgentConfig
from core.llm_client import LLMResponse, LLMResponseError, ToolCall
from core.tool_dispatcher import AllowListAuthorizer, DenyByDefaultAuthorizer, ToolDispatcher
from core.tool_registry import ToolDefinition, ToolRegistry
from security.approval import ApprovalDecision, ApprovalManager, PolicyAuthorizer
from security.permissions import PermissionPolicyEngine, PolicyConfig


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.messages = []
        self.tools = []

    def chat(self, messages, *, system_prompt=None, tools=None, response_schema=None, model=None):
        self.messages.append([dict(message) for message in messages])
        self.tools.append(tools)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeApproval:
    def request_approval(self, request, timeout_seconds):
        return ApprovalDecision.APPROVE


def echo(value: int) -> dict[str, int]:
    return {"value": value}


def fail_once(value: int) -> dict[str, int]:
    fail_once.attempts += 1
    if fail_once.attempts == 1:
        raise RuntimeError("temporary")
    return {"value": value}


fail_once.attempts = 0


def tool(name="echo", permission="read", implementation=echo) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="Echo integer",
        category="test",
        argument_schema={
            "type": "object",
            "properties": {"value": {"type": "integer"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        permission_level=permission,
        execution_timeout=1,
        implementation=implementation,
    )


def tool_response(name="echo", value=1) -> LLMResponse:
    return LLMResponse(
        model="test",
        tool_calls=(ToolCall(name=name, arguments={"value": value}),),
    )


def final_response(content="done") -> LLMResponse:
    return LLMResponse(model="test", content=content)


class AgentControllerTests(unittest.IsolatedAsyncioTestCase):
    def make_controller(self, responses, *, definition=None, authorizer=None, config=None):
        selected = definition or tool()
        registry = ToolRegistry([selected])
        dispatcher = ToolDispatcher(
            registry,
            authorizer=authorizer or AllowListAuthorizer(frozenset({selected.name})),
        )
        self.addCleanup(dispatcher.close)
        return AgentController(
            FakeLLM(responses),
            registry,
            dispatcher,
            config or AgentConfig(max_task_seconds=5),
        )

    async def test_single_tool_call_then_final_response(self):
        controller = self.make_controller([tool_response(value=4), final_response("4")])
        result = await controller.run("echo 4", session_id="s1", task_id="t1")
        self.assertEqual(result.answer, "4")
        self.assertEqual(result.steps, 2)
        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(result.tool_results[0].result_data, {"value": 4})

    async def test_multiple_tool_calls_are_executed_sequentially(self):
        controller = self.make_controller([
            LLMResponse(
                model="test",
                tool_calls=(ToolCall(name="echo", arguments={"value": 1}), ToolCall(name="echo", arguments={"value": 2})),
            ),
            final_response("both complete"),
        ])
        result = await controller.run("run twice")
        self.assertEqual(result.answer, "both complete")
        self.assertEqual(result.tool_calls, 2)
        self.assertEqual([item.result_data for item in result.tool_results], [{"value": 1}, {"value": 2}])

    async def test_controlled_tool_runs_after_human_approval(self):
        definition = tool(permission="write")
        policy = PermissionPolicyEngine(PolicyConfig(allowed_tools=frozenset({"echo"})))
        authorizer = PolicyAuthorizer(policy, ApprovalManager(FakeApproval()))
        controller = self.make_controller(
            [tool_response(), final_response()],
            definition=definition,
            authorizer=authorizer,
        )
        result = await controller.run("write")
        self.assertEqual(result.tool_results[0].status, "success")

    async def test_human_cancellation_stops_the_agent_loop(self):
        class CancelApproval:
            def request_approval(self, request, timeout_seconds):
                return ApprovalDecision.CANCEL

        definition = tool(permission="write")
        authorizer = PolicyAuthorizer(
            PermissionPolicyEngine(PolicyConfig(allowed_tools=frozenset({"echo"}))),
            ApprovalManager(CancelApproval()),
        )
        controller = self.make_controller(
            [tool_response(), final_response("must not be reached")],
            definition=definition,
            authorizer=authorizer,
        )
        result = await controller.run("write")
        self.assertTrue(result.cancelled)
        self.assertEqual(result.error_code, "CANCELLED")
        self.assertEqual(result.tool_results[0].error_code, "APPROVAL_CANCELLED")

    async def test_denied_tool_result_is_returned_to_model(self):
        controller = self.make_controller(
            [tool_response(), final_response("denied")],
            authorizer=DenyByDefaultAuthorizer(),
        )
        result = await controller.run("run")
        self.assertEqual(result.tool_results[0].status, "denied")

    async def test_step_limit_stops_repeated_model_tool_calls(self):
        controller = self.make_controller(
            [tool_response(), tool_response()],
            config=AgentConfig(max_steps=2, max_tool_calls=8, max_retries=0, max_task_seconds=5),
        )
        result = await controller.run("repeat")
        self.assertEqual(result.error_code, "STEP_LIMIT")
        self.assertEqual(result.steps, 2)

    async def test_tool_call_limit_is_enforced(self):
        controller = self.make_controller(
            [tool_response(), final_response()],
            config=AgentConfig(max_steps=3, max_tool_calls=0, max_retries=0, max_task_seconds=5),
        )
        result = await controller.run("no tools")
        self.assertEqual(result.error_code, "TOOL_CALL_LIMIT")
        self.assertEqual(result.tool_calls, 0)

    async def test_malformed_model_response_is_reported_safely(self):
        controller = self.make_controller([LLMResponseError("invalid structured tool response")])
        result = await controller.run("malformed")
        self.assertEqual(result.error_code, "LLMRESPONSEERROR")
        self.assertEqual(result.answer, "invalid structured tool response")

    async def test_cancellation_event_stops_before_model_request(self):
        controller = self.make_controller([final_response()])
        cancellation = asyncio.Event()
        cancellation.set()
        result = await controller.run("cancel", cancellation_event=cancellation)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.tool_calls, 0)

    async def test_cancellation_event_interrupts_pending_model_call(self):
        class SlowLLM:
            async def chat(self, messages, *, system_prompt=None, tools=None, response_schema=None, model=None):
                await asyncio.sleep(10)

        definition = tool()
        registry = ToolRegistry([definition])
        dispatcher = ToolDispatcher(registry, authorizer=AllowListAuthorizer(frozenset({"echo"})))
        self.addCleanup(dispatcher.close)
        controller = AgentController(
            SlowLLM(),
            registry,
            dispatcher,
            AgentConfig(max_task_seconds=5),
        )
        cancellation = asyncio.Event()
        task = asyncio.create_task(controller.run("cancel while waiting", cancellation_event=cancellation))
        await asyncio.sleep(0.01)
        cancellation.set()
        result = await asyncio.wait_for(task, timeout=0.5)
        self.assertTrue(result.cancelled)

    async def test_task_wall_clock_limit_is_enforced(self):
        class SlowLLM:
            async def chat(self, messages, *, system_prompt=None, tools=None, response_schema=None, model=None):
                await asyncio.sleep(0.1)

        definition = tool()
        registry = ToolRegistry([definition])
        dispatcher = ToolDispatcher(registry, authorizer=AllowListAuthorizer(frozenset({"echo"})))
        self.addCleanup(dispatcher.close)
        controller = AgentController(
            SlowLLM(),
            registry,
            dispatcher,
            AgentConfig(max_task_seconds=0.01),
        )
        result = await controller.run("timeout")
        self.assertEqual(result.error_code, "TASK_TIMEOUT")

    async def test_read_only_tool_failure_gets_bounded_retry(self):
        fail_once.attempts = 0
        controller = self.make_controller(
            [tool_response(), final_response()],
            definition=tool(implementation=fail_once),
            config=AgentConfig(max_steps=3, max_tool_calls=4, max_retries=1, max_task_seconds=5),
        )
        result = await controller.run("retry")
        self.assertEqual(result.tool_calls, 2)
        self.assertEqual([item.status for item in result.tool_results], ["error", "success"])


if __name__ == "__main__":
    unittest.main()
