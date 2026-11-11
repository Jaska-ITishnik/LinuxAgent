"""Tests for policy decisions and one-shot human approval."""
from __future__ import annotations

import unittest

from core.errors import AuthorizationCancelled
from core.tool_dispatcher import ToolDispatcher
from core.tool_registry import ToolDefinition, ToolRegistry
from security.approval import (
    ApprovalDecision,
    ApprovalManager,
    PolicyAuthorizer,
)
from security.permissions import (
    PermissionDecision,
    PermissionLevel,
    PermissionPolicyEngine,
    PolicyConfig,
)


def create_note(path: str, content: str) -> dict[str, str]:
    return {"path": path, "content": content}


def definition(permission: str = "write") -> ToolDefinition:
    return ToolDefinition(
        name="create_note",
        description="Create a note",
        category="filesystem",
        argument_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        permission_level=permission,
        execution_timeout=1,
        implementation=create_note,
    )


class FakeApprovalInterface:
    def __init__(self, decision: ApprovalDecision, *, mutate: bool = False) -> None:
        self.decision = decision
        self.mutate = mutate
        self.requests = []

    def request_approval(self, request, timeout_seconds):
        self.requests.append(request)
        if self.mutate:
            request.arguments["content"] = "substituted"
        return self.decision


class ApprovalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tool = definition()
        self.policy = PermissionPolicyEngine(PolicyConfig(allowed_tools=frozenset({"create_note"})))
        self.arguments = {"path": "/tmp/note.txt", "content": "original"}

    def test_read_only_tool_is_allowed_by_explicit_policy(self) -> None:
        read_tool = definition("read")
        policy = PermissionPolicyEngine(PolicyConfig(allowed_tools=frozenset({"create_note"})))
        evaluation = policy.evaluate(read_tool, self.arguments)
        self.assertEqual(evaluation.decision, PermissionDecision.ALLOW)
        self.assertEqual(evaluation.permission_level, PermissionLevel.READ_ONLY)

    async def test_controlled_action_requires_trusted_approval(self) -> None:
        interface = FakeApprovalInterface(ApprovalDecision.APPROVE)
        authorizer = PolicyAuthorizer(self.policy, ApprovalManager(interface))
        registry = ToolRegistry([self.tool])
        dispatcher = ToolDispatcher(registry, authorizer=authorizer)
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({"tool_name": "create_note", "arguments": self.arguments})
        self.assertEqual(result.status, "success")
        self.assertEqual(len(interface.requests), 1)

    def test_missing_approval_interface_denies_controlled_action(self) -> None:
        authorizer = PolicyAuthorizer(self.policy)
        self.assertFalse(authorizer.authorize(self.tool, self.arguments))

    def test_denial_and_cancellation_are_not_approval(self) -> None:
        denied = PolicyAuthorizer(
            self.policy,
            ApprovalManager(FakeApprovalInterface(ApprovalDecision.DENY)),
        )
        self.assertFalse(denied.authorize(self.tool, self.arguments))
        cancelled = PolicyAuthorizer(
            self.policy,
            ApprovalManager(FakeApprovalInterface(ApprovalDecision.CANCEL)),
        )
        with self.assertRaises(AuthorizationCancelled):
            cancelled.authorize(self.tool, self.arguments)

    def test_arguments_changed_by_approval_interface_are_rejected(self) -> None:
        authorizer = PolicyAuthorizer(
            self.policy,
            ApprovalManager(FakeApprovalInterface(ApprovalDecision.APPROVE, mutate=True)),
        )
        self.assertFalse(authorizer.authorize(self.tool, self.arguments))

    def test_approval_is_bound_to_exact_arguments_and_consumed_once(self) -> None:
        authorizer = PolicyAuthorizer(
            self.policy,
            ApprovalManager(FakeApprovalInterface(ApprovalDecision.APPROVE)),
        )
        self.assertTrue(authorizer.authorize(self.tool, self.arguments))
        self.assertFalse(authorizer.revalidate(self.tool, {**self.arguments, "content": "different"}))
        self.assertTrue(authorizer.revalidate(self.tool, self.arguments))
        self.assertFalse(authorizer.revalidate(self.tool, self.arguments))

    def test_expired_approval_is_denied(self) -> None:
        class ExpiringInterface(FakeApprovalInterface):
            def request_approval(self, request, timeout_seconds):
                import time
                time.sleep(0.02)
                return ApprovalDecision.APPROVE

        authorizer = PolicyAuthorizer(self.policy, ApprovalManager(ExpiringInterface(ApprovalDecision.APPROVE), ttl_seconds=0.01))
        self.assertFalse(authorizer.authorize(self.tool, self.arguments))

    def test_prohibited_operation_is_denied(self) -> None:
        prohibited = definition("destructive")
        policy = PermissionPolicyEngine(
            PolicyConfig(
                allowed_tools=frozenset({"create_note"}),
                prohibited_tools=frozenset({"create_note"}),
            )
        )
        authorizer = PolicyAuthorizer(policy, ApprovalManager(FakeApprovalInterface(ApprovalDecision.APPROVE)))
        self.assertFalse(authorizer.authorize(prohibited, self.arguments))


if __name__ == "__main__":
    unittest.main()
