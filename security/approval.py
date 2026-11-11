"""One-shot, operation-bound human approval interfaces."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import secrets
import time
from typing import Any, Protocol

from core.errors import ApprovalInterfaceError, AuthorizationCancelled
from core.tool_registry import ToolDefinition
from security.audit_logger import AuditLogger
from security.permissions import PermissionDecision, PermissionPolicyEngine, PolicyEvaluation


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"
    CANCEL = "cancel"


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str
    operation: str
    target_resource: str | None
    potential_impact: str
    arguments: dict[str, Any]
    expires_at: float


@dataclass(frozen=True)
class ApprovalResult:
    decision: ApprovalDecision
    receipt: str | None = None


class TrustedApprovalInterface(Protocol):
    """A trusted UI adapter; model text and tool results are never approval sources."""

    def request_approval(self, request: ApprovalRequest, timeout_seconds: float) -> ApprovalDecision: ...


def _binding(tool: ToolDefinition, arguments: dict[str, Any]) -> str:
    payload = json.dumps(
        {"tool": tool.name, "args": arguments},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApprovalManager:
    def __init__(
        self,
        interface: TrustedApprovalInterface | None,
        *,
        ttl_seconds: float = 60.0,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        if not 0 < ttl_seconds <= 600:
            raise ValueError("approval TTL must be between 0 and 600 seconds")
        self._interface = interface
        self._ttl = ttl_seconds
        self._audit_logger = audit_logger

    def request(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        evaluation: PolicyEvaluation,
    ) -> ApprovalResult:
        if self._interface is None:
            self._record(tool, arguments, ApprovalDecision.DENY, started=time.monotonic())
            return ApprovalResult(ApprovalDecision.DENY)
        now = time.monotonic()
        original_binding = _binding(tool, arguments)
        exact_arguments = json.loads(json.dumps(arguments, allow_nan=False))
        request = ApprovalRequest(
            approval_id=secrets.token_urlsafe(18),
            operation=f"{tool.name}: {tool.description}",
            target_resource=evaluation.target_resource,
            potential_impact=f"Permission level: {evaluation.permission_level.value}",
            arguments=exact_arguments,
            expires_at=now + self._ttl,
        )
        try:
            decision = self._interface.request_approval(request, self._ttl)
        except Exception as exc:
            self._record(tool, arguments, ApprovalDecision.DENY, started=now)
            raise ApprovalInterfaceError(
                "APPROVAL_INTERFACE_FAILED",
                "The approval interface failed; this action was denied",
            ) from exc
        if not isinstance(decision, ApprovalDecision):
            decision = ApprovalDecision.DENY
        if time.monotonic() > request.expires_at or decision is not ApprovalDecision.APPROVE:
            self._record(tool, arguments, decision, started=now)
            return ApprovalResult(decision)
        if _binding(tool, request.arguments) != original_binding:
            self._record(tool, arguments, ApprovalDecision.DENY, started=now)
            return ApprovalResult(ApprovalDecision.DENY)
        self._record(tool, arguments, decision, started=now)
        return ApprovalResult(decision, original_binding)

    def _record(
        self,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        decision: ApprovalDecision,
        *,
        started: float,
    ) -> None:
        if self._audit_logger:
            status = {
                ApprovalDecision.APPROVE: "approval_approved",
                ApprovalDecision.DENY: "approval_denied",
                ApprovalDecision.CANCEL: "approval_cancelled",
            }[decision]
            self._audit_logger.record(
                tool_name=tool.name,
                arguments=arguments,
                permission_decision="require_approval",
                execution_status=status,
                duration=max(0.0, time.monotonic() - started),
            )


class PolicyAuthorizer:
    """Adapter for ToolDispatcher that evaluates policy and consumes one-shot approval receipts."""

    def __init__(self, policy: PermissionPolicyEngine, approvals: ApprovalManager | None = None) -> None:
        self._policy = policy
        self._approvals = approvals or ApprovalManager(None)
        self._receipts: dict[str, PermissionDecision] = {}

    def authorize(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool:
        evaluation = self._policy.evaluate(tool, arguments)
        if evaluation.decision is PermissionDecision.ALLOW:
            self._receipts[_binding(tool, arguments)] = evaluation.decision
            return True
        if evaluation.decision is not PermissionDecision.REQUIRE_APPROVAL:
            return False
        result = self._approvals.request(tool, arguments, evaluation)
        if result.decision is ApprovalDecision.CANCEL:
            raise AuthorizationCancelled("APPROVAL_CANCELLED", "The user cancelled this operation")
        if result.decision is ApprovalDecision.APPROVE and result.receipt:
            self._receipts[result.receipt] = PermissionDecision.REQUIRE_APPROVAL
            return True
        return False

    def revalidate(self, tool: ToolDefinition, arguments: dict[str, Any]) -> bool:
        """Re-check current policy immediately before execution and consume its exact receipt."""
        evaluation = self._policy.evaluate(tool, arguments)
        binding = _binding(tool, arguments)
        issued_decision = self._receipts.pop(binding, None)
        if issued_decision is None:
            return False
        return evaluation.decision is issued_decision
