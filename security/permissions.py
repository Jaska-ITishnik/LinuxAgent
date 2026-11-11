"""Policy evaluation for registered tools and their target resources."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from core.tool_registry import ToolDefinition


class PermissionLevel(StrEnum):
    READ_ONLY = "read_only"
    CONTROLLED = "controlled"
    SENSITIVE = "sensitive"
    PROHIBITED = "prohibited"


class PermissionDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyConfig:
    allowed_tools: frozenset[str] = frozenset()
    prohibited_tools: frozenset[str] = frozenset()
    always_approval_tools: frozenset[str] = frozenset()
    approval_levels: frozenset[PermissionLevel] = frozenset({PermissionLevel.CONTROLLED, PermissionLevel.SENSITIVE})
    auto_allow_levels: frozenset[PermissionLevel] = frozenset({PermissionLevel.READ_ONLY})
    approval_if_true: frozenset[tuple[str, str]] = frozenset()


@dataclass(frozen=True)
class PolicyEvaluation:
    decision: PermissionDecision
    reason: str
    permission_level: PermissionLevel
    target_resource: str | None = None


class PermissionPolicyEngine:
    """Default-deny evaluation based on registry metadata and explicit user policy."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self._config = config or PolicyConfig()

    def evaluate(self, tool: ToolDefinition, arguments: dict[str, Any]) -> PolicyEvaluation:
        level = self._level(tool)
        if any(name == tool.name and arguments.get(key) is True for name, key in self._config.approval_if_true):
            level = PermissionLevel.CONTROLLED
        target = self._target(arguments)
        if tool.name in self._config.prohibited_tools or level is PermissionLevel.PROHIBITED:
            return PolicyEvaluation(PermissionDecision.DENY, "operation is prohibited", level, target)
        if tool.name not in self._config.allowed_tools:
            return PolicyEvaluation(PermissionDecision.DENY, "tool is not enabled by user policy", level, target)
        if tool.name in self._config.always_approval_tools:
            return PolicyEvaluation(PermissionDecision.REQUIRE_APPROVAL, "explicit user approval is always required", level, target)
        if level in self._config.approval_levels:
            return PolicyEvaluation(PermissionDecision.REQUIRE_APPROVAL, "explicit user approval is required", level, target)
        if level in self._config.auto_allow_levels:
            return PolicyEvaluation(PermissionDecision.ALLOW, "operation is allowed by user policy", level, target)
        return PolicyEvaluation(PermissionDecision.DENY, "no policy grants this operation", level, target)

    @staticmethod
    def _level(tool: ToolDefinition) -> PermissionLevel:
        mapping = {
            "read": PermissionLevel.READ_ONLY,
            "write": PermissionLevel.CONTROLLED,
            "external": PermissionLevel.SENSITIVE,
            "destructive": PermissionLevel.SENSITIVE,
        }
        return mapping.get(tool.permission_level, PermissionLevel.PROHIBITED)

    @staticmethod
    def _target(arguments: dict[str, Any]) -> str | None:
        for key in ("path", "target", "destination", "url"):
            value = arguments.get(key)
            if isinstance(value, str):
                return value[:512]
        return None
