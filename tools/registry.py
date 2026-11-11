"""Build the explicitly registered tool set from validated application policy."""
from __future__ import annotations

from typing import Any, Callable

from core.config import AppConfig
from core.tool_registry import ToolRegistry
from security.approval import ApprovalManager, PolicyAuthorizer, TrustedApprovalInterface
from security.audit_logger import AuditLogger
from security.path_guard import PathGuard
from security.permissions import PermissionLevel, PermissionPolicyEngine, PolicyConfig
from tools.advanced_files import register_advanced_file_tools
from tools.archives import register_archive_tools
from tools.controlled_files import register_controlled_file_tools
from tools.desktop import register_desktop_tool
from tools.documents import register_document_tools
from tools.document_writers import register_document_writer_tools
from tools.developer import register_developer_tools
from tools.functional import register_functional_tools
from tools.network_diagnostics import register_network_diagnostic_tools
from tools.system_monitor import register_system_monitor_tools
from tools.web import register_web_tools


def build_tool_registry(
    config: AppConfig,
    path_guard: PathGuard,
    *,
    weather_fetch_json: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
) -> ToolRegistry:
    """Create core and advanced tools, disabling categories absent from config."""
    registry = ToolRegistry()
    register_functional_tools(registry, path_guard, weather_fetch_json=weather_fetch_json)
    register_system_monitor_tools(registry)
    register_network_diagnostic_tools(registry)
    register_web_tools(registry)
    register_document_tools(registry, path_guard)
    register_document_writer_tools(registry, path_guard)
    register_developer_tools(registry, path_guard)
    register_advanced_file_tools(registry, path_guard)
    register_controlled_file_tools(registry, path_guard)
    register_archive_tools(registry, path_guard)
    register_desktop_tool(registry)
    enabled_categories = set(config.tools.enabled_categories)
    for definition in registry.list_tools(include_disabled=True):
        if definition.category not in enabled_categories:
            registry.disable(definition.name)
    return registry


def build_policy_authorizer(
    config: AppConfig,
    registry: ToolRegistry,
    *,
    approval_interface: TrustedApprovalInterface | None = None,
    audit_logger: AuditLogger | None = None,
) -> PolicyAuthorizer:
    """Bind enabled tool identities to the user's configured approval policy."""
    approval_levels = {
        "always": frozenset({PermissionLevel.CONTROLLED, PermissionLevel.SENSITIVE}),
        "destructive": frozenset({PermissionLevel.SENSITIVE}),
        "never": frozenset(),
    }[config.security.approval_policy]
    auto_allow_levels = {
        "always": frozenset({PermissionLevel.READ_ONLY}),
        "destructive": frozenset({PermissionLevel.READ_ONLY, PermissionLevel.CONTROLLED}),
        "never": frozenset({PermissionLevel.READ_ONLY}),
    }[config.security.approval_policy]
    allowed = frozenset(tool.name for tool in registry.list_tools())
    policy = PermissionPolicyEngine(PolicyConfig(
        allowed_tools=allowed,
        approval_levels=approval_levels,
        auto_allow_levels=auto_allow_levels,
        approval_if_true=frozenset({("organize_directory", "apply")}),
        always_approval_tools=frozenset({
            "create_markdown_document",
            "create_docx_document",
            "create_csv_document",
            "create_xlsx_document",
        }),
    ))
    approvals = ApprovalManager(
        approval_interface,
        ttl_seconds=min(60.0, config.agent.max_task_seconds),
        audit_logger=audit_logger,
    )
    return PolicyAuthorizer(policy, approvals)


def build_path_guard(config: AppConfig) -> PathGuard:
    """Create a filesystem guard from explicitly configured roots and protections."""
    return PathGuard(
        config.security.allowed_roots,
        config.security.protected_paths,
        allow_protected=config.security.allow_protected_paths,
    )
