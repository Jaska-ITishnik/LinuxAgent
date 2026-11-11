"""Compatibility migration for the original allowlisted desktop launcher."""
from __future__ import annotations

import subprocess
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry


_ALLOWED_APPS: dict[str, tuple[str, ...]] = {
    "calculator": ("gnome-calculator",),
    "files": ("nautilus",),
    "text_editor": ("gnome-text-editor",),
}


def open_application(app_name: str) -> dict[str, str]:
    """Request launch of a fixed application without shell interpretation."""
    command = _ALLOWED_APPS.get(app_name)
    if command is None:
        raise ToolExecutionError("APPLICATION_NOT_ALLOWED", "Application is not on the allowlist")
    try:
        subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError:
        raise ToolExecutionError("APPLICATION_LAUNCH_FAILED", "Application could not be launched") from None
    return {"status": "launch_requested", "application": app_name}


def register_desktop_tool(registry: ToolRegistry) -> None:
    registry.register(ToolDefinition(
        name="open_application",
        description="Launch one of three fixed desktop applications after trusted user approval.",
        category="desktop",
        argument_schema={
            "type": "object",
            "properties": {"app_name": {"type": "string", "enum": list(_ALLOWED_APPS)}},
            "required": ["app_name"],
            "additionalProperties": False,
        },
        permission_level="write",
        execution_timeout=5,
        implementation=open_application,
    ))
