"""Read-only network and process diagnostics with bounded external checks."""
from __future__ import annotations

import math
import re
import time
from typing import Any

import httpx
import psutil

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry


_TRUSTED_ENDPOINTS = (
    "https://www.google.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
)
_MAX_INTERFACES = 100
_SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _safe_percent(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(result, 2) if math.isfinite(result) else 0.0


def _safe_name(value: Any, *, limit: int = 128) -> str:
    text = value if isinstance(value, str) else "unknown"
    return "".join(char for char in text if char.isprintable())[:limit] or "unknown"


def get_network_interfaces(limit: int = 50) -> dict[str, Any]:
    """Return interface status and traffic counters, not network addresses."""
    if not 1 <= limit <= _MAX_INTERFACES:
        raise ToolExecutionError("INVALID_LIMIT", "Interface result limit must be between 1 and 100")
    try:
        statuses = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True) or {}
    except (OSError, RuntimeError, psutil.Error):
        raise ToolExecutionError("NETWORK_INTERFACES_UNAVAILABLE", "Network interface details could not be read") from None
    result = []
    for name in sorted(statuses):
        status = statuses[name]
        traffic = counters.get(name)
        result.append({
            "name": _safe_name(name, limit=64) if _SAFE_INTERFACE.fullmatch(name) else "other",
            "is_up": bool(status.isup),
            "speed_mbps": max(0, int(status.speed or 0)),
            "mtu": max(0, int(status.mtu or 0)),
            "bytes_sent": int(traffic.bytes_sent) if traffic else 0,
            "bytes_received": int(traffic.bytes_recv) if traffic else 0,
            "packets_sent": int(traffic.packets_sent) if traffic else 0,
            "packets_received": int(traffic.packets_recv) if traffic else 0,
            "errors_in": int(traffic.errin) if traffic else 0,
            "errors_out": int(traffic.errout) if traffic else 0,
            "drops_in": int(traffic.dropin) if traffic else 0,
            "drops_out": int(traffic.dropout) if traffic else 0,
        })
    return {"interfaces": result[:limit], "total_interfaces": len(result)}


def check_internet_connectivity(
    endpoint: str = _TRUSTED_ENDPOINTS[0],
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Check one explicitly trusted endpoint without following redirects."""
    if endpoint not in _TRUSTED_ENDPOINTS:
        raise ToolExecutionError("UNTRUSTED_ENDPOINT", "Connectivity checks are limited to configured trusted endpoints")
    if not 0.5 <= timeout_seconds <= 10:
        raise ToolExecutionError("INVALID_TIMEOUT", "Connectivity timeout must be between 0.5 and 10 seconds")
    started = time.monotonic()
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            with client.stream("GET", endpoint, headers={"Accept": "*/*"}) as response:
                status_code = response.status_code
        return {
            "reachable": 200 <= status_code < 300,
            "endpoint": endpoint,
            "status_code": status_code,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "error": None if 200 <= status_code < 300 else "unexpected_http_status",
        }
    except httpx.TimeoutException:
        return {
            "reachable": False,
            "endpoint": endpoint,
            "status_code": None,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "error": "timeout",
        }
    except httpx.HTTPError:
        return {
            "reachable": False,
            "endpoint": endpoint,
            "status_code": None,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "error": "connection_error",
        }


def inspect_process(pid: int) -> dict[str, Any]:
    """Return resource details for one PID without command-line or environment data."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
        raise ToolExecutionError("INVALID_PID", "Process ID must be a positive integer")
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            name = _safe_name(process.name())
            status = _safe_name(process.status(), limit=32)
            cpu_percent = _safe_percent(process.cpu_percent(interval=None))
            memory = process.memory_info()
            memory_percent = _safe_percent(process.memory_percent())
            threads = max(0, int(process.num_threads()))
    except psutil.NoSuchProcess:
        raise ToolExecutionError("PROCESS_NOT_FOUND", "The process no longer exists") from None
    except psutil.AccessDenied:
        raise ToolExecutionError("PROCESS_ACCESS_DENIED", "Permission to inspect this process was denied") from None
    except (OSError, RuntimeError, psutil.Error):
        raise ToolExecutionError("PROCESS_INSPECTION_FAILED", "Process details could not be read") from None
    return {
        "pid": pid,
        "name": name,
        "status": status,
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "memory_bytes": int(memory.rss),
        "thread_count": threads,
    }


def get_system_uptime() -> dict[str, Any]:
    """Report boot time and elapsed system uptime."""
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = max(0, int(time.time() - boot_time))
    except (OSError, RuntimeError, psutil.Error, TypeError, ValueError):
        raise ToolExecutionError("UPTIME_UNAVAILABLE", "System uptime could not be read") from None
    days, remainder = divmod(uptime_seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    return {
        "boot_time_epoch": round(boot_time, 3),
        "uptime_seconds": uptime_seconds,
        "uptime_human": f"{days}d {hours}h {minutes}m {seconds}s",
    }


def register_network_diagnostic_tools(registry: ToolRegistry) -> None:
    """Register read-only interface, connectivity, process, and uptime tools."""
    registry.register(ToolDefinition(
        name="get_network_interfaces",
        description="Get bounded interface status and traffic counters without exposing IP addresses.",
        category="system",
        argument_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": _MAX_INTERFACES, "default": 50}},
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=5,
        implementation=get_network_interfaces,
    ))
    registry.register(ToolDefinition(
        name="check_internet_connectivity",
        description="Check connectivity to one configured trusted HTTPS endpoint without redirects.",
        category="system",
        argument_schema={
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "enum": list(_TRUSTED_ENDPOINTS), "default": _TRUSTED_ENDPOINTS[0]},
                "timeout_seconds": {"type": "number", "minimum": 0.5, "maximum": 10, "default": 5},
            },
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=12,
        implementation=check_internet_connectivity,
    ))
    registry.register(ToolDefinition(
        name="inspect_process",
        description="Inspect resource usage for one process ID without command lines or environment.",
        category="system",
        argument_schema={
            "type": "object",
            "properties": {"pid": {"type": "integer", "minimum": 1}},
            "required": ["pid"],
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=5,
        implementation=inspect_process,
    ))
    registry.register(ToolDefinition(
        name="get_system_uptime",
        description="Get system boot time and human-readable uptime.",
        category="system",
        argument_schema={"type": "object", "properties": {}, "additionalProperties": False},
        permission_level="read",
        execution_timeout=5,
        implementation=get_system_uptime,
    ))
