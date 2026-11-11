"""Read-only CPU, memory, disk, and process monitoring tools."""
from __future__ import annotations

import math
import re
from typing import Any

import psutil

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry


_MAX_DISKS = 50
_MAX_PROCESSES = 50
_SAFE_FILESYSTEM = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")


def _readable_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if amount < 1024 or unit == "PB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PB"


def _percent(value: Any) -> float:
    try:
        normalized = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(normalized, 2) if math.isfinite(normalized) else 0.0


def get_cpu_details() -> dict[str, Any]:
    """Return CPU utilization and core counts."""
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        usage = psutil.cpu_percent(interval=0.1)
    except (OSError, RuntimeError):
        raise ToolExecutionError("CPU_DETAILS_UNAVAILABLE", "CPU details could not be read") from None
    return {
        "usage_percent": _percent(usage),
        "logical_cores": logical or 0,
        "physical_cores": physical,
    }


def get_memory_details() -> dict[str, Any]:
    """Return RAM and swap utilization."""
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
    except (OSError, RuntimeError):
        raise ToolExecutionError("MEMORY_DETAILS_UNAVAILABLE", "Memory details could not be read") from None
    return {
        "ram": {
            "total_bytes": memory.total,
            "used_bytes": memory.used,
            "available_bytes": memory.available,
            "used_percent": _percent(memory.percent),
            "total_readable": _readable_bytes(memory.total),
            "available_readable": _readable_bytes(memory.available),
        },
        "swap": {
            "total_bytes": swap.total,
            "used_bytes": swap.used,
            "free_bytes": swap.free,
            "used_percent": _percent(swap.percent),
            "total_readable": _readable_bytes(swap.total),
            "free_readable": _readable_bytes(swap.free),
        },
    }


def get_disk_details(limit: int = 20) -> dict[str, Any]:
    """Return usage for mounted filesystems, skipping inaccessible mounts."""
    if not 1 <= limit <= _MAX_DISKS:
        raise ToolExecutionError("INVALID_LIMIT", "Disk result limit must be between 1 and 50")
    try:
        partitions = psutil.disk_partitions(all=False)
    except (OSError, RuntimeError):
        raise ToolExecutionError("DISK_DETAILS_UNAVAILABLE", "Mounted filesystem details could not be read") from None
    disks = []
    skipped = 0
    seen_mountpoints: set[str] = set()
    for partition in partitions:
        mountpoint = str(partition.mountpoint)
        if mountpoint in seen_mountpoints:
            continue
        seen_mountpoints.add(mountpoint)
        try:
            usage = psutil.disk_usage(mountpoint)
        except (OSError, psutil.Error):
            skipped += 1
            continue
        filesystem = str(partition.fstype)
        disks.append({
            "mountpoint": mountpoint[:256],
            "filesystem": filesystem if _SAFE_FILESYSTEM.fullmatch(filesystem) else "other",
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": _percent(usage.percent),
            "total_readable": _readable_bytes(usage.total),
            "free_readable": _readable_bytes(usage.free),
        })
    disks.sort(key=lambda item: item["mountpoint"])
    return {"filesystems": disks[:limit], "total_accessible": len(disks), "skipped": skipped}


def list_processes(sort_by: str = "cpu", limit: int = 10) -> dict[str, Any]:
    """List top processes without collecting command lines or environment data."""
    if sort_by not in {"cpu", "memory"}:
        raise ToolExecutionError("INVALID_SORT", "Process sort must be cpu or memory")
    if not 1 <= limit <= _MAX_PROCESSES:
        raise ToolExecutionError("INVALID_LIMIT", "Process result limit must be between 1 and 50")
    processes = []
    inaccessible = 0
    try:
        process_iterator = psutil.process_iter(
            attrs=("pid", "name", "cpu_percent", "memory_percent", "memory_info"),
            ad_value=None,
        )
        for process in process_iterator:
            try:
                info = process.info
                memory_info = info.get("memory_info")
                name = info.get("name")
                safe_name = "".join(character for character in (name if isinstance(name, str) else "unknown") if character.isprintable())[:128]
                processes.append({
                    "pid": int(info["pid"]),
                    "name": safe_name or "unknown",
                    "cpu_percent": _percent(info.get("cpu_percent")),
                    "memory_percent": _percent(info.get("memory_percent")),
                    "memory_bytes": int(memory_info.rss) if memory_info is not None else 0,
                })
            except (KeyError, TypeError, ValueError, OSError, psutil.Error):
                inaccessible += 1
    except (OSError, RuntimeError, psutil.Error):
        raise ToolExecutionError("PROCESS_LIST_UNAVAILABLE", "Process information could not be read") from None
    key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
    processes.sort(key=lambda process: (-process[key], process["pid"]))
    return {
        "processes": processes[:limit],
        "sort_by": sort_by,
        "total_accessible": len(processes),
        "inaccessible": inaccessible,
    }


def register_system_monitor_tools(registry: ToolRegistry) -> None:
    """Register read-only system monitoring tools."""
    registry.register(ToolDefinition(
        name="get_cpu_details",
        description="Get CPU utilization and logical and physical core counts.",
        category="system",
        argument_schema={"type": "object", "properties": {}, "additionalProperties": False},
        permission_level="read",
        execution_timeout=5,
        implementation=get_cpu_details,
    ))
    registry.register(ToolDefinition(
        name="get_memory_details",
        description="Get RAM and swap capacity and utilization.",
        category="system",
        argument_schema={"type": "object", "properties": {}, "additionalProperties": False},
        permission_level="read",
        execution_timeout=5,
        implementation=get_memory_details,
    ))
    registry.register(ToolDefinition(
        name="get_disk_details",
        description="Get bounded usage statistics for mounted filesystems.",
        category="system",
        argument_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": _MAX_DISKS, "default": 20}},
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=10,
        implementation=get_disk_details,
    ))
    registry.register(ToolDefinition(
        name="list_processes",
        description="List bounded top processes by CPU or memory without command lines or environment.",
        category="system",
        argument_schema={
            "type": "object",
            "properties": {
                "sort_by": {"type": "string", "enum": ["cpu", "memory"], "default": "cpu"},
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_PROCESSES, "default": 10},
            },
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=10,
        implementation=list_processes,
    ))
