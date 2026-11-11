"""Approval-gated, no-overwrite file and directory mutations."""
from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_MAX_COPY_BYTES = 100 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


def _cleanup_destination(path_guard: PathGuard, destination: str, identity: os.stat_result | None) -> bool:
    if identity is None:
        return True
    try:
        path_guard.unlink_file(destination, expected=identity)
        return True
    except PathAccessError:
        return False


def _copy_contents(path_guard: PathGuard, source: str, destination: str) -> os.stat_result:
    source_fd = -1
    destination_fd = -1
    destination_stat: os.stat_result | None = None
    created = False
    try:
        source_fd = path_guard.open_read(source)
        source_stat = os.fstat(source_fd)
        if source_stat.st_size > _MAX_COPY_BYTES:
            raise ToolExecutionError("FILE_TOO_LARGE", "File exceeds the 100 MiB operation limit")
        destination_fd = path_guard.open_write(destination)
        created = True
        destination_stat = os.fstat(destination_fd)
        remaining = _MAX_COPY_BYTES + 1
        while remaining > 0:
            chunk = os.read(source_fd, min(_CHUNK_BYTES, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                raise ToolExecutionError("FILE_TOO_LARGE", "File exceeds the 100 MiB operation limit")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("file copy made no progress")
                view = view[written:]
        os.fsync(destination_fd)
        if os.fstat(source_fd).st_size != source_stat.st_size:
            raise ToolExecutionError("SOURCE_CHANGED", "Source changed while it was being copied")
        return source_stat
    except ToolExecutionError:
        if created and not _cleanup_destination(path_guard, destination, destination_stat):
            raise ToolExecutionError("PARTIAL_COPY", "Copy failed and its incomplete destination could not be removed") from None
        raise
    except FileExistsError:
        raise ToolExecutionError("DESTINATION_EXISTS", "Destination already exists; no files were changed") from None
    except PathAccessError as exc:
        if created and not _cleanup_destination(path_guard, destination, destination_stat):
            raise ToolExecutionError("PARTIAL_COPY", "Copy failed and its incomplete destination could not be removed") from None
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    except OSError:
        if created and not _cleanup_destination(path_guard, destination, destination_stat):
            raise ToolExecutionError("PARTIAL_COPY", "Copy failed and its incomplete destination could not be removed") from None
        raise ToolExecutionError("FILE_COPY_FAILED", "File copy failed; the source was preserved") from None
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def copy_file(path_guard: PathGuard, source: str, destination: str) -> dict[str, Any]:
    """Copy an authorized regular file to a new destination without overwriting."""
    if Path(source) == Path(destination):
        raise ToolExecutionError("SAME_PATH", "Source and destination must be different")
    try:
        source_stat = _copy_contents(path_guard, source, destination)
    except ToolExecutionError:
        raise
    return {
        "operation": "copy",
        "source": str(Path(source)),
        "destination": str(Path(destination)),
        "size_bytes": source_stat.st_size,
        "status": "completed",
    }


def move_file(path_guard: PathGuard, source: str, destination: str) -> dict[str, Any]:
    """Copy then remove the unchanged source; preserve source if removal fails."""
    if Path(source) == Path(destination):
        raise ToolExecutionError("SAME_PATH", "Source and destination must be different")
    try:
        source_fd = path_guard.open_read(source)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    try:
        source_stat = os.fstat(source_fd)
        if source_stat.st_size > _MAX_COPY_BYTES:
            raise ToolExecutionError("FILE_TOO_LARGE", "File exceeds the 100 MiB operation limit")
    finally:
        os.close(source_fd)

    copied = _copy_contents(path_guard, source, destination)
    if (copied.st_dev, copied.st_ino) != (source_stat.st_dev, source_stat.st_ino):
        raise ToolExecutionError(
            "SOURCE_CHANGED",
            "Source changed before move; the source and copied destination were preserved",
        )
    try:
        path_guard.unlink_file(source, expected=source_stat)
    except PathAccessError:
        raise ToolExecutionError(
            "MOVE_PARTIAL",
            "Destination was copied, but source could not be removed; both files may remain",
        ) from None
    return {
        "operation": "move",
        "source": str(Path(source)),
        "destination": str(Path(destination)),
        "size_bytes": copied.st_size,
        "status": "completed",
    }


def rename_file(path_guard: PathGuard, source: str, destination: str) -> dict[str, Any]:
    """Rename an authorized regular file without replacement or symlink following."""
    result = move_file(path_guard, source, destination)
    result["operation"] = "rename"
    return result


def create_directory(path_guard: PathGuard, path: str) -> dict[str, Any]:
    """Create one new authorized directory with owner-only permissions."""
    try:
        path_guard.create_directory(path, mode=0o700)
    except FileExistsError:
        raise ToolExecutionError("DESTINATION_EXISTS", "Directory already exists; no changes were made") from None
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    return {"operation": "create_directory", "path": str(Path(path)), "status": "created"}


def register_controlled_file_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register four controlled filesystem mutation tools."""
    source_schema = {"type": "string", "minLength": 1}
    destination_schema = {"type": "string", "minLength": 1}
    for name, description, implementation in (
        ("copy_file", "Copy a regular file to a new destination without overwriting.", copy_file),
        ("move_file", "Move a regular file without overwriting; preserve source on failure.", move_file),
        ("rename_file", "Rename a regular file without overwriting.", rename_file),
    ):
        registry.register(ToolDefinition(
            name=name,
            description=description,
            category="filesystem",
            argument_schema={
                "type": "object",
                "properties": {"source": source_schema, "destination": destination_schema},
                "required": ["source", "destination"],
                "additionalProperties": False,
            },
            permission_level="write",
            execution_timeout=30,
            implementation=lambda source, destination, operation=implementation: operation(
                path_guard, source, destination,
            ),
        ))
    registry.register(ToolDefinition(
        name="create_directory",
        description="Create one directory beneath an authorized root without replacing existing entries.",
        category="filesystem",
        argument_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "minLength": 1}},
            "required": ["path"],
            "additionalProperties": False,
        },
        permission_level="write",
        execution_timeout=10,
        implementation=lambda path: create_directory(path_guard, path),
    ))
