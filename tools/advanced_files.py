"""Bounded directory listing, recursive search, and metadata tools."""
from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path
import re
import stat
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import DirectoryEntry, PathAccessError, PathGuard


_MAX_DIRECTORY_ENTRIES = 5_000
_MAX_SCANNED_FILES = 10_000
_MAX_DEPTH = 10
_SAFE_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,16}$")


def _definition(name: str, description: str, schema: dict[str, Any], implementation: Any) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        category="filesystem",
        argument_schema=schema,
        permission_level="read",
        execution_timeout=20,
        implementation=implementation,
    )


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def list_directory(
    path_guard: PathGuard,
    path: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List a bounded, sorted page of direct directory entries."""
    if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
        raise ToolExecutionError("INVALID_PAGINATION", "Directory page limit or offset is outside supported bounds")
    try:
        entries = []
        truncated = False
        for entry in path_guard.iter_directory(path):
            if len(entries) >= _MAX_DIRECTORY_ENTRIES:
                truncated = True
                break
            entries.append(entry)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    entries.sort(key=lambda entry: entry.path.name.casefold())
    page = entries[offset:offset + limit]
    return {
        "path": str(Path(path)),
        "entries": [_entry_data(entry) for entry in page],
        "total_entries_scanned": len(entries),
        "offset": offset,
        "limit": limit,
        "truncated": truncated,
    }


def list_downloads(path_guard: PathGuard, root: str) -> dict[str, Any]:
    """Compatibility listing of the 20 most recently modified regular files."""
    try:
        entries = []
        scanned = 0
        truncated = False
        for entry in path_guard.iter_directory(root):
            scanned += 1
            if scanned > _MAX_DIRECTORY_ENTRIES:
                truncated = True
                break
            if stat.S_ISREG(entry.mode):
                entries.append(entry)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    entries.sort(key=lambda entry: entry.modified_time, reverse=True)
    return {
        "files": [entry.path.name for entry in entries[:20]],
        "total_files": len(entries),
        "scanned_limit_reached": truncated,
    }


def _entry_data(entry: DirectoryEntry) -> dict[str, Any]:
    return {
        "name": entry.path.name,
        "kind": _kind(entry.mode),
        "size_bytes": entry.size if stat.S_ISREG(entry.mode) else None,
        "modified_time": datetime.fromtimestamp(entry.modified_time, timezone.utc).isoformat(),
    }


def _walk_files(
    path_guard: PathGuard,
    root: str,
    depth_limit: int,
    max_scanned: int = _MAX_SCANNED_FILES,
) -> tuple[list[DirectoryEntry], int, bool]:
    if not 0 <= depth_limit <= _MAX_DEPTH:
        raise ToolExecutionError("INVALID_DEPTH", f"Recursive depth must be between 0 and {_MAX_DEPTH}")
    try:
        root_path = path_guard.validate(root, operation="list", must_exist=True)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    pending = [(root_path, 0)]
    files: list[DirectoryEntry] = []
    scanned = 0
    skipped_directories = 0
    truncated = False
    while pending:
        directory, depth = pending.pop()
        try:
            for entry in path_guard.iter_directory(directory):
                scanned += 1
                if scanned > max_scanned:
                    truncated = True
                    break
                if stat.S_ISLNK(entry.mode):
                    continue
                if stat.S_ISREG(entry.mode):
                    files.append(entry)
                elif stat.S_ISDIR(entry.mode) and depth < depth_limit:
                    pending.append((entry.path, depth + 1))
        except PathAccessError:
            if directory == root_path:
                raise ToolExecutionError("DIRECTORY_UNAVAILABLE", "Requested directory could not be scanned") from None
            skipped_directories += 1
            continue
        if truncated:
            break
    return files, skipped_directories, truncated


def _parse_date(value: str, field: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ToolExecutionError("INVALID_DATE", f"{field} must be an ISO 8601 date or timestamp") from None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def search_files_advanced(
    path_guard: PathGuard,
    root: str,
    filename_pattern: str = "*",
    extension: str = "",
    min_size: int = 0,
    max_size: int = 0,
    modified_after: str = "",
    modified_before: str = "",
    depth_limit: int = 3,
    sort_by: str = "name",
    descending: bool = False,
    limit: int = 10,
    offset: int = 0,
) -> dict[str, Any]:
    """Search safe regular files with bounded recursion, filters, sorting, and paging."""
    if not filename_pattern or len(filename_pattern) > 255 or "/" in filename_pattern or "\x00" in filename_pattern:
        raise ToolExecutionError("INVALID_PATTERN", "Filename pattern is invalid")
    if extension and not _SAFE_EXTENSION.fullmatch(extension):
        raise ToolExecutionError("INVALID_EXTENSION", "Extension must look like .txt or .py")
    if min_size < 0 or max_size < 0 or (max_size and max_size < min_size):
        raise ToolExecutionError("INVALID_SIZE_FILTER", "File size filters are invalid")
    if sort_by not in {"name", "size", "modified"}:
        raise ToolExecutionError("INVALID_SORT", "Sort field must be name, size, or modified")
    if not 1 <= limit <= 10 or not 0 <= offset <= 100_000:
        raise ToolExecutionError("INVALID_PAGINATION", "Search page limit or offset is outside supported bounds")
    after, before = _parse_date(modified_after, "modified_after"), _parse_date(modified_before, "modified_before")
    if after and before and after > before:
        raise ToolExecutionError("INVALID_DATE_RANGE", "modified_after must not be later than modified_before")

    files, skipped, truncated = _walk_files(path_guard, root, depth_limit)
    matches = []
    for entry in files:
        modified = datetime.fromtimestamp(entry.modified_time, timezone.utc)
        if not fnmatch.fnmatchcase(entry.path.name.casefold(), filename_pattern.casefold()):
            continue
        if extension and entry.path.suffix.casefold() != extension.casefold():
            continue
        if entry.size < min_size or (max_size and entry.size > max_size):
            continue
        if after and modified < after:
            continue
        if before and modified > before:
            continue
        matches.append(entry)
    key = {
        "name": lambda item: item.path.name.casefold(),
        "size": lambda item: item.size,
        "modified": lambda item: item.modified_time,
    }[sort_by]
    matches.sort(key=key, reverse=descending)
    page = matches[offset:offset + limit]
    return {
        "files": [
            {
                "name": item.path.name,
                "path": str(item.path),
                "size_bytes": item.size,
                "modified_time": datetime.fromtimestamp(item.modified_time, timezone.utc).isoformat(),
            }
            for item in page
        ],
        "total_matches": len(matches),
        "offset": offset,
        "limit": limit,
        "skipped_directories": skipped,
        "scanned_limit_reached": truncated,
    }


def get_file_metadata(path_guard: PathGuard, path: str) -> dict[str, Any]:
    """Return lstat-safe metadata for a guarded regular file or directory."""
    is_directory = False
    try:
        fd = path_guard.open_read(path)
    except PathAccessError:
        try:
            fd = path_guard.open_directory(path)
            is_directory = True
        except PathAccessError as exc:
            raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    try:
        info = os.fstat(fd)
    except OSError:
        raise ToolExecutionError("METADATA_UNAVAILABLE", "File metadata could not be read") from None
    finally:
        os.close(fd)
    return {
        "path": str(Path(path)),
        "name": Path(path).name,
        "kind": "directory" if is_directory else "file",
        "size_bytes": info.st_size,
        "modified_time": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
        "permissions": stat.S_IMODE(info.st_mode),
        "extension": Path(path).suffix if not is_directory else "",
    }


def find_large_files(
    path_guard: PathGuard,
    root: str,
    min_size: int = 0,
    depth_limit: int = 5,
    limit: int = 10,
) -> dict[str, Any]:
    """Find the largest authorized regular files under bounded scan/depth limits."""
    if min_size < 0:
        raise ToolExecutionError("INVALID_SIZE_FILTER", "Minimum file size cannot be negative")
    if not 1 <= limit <= 10:
        raise ToolExecutionError("INVALID_PAGINATION", "Result limit must be between 1 and 10")
    files, skipped, truncated = _walk_files(path_guard, root, depth_limit)
    large = sorted((item for item in files if item.size >= min_size), key=lambda item: item.size, reverse=True)
    return {
        "files": [
            {
                "name": item.path.name,
                "path": str(item.path),
                "size_bytes": item.size,
                "modified_time": datetime.fromtimestamp(item.modified_time, timezone.utc).isoformat(),
            }
            for item in large[:limit]
        ],
        "total_matches": len(large),
        "skipped_directories": skipped,
        "scanned_limit_reached": truncated,
    }


def register_advanced_file_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register four bounded file tools and the legacy recent-file listing."""
    path = {"type": "string", "minLength": 1}
    default_root = str(path_guard.allowed_roots[0])
    integer = lambda default, minimum, maximum: {
        "type": "integer", "minimum": minimum, "maximum": maximum, "default": default,
    }
    registry.register(_definition(
        "list_downloads",
        "List the 20 most recently modified regular files in the default allowed directory.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        lambda: list_downloads(path_guard, default_root),
    ))
    registry.register(_definition(
        "list_directory",
        "List sorted entries in an authorized directory with pagination.",
        {
            "type": "object",
            "properties": {
                "path": {**path, "default": default_root},
                "limit": integer(100, 1, 100),
                "offset": integer(0, 0, 100_000),
            },
            "required": [],
            "additionalProperties": False,
        },
        lambda path=default_root, limit=100, offset=0: list_directory(path_guard, path, limit, offset),
    ))
    registry.register(_definition(
        "search_files_advanced",
        "Search allowed files by name, extension, size, modification time, depth, and page.",
        {
            "type": "object",
            "properties": {
                "root": {**path, "default": default_root},
                "filename_pattern": {"type": "string", "minLength": 1, "maxLength": 255, "default": "*"},
                "extension": {"type": "string", "maxLength": 17, "default": ""},
                "min_size": integer(0, 0, 1_000_000_000_000),
                "max_size": integer(0, 0, 1_000_000_000_000),
                "modified_after": {"type": "string", "maxLength": 40, "default": ""},
                "modified_before": {"type": "string", "maxLength": 40, "default": ""},
                "depth_limit": integer(3, 0, _MAX_DEPTH),
                "sort_by": {"type": "string", "enum": ["name", "size", "modified"], "default": "name"},
                "descending": {"type": "boolean", "default": False},
                "limit": integer(10, 1, 10),
                "offset": integer(0, 0, 100_000),
            },
            "required": [],
            "additionalProperties": False,
        },
        lambda root=default_root, filename_pattern="*", extension="", min_size=0, max_size=0,
        modified_after="", modified_before="", depth_limit=3, sort_by="name",
        descending=False, limit=10, offset=0: search_files_advanced(
            path_guard, root, filename_pattern, extension, min_size, max_size,
            modified_after, modified_before, depth_limit, sort_by, descending, limit, offset,
        ),
    ))
    registry.register(_definition(
        "get_file_metadata",
        "Get safe metadata for an authorized regular file or directory.",
        {
            "type": "object",
            "properties": {"path": path},
            "required": ["path"],
            "additionalProperties": False,
        },
        lambda path: get_file_metadata(path_guard, path),
    ))
    registry.register(_definition(
        "find_large_files",
        "Find largest regular files under a scan-count and recursion-depth limit.",
        {
            "type": "object",
            "properties": {
                "root": {**path, "default": default_root},
                "min_size": integer(0, 0, 1_000_000_000_000),
                "depth_limit": integer(5, 0, _MAX_DEPTH),
                "limit": integer(10, 1, 10),
            },
            "required": [],
            "additionalProperties": False,
        },
        lambda root=default_root, min_size=0, depth_limit=5, limit=10: find_large_files(
            path_guard, root, min_size, depth_limit, limit,
        ),
    ))
