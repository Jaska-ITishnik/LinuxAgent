"""Preview-first file organization and bounded ZIP/TAR archive tools."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_MAX_FILES = 500
_MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 1000
_MAX_COMPRESSION_RATIO = 100
_CATEGORY_RULES = {
    "documents": {".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".md"},
    "images": {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"},
    "audio": {".aac", ".flac", ".m4a", ".mp3", ".ogg", ".wav"},
    "video": {".avi", ".mkv", ".mov", ".mp4", ".webm"},
    "archives": {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"},
    "code": {".c", ".cpp", ".go", ".java", ".js", ".py", ".rs", ".sh", ".ts"},
}
_SAFE_ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9._ -]{1,128}$")


def _validate_archive_name(name: str) -> str:
    if not _SAFE_ARCHIVE_NAME.fullmatch(name) or name in {".", ".."}:
        raise ToolExecutionError("INVALID_ARCHIVE_NAME", "Archive name contains unsupported characters")
    return name


def _relative_member(name: str) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive contains an unsafe path")
    member = PurePosixPath(name)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive path traversal is not allowed")
    if member.parts and ":" in member.parts[0]:
        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive contains an unsafe path")
    if len(member.parts) > 16 or any(len(part) > 255 for part in member.parts):
        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive path exceeds limits")
    return member


def _file_sha256(path_guard: PathGuard, path: str) -> str:
    try:
        fd = path_guard.open_read(path)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    digest = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > _MAX_ARCHIVE_BYTES:
                raise ToolExecutionError("FILE_TOO_LARGE", "File exceeds the hashing limit")
            digest.update(chunk)
    except OSError:
        raise ToolExecutionError("FILE_READ_FAILED", "File could not be read for hashing") from None
    finally:
        os.close(fd)
    return digest.hexdigest()


def find_duplicate_files(path_guard: PathGuard, root: str, limit: int = 100) -> dict[str, Any]:
    """Find duplicate regular files by size then SHA-256 without deleting anything."""
    if not 1 <= limit <= 100:
        raise ToolExecutionError("INVALID_LIMIT", "Duplicate result limit must be between 1 and 100")
    try:
        entries = list(path_guard.iter_directory(root))
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    files = [entry for entry in entries if stat.S_ISREG(entry.mode)]
    if len(files) > _MAX_FILES:
        raise ToolExecutionError("SCAN_LIMIT", "Directory exceeds the duplicate scan limit")
    by_size: dict[int, list[str]] = {}
    for entry in files:
        by_size.setdefault(entry.size, []).append(str(entry.path))
    groups = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_hash: dict[str, list[str]] = {}
        for path in paths:
            by_hash.setdefault(_file_sha256(path_guard, path), []).append(path)
        for digest, duplicates in by_hash.items():
            if len(duplicates) > 1:
                groups.append({"sha256": digest, "size_bytes": size, "paths": sorted(duplicates)})
    groups.sort(key=lambda item: (-item["size_bytes"], item["paths"]))
    return {"duplicate_groups": groups[:limit], "total_groups": len(groups), "deleted": False}


def plan_organization(
    path_guard: PathGuard,
    root: str,
    extension_rules: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Generate a deterministic file-to-category move plan without changing files."""
    rules = {key: set(value) for key, value in _CATEGORY_RULES.items()}
    if extension_rules is not None:
        if len(extension_rules) > 32:
            raise ToolExecutionError("INVALID_RULES", "Too many category rules")
        rules = {}
        for category, extensions in extension_rules.items():
            if not _SAFE_ARCHIVE_NAME.fullmatch(category) or not isinstance(extensions, list) or len(extensions) > 64:
                raise ToolExecutionError("INVALID_RULES", "Category rules are invalid")
            normalized = set()
            for extension in extensions:
                if not isinstance(extension, str) or not re.fullmatch(r"\.[A-Za-z0-9]{1,16}", extension):
                    raise ToolExecutionError("INVALID_RULES", "File extensions in category rules are invalid")
                normalized.add(extension.casefold())
            rules[category] = normalized
    try:
        entries = list(path_guard.iter_directory(root))
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    if len(entries) > _MAX_FILES:
        raise ToolExecutionError("SCAN_LIMIT", "Directory exceeds the organization plan limit")
    plan = []
    for entry in sorted(entries, key=lambda item: item.path.name.casefold()):
        if not stat.S_ISREG(entry.mode):
            continue
        if entry.path.name in {".", ".."} or "/" in entry.path.name or "\x00" in entry.path.name:
            raise ToolExecutionError("INVALID_FILENAME", "Directory contains a filename that cannot be organized safely")
        extension = entry.path.suffix.casefold()
        category = next((name for name, extensions in rules.items() if extension in extensions), "other")
        destination = Path(root) / category / entry.path.name
        plan.append({
            "source": str(entry.path),
            "destination": str(destination),
            "category": category,
            "conflict": destination.exists() or destination.is_symlink(),
        })
    return {"root": str(Path(root)), "plan": plan, "file_count": len(plan), "preview_only": True}


def organize_directory(
    path_guard: PathGuard,
    root: str,
    apply: bool = False,
    extension_rules: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Preview organization by default; when approved, move files without overwrites."""
    plan = plan_organization(path_guard, root, extension_rules)
    if not apply:
        return plan
    conflicts = [item["destination"] for item in plan["plan"] if item["conflict"]]
    if conflicts:
        raise ToolExecutionError(
            "DESTINATION_EXISTS",
            f"Organization would overwrite an existing destination: {Path(conflicts[0]).name}",
        )
    try:
        for category in sorted({item["category"] for item in plan["plan"]}):
            folder = Path(root) / category
            if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
                raise ToolExecutionError("DESTINATION_CONFLICT", "Category destination is not a safe directory")
            if not folder.exists():
                path_guard.create_directory(folder)
        completed = []
        for item in plan["plan"]:
            from tools.controlled_files import move_file
            completed.append(move_file(path_guard, item["source"], item["destination"]))
        return {"root": str(Path(root)), "moved": completed, "status": "organized"}
    except ToolExecutionError:
        raise
    except (PathAccessError, OSError) as exc:
        raise ToolExecutionError(
            "ORGANIZATION_PARTIAL",
            "Organization stopped after an error; review completed moves before retrying",
        ) from exc


def create_archive(
    path_guard: PathGuard,
    root: str,
    archive_path: str,
    format: str = "zip",
) -> dict[str, Any]:
    """Create a bounded ZIP or TAR archive from direct regular-file children."""
    if format not in {"zip", "tar"}:
        raise ToolExecutionError("INVALID_ARCHIVE_FORMAT", "Archive format must be zip or tar")
    extension = ".zip" if format == "zip" else ".tar"
    if Path(archive_path).suffix.casefold() != extension:
        raise ToolExecutionError("INVALID_ARCHIVE_PATH", f"Archive destination must end in {extension}")
    try:
        entries = [entry for entry in path_guard.iter_directory(root) if stat.S_ISREG(entry.mode)]
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    if len(entries) > _MAX_ARCHIVE_ENTRIES:
        raise ToolExecutionError("ARCHIVE_ENTRY_LIMIT", "Too many files to archive")
    total = sum(entry.size for entry in entries)
    if total > _MAX_ARCHIVE_BYTES:
        raise ToolExecutionError("ARCHIVE_SIZE_LIMIT", "Input exceeds the archive size limit")
    for entry in entries:
        _relative_member(entry.path.name)
    fd = -1
    target_identity = None
    try:
        fd = path_guard.open_write(archive_path)
        target_identity = os.fstat(fd)
        with os.fdopen(fd, "w+b") as output:
            fd = -1
            if format == "zip":
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    for entry in entries:
                        with os.fdopen(path_guard.open_read(entry.path), "rb") as source:
                            info = zipfile.ZipInfo(entry.path.name)
                            info.compress_type = zipfile.ZIP_DEFLATED
                            with archive.open(info, "w") as member:
                                while chunk := source.read(1024 * 1024):
                                    member.write(chunk)
            else:
                with tarfile.open(fileobj=output, mode="w") as archive:
                    for entry in entries:
                        with os.fdopen(path_guard.open_read(entry.path), "rb") as source:
                            info = tarfile.TarInfo(entry.path.name)
                            info.size = entry.size
                            info.mode = 0o600
                            archive.addfile(info, source)
            output.flush()
            os.fsync(output.fileno())
            size = output.tell()
            if size > _MAX_ARCHIVE_BYTES:
                raise ToolExecutionError("ARCHIVE_SIZE_LIMIT", "Created archive exceeds the size limit")
    except FileExistsError:
        raise ToolExecutionError("DESTINATION_EXISTS", "Archive destination already exists") from None
    except ToolExecutionError:
        _remove_partial_archive(path_guard, archive_path, target_identity)
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        _remove_partial_archive(path_guard, archive_path, target_identity)
        raise ToolExecutionError("ARCHIVE_CREATE_FAILED", "Archive could not be created") from None
    finally:
        if fd >= 0:
            os.close(fd)
    return {"archive_path": str(Path(archive_path)), "format": format, "files_archived": len(entries), "size_bytes": size}


def _remove_partial_archive(path_guard: PathGuard, path: str, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        path_guard.unlink_file(path, expected=identity)
    except PathAccessError:
        raise ToolExecutionError("PARTIAL_ARCHIVE", "Archive creation failed and the partial file could not be removed") from None


def _archive_members(path_guard: PathGuard, archive_path: str, format: str) -> list[tuple[str, bytes]]:
    try:
        fd = path_guard.open_read(archive_path)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    try:
        with os.fdopen(fd, "rb") as source:
            fd = -1
            raw = source.read(_MAX_ARCHIVE_BYTES + 1)
            if len(raw) > _MAX_ARCHIVE_BYTES:
                raise ToolExecutionError("ARCHIVE_SIZE_LIMIT", "Archive exceeds the input size limit")
    except OSError:
        raise ToolExecutionError("ARCHIVE_READ_FAILED", "Archive could not be read") from None
    finally:
        if fd >= 0:
            os.close(fd)
    members: list[tuple[str, bytes]] = []
    total = 0
    try:
        if format == "zip":
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_ARCHIVE_ENTRIES:
                    raise ToolExecutionError("ARCHIVE_ENTRY_LIMIT", "Archive contains too many entries")
                for info in infos:
                    relative = _relative_member(info.filename.rstrip("/")) if info.is_dir() else _relative_member(info.filename)
                    if info.is_dir():
                        continue
                    mode = info.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    if stat.S_ISLNK(mode) or file_type not in {0, stat.S_IFREG}:
                        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive contains a link or special file")
                    total += info.file_size
                    if total > _MAX_EXTRACTED_BYTES or info.file_size > _MAX_ARCHIVE_BYTES:
                        raise ToolExecutionError("EXTRACTION_SIZE_LIMIT", "Archive expands beyond the extraction limit")
                    if info.file_size > max(1, info.compress_size) * _MAX_COMPRESSION_RATIO:
                        raise ToolExecutionError("COMPRESSION_RATIO_LIMIT", "Archive compression ratio exceeds the safety limit")
                    with archive.open(info) as member:
                        content = member.read(info.file_size + 1)
                    if len(content) != info.file_size:
                        raise ToolExecutionError("CORRUPT_ARCHIVE", "Archive entry size does not match its header")
                    members.append((str(relative), content))
        elif format == "tar":
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                infos = archive.getmembers()
                if len(infos) > _MAX_ARCHIVE_ENTRIES:
                    raise ToolExecutionError("ARCHIVE_ENTRY_LIMIT", "Archive contains too many entries")
                for info in infos:
                    relative = _relative_member(info.name.rstrip("/")) if info.isdir() else _relative_member(info.name)
                    if info.isdir():
                        continue
                    if not info.isfile():
                        raise ToolExecutionError("UNSAFE_ARCHIVE_ENTRY", "Archive contains a link or special file")
                    total += info.size
                    if total > _MAX_EXTRACTED_BYTES:
                        raise ToolExecutionError("EXTRACTION_SIZE_LIMIT", "Archive expands beyond the extraction limit")
                    source = archive.extractfile(info)
                    if source is None:
                        raise ToolExecutionError("CORRUPT_ARCHIVE", "Archive member could not be read")
                    with source:
                        content = source.read(info.size + 1)
                    if len(content) != info.size:
                        raise ToolExecutionError("CORRUPT_ARCHIVE", "Archive entry size does not match its header")
                    members.append((str(relative), content))
        else:
            raise ToolExecutionError("INVALID_ARCHIVE_FORMAT", "Archive format must be zip or tar")
    except ToolExecutionError:
        raise
    except (OSError, zipfile.BadZipFile, tarfile.TarError, RuntimeError):
        raise ToolExecutionError("CORRUPT_ARCHIVE", "Archive is invalid or corrupted") from None
    return members


def extract_archive(
    path_guard: PathGuard,
    archive_path: str,
    destination: str,
    format: str = "zip",
) -> dict[str, Any]:
    """Extract regular files only under a new dedicated directory."""
    if format not in {"zip", "tar"}:
        raise ToolExecutionError("INVALID_ARCHIVE_FORMAT", "Archive format must be zip or tar")
    members = _archive_members(path_guard, archive_path, format)
    try:
        path_guard.create_directory(destination)
    except FileExistsError:
        raise ToolExecutionError("DESTINATION_EXISTS", "Extraction directory already exists") from None
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    created_files: list[tuple[str, os.stat_result]] = []
    created_directories = [Path(destination)]
    try:
        for name, content in members:
            current = Path(destination)
            parts = PurePosixPath(name).parts
            for part in parts[:-1]:
                current = current / part
                if current.exists():
                    if not current.is_dir() or current.is_symlink():
                        raise ToolExecutionError("DESTINATION_CONFLICT", "Archive paths conflict with an existing entry")
                else:
                    path_guard.create_directory(current)
                    created_directories.append(current)
            target = current / parts[-1]
            fd = path_guard.open_write(target)
            identity = os.fstat(fd)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
            except OSError:
                raise ToolExecutionError("EXTRACTION_WRITE_FAILED", "An extracted file could not be written") from None
            created_files.append((str(target), identity))
    except FileExistsError:
        clean = _cleanup_extraction(path_guard, created_files, created_directories)
        message = "Archive contains a conflicting destination path"
        if not clean:
            message += "; some partial files could not be removed"
        raise ToolExecutionError("DESTINATION_CONFLICT", message) from None
    except (OSError, PathAccessError) as exc:
        clean = _cleanup_extraction(path_guard, created_files, created_directories)
        message = "Extraction failed; created entries were removed"
        if not clean:
            message = "Extraction failed and some partial entries could not be removed"
        raise ToolExecutionError("EXTRACTION_PARTIAL", message) from exc
    except ToolExecutionError:
        clean = _cleanup_extraction(path_guard, created_files, created_directories)
        if not clean:
            raise ToolExecutionError("EXTRACTION_PARTIAL", "Extraction failed and some partial entries could not be removed") from None
        raise
    return {"destination": str(Path(destination)), "files_extracted": len(created_files), "status": "completed"}


def _cleanup_extraction(
    path_guard: PathGuard,
    files: list[tuple[str, os.stat_result]],
    directories: list[Path],
) -> bool:
    clean = True
    for path, identity in reversed(files):
        try:
            path_guard.unlink_file(path, expected=identity)
        except PathAccessError:
            clean = False
    for path in reversed(directories):
        try:
            path_guard.remove_directory(path)
        except (PathAccessError, OSError):
            clean = False
    return clean


def register_archive_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register preview, duplicate, archive, and extract capabilities."""
    root_schema = {"type": "string", "minLength": 1}
    registry.register(ToolDefinition(
        name="organize_directory",
        description="Preview file categories by default; move files only when apply is true and approved.",
        category="filesystem",
        argument_schema={
            "type": "object",
            "properties": {
                "root": root_schema,
                "apply": {"type": "boolean", "default": False},
                "extension_rules": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": {"type": "array", "items": {"type": "string"}},
                    "default": {},
                },
            },
            "required": ["root"],
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=60,
        implementation=lambda root, apply=False, extension_rules=None: organize_directory(
            path_guard, root, apply, extension_rules or None,
        ),
    ))
    registry.register(ToolDefinition(
        name="find_duplicate_files",
        description="Find duplicate direct-child files by SHA-256; never deletes files.",
        category="filesystem",
        argument_schema={
            "type": "object",
            "properties": {"root": root_schema, "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 100}},
            "required": ["root"],
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=60,
        implementation=lambda root, limit=100: find_duplicate_files(path_guard, root, limit),
    ))
    for name, description, implementation, permission in (
        ("create_archive", "Create a bounded ZIP or TAR archive of a directory's direct files.", create_archive, "write"),
        ("extract_archive", "Extract a bounded ZIP or TAR into a new directory without links or special files.", extract_archive, "write"),
    ):
        schema = {
            "type": "object",
            "properties": {
                "root" if name == "create_archive" else "archive_path": root_schema,
                "archive_path" if name == "create_archive" else "destination": root_schema,
                "format": {"type": "string", "enum": ["zip", "tar"], "default": "zip"},
            },
            "required": ["root", "archive_path"] if name == "create_archive" else ["archive_path", "destination"],
            "additionalProperties": False,
        }
        registry.register(ToolDefinition(
            name=name,
            description=description,
            category="filesystem",
            argument_schema=schema,
            permission_level=permission,
            execution_timeout=60,
            implementation=(
                (lambda root, archive_path, format="zip": create_archive(path_guard, root, archive_path, format))
                if name == "create_archive"
                else (lambda archive_path, destination, format="zip": extract_archive(path_guard, archive_path, destination, format))
            ),
        ))
