"""Bounded project inspection and restricted, non-executing Git diagnostics."""
from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import time
import tomllib
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_MAX_SCAN_FILES = 5_000
_MAX_DEPTH = 8
_MAX_GIT_DEPTH = 64
_MAX_SOURCE_BYTES = 1_000_000
_MAX_SEARCH_BYTES = 50 * 1024 * 1024
_MAX_GIT_OUTPUT_BYTES = 48_000
_GIT_TIMEOUT_SECONDS = 8.0
_SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".py", ".rb", ".rs", ".sh", ".sql", ".ts", ".tsx", ".vue",
}
_SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
}
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (\b(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|client[_-]?secret|credential|password|passwd|secret|token)\b\s*[:=]\s*)
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;#]+)
    """
)
_SECRET_BLOCK = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GIT_INCLUDE_OR_FILTER = re.compile(r"(?im)^\s*\[\s*(?:include(?:if)?|filter)\b")
_GIT_FILTER_ATTRIBUTE = re.compile(r"(?i)(?:^|\s)filter\s*=")
_DEPENDENCY_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,127})")


def _redact_secrets(text: str) -> str:
    text = _SECRET_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _AWS_KEY.sub("[REDACTED AWS KEY]", text)


def _project_root(path_guard: PathGuard, root: str) -> Path:
    try:
        return path_guard.validate(root, operation="list", must_exist=True)
    except PathAccessError as exc:
        raise ToolExecutionError("PROJECT_PATH_DENIED", str(exc)) from None


def _walk_project(
    path_guard: PathGuard,
    root: Path,
    *,
    depth_limit: int,
    max_files: int,
    reject_symlinks: bool = False,
) -> tuple[list[tuple[Path, int]], bool]:
    queue = deque([(root, 0)])
    files: list[tuple[Path, int]] = []
    scanned = 0
    truncated = False
    while queue:
        directory, depth = queue.popleft()
        try:
            entries = path_guard.iter_directory(directory)
            for entry in entries:
                scanned += 1
                if scanned > max_files:
                    truncated = True
                    return files, truncated
                if stat.S_ISDIR(entry.mode):
                    if depth < depth_limit and entry.path.name.casefold() not in _SKIP_DIRECTORIES:
                        queue.append((entry.path, depth + 1))
                    elif depth >= depth_limit and entry.path.name.casefold() not in _SKIP_DIRECTORIES:
                        truncated = True
                elif stat.S_ISREG(entry.mode):
                    files.append((entry.path, depth))
                elif stat.S_ISLNK(entry.mode) and reject_symlinks:
                    raise ToolExecutionError("UNSAFE_GIT_METADATA", "Git metadata contains a symlink")
        except PathAccessError as exc:
            raise ToolExecutionError("PROJECT_SCAN_FAILED", "Project directory could not be inspected safely") from exc
    return files, truncated


def _read_bounded(path_guard: PathGuard, path: Path, limit: int) -> bytes | None:
    try:
        fd = path_guard.open_read(path)
    except PathAccessError:
        return None
    fd_open = fd
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        with os.fdopen(fd, "rb") as source:
            fd_open = -1
            content = source.read(limit + 1)
        if len(content) > limit:
            return None
        return content
    except OSError:
        return None
    finally:
        if fd_open >= 0:
            os.close(fd_open)


def _dependency_names(path_guard: PathGuard, root: Path) -> tuple[str | None, list[str]]:
    dependencies: set[str] = set()
    project_name = None
    pyproject = _read_bounded(path_guard, root / "pyproject.toml", 200_000)
    if pyproject is not None:
        try:
            metadata = tomllib.loads(pyproject.decode("utf-8"))
            project = metadata.get("project", {})
            if isinstance(project, dict):
                name = project.get("name")
                project_name = name[:128] if isinstance(name, str) else None
                for item in project.get("dependencies", []):
                    if isinstance(item, str):
                        match = _DEPENDENCY_NAME.match(item)
                        if match:
                            dependencies.add(match.group(1))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise ToolExecutionError("INVALID_PROJECT_METADATA", "Project pyproject.toml is invalid") from None
    requirements = _read_bounded(path_guard, root / "requirements.txt", 200_000)
    if requirements is not None:
        try:
            for line in requirements.decode("utf-8").splitlines():
                stripped = line.split("#", 1)[0].strip()
                match = _DEPENDENCY_NAME.match(stripped)
                if match and not stripped.startswith("-"):
                    dependencies.add(match.group(1))
        except UnicodeDecodeError:
            raise ToolExecutionError("INVALID_PROJECT_METADATA", "Project requirements.txt is not UTF-8") from None
    return project_name, sorted(dependencies, key=str.casefold)


def inspect_python_project(
    path_guard: PathGuard,
    root: str,
    depth_limit: int = 4,
    max_files: int = 1_000,
) -> dict[str, Any]:
    """Inspect an approved project tree and dependency manifests without executing code."""
    if not 0 <= depth_limit <= _MAX_DEPTH or not 1 <= max_files <= _MAX_SCAN_FILES:
        raise ToolExecutionError("INVALID_LIMIT", "Project scan limits are outside the allowed range")
    project = _project_root(path_guard, root)
    entries, truncated = _walk_project(path_guard, project, depth_limit=depth_limit, max_files=max_files)
    tree = []
    python_modules = []
    for path, _depth in entries:
        relative = path.relative_to(project).as_posix()
        if len(tree) < 200:
            tree.append({"path": _redact_secrets(relative)[:512], "kind": "file"})
        if path.suffix.casefold() == ".py" and len(python_modules) < 200:
            python_modules.append(_redact_secrets(relative)[:512])
    directories = set()
    for path, _depth in entries:
        parent = path.parent
        while parent != project:
            directories.add(parent.relative_to(project).as_posix())
            parent = parent.parent
    for directory in sorted(directories, key=str.casefold):
        if len(tree) >= 200:
            truncated = True
            break
        tree.append({"path": _redact_secrets(directory)[:512], "kind": "directory"})
    tree.sort(key=lambda item: (item["path"].casefold(), item["kind"]))
    project_name, dependencies = _dependency_names(path_guard, project)
    return {
        "root": str(project),
        "project_name": project_name,
        "file_count": len(entries),
        "python_modules": sorted(python_modules, key=str.casefold),
        "dependencies": dependencies[:100],
        "dependency_count": len(dependencies),
        "tree": tree,
        "truncated": truncated or len(entries) > 200 or len(dependencies) > 100,
        "code_was_executed": False,
    }


def search_source_code(
    path_guard: PathGuard,
    root: str,
    query: str,
    max_results: int = 50,
    max_files: int = 1_000,
    depth_limit: int = 6,
) -> dict[str, Any]:
    """Search bounded source files for a literal, returning redacted snippets."""
    if not isinstance(query, str) or not query or len(query) > 256 or "\x00" in query:
        raise ToolExecutionError("INVALID_QUERY", "Search query must be between 1 and 256 characters")
    if not 1 <= max_results <= 100 or not 1 <= max_files <= _MAX_SCAN_FILES or not 0 <= depth_limit <= _MAX_DEPTH:
        raise ToolExecutionError("INVALID_LIMIT", "Source search limits are outside the allowed range")
    project = _project_root(path_guard, root)
    entries, truncated = _walk_project(path_guard, project, depth_limit=depth_limit, max_files=max_files)
    results = []
    files_searched = 0
    bytes_scanned = 0
    total_matches = 0
    for path, _depth in entries:
        if path.suffix.casefold() not in _SOURCE_EXTENSIONS:
            continue
        if bytes_scanned >= _MAX_SEARCH_BYTES:
            truncated = True
            break
        raw = _read_bounded(path_guard, path, _MAX_SOURCE_BYTES)
        if raw is None:
            truncated = True
            continue
        bytes_scanned += len(raw)
        if bytes_scanned > _MAX_SEARCH_BYTES:
            truncated = True
            break
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        files_searched += 1
        redacted = _redact_secrets(source)
        relative = path.relative_to(project).as_posix()
        for line_number, line in enumerate(redacted.splitlines(), start=1):
            if query.casefold() not in line.casefold():
                continue
            total_matches += 1
            if len(results) < max_results:
                results.append({
                    "path": _redact_secrets(relative)[:512],
                    "line": line_number,
                    "snippet": line.strip()[:500],
                })
            else:
                truncated = True
    return {
        "root": str(project),
        "query": _redact_secrets(query)[:256],
        "matches": results,
        "total_matches": total_matches,
        "files_searched": files_searched,
        "truncated": truncated or total_matches > len(results),
    }


def _read_git_config(path_guard: PathGuard, git_dir: Path) -> None:
    config_path = git_dir / "config"
    config = _read_bounded(path_guard, config_path, 256_000)
    if config is None and (config_path.exists() or config_path.is_symlink()):
        raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Git configuration could not be validated safely")
    if config is not None:
        text = config.decode("utf-8", errors="replace")
        if _GIT_INCLUDE_OR_FILTER.search(text):
            raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Git includes and custom filters are disabled for safety")
    attributes = git_dir / "info" / "attributes"
    raw = _read_bounded(path_guard, attributes, 256_000)
    if raw is None and (attributes.exists() or attributes.is_symlink()):
        raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Git attributes could not be validated safely")
    if raw and _GIT_FILTER_ATTRIBUTE.search(raw.decode("utf-8", errors="replace")):
        raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Git filters in repository attributes are disabled for safety")


def _validate_git_repository(path_guard: PathGuard, root: str) -> tuple[Path, Path]:
    project = _project_root(path_guard, root)
    git_dir = project / ".git"
    try:
        fd = path_guard.open_directory(git_dir)
        os.close(fd)
    except PathAccessError:
        raise ToolExecutionError("NOT_GIT_REPOSITORY", "Approved project directory is not a standard Git repository") from None
    metadata_files, metadata_truncated = _walk_project(
        path_guard,
        git_dir,
        depth_limit=_MAX_GIT_DEPTH,
        max_files=_MAX_SCAN_FILES,
        reject_symlinks=True,
    )
    if metadata_truncated:
        raise ToolExecutionError("PROJECT_SCAN_LIMIT", "Git metadata is too large to validate safely")
    if not any(path.name == "HEAD" for path, _depth in metadata_files):
        raise ToolExecutionError("NOT_GIT_REPOSITORY", "Git metadata is incomplete")
    for external_metadata in (git_dir / "commondir", git_dir / "objects" / "info" / "alternates"):
        if external_metadata.exists() or external_metadata.is_symlink():
            raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Git metadata that can reference external directories is disabled")
    _read_git_config(path_guard, git_dir)
    attributes, truncated = _walk_project(
        path_guard,
        project,
        depth_limit=_MAX_GIT_DEPTH,
        max_files=_MAX_SCAN_FILES,
        reject_symlinks=True,
    )
    if truncated:
        raise ToolExecutionError("PROJECT_SCAN_LIMIT", "Project is too large to validate Git attributes safely")
    for path, _depth in attributes:
        if path.name != ".gitattributes":
            continue
        raw = _read_bounded(path_guard, path, 256_000)
        if raw is None:
            raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Project Git attributes could not be validated safely")
        if _GIT_FILTER_ATTRIBUTE.search(raw.decode("utf-8", errors="replace")):
            raise ToolExecutionError("UNSAFE_GIT_CONFIG", "Custom Git filters are disabled for safety")
    return project, git_dir


def _run_git(project: Path, git_dir: Path, command: list[str], max_bytes: int) -> tuple[bytes, bool, int]:
    git = shutil.which("git", path="/usr/bin:/bin")
    if git is None:
        raise ToolExecutionError("GIT_UNAVAILABLE", "Git is not installed")
    args = [
        git,
        "--no-pager",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.pager=cat",
        "-c", "core.attributesFile=/dev/null",
        "-c", "diff.external=",
        "--git-dir", str(git_dir),
        "--work-tree", str(project),
        *command,
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "LC_ALL": "C",
    }
    try:
        process = subprocess.Popen(
            args,
            cwd=project,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            close_fds=True,
        )
    except OSError:
        raise ToolExecutionError("GIT_COMMAND_FAILED", "Git diagnostic command could not be started") from None
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    truncated = False
    deadline = time.monotonic() + _GIT_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise ToolExecutionError("GIT_TIMEOUT", "Git diagnostic command exceeded its time limit")
            events = selector.select(min(0.25, remaining))
            if not events and process.poll() is not None:
                break
            if not events:
                continue
            chunk = os.read(descriptor, min(8_192, max_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_bytes:
                truncated = True
                process.kill()
                break
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise ToolExecutionError("GIT_TIMEOUT", "Git diagnostic command exceeded its time limit") from None
    finally:
        selector.close()
        process.stdout.close()
    return bytes(output[:max_bytes]), truncated, return_code


def git_status(path_guard: PathGuard, root: str) -> dict[str, Any]:
    """Return bounded porcelain Git status for an approved repository."""
    project, git_dir = _validate_git_repository(path_guard, root)
    output, truncated, code = _run_git(
        project,
        git_dir,
        ["status", "--short", "--branch", "--untracked-files=normal", "--ignore-submodules=all"],
        _MAX_GIT_OUTPUT_BYTES,
    )
    if code != 0 and not truncated:
        raise ToolExecutionError("GIT_STATUS_FAILED", "Git status could not be read")
    text = _redact_secrets(output.decode("utf-8", errors="replace"))
    return {
        "root": str(project),
        "status": text[:_MAX_GIT_OUTPUT_BYTES],
        "truncated": truncated or len(text) > _MAX_GIT_OUTPUT_BYTES,
    }


def git_diff(path_guard: PathGuard, root: str, max_chars: int = 30_000) -> dict[str, Any]:
    """Return bounded staged and unstaged diff text with secrets redacted."""
    if not 1 <= max_chars <= 40_000:
        raise ToolExecutionError("INVALID_LIMIT", "Git diff limit must be between 1 and 40000 characters")
    project, git_dir = _validate_git_repository(path_guard, root)
    byte_limit = min(_MAX_GIT_OUTPUT_BYTES, max_chars * 4)
    common = ["--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--unified=3"]
    staged, staged_truncated, staged_code = _run_git(
        project,
        git_dir,
        ["diff", "--cached", *common, "--"],
        byte_limit,
    )
    remaining = max(1, byte_limit - len(staged))
    unstaged, unstaged_truncated, unstaged_code = _run_git(
        project,
        git_dir,
        ["diff", *common, "--"],
        remaining,
    )
    if (staged_code != 0 and not staged_truncated) or (unstaged_code != 0 and not unstaged_truncated):
        raise ToolExecutionError("GIT_DIFF_FAILED", "Git diff could not be read")
    output = staged + unstaged
    truncated = staged_truncated or unstaged_truncated
    text = _redact_secrets(output.decode("utf-8", errors="replace"))
    return {
        "root": str(project),
        "diff": text[:max_chars],
        "characters_returned": min(len(text), max_chars),
        "truncated": truncated or len(text) > max_chars,
        "secrets_redacted": True,
    }


def register_developer_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register project inspection, literal source search, and safe Git diagnostics."""
    root = {"type": "string", "minLength": 1}
    definitions = (
        ("inspect_python_project", "Inspect bounded project structure and Python dependencies without executing code.", {
            "root": root,
            "depth_limit": {"type": "integer", "minimum": 0, "maximum": _MAX_DEPTH, "default": 4},
            "max_files": {"type": "integer", "minimum": 1, "maximum": _MAX_SCAN_FILES, "default": 1_000},
        }, "read", lambda root, depth_limit=4, max_files=1_000: inspect_python_project(
            path_guard, root, depth_limit, max_files,
        ), 20),
        ("search_source_code", "Search bounded source files for a literal pattern and redact detected secrets.", {
            "root": root,
            "query": {"type": "string", "minLength": 1, "maxLength": 256},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
            "max_files": {"type": "integer", "minimum": 1, "maximum": _MAX_SCAN_FILES, "default": 1_000},
            "depth_limit": {"type": "integer", "minimum": 0, "maximum": _MAX_DEPTH, "default": 6},
        }, "read", lambda root, query, max_results=50, max_files=1_000, depth_limit=6: search_source_code(
            path_guard, root, query, max_results, max_files, depth_limit,
        ), 30),
        ("git_status", "Read bounded Git status without executing hooks or external helpers.", {
            "root": root,
        }, "read", lambda root: git_status(path_guard, root), 15),
        ("git_diff", "Read bounded, secret-redacted Git diff without external diff helpers or text conversions.", {
            "root": root,
            "max_chars": {"type": "integer", "minimum": 1, "maximum": 40_000, "default": 30_000},
        }, "read", lambda root, max_chars=30_000: git_diff(path_guard, root, max_chars), 20),
    )
    for name, description, properties, permission, implementation, timeout in definitions:
        registry.register(ToolDefinition(
            name=name,
            description=description,
            category="developer",
            argument_schema={
                "type": "object",
                "properties": properties,
                "required": ["root"] + (["query"] if name == "search_source_code" else []),
                "additionalProperties": False,
            },
            permission_level=permission,
            execution_timeout=timeout,
            implementation=implementation,
        ))
