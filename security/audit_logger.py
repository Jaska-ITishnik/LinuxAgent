"""Restrictive, structured JSONL audit logging with rotation and redaction."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import threading
from itertools import islice
from typing import Any, Iterator

from core.config import LoggingConfig, data_dir


_audit_context: ContextVar[tuple[str, str] | None] = ContextVar("audit_context", default=None)
_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|credential|authorization|cookie|private[_-]?key)", re.I)
_PRIVATE_CONTENT_KEYS = {"content", "text", "body", "note", "document"}
_MAX_REDACTION_NODES = 256
_MAX_REDACTED_STRING = 256
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_ASSIGNED_SECRET = re.compile(r"(?i)\b(password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^,\s;]+")
_ROTATED_NAME = re.compile(r"^audit\.log\.\d{8}(?:\.\d+)?$")


class AuditLogError(RuntimeError):
    """Audit data could not be safely persisted."""


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    session_id: str
    task_id: str
    tool_name: str
    arguments: Any
    permission_decision: str
    execution_status: str
    duration: float


def _redact(value: Any, *, key: str = "", depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > _MAX_REDACTION_NODES:
        return "[AUDIT SIZE LIMIT]"
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if key.lower() in _PRIVATE_CONTENT_KEYS:
        return "[CONTENT REDACTED]"
    if depth >= 8:
        return "[DEPTH LIMIT]"
    if isinstance(value, dict):
        return {
            str(child_key)[:128]: _redact(child, key=str(child_key), depth=depth + 1, budget=budget)
            for child_key, child in islice(value.items(), 100)
        }
    if isinstance(value, (list, tuple)):
        return [_redact(child, depth=depth + 1, budget=budget) for child in islice(value, 100)]
    if isinstance(value, str):
        if len(value) > _MAX_REDACTED_STRING:
            return "[LONG STRING REDACTED]"
        sanitized = _BEARER.sub("Bearer [REDACTED]", value)
        sanitized = _ASSIGNED_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", sanitized)
        return sanitized
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"[UNSERIALIZABLE {type(value).__name__}]"


class AuditLogger:
    """Append-only audit records in an owner-only directory and file."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        retention_days: int = 7,
        max_bytes: int = 10_000_000,
    ) -> None:
        if not 0 <= retention_days <= 3650 or not 1024 <= max_bytes <= 100_000_000:
            raise ValueError("Invalid audit retention or rotation size")
        self.path = (Path(path).expanduser().absolute() if path is not None else data_dir() / "logs" / "audit.log")
        self.retention_days = retention_days
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            resolved_parent = self.path.parent.resolve(strict=True)
            if resolved_parent != self.path.parent or self.path.is_symlink():
                raise AuditLogError("Audit path must not use symlinks")
            os.chmod(self.path.parent, 0o700)
        except AuditLogError:
            raise
        except OSError as exc:
            raise AuditLogError("Cannot create the protected audit directory") from exc

    @classmethod
    @contextmanager
    def context(cls, session_id: str, task_id: str) -> Iterator[None]:
        token = _audit_context.set((session_id, task_id))
        try:
            yield
        finally:
            _audit_context.reset(token)

    def record(
        self,
        *,
        tool_name: str,
        arguments: Any,
        permission_decision: str,
        execution_status: str,
        duration: float,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> None:
        context = _audit_context.get()
        if context:
            session_id = session_id or context[0]
            task_id = task_id or context[1]
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=(session_id or "unassigned")[:128],
            task_id=(task_id or "unassigned")[:128],
            tool_name=str(tool_name)[:128],
            arguments=_redact(arguments),
            permission_decision=str(permission_decision)[:64],
            execution_status=str(execution_status)[:64],
            duration=max(0.0, float(duration)),
        )
        try:
            encoded = (json.dumps(event.__dict__, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError, OverflowError) as exc:
            raise AuditLogError("Audit event could not be encoded") from exc

        with self._lock:
            try:
                self._rotate_if_needed(len(encoded))
                fd = os.open(
                    self.path,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                )
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise AuditLogError("Audit target is not a regular file")
                    os.fchmod(fd, 0o600)
                    offset = 0
                    while offset < len(encoded):
                        offset += os.write(fd, encoded[offset:])
                finally:
                    os.close(fd)
                self._prune()
            except AuditLogError:
                raise
            except OSError as exc:
                raise AuditLogError("Could not persist the audit event") from exc

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode):
            raise AuditLogError("Audit target is not a regular file")
        today = datetime.now(timezone.utc).date()
        log_day = datetime.fromtimestamp(info.st_mtime, timezone.utc).date()
        if info.st_size + incoming_bytes <= self.max_bytes and log_day == today:
            return
        suffix = today.strftime("%Y%m%d")
        destination = self.path.with_name(f"{self.path.name}.{suffix}")
        index = 1
        while destination.exists():
            destination = self.path.with_name(f"{self.path.name}.{suffix}.{index}")
            index += 1
        os.replace(self.path, destination)

    def _prune(self) -> None:
        cutoff = datetime.now(timezone.utc).timestamp() - self.retention_days * 86400
        try:
            for candidate in self.path.parent.iterdir():
                if not _ROTATED_NAME.fullmatch(candidate.name):
                    continue
                try:
                    info = candidate.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                    candidate.unlink()
        except OSError as exc:
            raise AuditLogError("Could not apply audit log retention") from exc


def audit_logger_from_config(config: LoggingConfig) -> AuditLogger:
    """Create an audit logger using the application's typed logging settings."""
    return AuditLogger(retention_days=config.retention, max_bytes=config.max_bytes)
