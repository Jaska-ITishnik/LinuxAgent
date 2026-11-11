"""Consent-aware local memory operations over the SQLite persistence layer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Literal

from storage.database import DatabaseError, SQLiteDatabase


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


class MemoryError(RuntimeError):
    """A safe, non-sensitive failure from the memory service."""


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _redact(value: str) -> str:
    value = _SECRET_BLOCK.sub("[REDACTED PRIVATE KEY]", value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}[REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    return _AWS_KEY.sub("[REDACTED AWS KEY]", value)


def _text(value: str, *, name: str, limit: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value) > limit or (not allow_empty and not value.strip()):
        raise MemoryError(f"{name} is invalid or exceeds its size limit")
    return _redact(value)


def _identifier(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128 or "\x00" in value:
        raise MemoryError(f"{name} is invalid")
    return value


class MemoryService:
    """Stores bounded local history, summaries, and explicitly approved notes."""

    def __init__(
        self,
        database: SQLiteDatabase | None = None,
        *,
        retention_days: int = 90,
    ) -> None:
        if isinstance(retention_days, bool) or not 1 <= retention_days <= 3_650:
            raise ValueError("Retention must be between 1 and 3650 days")
        try:
            self.database = database or SQLiteDatabase()
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None
        self.retention_days = retention_days
        self.purge_expired()

    def _purge(self, connection) -> dict[str, int]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
        removed = {}
        for table in ("conversations", "task_history", "tool_summaries", "persistent_notes"):
            cursor = connection.execute(f"DELETE FROM {table} WHERE created_at < ?", (cutoff,))
            removed[table] = cursor.rowcount
        return removed

    def purge_expired(self) -> dict[str, int]:
        try:
            with self.database.transaction() as connection:
                return self._purge(connection)
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def save_conversation(self, session_id: str, role: str, content: str) -> int:
        session_id = _identifier(session_id, name="Session ID")
        if role not in {"user", "assistant", "tool"}:
            raise MemoryError("Conversation role is invalid")
        content = _text(content, name="Conversation content", limit=20_000)
        try:
            with self.database.transaction() as connection:
                self._purge(connection)
                cursor = connection.execute(
                    "INSERT INTO conversations(session_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                    (session_id, role, content, _timestamp()),
                )
                return int(cursor.lastrowid)
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def save_task(
        self,
        task_id: str,
        session_id: str,
        request_summary: str,
        result_summary: str,
    ) -> int:
        task_id = _identifier(task_id, name="Task ID")
        session_id = _identifier(session_id, name="Session ID")
        request_summary = _text(request_summary, name="Task request", limit=5_000, allow_empty=False)
        result_summary = _text(result_summary, name="Task result", limit=5_000)
        try:
            with self.database.transaction() as connection:
                self._purge(connection)
                cursor = connection.execute(
                    "INSERT INTO task_history(task_id, session_id, request_summary, result_summary, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (task_id, session_id, request_summary, result_summary, _timestamp()),
                )
                return int(cursor.lastrowid)
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def save_tool_summary(
        self,
        task_id: str,
        session_id: str,
        tool_name: str,
        status: str,
        summary: str,
    ) -> int:
        task_id = _identifier(task_id, name="Task ID")
        session_id = _identifier(session_id, name="Session ID")
        tool_name = _identifier(tool_name, name="Tool name")
        if status not in {"success", "error", "denied", "timeout"}:
            raise MemoryError("Tool status is invalid")
        summary = _text(summary, name="Tool summary", limit=2_000)
        try:
            with self.database.transaction() as connection:
                self._purge(connection)
                cursor = connection.execute(
                    "INSERT INTO tool_summaries(task_id, session_id, tool_name, status, summary, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (task_id, session_id, tool_name, status, summary, _timestamp()),
                )
                return int(cursor.lastrowid)
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def save_note(
        self,
        content: str,
        *,
        user_approved: bool = False,
        persistent_preference: bool = False,
    ) -> int:
        if user_approved is not True:
            raise MemoryError("Explicit user approval is required to persist a note")
        if not isinstance(persistent_preference, bool):
            raise MemoryError("Preference consent flag is invalid")
        content = _text(content, name="Persistent note", limit=5_000, allow_empty=False)
        now = _timestamp()
        try:
            with self.database.transaction() as connection:
                self._purge(connection)
                cursor = connection.execute(
                    "INSERT INTO persistent_notes(content, is_preference, consented_at, created_at) VALUES (?, ?, ?, ?)",
                    (content, int(persistent_preference), now, now),
                )
                return int(cursor.lastrowid)
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def get_recent_conversations(self, limit: int = 20, *, session_id: str | None = None) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise MemoryError("Conversation limit must be between 1 and 100")
        try:
            with self.database.connection() as connection:
                self._purge(connection)
                if session_id is None:
                    rows = connection.execute(
                        "SELECT id, session_id, role, content, created_at FROM conversations "
                        "ORDER BY id DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                else:
                    session_id = _identifier(session_id, name="Session ID")
                    rows = connection.execute(
                        "SELECT id, session_id, role, content, created_at FROM conversations "
                        "WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                        (session_id, limit),
                    ).fetchall()
                return [dict(row) for row in rows]
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def search_task_history(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        query = _text(query, name="Search query", limit=256, allow_empty=False)
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise MemoryError("Search limit must be between 1 and 100")
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        try:
            with self.database.connection() as connection:
                self._purge(connection)
                rows = connection.execute(
                    "SELECT task_id, session_id, request_summary, result_summary, created_at "
                    "FROM task_history WHERE request_summary LIKE ? ESCAPE '\\' "
                    "OR result_summary LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?",
                    (f"%{escaped}%", f"%{escaped}%", limit),
                ).fetchall()
                return [dict(row) for row in rows]
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def list_notes(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise MemoryError("Note limit must be between 1 and 100")
        try:
            with self.database.connection() as connection:
                self._purge(connection)
                rows = connection.execute(
                    "SELECT id, content, is_preference, consented_at, created_at "
                    "FROM persistent_notes ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(row) for row in rows]
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None

    def delete_memory(
        self,
        scope: Literal["all", "session", "task", "note"],
        identifier: str | int | None = None,
        *,
        confirmed: bool = False,
    ) -> dict[str, int]:
        try:
            with self.database.transaction() as connection:
                if scope == "all":
                    if confirmed is not True or identifier is not None:
                        raise MemoryError("Explicit confirmation is required to delete all memory")
                    return {
                        table: connection.execute(f"DELETE FROM {table}").rowcount
                        for table in ("conversations", "task_history", "tool_summaries", "persistent_notes")
                    }
                if scope == "session":
                    session_id = _identifier(identifier, name="Session ID")
                    return {
                        "conversations": connection.execute(
                            "DELETE FROM conversations WHERE session_id = ?", (session_id,),
                        ).rowcount,
                        "tasks": connection.execute(
                            "DELETE FROM task_history WHERE session_id = ?", (session_id,),
                        ).rowcount,
                        "tool_summaries": connection.execute(
                            "DELETE FROM tool_summaries WHERE session_id = ?", (session_id,),
                        ).rowcount,
                    }
                if scope == "task":
                    task_id = _identifier(identifier, name="Task ID")
                    return {
                        "tasks": connection.execute("DELETE FROM task_history WHERE task_id = ?", (task_id,)).rowcount,
                        "tool_summaries": connection.execute(
                            "DELETE FROM tool_summaries WHERE task_id = ?", (task_id,),
                        ).rowcount,
                    }
                if scope == "note":
                    if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
                        raise MemoryError("Note ID is invalid")
                    return {"persistent_notes": connection.execute(
                        "DELETE FROM persistent_notes WHERE id = ?", (identifier,),
                    ).rowcount}
                raise MemoryError("Memory deletion scope is invalid")
        except DatabaseError as exc:
            raise MemoryError(str(exc)) from None
