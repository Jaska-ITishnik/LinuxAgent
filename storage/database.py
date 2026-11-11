"""Private SQLite database with transactional, versioned schema migrations."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator

from core.config import data_dir


class DatabaseError(RuntimeError):
    """A safe, non-sensitive database initialization or operation failure."""


_MIGRATIONS: tuple[tuple[str, ...], ...] = (
    (
        """CREATE TABLE conversations (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'assistant', 'tool')),
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE task_history (
            id INTEGER PRIMARY KEY,
            task_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            request_summary TEXT NOT NULL,
            result_summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE tool_summaries (
            id INTEGER PRIMARY KEY,
            task_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE persistent_notes (
            id INTEGER PRIMARY KEY,
            content TEXT NOT NULL,
            is_preference INTEGER NOT NULL CHECK(is_preference IN (0, 1)),
            consented_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
    ),
    (
        "CREATE INDEX conversations_session_created ON conversations(session_id, created_at DESC)",
        "CREATE INDEX task_history_session_created ON task_history(session_id, created_at DESC)",
        "CREATE INDEX task_history_task_id ON task_history(task_id)",
        "CREATE INDEX tool_summaries_task_id ON tool_summaries(task_id)",
        "CREATE INDEX persistent_notes_created ON persistent_notes(created_at DESC)",
    ),
)


class SQLiteDatabase:
    """Owns a restrictive local database file and applies migrations atomically."""

    def __init__(self, path: str | Path | None = None) -> None:
        requested = Path(path) if path is not None else data_dir() / "memory.sqlite3"
        uses_default_path = path is None
        if not requested.is_absolute() or requested.name in {"", ".", ".."}:
            raise DatabaseError("Database path must be an absolute file path")
        try:
            requested.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            parent = requested.parent.resolve(strict=True)
            if uses_default_path:
                if parent != requested.parent:
                    raise DatabaseError("Application data directory must not use a symlink")
                os.chmod(parent, 0o700)
            info = parent.stat()
            if (
                not parent.is_dir()
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise DatabaseError("Database directory must be private and owned by the current user")
            self.path = parent / requested.name
            self._secure_database_file()
            self.migrate()
        except DatabaseError:
            raise
        except OSError:
            raise DatabaseError("Database file could not be secured") from None

    def _secure_database_file(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError:
            raise DatabaseError("Database file could not be opened safely") from None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise DatabaseError("Database must be a regular, user-owned file without hard links")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA secure_delete=ON")
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            raise DatabaseError("Database connection could not be opened") from None
        try:
            yield connection
        except sqlite3.Error:
            raise DatabaseError("Database operation failed") from None
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def migrate(self) -> int:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            with self.transaction() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                )
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                ).fetchone()[0]
                if current > len(_MIGRATIONS):
                    raise DatabaseError("Database schema is newer than this application")
                for version in range(current + 1, len(_MIGRATIONS) + 1):
                    for statement in _MIGRATIONS[version - 1]:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (version, timestamp),
                    )
                return len(_MIGRATIONS)
        except DatabaseError:
            raise
        except sqlite3.Error:
            raise DatabaseError("Database schema migration failed") from None

    def schema_version(self) -> int:
        with self.connection() as connection:
            try:
                row = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
            except sqlite3.Error:
                raise DatabaseError("Database schema version could not be read") from None
        return int(row[0])
