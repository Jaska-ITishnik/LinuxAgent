"""Tests for private SQLite memory, migrations, retention, and consent."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from core.agent_controller import AgentController
from core.config import AgentConfig, AppConfig
from core.llm_client import LLMResponse
from core.memory import MemoryError, MemoryService
from core.runtime import create_agent_runtime
from core.tool_dispatcher import AllowListAuthorizer, ToolDispatcher
from core.tool_registry import ToolRegistry
from storage.database import DatabaseError, SQLiteDatabase


class FinalAnswerLLM:
    def chat(self, messages, **kwargs):
        return LLMResponse(model="test", content="Stored answer")


class MemoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "memory.sqlite3"
        self.database = SQLiteDatabase(self.path)
        self.memory = MemoryService(self.database)

    def tearDown(self):
        self.temp.cleanup()

    def test_migrations_are_applied_idempotently_and_file_is_private(self):
        self.assertEqual(self.database.schema_version(), 2)
        self.assertEqual(self.database.migrate(), 2)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        with self.database.connection() as connection:
            tables = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'",
                )
            }
        self.assertTrue({
            "schema_migrations", "conversations", "task_history",
            "tool_summaries", "persistent_notes",
        }.issubset(tables))

    def test_conversations_task_search_and_tool_summaries(self):
        self.memory.save_conversation("session-a", "user", "Find project status")
        self.memory.save_conversation("session-a", "assistant", "Project is clean")
        recent = self.memory.get_recent_conversations(1, session_id="session-a")
        self.assertEqual(recent[0]["role"], "assistant")

        self.memory.save_task("task-a", "session-a", "Find project status", "Project is clean")
        self.memory.save_tool_summary("task-a", "session-a", "git_status", "success", "working tree clean")
        results = self.memory.search_task_history("project")
        self.assertEqual(results[0]["task_id"], "task-a")
        self.assertEqual(self.memory.search_task_history("missing"), [])

    def test_explicit_note_consent_and_credential_redaction(self):
        with self.assertRaisesRegex(MemoryError, "approval"):
            self.memory.save_note("API_TOKEN=hidden")
        note_id = self.memory.save_note(
            "Preference: use short answers; API_TOKEN='hidden'; Bearer abcdef",
            user_approved=True,
            persistent_preference=True,
        )
        note = self.memory.list_notes()[0]
        self.assertEqual(note["id"], note_id)
        self.assertEqual(note["is_preference"], 1)
        self.assertIn("[REDACTED]", note["content"])
        self.assertNotIn("hidden", note["content"])
        self.assertNotIn("abcdef", note["content"])

    def test_retention_and_scoped_deletion(self):
        self.memory.save_conversation("old-session", "user", "old")
        self.memory.save_task("old-task", "old-session", "old request", "old result")
        old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="seconds")
        with self.database.transaction() as connection:
            connection.execute("UPDATE conversations SET created_at=? WHERE session_id='old-session'", (old,))
            connection.execute("UPDATE task_history SET created_at=? WHERE task_id='old-task'", (old,))
        short_retention = MemoryService(self.database, retention_days=1)
        self.assertEqual(short_retention.get_recent_conversations(session_id="old-session"), [])
        self.assertEqual(short_retention.search_task_history("old"), [])

        self.memory.save_conversation("session-b", "user", "keep until deleted")
        self.memory.save_task("task-b", "session-b", "request", "result")
        self.memory.save_tool_summary("task-b", "session-b", "calculate", "success", "value=1")
        deleted = self.memory.delete_memory("session", "session-b")
        self.assertEqual(deleted, {"conversations": 1, "tasks": 1, "tool_summaries": 1})
        with self.assertRaisesRegex(MemoryError, "confirmation"):
            self.memory.delete_memory("all")
        self.assertEqual(sum(self.memory.delete_memory("all", confirmed=True).values()), 0)

    def test_database_rejects_symlink_and_insecure_parent(self):
        target = self.root_path / "target.sqlite"
        target.write_bytes(b"not a database")
        link = self.root_path / "link.sqlite"
        link.symlink_to(target)
        with self.assertRaises(DatabaseError):
            SQLiteDatabase(link)
        insecure = self.root_path / "insecure"
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        with self.assertRaises(DatabaseError):
            SQLiteDatabase(insecure / "memory.sqlite")

    @property
    def root_path(self):
        return Path(self.temp.name)

    async def test_agent_controller_persists_conversations_and_tasks_when_enabled(self):
        registry = ToolRegistry()
        dispatcher = ToolDispatcher(registry, authorizer=AllowListAuthorizer(frozenset()))
        controller = AgentController(
            FinalAnswerLLM(),
            registry,
            dispatcher,
            AgentConfig(),
            memory_service=self.memory,
        )
        self.addCleanup(dispatcher.close)
        result = await controller.run("Remember this request", session_id="session-c", task_id="task-c")
        self.assertEqual(result.answer, "Stored answer")
        recent = self.memory.get_recent_conversations(2, session_id="session-c")
        self.assertEqual([item["role"] for item in reversed(recent)], ["user", "assistant"])
        self.assertEqual(self.memory.search_task_history("Remember")[0]["task_id"], "task-c")

    async def test_runtime_enables_default_memory_in_private_xdg_directory(self):
        data_root = Path(self.temp.name) / "xdg"
        config = AppConfig.model_validate({
            "security": {
                "allowed_roots": [self.temp.name],
                "protected_paths": [],
            },
        })
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(data_root)}):
            runtime = create_agent_runtime(config, llm_client=FinalAnswerLLM())
            self.addCleanup(runtime.close)
            self.assertIsNotNone(runtime.memory_service)
            result = await runtime.controller.run("Persist by default", session_id="runtime-session")
            self.assertEqual(result.answer, "Stored answer")
            self.assertEqual(
                runtime.memory_service.get_recent_conversations(session_id="runtime-session")[0]["role"],
                "assistant",
            )
            mode = stat.S_IMODE(runtime.memory_service.database.path.stat().st_mode)
            self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
