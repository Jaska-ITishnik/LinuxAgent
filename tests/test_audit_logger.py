"""Tests for sanitized audit records and dispatcher integration."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from core.tool_dispatcher import AllowListAuthorizer, ToolDispatcher
from core.tool_registry import ToolDefinition, ToolRegistry
from security.audit_logger import AuditLogError, AuditLogger


def echo(content: str, api_token: str) -> dict[str, str]:
    return {"content": content, "api_token": api_token}


def explode(content: str, api_token: str) -> None:
    raise RuntimeError("private stack details")


def make_tool(implementation=echo) -> ToolDefinition:
    return ToolDefinition(
        name="echo",
        description="Echo values",
        category="test",
        argument_schema={
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "api_token": {"type": "string"},
            },
            "required": ["content", "api_token"],
            "additionalProperties": False,
        },
        permission_level="read",
        execution_timeout=1,
        implementation=implementation,
    )


class AuditLoggerTests(unittest.TestCase):
    def test_event_is_structured_redacted_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "audit.log"
            logger = AuditLogger(path, retention_days=7)
            logger.record(
                tool_name="echo",
                arguments={"content": "private document", "api_token": "secret-value", "count": 2},
                permission_decision="allowed",
                execution_status="success",
                duration=0.25,
                session_id="session-1",
                task_id="task-1",
            )
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["session_id"], "session-1")
            self.assertEqual(record["task_id"], "task-1")
            self.assertEqual(record["arguments"]["content"], "[CONTENT REDACTED]")
            self.assertEqual(record["arguments"]["api_token"], "[REDACTED]")
            self.assertEqual(record["arguments"]["count"], 2)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_rotation_and_retention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logger = AuditLogger(Path(directory) / "audit.log", retention_days=1, max_bytes=1024)
            expired = Path(directory) / "audit.log.20000101"
            expired.write_text("expired", encoding="utf-8")
            os.utime(expired, (1, 1))
            for _ in range(5):
                logger.record(
                    tool_name="echo",
                    arguments={"value": "x" * 400},
                    permission_decision="allowed",
                    execution_status="success",
                    duration=0,
                )
            self.assertTrue(list(Path(directory).glob("audit.log.*")))
            self.assertLessEqual(Path(directory, "audit.log").stat().st_size, 1024)
            self.assertFalse(expired.exists())

    def test_symlink_audit_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            target.write_text("untouched", encoding="utf-8")
            link = Path(directory) / "audit.log"
            link.symlink_to(target)
            with self.assertRaises(AuditLogError):
                AuditLogger(link)
            self.assertEqual(target.read_text(encoding="utf-8"), "untouched")


class DispatcherAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_dispatcher_records_outcomes_and_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            logger = AuditLogger(path)
            dispatcher = ToolDispatcher(
                ToolRegistry([make_tool()]),
                authorizer=AllowListAuthorizer(frozenset({"echo"})),
                audit_logger=logger,
            )
            self.addCleanup(dispatcher.close)
            result = await dispatcher.dispatch(
                {
                    "tool_name": "echo",
                    "arguments": {"content": "document", "api_token": "secret"},
                },
                session_id="session-a",
                task_id="task-a",
            )
            self.assertEqual(result.status, "success")
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["permission_decision"], "allowed")
            self.assertEqual(record["execution_status"], "success")
            self.assertEqual(record["arguments"]["api_token"], "[REDACTED]")
            self.assertEqual(record["session_id"], "session-a")
            self.assertEqual(record["task_id"], "task-a")

    async def test_denial_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            dispatcher = ToolDispatcher(
                ToolRegistry([make_tool()]),
                audit_logger=AuditLogger(path),
            )
            self.addCleanup(dispatcher.close)
            result = await dispatcher.dispatch(
                {"tool_name": "echo", "arguments": {"content": "x", "api_token": "y"}}
            )
            self.assertEqual(result.status, "denied")
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["permission_decision"], "denied")

    async def test_tool_failure_is_audited_without_raw_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            dispatcher = ToolDispatcher(
                ToolRegistry([make_tool(explode)]),
                authorizer=AllowListAuthorizer(frozenset({"echo"})),
                audit_logger=AuditLogger(path),
            )
            self.addCleanup(dispatcher.close)
            result = await dispatcher.dispatch({
                "tool_name": "echo",
                "arguments": {"content": "x", "api_token": "y"},
            })
            self.assertEqual(result.error_code, "TOOL_EXECUTION_FAILED")
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["execution_status"], "error")
            self.assertEqual(record["permission_decision"], "allowed")
            self.assertNotIn("private stack details", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
