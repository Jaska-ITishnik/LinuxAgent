"""End-to-end controller integration for real registered tool implementations."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from core.config import AppConfig
from core.llm_client import LLMResponse, ToolCall
from core.memory import MemoryService
from core.runtime import create_agent_runtime
from security.approval import ApprovalDecision
from security.audit_logger import AuditLogger
from security.path_guard import PathGuard
from storage.database import SQLiteDatabase


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent_messages = []

    def chat(self, messages, *, system_prompt=None, tools=None, response_schema=None, model=None):
        self.sent_messages.append((messages, tools))
        return self.responses.pop(0)


class ApproveNotes:
    def request_approval(self, request, timeout_seconds):
        if request.operation.startswith("create_note:") and request.target_resource:
            return ApprovalDecision.APPROVE
        return ApprovalDecision.DENY


class AgentToolIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_search_read_and_approved_note_flow_through_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "documents"
            root.mkdir()
            source = root / "python-guide.md"
            source.write_text("# Python\nA readable programming language.", encoding="utf-8")
            output = root / "summary.md"
            audit = AuditLogger(base / "logs" / "audit.log")
            llm = ScriptedLLM([
                LLMResponse(model="test", tool_calls=(
                    ToolCall(name="search_files_advanced", arguments={
                        "root": str(root),
                        "filename_pattern": "python*",
                        "extension": ".md",
                        "depth_limit": 0,
                    }),
                )),
                LLMResponse(model="test", tool_calls=(
                    ToolCall(name="read_text_file", arguments={"path": str(source)}),
                )),
                LLMResponse(model="test", tool_calls=(
                    ToolCall(name="create_note", arguments={
                        "path": str(output),
                        "content": "Python guide: a readable programming language.",
                    }),
                )),
                LLMResponse(model="test", content="Found, read, and saved the summary."),
            ])
            config = AppConfig.model_validate({
                "security": {
                    "allowed_roots": [str(root)],
                    "protected_paths": [],
                    "approval_policy": "always",
                },
                "agent": {"max_steps": 8, "max_tool_calls": 8, "max_retries": 1},
            })
            runtime = create_agent_runtime(
                config,
                approval_interface=ApproveNotes(),
                llm_client=llm,
                path_guard=PathGuard([root]),
                audit_logger=audit,
                weather_fetch_json=lambda *_: {},
                memory_service=MemoryService(SQLiteDatabase(base / "memory.sqlite3")),
            )
            self.addCleanup(runtime.close)
            self.assertEqual(len(runtime.registry.list_tools()), 44)
            self.assertIn("open_application", {tool.name for tool in runtime.registry.list_tools()})

            result = await runtime.controller.run(
                "Find the Python guide, read it, and save a short summary.",
                session_id="integration-session",
                task_id="integration-task",
            )

            self.assertEqual(result.answer, "Found, read, and saved the summary.")
            self.assertEqual(result.tool_calls, 3)
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(encoding="utf-8"), "Python guide: a readable programming language.")
            self.assertEqual([item.status for item in result.tool_results], ["success", "success", "success"])
            self.assertTrue(all(call[1] for call in llm.sent_messages))
            audit_records = [json.loads(line) for line in (base / "logs" / "audit.log").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(
                any(record["execution_status"] == "approval_approved" for record in audit_records),
                audit_records,
            )
            self.assertEqual(
                sum(record["task_id"] == "integration-task" for record in audit_records),
                4,
            )


if __name__ == "__main__":
    unittest.main()
