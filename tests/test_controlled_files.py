"""Tests for approval-gated copy, move, rename, and directory creation."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from core.tool_dispatcher import ToolDispatcher
from core.tool_registry import ToolRegistry
from security.approval import ApprovalDecision, ApprovalManager, PolicyAuthorizer
from security.path_guard import PathGuard
from security.permissions import PermissionPolicyEngine, PolicyConfig
from tools.controlled_files import (
    copy_file,
    create_directory,
    move_file,
    register_controlled_file_tools,
    rename_file,
)


class ApprovalStub:
    def __init__(self, decision):
        self.decision = decision
        self.requests = []

    def request_approval(self, request, timeout_seconds):
        self.requests.append(request)
        return self.decision


class ControlledFileTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source.txt"
        self.source.write_text("original data", encoding="utf-8")
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_copy_and_move_success(self):
        copied = self.root / "copy.txt"
        self.assertEqual(copy_file(self.guard, str(self.source), str(copied))["status"], "completed")
        self.assertEqual(copied.read_text(encoding="utf-8"), "original data")
        self.assertTrue(self.source.exists())
        moved = self.root / "moved.txt"
        self.assertEqual(move_file(self.guard, str(copied), str(moved))["operation"], "move")
        self.assertFalse(copied.exists())
        self.assertTrue(self.source.exists())
        self.assertEqual(moved.read_text(encoding="utf-8"), "original data")

    def test_rename_and_create_directory(self):
        renamed = self.root / "renamed.md"
        self.assertEqual(rename_file(self.guard, str(self.source), str(renamed))["operation"], "rename")
        self.assertFalse(self.source.exists())
        folder = self.root / "new-folder"
        create_directory(self.guard, str(folder))
        self.assertTrue(folder.is_dir())
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)

    async def test_existing_destination_and_denied_path_leave_source_untouched(self):
        existing = self.root / "existing.txt"
        existing.write_text("keep", encoding="utf-8")
        dispatcher = self._dispatcher(ApprovalDecision.APPROVE)
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({
            "tool_name": "copy_file",
            "arguments": {"source": str(self.source), "destination": str(existing)},
        })
        self.assertEqual(result.error_code, "DESTINATION_EXISTS")
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
        self.assertTrue(self.source.exists())
        denied = await dispatcher.dispatch({
            "tool_name": "copy_file",
            "arguments": {"source": str(self.source), "destination": "/tmp/outside-copy.txt"},
        })
        self.assertEqual(denied.error_code, "PATH_DENIED")
        self.assertTrue(self.source.exists())

    async def test_mutations_require_approval_and_denial_prevents_changes(self):
        denied = self._dispatcher(ApprovalDecision.DENY)
        self.addCleanup(denied.close)
        result = await denied.dispatch({
            "tool_name": "move_file",
            "arguments": {"source": str(self.source), "destination": str(self.root / "new.txt")},
        })
        self.assertEqual(result.status, "denied")
        self.assertTrue(self.source.exists())
        self.assertFalse((self.root / "new.txt").exists())

    def test_partial_copy_failure_removes_destination_and_preserves_source(self):
        destination = self.root / "broken.txt"
        with patch("tools.controlled_files.os.write", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(Exception, "copy failed"):
                copy_file(self.guard, str(self.source), str(destination))
        self.assertTrue(self.source.exists())
        self.assertFalse(destination.exists())

    async def test_authorized_mutation_records_the_exact_approved_arguments(self):
        interface = ApprovalStub(ApprovalDecision.APPROVE)
        dispatcher = self._dispatcher(ApprovalDecision.APPROVE, interface=interface)
        self.addCleanup(dispatcher.close)
        destination = self.root / "approved.txt"
        result = await dispatcher.dispatch({
            "tool_name": "copy_file",
            "arguments": {"source": str(self.source), "destination": str(destination)},
        })
        self.assertEqual(result.status, "success")
        self.assertEqual(interface.requests[0].arguments["destination"], str(destination))

    def _dispatcher(self, decision, *, interface=None):
        registry = ToolRegistry()
        register_controlled_file_tools(registry, self.guard)
        approval = ApprovalManager(interface or ApprovalStub(decision))
        policy = PermissionPolicyEngine(PolicyConfig(
            allowed_tools=frozenset({"copy_file", "move_file", "rename_file", "create_directory"}),
        ))
        return ToolDispatcher(registry, authorizer=PolicyAuthorizer(policy, approval))


if __name__ == "__main__":
    unittest.main()
