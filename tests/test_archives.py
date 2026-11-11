"""Tests for preview-first organization and safe archive boundaries."""
from __future__ import annotations

import tempfile
from pathlib import Path
import stat
import unittest
import zipfile

from core.errors import ToolExecutionError
from core.tool_dispatcher import ToolDispatcher
from core.tool_registry import ToolRegistry
from security.approval import ApprovalDecision, ApprovalManager, PolicyAuthorizer
from security.path_guard import PathGuard
from security.permissions import PermissionPolicyEngine, PolicyConfig
from tools.archives import (
    create_archive,
    extract_archive,
    find_duplicate_files,
    organize_directory,
    register_archive_tools,
)


class ApprovalStub:
    def __init__(self, decision):
        self.decision = decision
        self.requests = []

    def request_approval(self, request, timeout_seconds):
        self.requests.append(request)
        return self.decision


class ArchiveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = PathGuard([self.root])
        (self.root / "report.txt").write_text("report data", encoding="utf-8")
        (self.root / "script.py").write_text("print('safe')", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_organization_preview_does_not_move_files(self):
        result = organize_directory(self.guard, str(self.root))
        self.assertTrue(result["preview_only"])
        self.assertEqual(result["file_count"], 2)
        self.assertTrue((self.root / "report.txt").exists())
        self.assertEqual({item["category"] for item in result["plan"]}, {"documents", "code"})

    def test_organization_conflicts_are_preflighted_before_changes(self):
        documents = self.root / "documents"
        documents.mkdir()
        (documents / "report.txt").write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(ToolExecutionError, "existing destination"):
            organize_directory(self.guard, str(self.root), apply=True)
        self.assertTrue((self.root / "report.txt").exists())
        self.assertTrue((self.root / "script.py").exists())
        self.assertFalse((self.root / "code").exists())

    async def test_organization_apply_moves_only_after_policy_approval(self):
        registry = ToolRegistry()
        register_archive_tools(registry, self.guard)
        interface = ApprovalStub(ApprovalDecision.APPROVE)
        policy = PermissionPolicyEngine(PolicyConfig(
            allowed_tools=frozenset({"organize_directory"}),
            approval_if_true=frozenset({("organize_directory", "apply")}),
        ))
        dispatcher = ToolDispatcher(registry, authorizer=PolicyAuthorizer(policy, ApprovalManager(interface)))
        self.addCleanup(dispatcher.close)
        preview = await dispatcher.dispatch({
            "tool_name": "organize_directory",
            "arguments": {"root": str(self.root)},
        })
        self.assertEqual(preview.status, "success")
        self.assertEqual(interface.requests, [])
        applied = await dispatcher.dispatch({
            "tool_name": "organize_directory",
            "arguments": {"root": str(self.root), "apply": True},
        })
        self.assertEqual(applied.status, "success")
        self.assertEqual(len(interface.requests), 1)
        self.assertFalse((self.root / "report.txt").exists())
        self.assertTrue((self.root / "documents" / "report.txt").exists())

    def test_duplicate_detection_uses_sha256_and_never_deletes(self):
        (self.root / "copy.txt").write_text("report data", encoding="utf-8")
        result = find_duplicate_files(self.guard, str(self.root))
        self.assertEqual(result["total_groups"], 1)
        self.assertEqual(len(result["duplicate_groups"][0]["paths"]), 2)
        self.assertFalse(result["deleted"])
        self.assertTrue((self.root / "report.txt").exists())

    def test_zip_and_tar_create_and_extract(self):
        for fmt, suffix in (("zip", ".zip"), ("tar", ".tar")):
            archive = self.root / f"bundle{suffix}"
            created = create_archive(self.guard, str(self.root), str(archive), fmt)
            self.assertGreater(created["files_archived"], 0)
            target = self.root / f"unpacked_{fmt}"
            result = extract_archive(self.guard, str(archive), str(target), fmt)
            self.assertGreaterEqual(result["files_extracted"], 2)
            self.assertEqual((target / "report.txt").read_text(encoding="utf-8"), "report data")
            with self.assertRaises(ToolExecutionError):
                extract_archive(self.guard, str(archive), str(target), fmt)

    def test_existing_archive_is_not_overwritten(self):
        archive = self.root / "already.zip"
        archive.write_text("unchanged", encoding="utf-8")
        with self.assertRaisesRegex(ToolExecutionError, "already exists"):
            create_archive(self.guard, str(self.root), str(archive), "zip")
        self.assertEqual(archive.read_text(encoding="utf-8"), "unchanged")

    def test_zip_traversal_and_symlink_members_are_rejected(self):
        malicious = self.root / "malicious.zip"
        with zipfile.ZipFile(malicious, "w") as archive:
            archive.writestr("../escaped.txt", "escape")
        with self.assertRaisesRegex(ToolExecutionError, "traversal"):
            extract_archive(self.guard, str(malicious), str(self.root / "out"), "zip")
        link_archive = self.root / "link.zip"
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(link_archive, "w") as archive:
            archive.writestr(info, "../../outside")
        with self.assertRaisesRegex(ToolExecutionError, "link or special"):
            extract_archive(self.guard, str(link_archive), str(self.root / "out2"), "zip")

    def test_archive_file_count_and_path_limits_are_checked(self):
        malicious = self.root / "many.zip"
        with zipfile.ZipFile(malicious, "w") as archive:
            archive.writestr("a/../../escape", "bad")
        with self.assertRaises(ToolExecutionError):
            extract_archive(self.guard, str(malicious), str(self.root / "out"), "zip")


if __name__ == "__main__":
    unittest.main()
