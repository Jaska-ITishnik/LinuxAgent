"""Tests for bounded recursive search and directory tools."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest

from core.errors import ToolExecutionError
from core.tool_dispatcher import AllowListAuthorizer, ToolDispatcher
from core.tool_registry import ToolRegistry
from security.path_guard import PathGuard
from tools.advanced_files import (
    find_large_files,
    get_file_metadata,
    list_directory,
    list_downloads,
    register_advanced_file_tools,
    search_files_advanced,
)


class AdvancedFileToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.child = self.root / "child"
        self.child.mkdir()
        (self.root / "alpha.txt").write_text("a", encoding="utf-8")
        (self.root / "beta.py").write_text("bb", encoding="utf-8")
        (self.child / "gamma.txt").write_text("ccc", encoding="utf-8")
        (self.child / "large.bin").write_bytes(b"x" * 2048)
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_list_directory_is_sorted_and_paginated(self):
        first = list_directory(self.guard, str(self.root), limit=1)
        second = list_directory(self.guard, str(self.root), limit=1, offset=1)
        self.assertEqual(first["entries"][0]["name"], "alpha.txt")
        self.assertEqual(second["entries"][0]["name"], "beta.py")
        self.assertEqual(first["total_entries_scanned"], 3)

    def test_legacy_recent_download_listing_is_preserved(self):
        os.utime(self.root / "alpha.txt", (1_600_000_000, 1_600_000_000))
        os.utime(self.child / "gamma.txt", (1_700_000_000, 1_700_000_000))
        result = list_downloads(self.guard, str(self.root))
        self.assertEqual(result["files"][0], "beta.py")
        self.assertEqual(result["total_files"], 2)

    def test_search_filters_name_extension_and_size(self):
        result = search_files_advanced(
            self.guard,
            str(self.root),
            filename_pattern="*.txt",
            extension=".txt",
            min_size=2,
            max_size=3,
            depth_limit=2,
        )
        self.assertEqual(result["total_matches"], 1)
        self.assertEqual(Path(result["files"][0]["path"]).name, "gamma.txt")

    def test_recursive_depth_limit_and_symlink_safety(self):
        deep = self.child / "deeper"
        deep.mkdir()
        (deep / "hidden.txt").write_text("hidden", encoding="utf-8")
        (self.root / "escape").symlink_to(self.root.parent, target_is_directory=True)
        shallow = search_files_advanced(self.guard, str(self.root), depth_limit=0)
        self.assertEqual(shallow["total_matches"], 2)
        recursive = search_files_advanced(self.guard, str(self.root), depth_limit=2)
        self.assertEqual(recursive["total_matches"], 5)
        self.assertNotIn(str(self.root.parent), [item["path"] for item in recursive["files"]])

    def test_metadata_reports_file_and_directory(self):
        file_data = get_file_metadata(self.guard, str(self.root / "alpha.txt"))
        directory_data = get_file_metadata(self.guard, str(self.child))
        self.assertEqual(file_data["size_bytes"], 1)
        self.assertEqual(file_data["extension"], ".txt")
        self.assertEqual(directory_data["kind"], "directory")

    def test_find_large_files_sorts_by_size_and_obeys_depth(self):
        result = find_large_files(self.guard, str(self.root), min_size=2, depth_limit=2)
        self.assertEqual(result["files"][0]["name"], "large.bin")
        self.assertEqual(result["total_matches"], 3)
        shallow = find_large_files(self.guard, str(self.root), min_size=0, depth_limit=0)
        self.assertEqual(shallow["total_matches"], 2)

    def test_modification_date_filter_and_size_sort(self):
        older = self.root / "alpha.txt"
        os.utime(older, (1_600_000_000, 1_600_000_000))
        after = datetime.fromtimestamp(1_650_000_000, timezone.utc).isoformat()
        result = search_files_advanced(
            self.guard,
            str(self.root),
            modified_after=after,
            sort_by="size",
            descending=True,
        )
        self.assertNotIn("alpha.txt", [item["name"] for item in result["files"]])
        self.assertEqual(result["files"][0]["name"], "large.bin")

    def test_permission_denied_is_a_safe_tool_error(self):
        with self.assertRaises(ToolExecutionError):
            search_files_advanced(self.guard, "/etc", depth_limit=0)
        with self.assertRaises(ToolExecutionError):
            list_directory(self.guard, str(self.root / "missing"))

    async def test_registered_tools_execute_through_dispatcher(self):
        registry = ToolRegistry()
        register_advanced_file_tools(registry, self.guard)
        dispatcher = ToolDispatcher(
            registry,
            authorizer=AllowListAuthorizer(frozenset({
                "list_directory", "search_files_advanced", "get_file_metadata", "find_large_files",
            })),
        )
        self.addCleanup(dispatcher.close)
        response = await dispatcher.dispatch({
            "tool_name": "search_files_advanced",
            "arguments": {
                "root": str(self.root),
                "extension": ".txt",
                "depth_limit": 1,
                "limit": 1,
            },
        })
        self.assertEqual(response.status, "success")
        self.assertEqual(response.result_data["total_matches"], 2)
        self.assertEqual(len(response.result_data["files"]), 1)
        invalid = await dispatcher.dispatch({
            "tool_name": "search_files_advanced",
            "arguments": {"root": str(self.root), "limit": 101},
        })
        self.assertEqual(invalid.error_code, "INVALID_ARGUMENTS")

    async def test_core_and_advanced_tools_register_with_model_schemas(self):
        from tools.functional import register_functional_tools

        registry = ToolRegistry()
        register_functional_tools(registry, self.guard, weather_fetch_json=lambda *_: {})
        register_advanced_file_tools(registry, self.guard)
        self.assertEqual(len(registry.list_tools()), 11)
        self.assertEqual(len(registry.model_schemas()), 11)


if __name__ == "__main__":
    unittest.main()
