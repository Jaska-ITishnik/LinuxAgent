"""Tests for the six registered core personal-agent tools."""
from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from core.errors import ToolExecutionError
from core.tool_dispatcher import AllowListAuthorizer, ToolDispatcher
from core.tool_registry import ToolRegistry
from security.approval import ApprovalDecision, ApprovalManager, PolicyAuthorizer
from security.path_guard import PathGuard
from security.permissions import PermissionPolicyEngine, PolicyConfig
from tools.functional import (
    calculate,
    get_system_status,
    get_weather,
    read_text_file,
    register_functional_tools,
    search_files,
)


class ApprovalStub:
    def __init__(self, decision=ApprovalDecision.APPROVE):
        self.decision = decision
        self.request_count = 0

    def request_approval(self, request, timeout_seconds):
        self.request_count += 1
        return self.decision


class FunctionalToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_search_files_filters_names_and_extensions(self):
        (self.root / "python-notes.md").write_text("notes", encoding="utf-8")
        (self.root / "python.py").write_text("print(1)", encoding="utf-8")
        (self.root / "other.txt").write_text("other", encoding="utf-8")
        (self.root / "link.md").symlink_to(self.root / "python-notes.md")
        result = search_files(self.guard, str(self.root), "python*", ".md")
        self.assertEqual(result["total_matches"], 1)
        self.assertEqual(result["files"][0]["name"], "python-notes.md")

    def test_text_reader_only_reads_allowed_utf8_text_files(self):
        target = self.root / "readme.md"
        target.write_text("# Hello", encoding="utf-8")
        self.assertEqual(read_text_file(self.guard, str(target))["content"], "# Hello")
        with self.assertRaises(ToolExecutionError):
            read_text_file(self.guard, str(self.root / "program.py"))
        with self.assertRaises(ToolExecutionError):
            read_text_file(self.guard, "/etc/passwd")

    async def test_note_creation_requires_approval_and_never_overwrites(self):
        registry = ToolRegistry()
        register_functional_tools(registry, self.guard, weather_fetch_json=lambda *_: {})
        approval = ApprovalStub()
        authorizer = PolicyAuthorizer(
            PermissionPolicyEngine(PolicyConfig(allowed_tools=frozenset({"create_note"}))),
            ApprovalManager(approval),
        )
        dispatcher = ToolDispatcher(registry, authorizer=authorizer)
        self.addCleanup(dispatcher.close)
        target = self.root / "summary.md"
        result = await dispatcher.dispatch({
            "tool_name": "create_note",
            "arguments": {"path": str(target), "content": "Summary"},
        })
        self.assertEqual(result.status, "success")
        self.assertEqual(target.read_text(encoding="utf-8"), "Summary")
        self.assertEqual(approval.request_count, 1)
        second = await dispatcher.dispatch({
            "tool_name": "create_note",
            "arguments": {"path": str(target), "content": "Changed"},
        })
        self.assertEqual(second.error_code, "FILE_EXISTS")
        self.assertEqual(target.read_text(encoding="utf-8"), "Summary")

    def test_calculator_supports_arithmetic_and_percentages_without_eval(self):
        self.assertEqual(calculate("250000 * (1 - 15%)")["value"], 212500.0)
        self.assertEqual(calculate("15% of 250000")["value"], 37500.0)
        self.assertEqual(calculate("7 % 2")["value"], 1)
        with self.assertRaises(ToolExecutionError):
            calculate("__import__('os').system('true')")
        with self.assertRaises(ToolExecutionError):
            calculate("1 / 0")
        with self.assertRaises(ToolExecutionError):
            calculate("2 ** 100")

    def test_system_status_reports_cpu_memory_and_disk(self):
        result = get_system_status()
        self.assertIn("cpu_percent", result)
        self.assertIn("ram_available_gb", result)
        self.assertIn("disk_free_gb", result)

    def test_weather_uses_two_bounded_public_api_requests_and_returns_conditions(self):
        requests = []

        def fake_json(url, params):
            requests.append((url, params))
            if "geocoding" in url:
                return {"results": [{
                    "name": "Tashkent", "country": "Uzbekistan",
                    "latitude": 41.3, "longitude": 69.2, "timezone": "Asia/Tashkent",
                }]}
            return {"current": {"temperature_2m": 22.1, "weather_code": 1}}

        result = get_weather("Tashkent", fake_json)
        self.assertEqual(result["city"], "Tashkent")
        self.assertEqual(result["current"]["temperature_2m"], 22.1)
        self.assertEqual(len(requests), 2)
        self.assertIn("geocoding-api.open-meteo.com", requests[0][0])
        self.assertEqual(requests[1][1]["latitude"], 41.3)

    def test_weather_reports_missing_city(self):
        with self.assertRaisesRegex(ToolExecutionError, "No matching city"):
            get_weather("Nowhere", lambda *_: {"results": []})


if __name__ == "__main__":
    unittest.main()
