"""Tests for bounded project inspection and restricted Git tools."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from core.errors import ToolExecutionError
from core.tool_registry import ToolRegistry
from security.path_guard import PathGuard
from tools.developer import (
    git_diff,
    git_status,
    inspect_python_project,
    register_developer_tools,
    search_source_code,
)


class DeveloperToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_project_inspection_lists_modules_and_parses_manifests(self):
        project = self.root / "project"
        (project / "pkg").mkdir(parents=True)
        (project / "pkg" / "module.py").write_text("class Example: pass\n", encoding="utf-8")
        (project / "pyproject.toml").write_text(
            '[project]\nname = "sample-project"\ndependencies = ["requests>=2", "pydantic>=2"]\n',
            encoding="utf-8",
        )
        (project / "requirements.txt").write_text("httpx>=0.27\n", encoding="utf-8")
        (project / ".venv").mkdir()
        (project / ".venv" / "hidden.py").write_text("not scanned\n", encoding="utf-8")
        result = inspect_python_project(self.guard, str(project))
        self.assertEqual(result["project_name"], "sample-project")
        self.assertEqual(result["python_modules"], ["pkg/module.py"])
        self.assertEqual(result["dependencies"], ["httpx", "pydantic", "requests"])
        self.assertFalse(result["code_was_executed"])

    def test_source_search_redacts_secrets_and_is_bounded(self):
        project = self.root / "source"
        project.mkdir()
        (project / "module.py").write_text(
            'API_TOKEN = "do-not-show"\nclass UsefulName: pass\n',
            encoding="utf-8",
        )
        result = search_source_code(self.guard, str(project), "API_TOKEN")
        self.assertIn("[REDACTED]", result["matches"][0]["snippet"])
        self.assertNotIn("do-not-show", result["matches"][0]["snippet"])
        secret_query = search_source_code(self.guard, str(project), 'API_TOKEN="query-secret"')
        self.assertNotIn("query-secret", secret_query["query"])
        with self.assertRaises(ToolExecutionError):
            search_source_code(self.guard, "/etc", "root")

    def _create_repository(self) -> Path:
        project = self.root / "repo"
        project.mkdir()
        subprocess.run(["git", "init", "--quiet", str(project)], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(project), "config", "user.name", "Test User"], check=True)
        source = project / "app.py"
        source.write_text('VALUE = "original"\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "add", "app.py"], check=True)
        subprocess.run(["git", "-C", str(project), "commit", "--quiet", "-m", "initial"], check=True)
        return project

    def test_git_status_and_diff_are_bounded_and_secret_redacted(self):
        project = self._create_repository()
        source = project / "app.py"
        source.write_text('VALUE = "updated"\nAPI_TOKEN = "hidden-value"\n', encoding="utf-8")
        staged = project / "staged.py"
        staged.write_text('PASSWORD = "staged-secret"\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(project), "add", "staged.py"], check=True)

        status = git_status(self.guard, str(project))
        self.assertIn("app.py", status["status"])
        self.assertIn("staged.py", status["status"])
        diff = git_diff(self.guard, str(project), max_chars=10_000)
        self.assertIn("updated", diff["diff"])
        self.assertNotIn("hidden-value", diff["diff"])
        self.assertNotIn("staged-secret", diff["diff"])
        self.assertTrue(diff["secrets_redacted"])

    def test_non_repository_and_unsafe_git_configuration_are_rejected(self):
        project = self.root / "plain"
        project.mkdir()
        with self.assertRaisesRegex(ToolExecutionError, "not a standard Git"):
            git_status(self.guard, str(project))

        repository = self._create_repository()
        config = repository / ".git" / "config"
        config.write_text(config.read_text(encoding="utf-8") + '\n[include]\npath = "/tmp/outside"\n', encoding="utf-8")
        with self.assertRaisesRegex(ToolExecutionError, "includes"):
            git_status(self.guard, str(repository))

    def test_developer_tools_are_registered_under_opt_in_category(self):
        registry = ToolRegistry()
        register_developer_tools(registry, self.guard)
        self.assertEqual(len(registry.list_tools(category="developer")), 4)
        self.assertTrue(all(tool.permission_level == "read" for tool in registry.list_tools()))


if __name__ == "__main__":
    unittest.main()
