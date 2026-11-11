"""Tests for typed configuration loading and validation."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.config import (
    AppConfig,
    ConfigLoadError,
    default_config_path,
    data_dir,
    load_config,
)


class ConfigTests(unittest.TestCase):
    def test_valid_configuration(self) -> None:
        config = AppConfig.model_validate({
            "ollama": {"host": "http://localhost:11434", "model": "gemma4:e2b-it-qat", "timeout": 30},
            "agent": {"max_steps": 5, "max_tool_calls": 4, "max_retries": 1},
            "security": {"allowed_roots": ["~/Documents"], "protected_paths": ["~/.ssh"], "approval_policy": "always"},
            "tools": {"enabled_categories": ["filesystem", "system"]},
            "logging": {"level": "debug", "retention": 14},
        })
        self.assertEqual(config.ollama.timeout, 30)
        self.assertEqual(config.logging.level, "DEBUG")
        self.assertTrue(config.security.allowed_roots[0].is_absolute())

    def test_invalid_configuration_has_safe_error(self) -> None:
        with self.assertRaisesRegex(Exception, "timeout"):
            AppConfig.model_validate({"ollama": {"timeout": 0}})
        with self.assertRaises(ConfigLoadError) as raised:
            load_config(environ={"AGENT_OLLAMA__HOST": "http://user:secret@localhost:11434"})
        self.assertNotIn("secret", str(raised.exception))

    def test_environment_overrides_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.yaml"
            config_file.write_text("ollama:\n  model: yaml-model\nagent:\n  max_steps: 3\n", encoding="utf-8")
            config = load_config(config_file, environ={
                "AGENT_OLLAMA__MODEL": "env-model",
                "AGENT_AGENT__MAX_STEPS": "6",
            })
        self.assertEqual(config.ollama.model, "env-model")
        self.assertEqual(config.agent.max_steps, 6)

    def test_environment_overrides_paths_and_categories(self) -> None:
        config = load_config(environ={
            "AGENT_SECURITY__ALLOWED_ROOTS": "/tmp/agent-test",
            "AGENT_TOOLS__ENABLED_CATEGORIES": "filesystem,weather",
        })
        self.assertEqual(config.security.allowed_roots, (Path("/tmp/agent-test"),))
        self.assertEqual(config.tools.enabled_categories, ("filesystem", "weather"))

    def test_missing_optional_settings_use_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(Path(directory) / "missing.yaml", environ={})
        self.assertEqual(config.ollama.host, "http://127.0.0.1:11434")
        self.assertEqual(config.ollama.model, "gemma4:e2b-it-qat")
        self.assertEqual(config.agent.max_steps, 8)
        self.assertTrue(default_config_path().as_posix().endswith("linuxagent/config.yaml"))
        self.assertTrue(data_dir().as_posix().endswith("linuxagent"))

    def test_unsafe_paths_rejected(self) -> None:
        with self.assertRaisesRegex(Exception, "filesystem root"):
            AppConfig.model_validate({"security": {"allowed_roots": ["/"]}})
        with self.assertRaisesRegex(Exception, "absolute"):
            AppConfig.model_validate({"security": {"allowed_roots": ["relative/path"]}})

    def test_non_local_ollama_host_rejected(self) -> None:
        with self.assertRaisesRegex(Exception, "localhost"):
            AppConfig.model_validate({"ollama": {"host": "https://example.com"}})


if __name__ == "__main__":
    unittest.main()
