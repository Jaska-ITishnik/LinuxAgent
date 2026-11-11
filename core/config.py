"""Typed configuration loading for the local personal AI agent."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


DEFAULT_MODEL = "gemma4:e2b-it-qat"
ENV_PREFIX = "AGENT_"
ApprovalPolicy = Literal["always", "destructive", "never"]


def config_dir() -> Path:
    """Return the XDG user configuration directory for this application."""
    configured = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser()
    return (configured if configured.is_absolute() else Path.home() / ".config") / "linuxagent"


def data_dir() -> Path:
    """Return the XDG user data directory for this application."""
    configured = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")).expanduser()
    return (configured if configured.is_absolute() else Path.home() / ".local" / "share") / "linuxagent"


def default_config_path() -> Path:
    return config_dir() / "config.yaml"


def _safe_absolute_path(value: Path | str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    resolved = path.resolve(strict=False)
    if resolved == Path(resolved.anchor):
        raise ValueError("filesystem root cannot be configured as a tool path")
    return resolved


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OllamaConfig(StrictModel):
    host: str = "http://127.0.0.1:11434"
    model: str = DEFAULT_MODEL
    timeout: float = Field(default=180.0, gt=0, le=3600)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("host must be an HTTP(S) URL without embedded credentials")
        hostname = parts.hostname.lower()
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Ollama host must bind to localhost")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ValueError("host must contain only scheme, localhost, and optional port")
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError("host contains an invalid port") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("host port must be between 1 and 65535")
        return value

    @field_validator("model")
    @classmethod
    def validate_model_name(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 200 or "\n" in value:
            raise ValueError("model must be a non-empty name of at most 200 characters")
        return value


class AgentConfig(StrictModel):
    max_steps: int = Field(default=8, ge=1, le=100)
    max_tool_calls: int = Field(default=8, ge=0, le=100)
    max_retries: int = Field(default=2, ge=0, le=10)
    max_task_seconds: float = Field(default=300.0, gt=0, le=3600)


class SecurityConfig(StrictModel):
    allowed_roots: tuple[Path, ...] = (Path.home() / "Downloads",)
    protected_paths: tuple[Path, ...] = (
        Path.home() / ".ssh",
        Path.home() / ".aws",
        Path.home() / ".gnupg",
        Path.home() / ".mozilla",
        Path.home() / ".config" / "google-chrome",
        Path.home() / ".config" / "chromium",
        Path.home() / ".config" / "BraveSoftware",
        Path.home() / ".config" / "microsoft-edge",
        Path.home() / ".config" / "gh",
        Path("/etc"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/boot"),
        Path("/proc"),
        Path("/sys"),
        Path("/dev"),
        Path("/root"),
        Path("/var/lib"),
        Path("/var/log"),
        Path("/run"),
    )
    allow_protected_paths: bool = False
    approval_policy: ApprovalPolicy = "always"

    @field_validator("allowed_roots", "protected_paths", mode="before")
    @classmethod
    def validate_paths(cls, values: Any) -> tuple[Path, ...]:
        if not isinstance(values, (list, tuple)):
            raise ValueError("must be a list of absolute paths")
        normalized = tuple(_safe_absolute_path(path) for path in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("duplicate paths are not allowed")
        return normalized


class ToolsConfig(StrictModel):
    enabled_categories: tuple[str, ...] = ("filesystem", "system", "external", "desktop", "developer")

    @field_validator("enabled_categories", mode="before")
    @classmethod
    def validate_categories(cls, values: Any) -> tuple[str, ...]:
        if not isinstance(values, (list, tuple)):
            raise ValueError("must be a list of category names")
        categories = tuple(str(item).strip().lower() for item in values)
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", item) for item in categories):
            raise ValueError("category names must contain only letters, digits, '_' or '-' (max 32 chars)")
        if len(set(categories)) != len(categories):
            raise ValueError("duplicate categories are not allowed")
        return categories


class LoggingConfig(StrictModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    retention: int = Field(default=7, ge=0, le=3650)
    max_bytes: int = Field(default=10_000_000, ge=1024, le=100_000_000)

    @field_validator("level", mode="before")
    @classmethod
    def normalize_level(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value


class AppConfig(StrictModel):
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


class ConfigLoadError(ValueError):
    """A safe, user-facing configuration loading or validation failure."""


def _set_nested(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current = target
    for key in path[:-1]:
        existing = current.setdefault(key, {})
        if not isinstance(existing, dict):
            raise ConfigLoadError(f"Environment override conflicts at {'.'.join(path[:-1])}")
        current = existing
    current[path[-1]] = value


def _environment_overrides(environ: dict[str, str]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    sections = {"OLLAMA", "AGENT", "SECURITY", "TOOLS", "LOGGING"}
    for name, value in environ.items():
        if not name.startswith(ENV_PREFIX) or "__" not in name:
            continue
        path = tuple(part.lower() for part in name[len(ENV_PREFIX):].split("__"))
        if len(path) != 2 or path[0].upper() not in sections:
            continue
        parsed: Any = value
        if path in {("security", "allowed_roots"), ("security", "protected_paths")}:
            parsed = [part for part in value.split(os.pathsep) if part]
        elif path == ("tools", "enabled_categories"):
            parsed = [part.strip() for part in value.split(",") if part.strip()]
        _set_nested(overrides, path, parsed)
    # Keep the original entry-point environment variables compatible.
    if "OLLAMA_HOST" in environ:
        overrides.setdefault("ollama", {})["host"] = environ["OLLAMA_HOST"]
    if "AGENT_MODEL" in environ:
        overrides.setdefault("ollama", {})["model"] = environ["AGENT_MODEL"]
    return overrides


def load_config(
    path: str | Path | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> AppConfig:
    """Load YAML settings, apply environment overrides, and validate them."""
    config_path = Path(path).expanduser() if path is not None else default_config_path()
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            import yaml
        except ImportError as exc:
            raise ConfigLoadError("PyYAML is required to read config.yaml; install project dependencies") from exc
        try:
            with config_path.open("r", encoding="utf-8") as stream:
                loaded = yaml.safe_load(stream)
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigLoadError(f"Cannot read configuration file {config_path}: {type(exc).__name__}") from exc
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ConfigLoadError("Configuration file must contain a YAML mapping at its top level")
        raw = loaded
    overrides = _environment_overrides(dict(os.environ if environ is None else environ))
    for section, values in overrides.items():
        if not isinstance(raw.get(section), dict):
            raw[section] = {}
        raw[section].update(values)
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        # Error locations and messages are safe; never include input values that may contain credentials.
        issues = [f"{'.'.join(map(str, error['loc']))}: {error['msg']}" for error in exc.errors(include_input=False)]
        raise ConfigLoadError("Invalid configuration: " + "; ".join(issues)) from None
