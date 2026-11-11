"""The six core personal-agent tools with explicit safety boundaries."""
from __future__ import annotations

import ast
import fnmatch
import httpx
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable

import psutil

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_TEXT_EXTENSIONS = {".txt", ".md"}
_MAX_TEXT_BYTES = 48_000
_MAX_SEARCH_ENTRIES = 5_000
_SAFE_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,16}$")


def _tool(
    name: str,
    description: str,
    schema: dict[str, Any],
    permission: str,
    implementation: Callable[..., Any],
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        category="filesystem" if name in {"search_files", "read_text_file", "create_note"} else (
            "external" if name == "get_weather" else "system"
        ),
        argument_schema=schema,
        permission_level=permission,
        execution_timeout=10 if name == "get_weather" else 15,
        implementation=implementation,
    )


def _validate_extension(extension: str) -> str:
    extension = extension.strip()
    if extension and not _SAFE_EXTENSION.fullmatch(extension):
        raise ToolExecutionError("INVALID_EXTENSION", "File extension must look like .txt or .py")
    return extension.casefold()


def search_files(
    path_guard: PathGuard,
    root: str,
    pattern: str = "*",
    extension: str = "",
) -> dict[str, Any]:
    """Search direct children of an authorized directory by pattern/extension."""
    extension = _validate_extension(extension)
    if not pattern or len(pattern) > 255 or "/" in pattern or "\x00" in pattern:
        raise ToolExecutionError("INVALID_PATTERN", "Filename pattern is invalid")
    try:
        entries = path_guard.iter_directory(root)
        matches = []
        total = 0
        scanned = 0
        truncated = False
        for entry in entries:
            scanned += 1
            if scanned > _MAX_SEARCH_ENTRIES:
                truncated = True
                break
            if not stat.S_ISREG(entry.mode):
                continue
            if not fnmatch.fnmatchcase(entry.path.name.casefold(), pattern.casefold()):
                continue
            if extension and entry.path.suffix.casefold() != extension:
                continue
            total += 1
            if len(matches) < 10:
                matches.append({
                    "name": entry.path.name,
                    "path": str(entry.path),
                    "size_bytes": entry.size,
                    "modified_time": entry.modified_time,
                })
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    matches.sort(key=lambda item: item["name"].casefold())
    return {
        "files": matches,
        "total_matches": total,
        "truncated": truncated or total > len(matches),
        "scanned_limit_reached": truncated,
    }


def read_text_file(path_guard: PathGuard, path: str, max_chars: int = 12_000) -> dict[str, Any]:
    """Read bounded UTF-8 content from an authorized .txt or .md regular file."""
    if not 1 <= max_chars <= 12_000:
        raise ToolExecutionError("INVALID_LIMIT", "Text limit must be between 1 and 12000 characters")
    if Path(path).suffix.casefold() not in _TEXT_EXTENSIONS:
        raise ToolExecutionError("UNSUPPORTED_FILE_TYPE", "Only .txt and .md files can be read")
    try:
        fd = path_guard.open_read(path)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    try:
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(_MAX_TEXT_BYTES + 1)
    except OSError:
        raise ToolExecutionError("FILE_READ_FAILED", "Text file could not be read") from None
    byte_truncated = len(raw) > _MAX_TEXT_BYTES
    try:
        text = raw[:_MAX_TEXT_BYTES].decode("utf-8", errors="ignore" if byte_truncated else "strict")
    except UnicodeDecodeError:
        raise ToolExecutionError("INVALID_TEXT_ENCODING", "Text file must use UTF-8 encoding") from None
    truncated = byte_truncated or len(text) > max_chars
    return {
        "path": str(Path(path)),
        "content": text[:max_chars],
        "characters_returned": min(len(text), max_chars),
        "truncated": truncated,
    }


def create_note(path_guard: PathGuard, path: str, content: str) -> dict[str, Any]:
    """Create a new UTF-8 note without replacing an existing file."""
    if Path(path).suffix.casefold() not in _TEXT_EXTENSIONS:
        raise ToolExecutionError("UNSUPPORTED_FILE_TYPE", "Notes must use a .txt or .md extension")
    if not content.strip() or len(content) > 20_000:
        raise ToolExecutionError("INVALID_NOTE", "Note content must be between 1 and 20000 characters")
    try:
        fd = path_guard.open_write(path)
    except FileExistsError:
        raise ToolExecutionError("FILE_EXISTS", "The note already exists; choose a different filename") from None
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    except OSError:
        raise ToolExecutionError("NOTE_CREATE_FAILED", "The note could not be created") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
    except OSError:
        raise ToolExecutionError("NOTE_WRITE_FAILED", "The note could not be fully written") from None
    return {"path": str(Path(path)), "characters_written": len(content), "status": "created"}


def _arithmetic_value(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _arithmetic_value(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        value = node.value
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = _arithmetic_value(node.operand)
        value = operand if isinstance(node.op, ast.UAdd) else -operand
    elif isinstance(node, ast.BinOp):
        left, right = _arithmetic_value(node.left), _arithmetic_value(node.right)
        if isinstance(node.op, ast.Add):
            value = left + right
        elif isinstance(node.op, ast.Sub):
            value = left - right
        elif isinstance(node.op, ast.Mult):
            value = left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ToolExecutionError("DIVISION_BY_ZERO", "Division by zero is not allowed")
            value = left / right
        elif isinstance(node.op, ast.FloorDiv):
            if right == 0:
                raise ToolExecutionError("DIVISION_BY_ZERO", "Division by zero is not allowed")
            value = left // right
        elif isinstance(node.op, ast.Mod):
            if right == 0:
                raise ToolExecutionError("DIVISION_BY_ZERO", "Division by zero is not allowed")
            value = left % right
        elif isinstance(node.op, ast.Pow):
            if abs(right) > 12:
                raise ToolExecutionError("EXPONENT_LIMIT", "Exponent must be between -12 and 12")
            value = left**right
        else:
            raise ToolExecutionError("INVALID_EXPRESSION", "Expression contains an unsupported operator")
    else:
        raise ToolExecutionError("INVALID_EXPRESSION", "Expression contains an unsupported operation")
    if not isinstance(value, (int, float)):
        raise ToolExecutionError("RESULT_OUT_OF_RANGE", "Calculation result is outside the supported range")
    if (isinstance(value, float) and not math.isfinite(value)) or abs(value) > 1e100:
        raise ToolExecutionError("RESULT_OUT_OF_RANGE", "Calculation result is outside the supported range")
    return value


def calculate(expression: str) -> dict[str, Any]:
    """Evaluate bounded arithmetic without eval or arbitrary code execution."""
    expression = expression.strip()
    if not expression or len(expression) > 256:
        raise ToolExecutionError("INVALID_EXPRESSION", "Expression must be between 1 and 256 characters")
    expression = re.sub(
        r"(?<![\w.])(\d+(?:\.\d+)?)\s*%(?!\s*\d)",
        r"(\1/100)",
        expression,
    )
    expression = re.sub(r"\bof\b", "*", expression, flags=re.IGNORECASE)
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError):
        raise ToolExecutionError("INVALID_EXPRESSION", "Expression is not valid arithmetic") from None
    if sum(1 for _ in ast.walk(tree)) > 64:
        raise ToolExecutionError("EXPRESSION_TOO_COMPLEX", "Expression is too complex")
    try:
        value = _arithmetic_value(tree)
    except (OverflowError, ZeroDivisionError):
        raise ToolExecutionError("RESULT_OUT_OF_RANGE", "Calculation result is outside the supported range") from None
    return {"expression": expression, "value": value}


def get_system_status() -> dict[str, Any]:
    """Report CPU, RAM, and root disk status without exposing process data."""
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        cpu = psutil.cpu_percent(interval=0.1)
    except (OSError, RuntimeError):
        raise ToolExecutionError("SYSTEM_STATUS_UNAVAILABLE", "System status could not be read") from None
    return {
        "cpu_percent": cpu,
        "ram_total_gb": round(memory.total / 1024**3, 2),
        "ram_used_percent": memory.percent,
        "ram_available_gb": round(memory.available / 1024**3, 2),
        "disk_used_percent": disk.percent,
        "disk_free_gb": round(disk.free / 1024**3, 2),
    }


def _http_json(url: str, params: dict[str, Any]) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            with client.stream("GET", url, params=params) as response:
                response.raise_for_status()
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > 32_000:
                        raise ToolExecutionError("WEATHER_RESPONSE_TOO_LARGE", "Weather service returned too much data")
                payload = json.loads(chunks)
    except ToolExecutionError:
        raise
    except (httpx.HTTPError, ValueError):
        raise ToolExecutionError("WEATHER_UNAVAILABLE", "Weather service could not be reached") from None
    if not isinstance(payload, dict):
        raise ToolExecutionError("INVALID_WEATHER_RESPONSE", "Weather service returned an invalid response")
    return payload


def get_weather(city: str, fetch_json: Callable[[str, dict[str, Any]], dict[str, Any]] = _http_json) -> dict[str, Any]:
    """Fetch current conditions through the Open-Meteo public API."""
    city = city.strip()
    if not city or len(city) > 120:
        raise ToolExecutionError("INVALID_CITY", "City name must be between 1 and 120 characters")
    locations = fetch_json(
        "https://geocoding-api.open-meteo.com/v1/search",
        {"name": city, "count": 1, "language": "en", "format": "json"},
    ).get("results")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        raise ToolExecutionError("CITY_NOT_FOUND", "No matching city was found")
    location = locations[0]
    try:
        latitude, longitude = float(location["latitude"]), float(location["longitude"])
    except (KeyError, TypeError, ValueError):
        raise ToolExecutionError("INVALID_WEATHER_RESPONSE", "Weather service returned invalid location data") from None
    current = fetch_json(
        "https://api.open-meteo.com/v1/forecast",
        {
            "latitude": latitude,
            "longitude": longitude,
            "current": "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m",
            "timezone": "auto",
        },
    ).get("current")
    if not isinstance(current, dict):
        raise ToolExecutionError("INVALID_WEATHER_RESPONSE", "Weather service returned no current conditions")
    return {
        "city": str(location.get("name", city))[:120],
        "country": str(location.get("country", ""))[:120],
        "timezone": str(location.get("timezone", ""))[:120],
        "current": current,
    }


def register_functional_tools(
    registry: ToolRegistry,
    path_guard: PathGuard,
    *,
    weather_fetch_json: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
) -> None:
    """Register the six core tools explicitly in a caller-owned registry."""
    string_schema = {"type": "string", "minLength": 1}
    registry.register(_tool(
        "search_files",
        "Find direct child files by filename pattern and optional extension.",
        {
            "type": "object",
            "properties": {
                "root": string_schema,
                "pattern": {"type": "string", "minLength": 1, "maxLength": 255, "default": "*"},
                "extension": {"type": "string", "maxLength": 17, "default": ""},
            },
            "required": ["root"],
            "additionalProperties": False,
        },
        "read",
        lambda root, pattern="*", extension="": search_files(path_guard, root, pattern, extension),
    ))
    registry.register(_tool(
        "read_text_file",
        "Read a bounded UTF-8 .txt or .md file beneath an allowed root.",
        {
            "type": "object",
            "properties": {
                "path": string_schema,
                "max_chars": {"type": "integer", "minimum": 1, "maximum": 12000, "default": 12000},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "read",
        lambda path, max_chars=12000: read_text_file(path_guard, path, max_chars),
    ))
    registry.register(_tool(
        "create_note",
        "Create a new .txt or .md note after explicit trusted-interface approval.",
        {
            "type": "object",
            "properties": {
                "path": string_schema,
                "content": {"type": "string", "minLength": 1, "maxLength": 20000},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "write",
        lambda path, content: create_note(path_guard, path, content),
    ))
    registry.register(_tool(
        "calculate",
        "Calculate bounded arithmetic, including percentage expressions such as 15% of 250000.",
        {
            "type": "object",
            "properties": {"expression": {"type": "string", "minLength": 1, "maxLength": 256}},
            "required": ["expression"],
            "additionalProperties": False,
        },
        "read",
        calculate,
    ))
    registry.register(_tool(
        "get_system_status",
        "Get CPU, RAM, and root disk usage.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "read",
        get_system_status,
    ))
    weather_impl = (
        (lambda city: get_weather(city, weather_fetch_json))
        if weather_fetch_json is not None
        else get_weather
    )
    registry.register(_tool(
        "get_weather",
        "Get current conditions for a city using the Open-Meteo public API.",
        {
            "type": "object",
            "properties": {"city": {"type": "string", "minLength": 1, "maxLength": 120}},
            "required": ["city"],
            "additionalProperties": False,
        },
        "external",
        weather_impl,
    ))
