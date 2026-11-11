"""Approval-gated document creation with atomic no-overwrite publication."""
from __future__ import annotations

import csv
import hashlib
import io
import os
from pathlib import Path
import secrets
from typing import Any, Callable
import zipfile

from docx import Document
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
_MAX_ROWS = 500
_MAX_COLUMNS = 100
_MAX_CELL_CHARS = 2_000
_MAX_CONTENT_CHARS = 100_000
_CHUNK_BYTES = 64 * 1024


def _validate_text(value: Any, *, limit: int = _MAX_CELL_CHARS, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value) > limit or (not allow_empty and not value.strip()):
        raise ToolExecutionError("INVALID_CONTENT", "Document text is invalid or exceeds its size limit")
    return value


def _validate_grid(headers: list[str], rows: list[list[str]]) -> tuple[list[str], list[list[str]]]:
    if not isinstance(headers, list) or not 1 <= len(headers) <= _MAX_COLUMNS:
        raise ToolExecutionError("INVALID_CONTENT", "Documents must contain between 1 and 100 columns")
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        raise ToolExecutionError("INVALID_CONTENT", "Documents may contain at most 500 data rows")
    normalized_headers = [_validate_text(value) for value in headers]
    normalized_rows = []
    total_cells = len(normalized_headers)
    total_chars = sum(map(len, normalized_headers))
    for row in rows:
        if not isinstance(row, list) or len(row) != len(normalized_headers):
            raise ToolExecutionError("INVALID_CONTENT", "Each document row must match the header column count")
        normalized = [_validate_text(value) for value in row]
        normalized_rows.append(normalized)
        total_cells += len(normalized)
        total_chars += sum(map(len, normalized))
        if total_cells > 20_000 or total_chars > _MAX_CONTENT_CHARS:
            raise ToolExecutionError("INVALID_CONTENT", "Structured document content exceeds its size limit")
    return normalized_headers, normalized_rows


def _cleanup_temp(path_guard: PathGuard, path: str, identity: os.stat_result | None) -> bool:
    if identity is None:
        return True
    try:
        path_guard.unlink_file(path, expected=identity)
        return True
    except (PathAccessError, OSError):
        return False


def _verify_published_file(path_guard: PathGuard, path: str, expected: bytes, format: str) -> os.stat_result:
    try:
        fd = path_guard.open_read(path)
    except PathAccessError as exc:
        raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document could not be reopened for verification") from exc
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            actual = source.read(_MAX_OUTPUT_BYTES + 1)
    except OSError:
        raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document could not be verified") from None
    if len(actual) > _MAX_OUTPUT_BYTES or actual != expected:
        raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document did not match its verified content")
    if format in {"docx", "xlsx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(actual)) as archive:
                if archive.testzip() is not None:
                    raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document archive is corrupted")
                required = "word/document.xml" if format == "docx" else "xl/workbook.xml"
                if required not in archive.namelist():
                    raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document structure is incomplete")
        except (OSError, zipfile.BadZipFile):
            raise ToolExecutionError("OUTPUT_VERIFY_FAILED", "Created document archive is corrupted") from None
    return info


def _write_new_document(path_guard: PathGuard, path: str, content: bytes, format: str) -> dict[str, Any]:
    if len(content) > _MAX_OUTPUT_BYTES:
        raise ToolExecutionError("OUTPUT_TOO_LARGE", "Generated document exceeds the 10 MiB output limit")
    try:
        destination = path_guard.validate(path, operation="write", must_exist=False)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    temp_path = destination.parent / f".linuxagent-{secrets.token_hex(16)}.tmp"
    fd = -1
    identity = None
    try:
        fd = path_guard.open_write(temp_path)
        identity = os.fstat(fd)
        view = memoryview(content)
        while view:
            chunk = view[:_CHUNK_BYTES]
            written = os.write(fd, chunk)
            if written <= 0:
                raise OSError("document write made no progress")
            view = view[written:]
        os.fsync(fd)
    except FileExistsError:
        raise ToolExecutionError("TEMPORARY_FILE_CONFLICT", "A temporary output file already exists") from None
    except (PathAccessError, OSError):
        if not _cleanup_temp(path_guard, str(temp_path), identity):
            raise ToolExecutionError("PARTIAL_WRITE", "Document write failed and its temporary file could not be removed") from None
        raise ToolExecutionError("DOCUMENT_WRITE_FAILED", "Document could not be written to a temporary file") from None
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        path_guard.publish_file(str(temp_path), path, expected=identity)
    except FileExistsError:
        if not _cleanup_temp(path_guard, str(temp_path), identity):
            raise ToolExecutionError("PARTIAL_WRITE", "Destination exists and the temporary file could not be removed") from None
        raise ToolExecutionError("DESTINATION_EXISTS", "Destination already exists; no file was overwritten") from None
    except PathAccessError as exc:
        clean = _cleanup_temp(path_guard, str(temp_path), identity)
        if "was published but" in str(exc):
            if not clean:
                raise ToolExecutionError("PUBLISH_PARTIAL", "Document was published but temporary-file cleanup failed") from None
        else:
            if not clean:
                raise ToolExecutionError("PARTIAL_WRITE", "Document publication failed and its temporary file could not be removed") from None
            raise ToolExecutionError("PUBLISH_FAILED", "Document could not be safely published") from None
    try:
        published = _verify_published_file(path_guard, path, content, format)
    except ToolExecutionError:
        try:
            path_guard.unlink_file(path, expected=identity)
        except (PathAccessError, OSError):
            raise ToolExecutionError("OUTPUT_VERIFY_PARTIAL", "Output verification failed and the published file could not be removed") from None
        raise
    return {
        "path": str(Path(path)),
        "format": format,
        "size_bytes": published.st_size,
        "sha256": hashlib.sha256(content).hexdigest(),
        "verified": True,
        "status": "created",
    }


def create_markdown_document(path_guard: PathGuard, path: str, content: str) -> dict[str, Any]:
    """Create a new UTF-8 Markdown document without overwriting existing files."""
    if Path(path).suffix.casefold() != ".md":
        raise ToolExecutionError("INVALID_OUTPUT_PATH", "Markdown output path must use the .md extension")
    content = _validate_text(content, limit=50_000, allow_empty=False)
    return _write_new_document(path_guard, path, content.encode("utf-8"), "markdown")


def create_docx_document(
    path_guard: PathGuard,
    path: str,
    title: str = "",
    paragraphs: list[str] | None = None,
    tables: list[list[list[str]]] | None = None,
) -> dict[str, Any]:
    """Create a simple DOCX with validated text and tables."""
    if Path(path).suffix.casefold() != ".docx":
        raise ToolExecutionError("INVALID_OUTPUT_PATH", "DOCX output path must use the .docx extension")
    title = _validate_text(title, limit=200)
    paragraphs = paragraphs or []
    tables = tables or []
    if len(paragraphs) > 200 or len(tables) > 20:
        raise ToolExecutionError("INVALID_CONTENT", "DOCX content exceeds its paragraph or table limit")
    paragraphs = [_validate_text(item) for item in paragraphs]
    normalized_tables = []
    total_chars = len(title) + sum(map(len, paragraphs))
    for table in tables:
        if not isinstance(table, list) or len(table) > 100:
            raise ToolExecutionError("INVALID_CONTENT", "DOCX tables may contain at most 100 rows")
        normalized_table = []
        width = None
        for row in table:
            if not isinstance(row, list) or not 1 <= len(row) <= 20 or (width is not None and len(row) != width):
                raise ToolExecutionError("INVALID_CONTENT", "DOCX table rows must have a consistent width of 1-20 cells")
            width = len(row)
            normalized = [_validate_text(value) for value in row]
            total_chars += sum(map(len, normalized))
            normalized_table.append(normalized)
        normalized_tables.append(normalized_table)
    if total_chars > _MAX_CONTENT_CHARS:
        raise ToolExecutionError("INVALID_CONTENT", "DOCX text exceeds the 100000 character limit")
    if not title and not paragraphs and not any(normalized_tables):
        raise ToolExecutionError("INVALID_CONTENT", "DOCX must contain a title, paragraph, or table")
    document = Document()
    if title:
        document.add_heading(title, level=1)
    for paragraph in paragraphs:
        document.add_paragraph(paragraph)
    for table_data in normalized_tables:
        if not table_data:
            continue
        table = document.add_table(rows=0, cols=len(table_data[0]))
        for row_data in table_data:
            cells = table.add_row().cells
            for cell, value in zip(cells, row_data):
                cell.text = value
    output = io.BytesIO()
    document.save(output)
    return _write_new_document(path_guard, path, output.getvalue(), "docx")


def _spreadsheet_safe(value: str) -> str:
    stripped = value.lstrip(" \t\r\n\v\f\ufeff")
    if value.startswith(("\t", "\r", "\n")) or stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def create_csv_document(
    path_guard: PathGuard,
    path: str,
    headers: list[str],
    rows: list[list[str]],
) -> dict[str, Any]:
    """Create a CSV with formula-injection-safe string cells."""
    if Path(path).suffix.casefold() != ".csv":
        raise ToolExecutionError("INVALID_OUTPUT_PATH", "CSV output path must use the .csv extension")
    headers, rows = _validate_grid(headers, rows)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([_spreadsheet_safe(value) for value in headers])
    writer.writerows([_spreadsheet_safe(value) for value in row] for row in rows)
    return _write_new_document(path_guard, path, output.getvalue().encode("utf-8"), "csv")


def create_xlsx_document(
    path_guard: PathGuard,
    path: str,
    headers: list[str],
    rows: list[list[str]],
) -> dict[str, Any]:
    """Create an XLSX worksheet whose untrusted strings are always stored as text."""
    if Path(path).suffix.casefold() != ".xlsx":
        raise ToolExecutionError("INVALID_OUTPUT_PATH", "XLSX output path must use the .xlsx extension")
    headers, rows = _validate_grid(headers, rows)
    workbook = Workbook(write_only=True)
    worksheet = workbook.create_sheet(title="Data")
    for row in [headers, *rows]:
        cells = []
        for value in row:
            cell = WriteOnlyCell(worksheet, value=value)
            cell.data_type = "s"
            cells.append(cell)
        worksheet.append(cells)
    output = io.BytesIO()
    workbook.save(output)
    workbook.close()
    return _write_new_document(path_guard, path, output.getvalue(), "xlsx")


def register_document_writer_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register document writers that require explicit policy approval."""
    text = {"type": "string", "maxLength": _MAX_CELL_CHARS}
    grid = {
        "headers": {"type": "array", "items": text, "minItems": 1, "maxItems": _MAX_COLUMNS},
        "rows": {
            "type": "array",
            "items": {"type": "array", "items": text, "maxItems": _MAX_COLUMNS},
            "maxItems": _MAX_ROWS,
        },
    }
    definitions: tuple[tuple[str, str, dict[str, Any], Callable[..., Any]], ...] = (
        ("create_markdown_document", "Create a new Markdown document after explicit approval.", {
            "path": {"type": "string", "minLength": 1},
            "content": {"type": "string", "minLength": 1, "maxLength": 50_000},
        }, create_markdown_document),
        ("create_docx_document", "Create a new DOCX document from approved structured content.", {
            "path": {"type": "string", "minLength": 1},
            "title": {"type": "string", "maxLength": 200, "default": ""},
            "paragraphs": {"type": "array", "items": text, "maxItems": 200, "default": []},
            "tables": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": {"type": "array", "items": text, "minItems": 1, "maxItems": 20},
                    "maxItems": 100,
                },
                "maxItems": 20,
                "default": [],
            },
        }, create_docx_document),
        ("create_csv_document", "Create an approved CSV with formula-injection-safe text cells.", {
            "path": {"type": "string", "minLength": 1},
            **grid,
        }, create_csv_document),
        ("create_xlsx_document", "Create an approved XLSX worksheet with all untrusted values stored as text.", {
            "path": {"type": "string", "minLength": 1},
            **grid,
        }, create_xlsx_document),
    )
    for name, description, properties, implementation in definitions:
        required = ["path"]
        if name == "create_markdown_document":
            required.append("content")
        elif name in {"create_csv_document", "create_xlsx_document"}:
            required.extend(["headers", "rows"])
        registry.register(ToolDefinition(
            name=name,
            description=description,
            category="filesystem",
            argument_schema={
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
            permission_level="write",
            execution_timeout=30,
            implementation=lambda _implementation=implementation, **arguments: _implementation(
                path_guard, **arguments,
            ),
        ))
