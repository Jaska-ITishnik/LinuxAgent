"""Bounded, read-only document extraction through the shared filesystem guard."""
from __future__ import annotations

import csv
import io
import math
import os
from pathlib import Path
import stat
import zipfile
from typing import Any

from core.errors import ToolExecutionError
from core.tool_registry import ToolDefinition, ToolRegistry
from security.path_guard import PathAccessError, PathGuard


_MAX_INPUT_BYTES = 20 * 1024 * 1024
_MAX_ZIP_ENTRIES = 2_000
_MAX_ZIP_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 100
_MAX_ROWS = 500
_MAX_COLUMNS = 100
_MAX_CELL_CHARS = 2_000
_MAX_CELLS = 2_000
_MAX_CELL_TEXT_TOTAL = 12_000
_MAX_TEXT_CHARS = 20_000


def _read_document(path_guard: PathGuard, path: str, suffix: str) -> tuple[bytes, int]:
    if Path(path).suffix.casefold() != suffix:
        raise ToolExecutionError("UNSUPPORTED_FILE_TYPE", f"Only {suffix} files are supported")
    try:
        fd = path_guard.open_read(path)
    except PathAccessError as exc:
        raise ToolExecutionError("PATH_DENIED", str(exc)) from None
    fd_open = fd
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ToolExecutionError("INVALID_DOCUMENT", "Document must be a regular file")
        if info.st_size > _MAX_INPUT_BYTES:
            raise ToolExecutionError("DOCUMENT_TOO_LARGE", "Document exceeds the 20 MiB input limit")
        with os.fdopen(fd, "rb") as source:
            fd_open = -1
            raw = source.read(_MAX_INPUT_BYTES + 1)
        if len(raw) > _MAX_INPUT_BYTES:
            raise ToolExecutionError("DOCUMENT_TOO_LARGE", "Document exceeds the 20 MiB input limit")
        return raw, info.st_size
    except ToolExecutionError:
        raise
    except OSError:
        raise ToolExecutionError("DOCUMENT_READ_FAILED", "Document could not be read") from None
    finally:
        if fd_open >= 0:
            os.close(fd_open)


def _check_zip_container(raw: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > _MAX_ZIP_ENTRIES:
                raise ToolExecutionError("DOCUMENT_COMPLEXITY_LIMIT", "Document contains too many embedded entries")
            expanded = 0
            for entry in entries:
                expanded += entry.file_size
                if expanded > _MAX_ZIP_EXPANDED_BYTES:
                    raise ToolExecutionError("DOCUMENT_EXPANSION_LIMIT", "Document expands beyond the 100 MiB processing limit")
                if entry.file_size > max(1, entry.compress_size) * _MAX_COMPRESSION_RATIO:
                    raise ToolExecutionError("DOCUMENT_COMPRESSION_LIMIT", "Document entry compression ratio exceeds the safety limit")
                if entry.filename.startswith(("/", "\\")) or ".." in Path(entry.filename).parts:
                    raise ToolExecutionError("INVALID_DOCUMENT", "Document contains an unsafe embedded path")
                mode = entry.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ToolExecutionError("INVALID_DOCUMENT", "Document contains an unsupported embedded file type")
    except ToolExecutionError:
        raise
    except (OSError, zipfile.BadZipFile, ValueError):
        raise ToolExecutionError("CORRUPT_DOCUMENT", "Document container is invalid or corrupted") from None


def _bounded_text(value: Any, limit: int = _MAX_CELL_CHARS) -> tuple[str, bool]:
    text = "".join(char if char in "\t\n" or char.isprintable() else " " for char in str(value))
    return text[:limit], len(text) > limit


def _bounded_cell(value: Any, budget: list[int]) -> tuple[str, bool]:
    allowance = min(_MAX_CELL_CHARS, budget[0])
    text, truncated = _bounded_text(value, allowance)
    budget[0] -= len(text)
    return text, truncated or len(text) < len(str(value))


def read_pdf(path_guard: PathGuard, path: str, max_pages: int = 20, max_chars: int = 20_000) -> dict[str, Any]:
    """Extract bounded text from a PDF without fetching external resources."""
    if not 1 <= max_pages <= 50 or not 100 <= max_chars <= _MAX_TEXT_CHARS:
        raise ToolExecutionError("INVALID_LIMIT", "PDF limits must be 1-50 pages and 100-20000 characters")
    raw, file_bytes = _read_document(path_guard, path, ".pdf")
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError

        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise ToolExecutionError("ENCRYPTED_DOCUMENT", "Encrypted PDFs are not supported")
        page_count = len(reader.pages)
        pages = []
        text_parts = []
        characters = 0
        truncated = page_count > max_pages
        for index in range(min(page_count, max_pages)):
            text = reader.pages[index].extract_text() or ""
            text = "".join(char if char in "\t\n" or char.isprintable() else " " for char in text)
            remaining = max_chars - characters
            if len(text) > remaining:
                text = text[:remaining]
                truncated = True
            pages.append({"page": index + 1, "characters": len(text)})
            text_parts.append(text)
            characters += len(text)
            if characters >= max_chars:
                truncated = truncated or index + 1 < page_count
                break
    except ToolExecutionError:
        raise
    except (PdfReadError, OSError, ValueError, TypeError, KeyError):
        raise ToolExecutionError("CORRUPT_DOCUMENT", "PDF is invalid or could not be parsed") from None
    return {
        "path": str(Path(path)),
        "format": "pdf",
        "file_bytes": file_bytes,
        "page_count": page_count,
        "pages_returned": len(pages),
        "truncated": truncated,
        "content_is_untrusted": True,
        "text": "\n".join(text_parts),
        "pages": pages,
    }


def read_docx(
    path_guard: PathGuard,
    path: str,
    max_chars: int = 20_000,
    max_rows: int = 100,
) -> dict[str, Any]:
    """Extract bounded paragraphs and table rows from a DOCX document."""
    if not 100 <= max_chars <= _MAX_TEXT_CHARS or not 1 <= max_rows <= _MAX_ROWS:
        raise ToolExecutionError("INVALID_LIMIT", "DOCX limits must be 100-20000 characters and 1-500 table rows")
    raw, file_bytes = _read_document(path_guard, path, ".docx")
    _check_zip_container(raw)
    try:
        from docx import Document
        from docx.opc.exceptions import PackageNotFoundError

        document = Document(io.BytesIO(raw))
        paragraphs = []
        characters = 0
        truncated = False
        for paragraph in document.paragraphs:
            text = paragraph.text
            if not text:
                continue
            remaining = max_chars - characters
            if len(text) > remaining:
                text = text[:remaining]
                truncated = True
            paragraphs.append(text)
            characters += len(text)
            if characters >= max_chars:
                truncated = truncated or len(paragraphs) < len(document.paragraphs)
                break
        tables = []
        row_count = 0
        cell_budget = [_MAX_CELL_TEXT_TOTAL]
        cell_count = 0
        for table in document.tables:
            rows = []
            for row in table.rows:
                if row_count >= max_rows or cell_count >= _MAX_CELLS:
                    truncated = True
                    break
                values = []
                for cell in row.cells[:_MAX_COLUMNS]:
                    if cell_count >= _MAX_CELLS:
                        truncated = True
                        break
                    value, cell_truncated = _bounded_cell(cell.text, cell_budget)
                    values.append(value)
                    truncated |= cell_truncated
                    cell_count += 1
                rows.append(values)
                row_count += 1
            if rows:
                tables.append(rows)
            if row_count >= max_rows:
                truncated = truncated or len(tables) < len(document.tables)
                break
    except ToolExecutionError:
        raise
    except (PackageNotFoundError, OSError, ValueError, KeyError, zipfile.BadZipFile):
        raise ToolExecutionError("CORRUPT_DOCUMENT", "DOCX is invalid or could not be parsed") from None
    return {
        "path": str(Path(path)),
        "format": "docx",
        "file_bytes": file_bytes,
        "paragraph_count": len(document.paragraphs),
        "table_count": len(document.tables),
        "table_rows_returned": row_count,
        "truncated": truncated,
        "content_is_untrusted": True,
        "text": "\n".join(paragraphs),
        "tables": tables,
    }


def read_csv(path_guard: PathGuard, path: str, max_rows: int = 100) -> dict[str, Any]:
    """Read bounded UTF-8 CSV rows as structured cell data."""
    if not 1 <= max_rows <= _MAX_ROWS:
        raise ToolExecutionError("INVALID_LIMIT", "CSV row limit must be between 1 and 500")
    raw, file_bytes = _read_document(path_guard, path, ".csv")
    try:
        text = raw.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header_raw = next(reader, None)
        header = None
        truncated = False
        cell_budget = [_MAX_CELL_TEXT_TOTAL]
        cell_count = 0
        if header_raw is not None:
            header = []
            if len(header_raw) > _MAX_COLUMNS:
                truncated = True
            for value in header_raw[:_MAX_COLUMNS]:
                if cell_count >= _MAX_CELLS:
                    truncated = True
                    break
                bounded, was_truncated = _bounded_cell(value, cell_budget)
                header.append(bounded)
                truncated |= was_truncated
                cell_count += 1
        rows = []
        for row in reader:
            if len(rows) >= max_rows or cell_count >= _MAX_CELLS:
                truncated = True
                break
            if len(row) > _MAX_COLUMNS:
                truncated = True
            values = []
            for value in row[:_MAX_COLUMNS]:
                if cell_count >= _MAX_CELLS:
                    truncated = True
                    break
                bounded, was_truncated = _bounded_cell(value, cell_budget)
                values.append(bounded)
                truncated |= was_truncated
                cell_count += 1
            rows.append(values)
    except UnicodeDecodeError:
        raise ToolExecutionError("INVALID_TEXT_ENCODING", "CSV must use UTF-8 encoding") from None
    except csv.Error:
        raise ToolExecutionError("CORRUPT_DOCUMENT", "CSV is invalid or could not be parsed") from None
    return {
        "path": str(Path(path)),
        "format": "csv",
        "file_bytes": file_bytes,
        "columns": len(header or []),
        "rows_returned": len(rows),
        "truncated": truncated,
        "content_is_untrusted": True,
        "header": header,
        "rows": rows,
    }


def _xlsx_value(value: Any, budget: list[int]) -> tuple[Any, bool]:
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            return _bounded_cell(value, budget)
        return value, False
    if isinstance(value, float):
        return (value if math.isfinite(value) else str(value)), False
    if hasattr(value, "isoformat") and callable(value.isoformat):
        return _bounded_cell(value.isoformat(), budget)
    return _bounded_cell(str(value), budget)


def read_xlsx(path_guard: PathGuard, path: str, max_rows: int = 100) -> dict[str, Any]:
    """Read bounded worksheet rows from XLSX without evaluating formulas."""
    if not 1 <= max_rows <= _MAX_ROWS:
        raise ToolExecutionError("INVALID_LIMIT", "XLSX row limit must be between 1 and 500")
    raw, file_bytes = _read_document(path_guard, path, ".xlsx")
    _check_zip_container(raw)
    try:
        from openpyxl import load_workbook
        from openpyxl.utils.exceptions import InvalidFileException

        workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True, keep_links=False)
        worksheets = []
        rows_seen = 0
        cell_count = 0
        cell_budget = [_MAX_CELL_TEXT_TOTAL]
        truncated = len(workbook.worksheets) > 20
        try:
            for worksheet in workbook.worksheets[:20]:
                rows = []
                if worksheet.max_column and worksheet.max_column > _MAX_COLUMNS:
                    truncated = True
                column_limit = min(_MAX_COLUMNS, max(1, worksheet.max_column or 1))
                for row in worksheet.iter_rows(values_only=True, max_col=column_limit):
                    if rows_seen >= max_rows or cell_count >= _MAX_CELLS:
                        truncated = True
                        break
                    if len(row) > _MAX_COLUMNS:
                        truncated = True
                    values = []
                    for value in row[:_MAX_COLUMNS]:
                        if cell_count >= _MAX_CELLS:
                            truncated = True
                            break
                        cell_value, cell_truncated = _xlsx_value(value, cell_budget)
                        values.append(cell_value)
                        truncated |= cell_truncated
                        cell_count += 1
                    rows.append(values)
                    rows_seen += 1
                worksheets.append({"name": worksheet.title[:128], "rows": rows})
                if rows_seen >= max_rows:
                    truncated = truncated or worksheet is not workbook.worksheets[-1]
                    break
        finally:
            workbook.close()
    except (InvalidFileException, OSError, ValueError, KeyError, zipfile.BadZipFile):
        raise ToolExecutionError("CORRUPT_DOCUMENT", "XLSX is invalid or could not be parsed") from None
    return {
        "path": str(Path(path)),
        "format": "xlsx",
        "file_bytes": file_bytes,
        "sheet_count": len(worksheets),
        "rows_returned": rows_seen,
        "truncated": truncated,
        "content_is_untrusted": True,
        "sheets": worksheets,
    }


def register_document_tools(registry: ToolRegistry, path_guard: PathGuard) -> None:
    """Register four read-only bounded document readers."""
    path_schema = {"type": "string", "minLength": 1}
    definitions = (
        ("read_pdf", "Read bounded text from an authorized PDF file.", {
            "path": path_schema,
            "max_pages": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            "max_chars": {"type": "integer", "minimum": 100, "maximum": _MAX_TEXT_CHARS, "default": _MAX_TEXT_CHARS},
        }, ["path"], read_pdf, 30),
        ("read_docx", "Read bounded paragraphs and table rows from an authorized DOCX file.", {
            "path": path_schema,
            "max_chars": {"type": "integer", "minimum": 100, "maximum": _MAX_TEXT_CHARS, "default": _MAX_TEXT_CHARS},
            "max_rows": {"type": "integer", "minimum": 1, "maximum": _MAX_ROWS, "default": 100},
        }, ["path"], read_docx, 30),
        ("read_csv", "Read bounded structured rows from an authorized UTF-8 CSV file.", {
            "path": path_schema,
            "max_rows": {"type": "integer", "minimum": 1, "maximum": _MAX_ROWS, "default": 100},
        }, ["path"], read_csv, 15),
        ("read_xlsx", "Read bounded worksheet rows from an authorized XLSX file without evaluating formulas.", {
            "path": path_schema,
            "max_rows": {"type": "integer", "minimum": 1, "maximum": _MAX_ROWS, "default": 100},
        }, ["path"], read_xlsx, 30),
    )
    for name, description, properties, required, implementation, timeout in definitions:
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
            permission_level="read",
            execution_timeout=timeout,
            implementation=(
                (lambda path, _reader=implementation, **kwargs: _reader(path_guard, path, **kwargs))
            ),
        ))
