"""Tests for bounded, filesystem-guarded document readers."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

from docx import Document
from openpyxl import Workbook
from pypdf import PdfWriter

from core.tool_dispatcher import AllowListAuthorizer, ToolDispatcher
from core.errors import ToolExecutionError
from core.tool_registry import ToolRegistry
from security.path_guard import PathGuard
from tools.documents import (
    read_csv,
    read_docx,
    read_pdf,
    read_xlsx,
    register_document_tools,
)


class DocumentReaderTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_csv_rows_are_structured_and_bounded(self):
        path = self.root / "table.csv"
        path.write_text("name,count\nalpha,1\nbeta,2\n", encoding="utf-8")
        result = read_csv(self.guard, str(path), max_rows=1)
        self.assertEqual(result["header"], ["name", "count"])
        self.assertEqual(result["rows"], [["alpha", "1"]])
        self.assertTrue(result["truncated"])

    def test_docx_extracts_paragraphs_and_tables(self):
        path = self.root / "report.docx"
        document = Document()
        document.add_paragraph("Quarterly report")
        table = document.add_table(rows=1, cols=2)
        table.cell(0, 0).text = "Region"
        table.cell(0, 1).text = "North"
        document.save(path)
        result = read_docx(self.guard, str(path))
        self.assertIn("Quarterly report", result["text"])
        self.assertEqual(result["tables"], [[["Region", "North"]]])
        self.assertTrue(result["content_is_untrusted"])

    def test_pdf_page_and_character_limits(self):
        path = self.root / "blank.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_blank_page(width=100, height=100)
        with path.open("wb") as stream:
            writer.write(stream)
        result = read_pdf(self.guard, str(path), max_pages=1)
        self.assertEqual(result["page_count"], 2)
        self.assertEqual(result["pages_returned"], 1)
        self.assertTrue(result["truncated"])

    def test_xlsx_reads_values_without_evaluating_formulas(self):
        path = self.root / "values.xlsx"
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Data"
        sheet.append(["Name", "Value"])
        sheet.append(["item", 5])
        sheet.append(["formula", "=1+1"])
        workbook.save(path)
        result = read_xlsx(self.guard, str(path))
        self.assertEqual(result["sheets"][0]["name"], "Data")
        self.assertEqual(result["sheets"][0]["rows"][1], ["item", 5])
        self.assertIsNone(result["sheets"][0]["rows"][2][1])

    def test_empty_csv_and_corrupted_documents(self):
        empty_csv = self.root / "empty.csv"
        empty_csv.write_text("", encoding="utf-8")
        self.assertEqual(read_csv(self.guard, str(empty_csv))["rows"], [])
        for suffix, reader in (
            (".pdf", read_pdf),
            (".docx", read_docx),
            (".xlsx", read_xlsx),
        ):
            target = self.root / f"corrupt{suffix}"
            target.write_bytes(b"not a document")
            with self.subTest(suffix=suffix), self.assertRaises(ToolExecutionError):
                reader(self.guard, str(target))

    def test_oversized_and_unauthorized_documents_are_rejected(self):
        oversized = self.root / "large.csv"
        with oversized.open("wb") as stream:
            stream.truncate(20 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ToolExecutionError, "20 MiB"):
            read_csv(self.guard, str(oversized))
        with self.assertRaises(ToolExecutionError):
            read_csv(self.guard, "/etc/passwd")

    async def test_registered_csv_reader_runs_through_dispatcher(self):
        path = self.root / "dispatch.csv"
        path.write_text("a\nb\n", encoding="utf-8")
        registry = ToolRegistry()
        register_document_tools(registry, self.guard)
        dispatcher = ToolDispatcher(
            registry,
            authorizer=AllowListAuthorizer(frozenset({"read_csv"})),
        )
        self.addCleanup(dispatcher.close)
        result = await dispatcher.dispatch({
            "tool_name": "read_csv",
            "arguments": {"path": str(path)},
        })
        self.assertEqual(result.status, "success")
        self.assertEqual(result.result_data["format"], "csv")


if __name__ == "__main__":
    unittest.main()
