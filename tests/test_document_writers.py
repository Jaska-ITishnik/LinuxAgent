"""Tests for approval-gated atomic document creation."""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from docx import Document
from openpyxl import load_workbook

from core.config import AppConfig
from core.errors import ToolExecutionError
from core.tool_dispatcher import ToolDispatcher
from core.tool_registry import ToolRegistry
from security.approval import ApprovalDecision
from security.path_guard import PathGuard
from tools.document_writers import (
    create_csv_document,
    create_docx_document,
    create_markdown_document,
    create_xlsx_document,
    register_document_writer_tools,
)
from tools.registry import build_policy_authorizer


class ApprovalStub:
    def __init__(self, decision):
        self.decision = decision
        self.requests = []

    def request_approval(self, request, timeout_seconds):
        self.requests.append(request)
        return self.decision


class DocumentWriterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = PathGuard([self.root])

    def tearDown(self):
        self.temp.cleanup()

    def test_markdown_and_docx_outputs_are_verified_and_non_overwriting(self):
        markdown = self.root / "notes.md"
        result = create_markdown_document(self.guard, str(markdown), "# Summary")
        self.assertTrue(result["verified"])
        self.assertEqual(markdown.read_text(encoding="utf-8"), "# Summary")
        with self.assertRaisesRegex(ToolExecutionError, "already exists"):
            create_markdown_document(self.guard, str(markdown), "replace")
        self.assertEqual(markdown.read_text(encoding="utf-8"), "# Summary")

        docx_path = self.root / "report.docx"
        created = create_docx_document(
            self.guard,
            str(docx_path),
            title="Report",
            paragraphs=["Visible paragraph"],
            tables=[[["Name", "Value"], ["Item", "3"]]],
        )
        self.assertTrue(created["verified"])
        document = Document(docx_path)
        self.assertEqual(document.paragraphs[0].text, "Report")
        self.assertEqual(document.tables[0].cell(1, 0).text, "Item")

    def test_csv_and_xlsx_spreadsheet_values_cannot_become_formulas(self):
        headers = ["Name", "=SUM(A1:A2)"]
        rows = [["alpha", "  =1+1"], ["beta", "@cmd"]]
        csv_path = self.root / "safe.csv"
        create_csv_document(self.guard, str(csv_path), headers, rows)
        with csv_path.open(encoding="utf-8", newline="") as stream:
            data = list(csv.reader(stream))
        self.assertEqual(data[0][1], "'=SUM(A1:A2)")
        self.assertEqual(data[1][1], "'  =1+1")
        self.assertEqual(data[2][1], "'@cmd")

        xlsx_path = self.root / "safe.xlsx"
        create_xlsx_document(self.guard, str(xlsx_path), headers, rows)
        workbook = load_workbook(xlsx_path, data_only=False)
        sheet = workbook["Data"]
        self.assertEqual(sheet["B1"].value, "=SUM(A1:A2)")
        self.assertEqual(sheet["B1"].data_type, "s")
        self.assertEqual(sheet["B2"].data_type, "s")
        workbook.close()

    def test_invalid_structured_content_is_rejected(self):
        with self.assertRaisesRegex(ToolExecutionError, "row must match"):
            create_csv_document(self.guard, str(self.root / "bad.csv"), ["a", "b"], [["one"]])
        with self.assertRaisesRegex(ToolExecutionError, "extension"):
            create_markdown_document(self.guard, str(self.root / "bad.txt"), "not markdown")

    async def test_writers_always_require_trusted_approval(self):
        registry = ToolRegistry()
        register_document_writer_tools(registry, self.guard)
        approval = ApprovalStub(ApprovalDecision.DENY)
        dispatcher = ToolDispatcher(
            registry,
            authorizer=build_policy_authorizer(
                AppConfig.model_validate({"security": {"approval_policy": "never"}}),
                registry,
                approval_interface=approval,
            ),
        )
        self.addCleanup(dispatcher.close)
        destination = self.root / "denied.md"
        denied = await dispatcher.dispatch({
            "tool_name": "create_markdown_document",
            "arguments": {"path": str(destination), "content": "not written"},
        })
        self.assertEqual(denied.status, "denied")
        self.assertFalse(destination.exists())
        self.assertEqual(len(approval.requests), 1)

        approval.decision = ApprovalDecision.APPROVE
        approved = await dispatcher.dispatch({
            "tool_name": "create_markdown_document",
            "arguments": {"path": str(destination), "content": "approved"},
        })
        self.assertEqual(approved.status, "success")
        self.assertEqual(destination.read_text(encoding="utf-8"), "approved")


if __name__ == "__main__":
    unittest.main()
