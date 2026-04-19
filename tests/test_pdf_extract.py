"""Tests for PDF attachment extraction.

Uses a minimal hand-built PDF with an evidence.json attachment so we
don't need the full KobSign backend to exercise this layer.
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pikepdf
import pytest

from kobsign_evidence.pdf_extract import extract_attachment, list_attachments


def _build_pdf_with_attachment(attachment_name: str, attachment_bytes: bytes) -> bytes:
    """Produce a minimal PDF with one embedded file — matches KobSign's format."""
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(595, 842))

    stream = pikepdf.Stream(pdf, attachment_bytes)
    stream["/Type"] = pikepdf.Name("/EmbeddedFile")
    stream["/Subtype"] = pikepdf.Name("/application/json")
    stream["/Params"] = pikepdf.Dictionary({"/Size": len(attachment_bytes)})

    filespec = pikepdf.Dictionary(
        {
            "/Type": pikepdf.Name("/Filespec"),
            "/F": pikepdf.String(attachment_name),
            "/UF": pikepdf.String(attachment_name),
            "/EF": pikepdf.Dictionary({"/F": stream}),
            "/AFRelationship": pikepdf.Name("/Data"),
        }
    )

    if "/Names" not in pdf.Root:
        pdf.Root.Names = pikepdf.Dictionary()
    pdf.Root.Names.EmbeddedFiles = pikepdf.Dictionary()
    pdf.Root.Names.EmbeddedFiles.Names = pikepdf.Array()
    pdf.Root.Names.EmbeddedFiles.Names.append(pikepdf.String(attachment_name))
    pdf.Root.Names.EmbeddedFiles.Names.append(pdf.make_indirect(filespec))

    pdf.Root.AF = pikepdf.Array()
    pdf.Root.AF.append(pdf.make_indirect(filespec))

    buf = BytesIO()
    pdf.save(buf)
    return buf.getvalue()


@pytest.fixture
def pdf_with_evidence(tmp_path):
    evidence = {"signatures": [{"name": "Alice"}], "_schema": {"version": "3.4.0"}}
    body = json.dumps(evidence).encode("utf-8")
    pdf_path = tmp_path / "with_evidence.pdf"
    pdf_path.write_bytes(_build_pdf_with_attachment("evidence.json", body))
    return pdf_path


@pytest.fixture
def pdf_without_attachments(tmp_path):
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(595, 842))
    buf = BytesIO()
    pdf.save(buf)
    pdf_path = tmp_path / "empty.pdf"
    pdf_path.write_bytes(buf.getvalue())
    return pdf_path


class TestExtractAttachment:
    def test_returns_bytes_for_existing_attachment(self, pdf_with_evidence):
        data = extract_attachment(str(pdf_with_evidence), "evidence.json")
        assert data is not None
        parsed = json.loads(data)
        assert parsed["signatures"][0]["name"] == "Alice"

    def test_returns_none_for_missing_attachment(self, pdf_with_evidence):
        assert extract_attachment(str(pdf_with_evidence), "missing.json") is None

    def test_returns_none_for_pdf_without_any_attachments(self, pdf_without_attachments):
        assert extract_attachment(str(pdf_without_attachments), "evidence.json") is None


class TestListAttachments:
    def test_lists_embedded_files(self, pdf_with_evidence):
        names = list_attachments(str(pdf_with_evidence))
        assert names == ["evidence.json"]

    def test_empty_list_for_pdf_without_attachments(self, pdf_without_attachments):
        assert list_attachments(str(pdf_without_attachments)) == []
