"""The data QR as layer 9 of the verifier, and how the CLI takes one.

A QR is read off paper, by a person standing over a printout with a
phone. So the payload arrives as text on the command line — not pulled
out of the PDF — and the verifier's job is to bind that text to the file
in front of it.
"""

from __future__ import annotations

import hashlib
import json

import pdf_factory
import pytest
import qr_factory

from kobsign_evidence.cli import main
from kobsign_evidence.evidence import canonicalize
from kobsign_evidence.verifier import verify


@pytest.fixture
def evidence() -> dict:
    package = {
        "document_title": "QR integration fixture",
        "koblink_id": "KB-PERSON-VERIFY001-DOC-2026-00002",
        "signatures": [{"name": "Ola Nordmann", "level": "AES"}],
        "original_document_hash": "a" * 128,
        "evidence_json_hash": "",
        "_schema": {
            "version": "3.12.0",
            "type": "DocumentEvidencePackage",
            "canonicalization_version": "1",
        },
    }
    package["evidence_json_hash"] = hashlib.sha256(canonicalize(package)).hexdigest()
    return package


@pytest.fixture
def signed_pdf(tmp_path, evidence, signer_identity) -> str:
    raw = json.dumps(evidence).encode("utf-8")
    with_evidence = pdf_factory.attach_evidence_json(pdf_factory.blank_pdf(), raw)
    path = tmp_path / "with_evidence.pdf"
    path.write_bytes(pdf_factory.sign(with_evidence, signer_identity))
    return str(path)


@pytest.fixture
def qr_identity() -> qr_factory.QrIdentity:
    return qr_factory.QrIdentity.generate()


def good_qr(identity, evidence) -> str:
    return qr_factory.make_qr(
        identity,
        qr_factory.payload_map(
            koblink_id=evidence["koblink_id"],
            evidence_hash=hashlib.sha256(canonicalize(evidence)).digest(),
            signer_count=1,
            levels={2: 1},
        ),
    )


def _layer(result, name: str):
    return next(layer for layer in result.layers if name in layer.name)


class TestLayerNine:
    def test_the_layer_is_reported_even_when_no_qr_is_supplied(self, signed_pdf):
        result = verify(signed_pdf)
        layer = _layer(result, "Data QR")
        assert layer.na, "a file checked without a printout in hand is not a failure"

    def test_a_matching_qr_passes_the_layer(self, signed_pdf, qr_identity, evidence):
        result = verify(
            signed_pdf,
            qr_payload=good_qr(qr_identity, evidence),
            extra_qr_keys=[qr_identity.public_pem],
        )
        layer = _layer(result, "Data QR")
        assert layer.ok, layer.detail
        assert not layer.na

    def test_a_qr_for_another_document_fails_the_layer(
        self, signed_pdf, qr_identity, evidence
    ):
        other = qr_factory.make_qr(
            qr_identity,
            qr_factory.payload_map(
                koblink_id=evidence["koblink_id"],
                evidence_hash=bytes(32),
                signer_count=1,
                levels={2: 1},
            ),
        )
        result = verify(
            signed_pdf, qr_payload=other, extra_qr_keys=[qr_identity.public_pem]
        )
        layer = _layer(result, "Data QR")
        assert not layer.ok
        assert not layer.na
        assert not result.verified

    def test_an_unverifiable_qr_is_never_rounded_down_to_not_applicable(
        self, signed_pdf, qr_identity, evidence
    ):
        """No archived key is a failure to verify, not an absence of a QR."""
        result = verify(signed_pdf, qr_payload=good_qr(qr_identity, evidence))
        layer = _layer(result, "Data QR")
        assert not layer.ok
        assert not layer.na

    def test_the_result_carries_the_decoded_payload(
        self, signed_pdf, qr_identity, evidence
    ):
        result = verify(
            signed_pdf,
            qr_payload=good_qr(qr_identity, evidence),
            extra_qr_keys=[qr_identity.public_pem],
        )
        assert result.qr is not None
        assert result.qr.payload.koblink_id == evidence["koblink_id"]


class TestCommandLine:
    def test_qr_text_is_accepted_on_the_command_line(
        self, signed_pdf, qr_identity, evidence, capsys
    ):
        code = main([signed_pdf, "--qr", good_qr(qr_identity, evidence), "--verbose"])
        out = capsys.readouterr().out
        assert "Data QR" in out
        # The signer is self-signed, so the file fails on trust regardless —
        # what matters here is that the QR layer ran and reported itself.
        assert code in (0, 1)
        assert "no data QR supplied" not in out

    def test_qr_can_be_read_from_a_file(
        self, tmp_path, signed_pdf, qr_identity, evidence, capsys
    ):
        payload = tmp_path / "scan.txt"
        payload.write_text(good_qr(qr_identity, evidence) + "\n")
        main([signed_pdf, "--qr-file", str(payload), "--verbose"])
        out = capsys.readouterr().out
        assert "Data QR" in out
        assert "not valid" not in out

    def test_a_missing_qr_file_is_an_argument_error(self, signed_pdf, capsys):
        assert main([signed_pdf, "--qr-file", "/nonexistent/scan.txt"]) == 2

    def test_qr_and_qr_file_together_are_refused(self, tmp_path, signed_pdf, capsys):
        payload = tmp_path / "scan.txt"
        payload.write_text("BB8")
        assert main([signed_pdf, "--qr", "BB8", "--qr-file", str(payload)]) == 2

    def test_json_output_carries_the_qr_findings(
        self, signed_pdf, qr_identity, evidence, capsys
    ):
        main([signed_pdf, "--qr", good_qr(qr_identity, evidence), "--json"])
        report = json.loads(capsys.readouterr().out)
        assert any("Data QR" in layer["name"] for layer in report["layers"])
        assert "qr" in report


class TestMalformedEvidenceInThePdf:
    """evidence.json is attacker-influenced input; verify() still returns."""

    @pytest.mark.parametrize("content", [b"[1, 2, 3]", b'"a string"', b"null", b"{"])
    def test_a_non_object_evidence_json_yields_a_verdict_not_a_traceback(
        self, tmp_path, signer_identity, content
    ):
        pdf = pdf_factory.attach_evidence_json(pdf_factory.blank_pdf(), content)
        path = tmp_path / "bad_evidence.pdf"
        path.write_bytes(pdf_factory.sign(pdf, signer_identity))

        result = verify(str(path), qr_payload="BB8")
        assert not result.verified
        assert not _layer(result, "evidence.json").ok
        assert not _layer(result, "Data QR").ok
