"""Layer 7 — what the verifier says the original document hash *is*.

The algorithm used to be inferred from the digest's width, which cannot
tell SHA-512 from SHA3-512 and had "SHA3-512" hard-coded for anything 64
bytes long. evidence.json carries a ``hash_algorithm`` field, so the
first move is to read it.

The catch, and why this has its own tests: the field and the value can
disagree. ``prod.pdf`` in this repository declares ``SHA-256`` and
records a 512-bit digest, which SHA-256 cannot produce. A report that
repeats a declaration the data contradicts puts a false statement in
front of a court, so a contradiction is named as one and neither side is
presented as the answer.
"""

from __future__ import annotations

import json

import pytest

from kobsign_evidence.pdf_extract import extract_attachment
from kobsign_evidence.verifier import _layer_7_document_hashes


def _evidence(digest_bytes: int, algorithm: str | None = None) -> dict:
    evidence: dict = {"original_document_hash": "ab" * digest_bytes}
    if algorithm is not None:
        evidence["hash_algorithm"] = algorithm
    return evidence


class TestDeclaredAlgorithm:
    def test_a_declaration_the_width_supports_is_used(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(32, "SHA-256"))
        assert layer.ok
        assert "SHA-256" in layer.detail
        assert "declared" in layer.detail

    @pytest.mark.parametrize(
        ("algorithm", "digest_bytes"),
        [("SHA-512", 64), ("SHA3-512", 64), ("SHA-384", 48), ("SHA3-256", 32)],
    )
    def test_the_field_distinguishes_what_width_alone_cannot(
        self, algorithm, digest_bytes
    ):
        """SHA-512 and SHA3-512 are both 64 bytes. Only the file can say."""
        layer = _layer_7_document_hashes("x.pdf", _evidence(digest_bytes, algorithm))
        assert layer.ok
        assert algorithm in layer.detail

    def test_a_declaration_the_width_contradicts_is_named_as_a_contradiction(self):
        """SHA-256 cannot produce 512 bits. Neither side is presented as fact."""
        layer = _layer_7_document_hashes("x.pdf", _evidence(64, "SHA-256"))
        assert layer.ok, "the digest is still recorded and well-formed"
        assert "SHA-256" in layer.detail
        assert "512-bit" in layer.detail
        assert "cannot" in layer.detail

    def test_an_unrecognised_algorithm_name_is_repeated_not_resolved(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(32, "BLAKE3"))
        assert layer.ok
        assert "BLAKE3" in layer.detail

    def test_without_a_declaration_the_width_is_all_there_is_and_it_says_so(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(64))
        assert layer.ok
        assert "512-bit" in layer.detail
        assert "not stated" in layer.detail
        assert "SHA3-512" not in layer.detail, "the old guess must not come back"


class TestUnchangedRejections:
    """The layer's existing refusals are untouched."""

    @pytest.mark.parametrize(
        "evidence",
        [
            {},
            {"original_document_hash": ""},
            {"original_document_hash": "too short"},
            {"original_document_hash": "z" * 64},
            {"original_document_hash": 12345},
        ],
    )
    def test_a_missing_or_malformed_digest_still_fails(self, evidence):
        assert not _layer_7_document_hashes("x.pdf", evidence).ok

    def test_no_evidence_at_all_still_fails(self):
        assert not _layer_7_document_hashes("x.pdf", None).ok


class TestAgainstTheBundledSample:
    def test_prod_pdf_exhibits_the_contradiction(self):
        """Pinned because it is the reason this code is careful.

        If a later sample stops contradicting itself, this test fails and
        the message above should be re-read rather than the test deleted.
        """
        evidence = json.loads(extract_attachment("prod.pdf", "evidence.json"))
        assert evidence["hash_algorithm"] == "SHA-256"
        assert len(evidence["original_document_hash"]) == 128  # 512 bits

        layer = _layer_7_document_hashes("prod.pdf", evidence)
        assert layer.ok
        assert "cannot" in layer.detail
