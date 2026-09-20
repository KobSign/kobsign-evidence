"""Layer 7 — what the verifier says the original document hash *is*.

Two things this layer must not do, both learned the hard way.

It must not read ``hash_algorithm`` from evidence.json. That field is a
compliance label, never assigned anywhere in the producing codebase: it
sits in a ``LEGAL & COMPLIANCE`` block beside ``signature_standard`` and
``timestamp_authority``, and renders on the cover page as one item in
the line "PAdES-LTA (ETSI) · PDF/A-3 (ISO) · SHA-256 · RFC 3161 TSA".
It describes the signature and timestamp, not the digest of the uploaded
document, and reading it as a label on that digest would put a claim in
front of a court that the file never made.

And it must not infer the algorithm from the digest's width. A width
cannot tell SHA-512 from SHA3-512, and the field it would be guessing
about is one evidence.json simply does not state. The honest sentence is
that the algorithm is not stated — which is also the only sentence that
stays true whatever the producer does next.

What *is* an invariant: the pipeline writes SHA-256 here, 64 hex
characters, and the data-QR builder refuses to issue a QR for anything
else. A digest of another width is worth flagging as unexpected — but
not worth failing a document over, since nothing about it says the
digest is wrong.
"""

from __future__ import annotations

import json

import pytest

from kobsign_evidence.pdf_extract import extract_attachment
from kobsign_evidence.verifier import _layer_7_document_hashes


def _evidence(digest_bytes: int, **extra) -> dict:
    evidence: dict = {"original_document_hash": "ab" * digest_bytes}
    evidence.update(extra)
    return evidence


class TestTheAlgorithmIsNotStated:
    def test_the_expected_width_is_accepted_and_the_algorithm_is_not_claimed(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(32))
        assert layer.ok
        assert "not state" in layer.detail

    @pytest.mark.parametrize("declared", ["SHA-256", "SHA3-512", "BLAKE3", ""])
    def test_hash_algorithm_is_never_read_for_this_digest(self, declared):
        """It labels the signature and timestamp, not the document digest."""
        with_field = _layer_7_document_hashes(
            "x.pdf", _evidence(32, hash_algorithm=declared)
        )
        without_field = _layer_7_document_hashes("x.pdf", _evidence(32))
        assert with_field.detail == without_field.detail

    def test_a_reader_is_told_what_to_hash_their_own_copy_with(self):
        """A court comparing digests needs an algorithm to run, attributed."""
        layer = _layer_7_document_hashes("x.pdf", _evidence(32))
        assert "SHA-256" in layer.detail
        assert "pipeline" in layer.detail or "KobSign" in layer.detail

    def test_no_algorithm_is_guessed_from_a_wider_digest(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(64))
        assert "SHA3-512" not in layer.detail
        assert "SHA-512" not in layer.detail


class TestUnexpectedWidth:
    def test_an_unexpected_width_is_flagged_without_failing_the_layer(self):
        """Worth saying. Not worth calling a sound document unverified."""
        layer = _layer_7_document_hashes("x.pdf", _evidence(64))
        assert layer.ok, "the digest is recorded and well-formed"
        assert "64-byte" in layer.detail or "512-bit" in layer.detail
        assert "32" in layer.detail, "the expected width is named"

    def test_the_expected_width_is_not_flagged(self):
        layer = _layer_7_document_hashes("x.pdf", _evidence(32))
        assert "unexpected" not in layer.detail.lower()


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
    def test_prod_pdf_gets_a_verdict_that_claims_nothing_untrue(self):
        """``prod.pdf`` is a fixture, not production output.

        Its ``original_document_hash`` is the literal placeholder
        ``"a" * 128`` — the same one ``tests/conftest.py`` writes — so it
        is neither a digest nor the width the pipeline produces. The
        point of this test is not to pin that quirk in place: it is that
        whatever the sample holds, the layer reports it without naming an
        algorithm it cannot know.
        """
        evidence = json.loads(extract_attachment("prod.pdf", "evidence.json"))
        layer = _layer_7_document_hashes("prod.pdf", evidence)
        assert layer.ok
        declared = evidence.get("hash_algorithm")
        if declared:
            assert f"declares {declared}" not in layer.detail
            assert "as declared" not in layer.detail
