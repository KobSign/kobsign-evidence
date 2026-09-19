"""Negative tests for the two gaps that a green verdict must not hide.

These run everywhere — they build their own signed PDFs (see
``pdf_factory.py``) and never touch the KobSign backend or the network.

Gap 1: a certificate must chain to a bundled trust root. A self-signed
certificate, however cryptographically sound the signature over it,
proves only that whoever made it had a key. It must never be reported as
``trusted``.

Gap 2: ``intact`` does not mean unmodified. A PDF grows by incremental
update — new bytes appended, old bytes untouched — so a signature over
the original byte range still hashes correctly after someone has added a
page or an annotation on top. The reader sees the last revision; the
signature covers the first.

Both gaps were found in KobSign's server-side validator on 2026-08-02 and
fixed there in PR #335. These tests pin the offline verifier against them.
"""

from __future__ import annotations

import pdf_factory
import pytest

from kobsign_evidence.pades import verify_pades
from kobsign_evidence.verifier import verify


def _write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _layer(result, needle: str):
    return next(layer for layer in result.layers if needle in layer.name)


class TestCertificateChain:
    """Gap 1 — a foreign certificate is never trusted."""

    def test_self_signed_is_never_trusted_against_bundled_roots(
        self, tmp_path, standalone_signed_pdf
    ):
        path = _write(tmp_path, "self_signed.pdf", standalone_signed_pdf)
        result = verify_pades(path)
        assert result.signature_count == 1
        signature = result.signatures[0]
        # The maths is fine — that is precisely why this case is dangerous.
        assert signature.intact
        assert not signature.trusted

    def test_verify_reports_the_chain_layer_as_the_failure(
        self, tmp_path, standalone_signed_pdf
    ):
        path = _write(tmp_path, "self_signed.pdf", standalone_signed_pdf)
        result = verify(path)
        assert not result.verified
        assert not _layer(result, "Certificate chain").ok

    def test_trusting_the_test_root_is_the_only_thing_that_changes_it(
        self, tmp_path, standalone_signed_pdf, signer_identity
    ):
        """The negative result above is about trust, not about a broken file."""
        path = _write(tmp_path, "self_signed.pdf", standalone_signed_pdf)
        result = verify_pades(path, extra_trust_roots=[signer_identity.cert_der])
        assert result.signatures[0].trusted

    def test_a_different_self_signed_root_does_not_help(
        self, tmp_path, standalone_signed_pdf
    ):
        """Trusting *some* root is not trusting *this* signer's root."""
        stranger = pdf_factory.TestIdentity("Unrelated Authority")
        path = _write(tmp_path, "self_signed.pdf", standalone_signed_pdf)
        result = verify_pades(path, extra_trust_roots=[stranger.cert_der])
        assert not result.signatures[0].trusted


class TestTamperedBytes:
    """A corrupted signed byte range breaks the signature outright."""

    def test_byte_flip_breaks_the_signature(
        self, tmp_path, standalone_signed_pdf, signer_identity
    ):
        tampered = pdf_factory.flip_a_byte(standalone_signed_pdf)
        path = _write(tmp_path, "tampered.pdf", tampered)
        result = verify_pades(path, extra_trust_roots=[signer_identity.cert_der])
        if result.signature_count == 0:
            assert result.errors  # pyHanko refused to parse it — also a failure
            return
        assert not any(signature.intact for signature in result.signatures)

    def test_verify_refuses_a_tampered_file(self, tmp_path, standalone_signed_pdf):
        tampered = pdf_factory.flip_a_byte(standalone_signed_pdf)
        path = _write(tmp_path, "tampered.pdf", tampered)
        assert not verify(path).verified


class TestPostSignatureRevisions:
    """Gap 2 — content appended after signing, with the signature intact."""

    def test_appended_annotation_is_detected(
        self, tmp_path, standalone_signed_pdf, signer_identity
    ):
        modified = pdf_factory.append_annotation_after_signing(standalone_signed_pdf)
        # The original bytes survive verbatim — that is what makes the
        # signature keep verifying.
        assert modified[: len(standalone_signed_pdf)] == standalone_signed_pdf

        path = _write(tmp_path, "appended.pdf", modified)
        result = verify_pades(path, extra_trust_roots=[signer_identity.cert_der])
        signature = result.signatures[0]
        assert signature.intact, "the signature itself still verifies — that is the trap"
        assert signature.trusted
        assert result.revision_problems, "appended content must be reported"
        assert not result.ok

    def test_verify_fails_on_the_post_signature_layer(
        self, tmp_path, standalone_signed_pdf
    ):
        modified = pdf_factory.append_annotation_after_signing(standalone_signed_pdf)
        path = _write(tmp_path, "appended.pdf", modified)
        result = verify(path)
        layer = _layer(result, "Post-signature revisions")
        assert not layer.ok
        assert not result.verified

    def test_clean_signature_has_no_revision_problems(
        self, tmp_path, standalone_signed_pdf, signer_identity
    ):
        path = _write(tmp_path, "clean.pdf", standalone_signed_pdf)
        result = verify_pades(path, extra_trust_roots=[signer_identity.cert_der])
        assert result.revision_problems == []
        assert result.signatures[0].coverage == "ENTIRE_FILE"
        assert result.signatures[0].modification_level == "NONE"
        assert result.ok


class TestLegitimateIncrementalUpdates:
    """The check must not fire on what PAdES-LTA does by design."""

    def test_archival_timestamp_is_allowed(
        self, tmp_path, standalone_lta_pdf, signer_identity, tsa_identity
    ):
        path = _write(tmp_path, "lta.pdf", standalone_lta_pdf)
        result = verify_pades(
            path,
            extra_trust_roots=[signer_identity.cert_der, tsa_identity.cert_der],
        )
        assert result.doctimestamp_count >= 1
        assert result.revision_problems == [], result.revision_problems
        assert result.signatures[0].modification_level == "LTA_UPDATES"
        assert result.ok

    def test_second_signer_is_allowed(
        self, tmp_path, standalone_multi_signer_pdf, signer_identity
    ):
        path = _write(tmp_path, "multi.pdf", standalone_multi_signer_pdf)
        result = verify_pades(path, extra_trust_roots=[signer_identity.cert_der])
        assert result.signature_count == 2
        assert result.revision_problems == [], result.revision_problems
        assert result.signatures[0].modification_level == "FORM_FILLING"
        assert result.ok

    @pytest.mark.parametrize(
        "fixture", ["standalone_lta_pdf", "standalone_multi_signer_pdf"]
    )
    def test_appending_on_top_of_a_legitimate_update_is_still_caught(
        self, tmp_path, request, fixture, signer_identity, tsa_identity
    ):
        base = request.getfixturevalue(fixture)
        modified = pdf_factory.append_annotation_after_signing(base)
        path = _write(tmp_path, f"{fixture}_appended.pdf", modified)
        result = verify_pades(
            path,
            extra_trust_roots=[signer_identity.cert_der, tsa_identity.cert_der],
        )
        assert result.revision_problems
        assert not result.ok
