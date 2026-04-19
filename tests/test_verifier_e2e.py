"""End-to-end verifier tests against signed PDFs.

These tests reach into the KobSign backend to produce realistic signed
PDFs (via the self-signed provider, so no Azure Key Vault is needed).
Skipped outside the monorepo.

Acceptance target (from evidence-win-court-case.md Leveranse 5):
    3 ekte signerte PDF-er (verifiserer OK) + 3 manipulerte (feiler med
    riktig grunn)

We cover two tampered variants here — (a) tampered document bytes, and
(b) tampered evidence.json — and one valid signature. The third
manipulated variant (broken certificate chain) is covered by the
production path: any PDF signed with a non-DigiCert cert automatically
fails layer 3 when ``extra_trust_roots`` is not supplied.
"""

from __future__ import annotations

import json

import pytest

from kobsign_evidence.pades import verify_pades
from kobsign_evidence.pdf_extract import extract_attachment
from kobsign_evidence.verifier import verify


class TestValidSignedPDF:
    def test_evidence_json_is_extractable(self, signed_pdf_pair):
        valid, _ = signed_pdf_pair
        data = extract_attachment(str(valid), "evidence.json")
        assert data is not None
        parsed = json.loads(data)
        assert parsed["document_title"] == "Verifier fixture"
        assert parsed["_schema"]["version"] == "3.4.0"

    def test_evidence_hash_matches_on_valid_pdf(self, signed_pdf_pair):
        valid, _ = signed_pdf_pair
        result = verify(str(valid))
        # Layer 5 (evidence.json integrity) must pass
        layer5 = next(layer for layer in result.layers if "evidence.json" in layer.name)
        assert layer5.ok, f"layer 5 failed: {layer5.detail}"

    def test_pades_signature_intact_with_test_trust_root(
        self, signed_pdf_pair, self_signed_trust_root
    ):
        valid, _ = signed_pdf_pair
        pades_result = verify_pades(str(valid), extra_trust_roots=[self_signed_trust_root])
        assert pades_result.signature_count >= 1
        for sig in pades_result.signatures:
            assert sig.intact, f"signature not intact: {sig.errors}"
            assert sig.trusted, f"signature not trusted: {sig.errors}"


class TestTamperedDocument:
    def test_layer_2_catches_byte_flip(self, signed_pdf_pair, self_signed_trust_root):
        _, tampered = signed_pdf_pair
        pades_result = verify_pades(
            str(tampered), extra_trust_roots=[self_signed_trust_root]
        )
        if pades_result.signature_count == 0:
            # pyhanko refused to parse the signature at all — also a failure
            assert pades_result.errors
            return
        # At least one signature must be non-intact
        assert any(not sig.intact for sig in pades_result.signatures)


class TestTamperedEvidenceHash:
    def test_layer_5_catches_modified_evidence(self, signed_pdf_pair, tmp_path):
        """Lift evidence.json out, modify a field, and verify the hash check fails.

        We don't re-embed into the PDF (which would require re-signing) —
        we test ``verify_evidence_hash`` directly on the modified dict,
        simulating what layer 5 would do if the attachment had been
        tampered with post-hoc.
        """
        from kobsign_evidence.evidence import verify_evidence_hash

        valid, _ = signed_pdf_pair
        raw = extract_attachment(str(valid), "evidence.json")
        evidence = json.loads(raw)

        # First confirm the untouched evidence passes
        assert verify_evidence_hash(evidence).ok

        # Now tamper with a signer name and confirm failure
        evidence["signatures"][0]["name"] = "Mallory (attacker)"
        result = verify_evidence_hash(evidence)
        assert not result.ok
        assert "mismatch" in result.reason.lower()


class TestFullVerifier:
    def test_verify_returns_result_structure(self, signed_pdf_pair):
        valid, _ = signed_pdf_pair
        result = verify(str(valid))
        assert result.signature_count >= 1
        assert len(result.layers) == 6
        # Without test trust roots, layer 3 will fail for the self-signed cert,
        # so the overall result is False. That's expected — the CLI reports
        # a specific layer failure which is what the user sees.
        layer_names = [layer.name for layer in result.layers]
        assert "PDF structure" in layer_names[0]
        assert "PAdES-LTA" in layer_names[1]
        assert "Certificate chain" in layer_names[2]
        assert "Qualified timestamp" in layer_names[3]
        assert "evidence.json" in layer_names[4]
        assert "Document hashes" in layer_names[5]

    def test_self_signed_fails_certificate_chain_without_override(self, signed_pdf_pair):
        """Production invariant: a PDF signed with a random self-signed cert
        MUST NOT verify against the bundled DigiCert trust roots.
        """
        valid, _ = signed_pdf_pair
        result = verify(str(valid))
        layer3 = result.layers[2]
        assert "Certificate chain" in layer3.name
        assert not layer3.ok, "self-signed cert must not chain to DigiCert roots"
