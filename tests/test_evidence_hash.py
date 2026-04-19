"""Tests for evidence.json canonicalization and hash verification.

This module tests the standalone hash verifier — no PDF needed.
All tests must pass on any machine with Python 3.10+, no other deps.
"""

from __future__ import annotations

import hashlib
import unicodedata

from kobsign_evidence.evidence import (
    SUPPORTED_CANONICALIZATION_VERSIONS,
    canonicalize,
    verify_evidence_hash,
)


def _compute(evidence: dict) -> str:
    return hashlib.sha256(canonicalize(evidence)).hexdigest()


def _make_evidence(hash_value: str = "") -> dict:
    """Build a minimal valid evidence.json structure."""
    return {
        "document_title": "Test",
        "signatures": [{"name": "Alice", "level": "AES"}],
        "_schema": {
            "version": "3.4.0",
            "type": "DocumentEvidencePackage",
            "canonicalization_version": "1",
        },
        "evidence_json_hash": hash_value,
    }


class TestCanonicalization:
    def test_hash_field_is_zeroed_before_hashing(self):
        """Changing the hash field itself must not change the canonical form."""
        ev1 = _make_evidence(hash_value="")
        ev2 = _make_evidence(hash_value="a" * 64)
        assert canonicalize(ev1) == canonicalize(ev2)

    def test_validation_timestamp_is_zeroed(self):
        """validated_at timestamps must not affect the hash."""
        ev1 = _make_evidence()
        ev2 = _make_evidence()
        ev1["validation_result"] = {"validated_at": "2026-01-01T00:00:00Z", "passed": True}
        ev2["validation_result"] = {"validated_at": "2099-12-31T23:59:59Z", "passed": True}
        assert canonicalize(ev1) == canonicalize(ev2)

    def test_keys_are_sorted_at_every_level(self):
        """Serialized output must use lexicographic key ordering recursively."""
        ev = {"z": 1, "a": {"z": 2, "a": 3}, "_schema": {"canonicalization_version": "1"}}
        ev["evidence_json_hash"] = ""
        canonical = canonicalize(ev).decode("utf-8")
        # "a" appears before "z" at each nesting level
        assert canonical.index('"a"') < canonical.index('"z"')

    def test_unicode_nfc_normalisation_applies(self):
        """Precomposed and decomposed forms of the same character hash equally."""
        precomposed = "\u00f8"  # ø
        decomposed = "o\u0338"  # o + combining stroke
        # Only the precomposed form is canonical NFC, but both inputs should
        # normalize to the same bytes.
        ev1 = _make_evidence()
        ev1["signatures"][0]["name"] = precomposed + "rnulf"
        ev2 = _make_evidence()
        ev2["signatures"][0]["name"] = unicodedata.normalize("NFD", precomposed + "rnulf")
        assert canonicalize(ev1) == canonicalize(ev2)

    def test_non_ascii_characters_preserved_as_utf8(self):
        """ensure_ascii must be False so ø stays as UTF-8 bytes, not \\u00f8."""
        ev = _make_evidence()
        ev["signatures"][0]["name"] = "Bjørn"
        canonical = canonicalize(ev)
        assert "Bjørn".encode("utf-8") in canonical
        assert b"\\u00f8" not in canonical

    def test_no_whitespace_between_tokens(self):
        """Compact separators must be used — no spaces, no newlines."""
        ev = _make_evidence()
        canonical = canonicalize(ev).decode("utf-8")
        assert ": " not in canonical
        assert ", " not in canonical
        assert "\n" not in canonical


class TestHashVerification:
    def test_matching_hash_verifies_ok(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = _compute(ev)
        result = verify_evidence_hash(ev)
        assert result.ok
        assert result.claimed_hash == result.computed_hash
        assert result.reason is None

    def test_tampered_content_fails_hash(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = _compute(ev)
        # Tamper with the content after signing the hash
        ev["signatures"][0]["name"] = "Mallory"
        result = verify_evidence_hash(ev)
        assert not result.ok
        assert "mismatch" in result.reason.lower()
        assert result.claimed_hash != result.computed_hash

    def test_tampered_hash_fails(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = "0" * 64
        result = verify_evidence_hash(ev)
        assert not result.ok

    def test_missing_hash_field_fails(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = ""
        result = verify_evidence_hash(ev)
        assert not result.ok
        assert "missing" in result.reason.lower()

    def test_unknown_canonicalization_version_rejected(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = _compute(ev)
        ev["_schema"]["canonicalization_version"] = "99"
        result = verify_evidence_hash(ev)
        assert not result.ok
        assert "unsupported" in result.reason.lower()

    def test_missing_schema_treated_as_unsupported(self):
        ev = _make_evidence()
        ev["evidence_json_hash"] = "a" * 64
        del ev["_schema"]
        result = verify_evidence_hash(ev)
        assert not result.ok
        assert "unsupported" in result.reason.lower()

    def test_protocol_version_1_is_supported(self):
        assert "1" in SUPPORTED_CANONICALIZATION_VERSIONS

    def test_hash_output_is_lowercase_hex(self):
        ev = _make_evidence()
        computed = _compute(ev)
        assert computed == computed.lower()
        assert len(computed) == 64
        bytes.fromhex(computed)  # raises if not valid hex
