"""
Evidence JSON canonicalization and hash verification.

Implements protocol version 1 as documented in EVIDENCE_HASH_PROTOCOL.md.
This module has NO dependencies beyond the Python standard library —
deliberately so. It must remain verifiable on any machine with Python,
even if KobSign ceases to exist.

Reference: docs/security/EVIDENCE_HASH_PROTOCOL.md in the KobSign repo.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from copy import deepcopy
from dataclasses import dataclass

SUPPORTED_CANONICALIZATION_VERSIONS = frozenset({"1"})


@dataclass(frozen=True)
class EvidenceHashResult:
    """Outcome of evidence.json hash verification."""

    ok: bool
    claimed_hash: str
    computed_hash: str
    canonicalization_version: str | None
    reason: str | None = None  # None when ok=True


def canonicalize(evidence: dict) -> bytes:
    """Produce canonical bytes over which evidence_json_hash is SHA-256.

    Protocol version 1 — see EVIDENCE_HASH_PROTOCOL.md for the full
    specification. Steps:
        1. Zero the self-referential ``evidence_json_hash`` field.
        2. Zero ``validation_result.validated_at`` (non-deterministic).
        3. NFC-normalise every string (including dict keys).
        4. Sort keys alphabetically at every level.
        5. Compact separators, no whitespace.
        6. Preserve non-ASCII characters (ensure_ascii=False).
        7. UTF-8 encode.
    """
    copy = deepcopy(evidence)
    copy["evidence_json_hash"] = ""
    if isinstance(copy.get("validation_result"), dict):
        copy["validation_result"]["validated_at"] = ""

    def nfc(obj):
        if isinstance(obj, str):
            return unicodedata.normalize("NFC", obj)
        if isinstance(obj, dict):
            return {
                (unicodedata.normalize("NFC", k) if isinstance(k, str) else k): nfc(v)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [nfc(v) for v in obj]
        return obj

    normalized = nfc(copy)
    serialized = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return serialized.encode("utf-8")


def verify_evidence_hash(evidence: dict) -> EvidenceHashResult:
    """Verify the evidence_json_hash field matches the canonicalised content.

    Returns an EvidenceHashResult — never raises on bad data; callers can
    rely on ``.ok`` and ``.reason`` for a clean boolean + message.
    """
    claimed = evidence.get("evidence_json_hash", "")
    schema = evidence.get("_schema", {}) if isinstance(evidence.get("_schema"), dict) else {}
    version = schema.get("canonicalization_version")

    if not claimed:
        return EvidenceHashResult(
            ok=False,
            claimed_hash="",
            computed_hash="",
            canonicalization_version=version,
            reason="evidence.json is missing evidence_json_hash",
        )

    if version not in SUPPORTED_CANONICALIZATION_VERSIONS:
        return EvidenceHashResult(
            ok=False,
            claimed_hash=claimed,
            computed_hash="",
            canonicalization_version=version,
            reason=(
                f"unsupported canonicalization_version={version!r}; "
                f"this verifier implements {sorted(SUPPORTED_CANONICALIZATION_VERSIONS)}"
            ),
        )

    computed = hashlib.sha256(canonicalize(evidence)).hexdigest()
    if computed == claimed:
        return EvidenceHashResult(
            ok=True,
            claimed_hash=claimed,
            computed_hash=computed,
            canonicalization_version=version,
        )
    return EvidenceHashResult(
        ok=False,
        claimed_hash=claimed,
        computed_hash=computed,
        canonicalization_version=version,
        reason="evidence.json hash mismatch — content has been modified",
    )
