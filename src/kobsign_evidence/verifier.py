"""
Main verifier — orchestrates six independent verification layers.

The verifier never raises from ``verify()``. Every failure mode is
reported as ``ok=False`` plus a human-readable reason on the layer. A
court using this tool must be able to tell, from exit code alone,
whether the PDF is intact — without parsing error messages.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .evidence import verify_evidence_hash
from .pades import verify_pades
from .pdf_extract import extract_attachment, list_attachments


@dataclass
class LayerResult:
    """Outcome of one verification layer."""

    name: str
    ok: bool
    detail: str = ""
    # True when the layer does not apply to this document (e.g. a feature
    # introduced in a later schema version than the document uses). Layers
    # marked N/A do not count against the overall verdict.
    na: bool = False


@dataclass
class VerificationResult:
    """Overall outcome — ``verified`` is the single bit a court reads."""

    verified: bool
    layers: list[LayerResult] = field(default_factory=list)
    # Raw details the --verbose / --json output exposes.
    signature_count: int = 0
    evidence_schema_version: str | None = None
    canonicalization_version: str | None = None

    @property
    def failed_layer(self) -> LayerResult | None:
        for layer in self.layers:
            if not layer.ok and not layer.na:
                return layer
        return None


def _layer_1_structure(pdf_path: str) -> LayerResult:
    try:
        attachments = list_attachments(pdf_path)
    except Exception as exc:
        return LayerResult("PDF structure", False, f"could not read PDF: {exc}")
    return LayerResult(
        "PDF structure", True, f"{len(attachments)} embedded attachments"
    )


def _layers_2_3_4_pades(pdf_path: str) -> tuple[LayerResult, LayerResult, LayerResult, int]:
    overall = verify_pades(pdf_path)
    if overall.errors:
        err = "; ".join(overall.errors)
        failed = LayerResult("PAdES-LTA signature", False, err)
        return (
            failed,
            LayerResult("Certificate chain", False, "skipped (signature did not load)"),
            LayerResult("Qualified timestamp", False, "skipped (signature did not load)"),
            0,
        )

    if overall.signature_count == 0:
        return (
            LayerResult("PAdES-LTA signature", False, "no signatures in PDF"),
            LayerResult("Certificate chain", False, "skipped"),
            LayerResult("Qualified timestamp", False, "skipped"),
            0,
        )

    intact = all(s.intact for s in overall.signatures)
    trusted = all(s.trusted for s in overall.signatures)
    has_ts = all(s.has_timestamp for s in overall.signatures)

    intact_reason = "document bytes match signed content" if intact else (
        "document has been modified after signing"
    )
    trusted_reason = (
        "chain resolves to a bundled trust root"
        if trusted
        else "signer certificate does not chain to a trusted root"
    )
    ts_reason = (
        f"timestamped by {overall.signatures[0].signer_issuer or 'qualified TSA'}"
        if has_ts
        else "no qualified timestamp present"
    )

    return (
        LayerResult("PAdES-LTA signature", intact, intact_reason),
        LayerResult("Certificate chain", trusted, trusted_reason),
        LayerResult("Qualified timestamp", has_ts, ts_reason),
        overall.signature_count,
    )


def _layer_5_evidence_hash(pdf_path: str) -> tuple[LayerResult, dict | None, str | None, str | None]:
    raw = None
    try:
        raw = extract_attachment(pdf_path, "evidence.json")
    except Exception as exc:
        return (
            LayerResult("evidence.json integrity", False, f"extraction failed: {exc}"),
            None,
            None,
            None,
        )
    if raw is None:
        return (
            LayerResult(
                "evidence.json integrity",
                False,
                "no evidence.json attachment in this PDF",
            ),
            None,
            None,
            None,
        )
    try:
        evidence = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return (
            LayerResult("evidence.json integrity", False, f"parse error: {exc}"),
            None,
            None,
            None,
        )

    result = verify_evidence_hash(evidence)
    detail = (
        f"SHA-256 matches (canonicalization v{result.canonicalization_version})"
        if result.ok
        else (result.reason or "hash mismatch")
    )
    schema = evidence.get("_schema", {}) if isinstance(evidence.get("_schema"), dict) else {}
    schema_version = schema.get("version")
    return (
        LayerResult(
            "evidence.json integrity",
            result.ok,
            detail,
            na=result.not_applicable,
        ),
        evidence,
        schema_version,
        result.canonicalization_version,
    )


def _layer_6_document_hashes(pdf_path: str, evidence: dict | None) -> LayerResult:
    """Verify ``original_document_hash`` in evidence.json matches the user's
    uploaded PDF bytes.

    KobSign stores ``original_document_hash`` (SHA3-512 of the uploaded
    PDF, before any cover page / signatures are added). This verifier
    does NOT have access to the original PDF — it only has the final
    signed PDF, which contains the original PDF's *hash* but not its
    bytes. So layer 6 verifies internal consistency: the hash field is
    non-empty, well-formed, and the algorithm is declared.

    Full original-PDF equality requires the court to have the original
    PDF (e.g. attached to the agreement) and hash it themselves — which
    is the correct legal model. We surface what we can check.
    """
    if evidence is None:
        return LayerResult("Document hashes", False, "evidence.json not available")

    orig = evidence.get("original_document_hash")
    if not orig:
        return LayerResult(
            "Document hashes",
            False,
            "original_document_hash is missing from evidence.json",
        )
    if not isinstance(orig, str) or len(orig) < 64:
        return LayerResult(
            "Document hashes",
            False,
            "original_document_hash is malformed (expected hex digest)",
        )
    # Hex check — any non-hex char fails.
    try:
        bytes.fromhex(orig)
    except ValueError:
        return LayerResult(
            "Document hashes",
            False,
            "original_document_hash is not a valid hex digest",
        )
    algo = "SHA3-512" if len(orig) == 128 else f"{len(orig) * 4}-bit digest"
    return LayerResult(
        "Document hashes",
        True,
        f"{algo} recorded; compare against the original PDF in your possession",
    )


def verify(pdf_path: str) -> VerificationResult:
    """Run all six layers and return a combined verification result."""
    layer1 = _layer_1_structure(pdf_path)
    layers: list[LayerResult] = [layer1]
    if not layer1.ok:
        # No point continuing — we cannot even open the file.
        return VerificationResult(verified=False, layers=layers)

    layer2, layer3, layer4, sig_count = _layers_2_3_4_pades(pdf_path)
    layers.extend([layer2, layer3, layer4])

    layer5, evidence, schema_version, canon_version = _layer_5_evidence_hash(pdf_path)
    layers.append(layer5)

    layer6 = _layer_6_document_hashes(pdf_path, evidence)
    layers.append(layer6)

    # A layer that does not apply to this document (``na=True``) does not
    # count against the overall verdict. Primary integrity (PAdES-LTA,
    # certificate chain, qualified timestamp) must still pass.
    verified = all(layer.ok or layer.na for layer in layers)
    return VerificationResult(
        verified=verified,
        layers=layers,
        signature_count=sig_count,
        evidence_schema_version=schema_version,
        canonicalization_version=canon_version,
    )
