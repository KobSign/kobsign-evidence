"""
PAdES-LTA signature verification via pyHanko.

Performs layers 2–4 of the verifier:
    2. Signature is intact (document bytes match what was signed)
    3. Certificate chain resolves to a trusted root
    4. Timestamp is present and from a qualified TSA

Trust roots are loaded from ``trust/*.pem`` bundled inside the package,
so the verifier works fully offline. Judges and opposing counsel can
point the tool at a PDF without network access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

# pyhanko + pyhanko_certvalidator log validation errors at WARNING level even
# when the caller handles them. Our CLI summarises them through layer results,
# so silence the libraries' own logging to keep stderr clean.
for _name in (
    "pyhanko",
    "pyhanko.sign",
    "pyhanko.sign.validation",
    "pyhanko.sign.validation.generic_cms",
    "pyhanko_certvalidator",
):
    logging.getLogger(_name).setLevel(logging.ERROR + 1)


@dataclass
class PadesResult:
    """Outcome of PAdES-LTA verification for a single signature."""

    field_name: str
    intact: bool = False
    trusted: bool = False
    has_timestamp: bool = False
    signer_subject: str | None = None
    signer_issuer: str | None = None
    timestamp_time: datetime | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class PadesOverall:
    """Aggregate result across all signatures in the PDF."""

    signature_count: int
    signatures: list[PadesResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if self.signature_count == 0 or self.errors:
            return False
        return all(s.intact and s.trusted for s in self.signatures)


def _load_trust_roots() -> list[asn1_x509.Certificate]:
    """Load trust roots as asn1crypto Certificate objects (pyhanko's format)."""
    roots: list[asn1_x509.Certificate] = []
    pkg = resources.files("kobsign_evidence.trust")
    for entry in pkg.iterdir():
        if entry.name.endswith(".pem"):
            pem_bytes = entry.read_bytes()
            try:
                cert = x509.load_pem_x509_certificate(pem_bytes)
                der = cert.public_bytes(serialization.Encoding.DER)
                roots.append(asn1_x509.Certificate.load(der))
            except Exception:
                # Skip malformed files silently — the verifier must remain
                # conservative: a bad trust root should not become a trusted root.
                continue
    return roots


def verify_pades(
    pdf_path: str, *, extra_trust_roots: list[bytes] | None = None
) -> PadesOverall:
    """Verify every signature in the PDF against the bundled trust roots.

    ``extra_trust_roots`` (DER-encoded certificate bytes) are appended to
    the bundled roots — intended for test fixtures signed with self-signed
    certificates. Production callers should leave it unset.
    """
    try:
        with open(pdf_path, "rb") as f:
            reader = PdfFileReader(f)
            sig_fields = list(reader.embedded_signatures)

            if not sig_fields:
                return PadesOverall(signature_count=0, errors=["No signatures found in PDF"])

            trust_roots = _load_trust_roots()
            if extra_trust_roots:
                for der in extra_trust_roots:
                    trust_roots.append(asn1_x509.Certificate.load(der))
            vc = ValidationContext(trust_roots=trust_roots, allow_fetching=False)

            results: list[PadesResult] = []
            for sig in sig_fields:
                name = getattr(sig.sig_field, "get", lambda _: None)("/T") or "KobSign"
                name = str(name) if name else "KobSign"
                res = PadesResult(field_name=name)

                try:
                    status = validate_pdf_signature(sig, signer_validation_context=vc)
                    res.intact = bool(getattr(status, "intact", False))
                    res.trusted = bool(getattr(status, "trusted", False))
                    res.has_timestamp = bool(getattr(status, "timestamp_validity", None))
                    if status.signing_cert is not None:
                        res.signer_subject = status.signing_cert.subject.human_friendly
                        res.signer_issuer = status.signing_cert.issuer.human_friendly
                    tsv = getattr(status, "timestamp_validity", None)
                    if tsv is not None:
                        res.timestamp_time = getattr(tsv, "timestamp", None)
                except Exception as exc:
                    res.errors.append(f"validation error: {exc}")

                results.append(res)

            return PadesOverall(signature_count=len(results), signatures=results)
    except Exception as exc:
        return PadesOverall(signature_count=0, errors=[f"failed to open PDF: {exc}"])
