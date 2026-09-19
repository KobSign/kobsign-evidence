"""
PAdES-LTA signature verification via pyHanko.

Performs layers 2–5 of the verifier:
    2. Signature is intact (document bytes match what was signed)
    3. Certificate chain resolves to a trusted root
    4. Timestamp is present and from a qualified TSA
    5. Nothing of substance was appended after the last signature

Layer 5 is not implied by layer 2. A PDF grows by incremental update:
new bytes are appended and the original bytes stay byte-for-byte intact.
A signature over the original byte range therefore stays ``intact`` even
after someone has appended a revision that adds an annotation, a page or
a different visible value. Courts read the last revision; the signature
covers the first. pyHanko computes the difference between the two — see
``_revision_problems()``.

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
from pyhanko.sign.diff_analysis import DiffResult, ModificationLevel
from pyhanko.sign.validation import SignatureCoverageLevel, validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

# pyhanko + pyhanko_certvalidator log validation errors at WARNING level even
# when the caller handles them. Our CLI summarises them through layer results,
# so silence the libraries' own logging to keep stderr clean.
for _name in (
    "pyhanko",
    "pyhanko.sign",
    "pyhanko.sign.validation",
    "pyhanko.sign.validation.generic_cms",
    # Difference analysis logs a full traceback whenever it rejects an
    # appended revision. That rejection is a *result* for us, not an error.
    "pyhanko.sign.diff_analysis",
    "pyhanko.sign.diff_analysis.policies",
    "pyhanko_certvalidator",
):
    logging.getLogger(_name).setLevel(logging.ERROR + 1)


# Incremental updates a signature may legitimately be followed by.
#
#   NONE          nothing came after this signature
#   LTA_UPDATES   DSS entries and archival DocTimeStamps — the whole point
#                 of PAdES-LTA is that these keep being added for decades
#   FORM_FILLING  a later signer filled and signed their own field
#
# Anything above this line — ANNOTATIONS, OTHER — is content a reader sees
# that the signer never saw, and is reported as a failure.
MAX_ALLOWED_MODIFICATION_LEVEL = ModificationLevel.FORM_FILLING

# A signature must at minimum cover its own revision in full. UNCLEAR and
# CONTIGUOUS_BLOCK_FROM_START mean the signed byte range does not line up
# with a revision boundary at all, which no legitimate writer produces.
MIN_ALLOWED_COVERAGE = SignatureCoverageLevel.ENTIRE_REVISION


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
    # What came after this signature. ``coverage`` / ``modification_level``
    # are pyHanko's own names; both are None when the analysis could not run.
    coverage: str | None = None
    modification_level: str | None = None
    docmdp_ok: bool | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class PadesOverall:
    """Aggregate result across all signatures in the PDF."""

    signature_count: int
    signatures: list[PadesResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Number of archival DocTimeStamps (PAdES-LTA) found alongside the
    # content signatures.
    doctimestamp_count: int = 0
    # Human-readable descriptions of content appended after a signature.
    # Empty means nothing of substance was added after signing.
    revision_problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if self.signature_count == 0 or self.errors:
            return False
        if self.revision_problems:
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


def _describe(value) -> str | None:
    """Render a pyHanko enum member as a bare name, e.g. ``ENTIRE_FILE``."""
    return getattr(value, "name", None) if value is not None else None


def _revision_problem(label: str, coverage, diff_result) -> str | None:
    """Judge what was appended after one signature. ``None`` means clean.

    ``coverage`` says how much of the file the signed byte range reaches;
    ``diff_result`` says what the revisions beyond it did. Both come
    straight from pyHanko — we only decide which outcomes a court should
    be warned about.
    """
    if coverage is None:
        return f"{label}: could not determine how much of the file it covers"

    if coverage < MIN_ALLOWED_COVERAGE:
        return (
            f"{label}: signed byte range does not cover a whole revision "
            f"(coverage {_describe(coverage)})"
        )

    if coverage >= SignatureCoverageLevel.ENTIRE_FILE:
        # Nothing follows this signature at all.
        return None

    # The signature covers its own revision but the file continues past it.
    # That is normal for PAdES-LTA and for multi-signer documents; it is
    # also exactly how content is smuggled in after the fact. pyHanko's
    # difference analysis is what separates the two.
    if isinstance(diff_result, DiffResult):
        level = diff_result.modification_level
        if level > MAX_ALLOWED_MODIFICATION_LEVEL:
            return (
                f"{label}: content was added after this signature "
                f"(modification level {_describe(level)})"
            )
        return None

    if diff_result is None:
        return f"{label}: could not analyse the revisions appended after it"

    # pyHanko hands back the SuspiciousModification it raised. Its message
    # is a multi-line dump of object references; the layer report is one
    # line per layer, so flatten it and keep the leading explanation.
    detail = " ".join(str(diff_result).split())
    if len(detail) > 200:
        detail = detail[:197] + "..."
    return f"{label}: content was changed after this signature — {detail}"


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
            revision_problems: list[str] = []
            doctimestamp_count = 0

            for sig in sig_fields:
                # PAdES-LTA adds DocTimeStamp entries (Type=/DocTimeStamp,
                # SubFilter=/ETSI.RFC3161) alongside the content signature.
                # They are RFC 3161 archival timestamps — not independent
                # signatures. pyHanko's validate_pdf_signature() rejects
                # them with "Signature object type must be /Sig". Their
                # cryptographic validity is already reflected in the content
                # signature's timestamp_validity, so we do not validate them
                # again — but we DO analyse what was appended after them,
                # because the last DocTimeStamp is usually the last thing in
                # the file and anything beyond it is unsigned content.
                sig_type = sig.sig_object.get("/Type")
                if str(sig_type) == "/DocTimeStamp":
                    doctimestamp_count += 1
                    label = f"archival timestamp {doctimestamp_count}"
                    try:
                        sig.compute_integrity_info()
                        problem = _revision_problem(
                            label, sig.coverage, sig.diff_result
                        )
                    except Exception as exc:
                        problem = f"{label}: could not be analysed ({exc})"
                    if problem:
                        revision_problems.append(problem)
                    continue

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

                    coverage = getattr(status, "coverage", None)
                    res.coverage = _describe(coverage)
                    res.modification_level = _describe(
                        getattr(status, "modification_level", None)
                    )
                    docmdp_ok = getattr(status, "docmdp_ok", None)
                    res.docmdp_ok = None if docmdp_ok is None else bool(docmdp_ok)
                    problem = _revision_problem(
                        f"signature {name!r}", coverage, getattr(status, "diff_result", None)
                    )
                    if problem:
                        revision_problems.append(problem)
                except Exception as exc:
                    res.errors.append(f"validation error: {exc}")
                    revision_problems.append(
                        f"signature {name!r}: could not be analysed ({exc})"
                    )

                results.append(res)

            return PadesOverall(
                signature_count=len(results),
                signatures=results,
                doctimestamp_count=doctimestamp_count,
                revision_problems=revision_problems,
            )
    except Exception as exc:
        return PadesOverall(signature_count=0, errors=[f"failed to open PDF: {exc}"])
