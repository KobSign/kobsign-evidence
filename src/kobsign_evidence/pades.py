"""
PAdES-LTA signature verification via pyHanko.

Performs layers 2–5 of the verifier:
    2. Signature is intact (document bytes match what was signed)
    3. Certificate chain resolves to a trusted root
    4. Timestamp is present AND the TSA's own chain resolves to a
       trusted root
    5. Nothing of substance was appended after the last signature

Layer 4 checks a chain, not a presence. A timestamp token proves only
that someone held a key at some point; it is worth something in court
because the authority behind it chains to a root the reader already
trusts. That is the same check layer 3 makes of the signer, applied to
the TSA — including the archival DocTimeStamps that PAdES-LTA is built
out of, which carry the timestamp for the whole document.

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
from pyhanko.sign.validation import (
    SignatureCoverageLevel,
    validate_pdf_signature,
    validate_pdf_timestamp,
)
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
    # A timestamp token is present (``has_timestamp``) and the TSA that
    # issued it chains to a bundled trust root (``timestamp_trusted``).
    # The two are deliberately separate: presence without trust is the
    # case a report must not round up to "timestamped".
    timestamp_trusted: bool = False
    timestamp_authority: str | None = None
    timestamp_time: datetime | None = None
    # What came after this signature. ``coverage`` / ``modification_level``
    # are pyHanko's own names; both are None when the analysis could not run.
    coverage: str | None = None
    modification_level: str | None = None
    docmdp_ok: bool | None = None
    # pyHanko's own aggregate judgment, kept as a backstop against our
    # reading of the individual fields being too generous. None when the
    # signature could not be validated at all.
    bottom_line: bool | None = None
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
    # How many of those archival timestamps were issued by a TSA whose own
    # chain resolves to a bundled trust root. An untrusted one still counts
    # as a DocTimeStamp — it just does not count as a qualified timestamp.
    trusted_doctimestamp_count: int = 0
    # Human-readable descriptions of content appended after a signature.
    # Empty means nothing of substance was added after signing.
    revision_problems: list[str] = field(default_factory=list)
    # Timestamp tokens that did not stand up — the wrong authority, or no
    # authority this tool can chain to a bundled root. Reported by layer 4.
    timestamp_problems: list[str] = field(default_factory=list)
    # Anything else validation came back unhappy about: a signature pyHanko
    # judges invalid for a reason none of our own layers named. Reported by
    # layer 2, because that is where "the signature does not stand up" lives.
    other_problems: list[str] = field(default_factory=list)

    @property
    def validation_problems(self) -> list[str]:
        """Every non-revision problem found, in reporting order."""
        return [*self.timestamp_problems, *self.other_problems]

    @property
    def has_qualified_timestamp(self) -> bool:
        """Is the document timestamped by an authority we can vouch for?

        Two shapes qualify. Either every content signature carries its own
        trusted RFC 3161 timestamp token, or the document carries at least
        one trusted archival DocTimeStamp — which is applied over the whole
        file, signatures included, and is what PAdES-LTA actually uses.
        """
        if self.trusted_doctimestamp_count > 0:
            return True
        return bool(self.signatures) and all(
            s.has_timestamp and s.timestamp_trusted for s in self.signatures
        )

    @property
    def ok(self) -> bool:
        if self.signature_count == 0 or self.errors:
            return False
        if self.revision_problems or self.validation_problems:
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


def _timestamp_problem(label: str, status) -> str | None:
    """Judge a timestamp token. ``None`` means it stands up.

    A token is only as good as the authority behind it. ``intact`` and
    ``valid`` say the token was not tampered with and the maths checks
    out — which a forger with their own key achieves too. ``trusted`` is
    the one that says the TSA chains to a root bundled with this tool.
    """
    if not (status.intact and status.valid):
        return f"{label}: the timestamp token is not cryptographically sound"
    if not status.trusted:
        authority = _subject_of(status)
        return (
            f"{label}: issued by {authority or 'an unknown authority'}, whose "
            f"certificate does not chain to a bundled trust root"
        )
    return None


def _subject_of(status) -> str | None:
    """Human-readable subject of the certificate a status was built from."""
    cert = getattr(status, "signing_cert", None)
    if cert is None:
        return None
    try:
        return cert.subject.human_friendly
    except Exception:
        return None


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
            timestamp_problems: list[str] = []
            other_problems: list[str] = []
            doctimestamp_count = 0
            trusted_doctimestamp_count = 0
            doctimestamp_times: list[datetime] = []
            doctimestamp_authorities: list[str] = []

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
                        ts_status = validate_pdf_timestamp(
                            sig, validation_context=vc
                        )
                    except Exception as exc:
                        timestamp_problems.append(
                            f"{label}: could not be validated ({exc})"
                        )
                        continue

                    ts_problem = _timestamp_problem(label, ts_status)
                    if ts_problem:
                        timestamp_problems.append(ts_problem)
                    else:
                        trusted_doctimestamp_count += 1
                        if ts_status.timestamp is not None:
                            doctimestamp_times.append(ts_status.timestamp)
                        authority = _subject_of(ts_status)
                        if authority:
                            doctimestamp_authorities.append(authority)

                    problem = _revision_problem(
                        label, ts_status.coverage, ts_status.diff_result
                    )
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
                    if status.signing_cert is not None:
                        res.signer_subject = status.signing_cert.subject.human_friendly
                        res.signer_issuer = status.signing_cert.issuer.human_friendly

                    # The timestamp token gets the same treatment as the
                    # signer: presence is recorded, trust is decided by the
                    # TSA's own chain. A token we cannot back is a problem
                    # to report, not a field to leave unread.
                    tsv = getattr(status, "timestamp_validity", None)
                    res.has_timestamp = tsv is not None
                    if tsv is not None:
                        res.timestamp_time = getattr(tsv, "timestamp", None)
                        res.timestamp_authority = _subject_of(tsv)
                        ts_problem = _timestamp_problem(
                            f"signature {name!r} timestamp", tsv
                        )
                        res.timestamp_trusted = ts_problem is None
                        if ts_problem:
                            timestamp_problems.append(ts_problem)

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
                    if res.docmdp_ok is False and problem is None:
                        # A certification signature that declared what later
                        # revisions may change, and was changed beyond it.
                        problem = (
                            f"signature {name!r}: a later revision broke the "
                            f"document modification policy this signature set"
                        )
                    if problem:
                        revision_problems.append(problem)

                    # pyHanko's aggregate judgment, as a backstop. Everything
                    # above is our own reading of individual fields; if that
                    # reading comes out green where pyHanko's does not, the
                    # difference is ours to explain, and until it is explained
                    # the file does not pass.
                    bottom_line = getattr(status, "bottom_line", None)
                    res.bottom_line = None if bottom_line is None else bool(bottom_line)
                    already_flagged = (
                        not res.intact
                        or not res.trusted
                        or problem is not None
                        or (tsv is not None and not res.timestamp_trusted)
                    )
                    if res.bottom_line is False and not already_flagged:
                        other_problems.append(
                            f"signature {name!r}: pyHanko judges this signature "
                            f"invalid for a reason none of the layers above named"
                        )
                except Exception as exc:
                    res.errors.append(f"validation error: {exc}")
                    revision_problems.append(
                        f"signature {name!r}: could not be analysed ({exc})"
                    )

                results.append(res)

            # An archival DocTimeStamp is applied over the whole file, so a
            # trusted one timestamps every signature under it. Carry its
            # authority and time onto the signatures that have none of their
            # own, so a report can name what actually backs the date.
            for res in results:
                if not res.has_timestamp and trusted_doctimestamp_count:
                    res.timestamp_trusted = True
                    res.timestamp_authority = (
                        doctimestamp_authorities[-1] if doctimestamp_authorities else None
                    )
                    res.timestamp_time = (
                        doctimestamp_times[-1] if doctimestamp_times else None
                    )

            return PadesOverall(
                signature_count=len(results),
                signatures=results,
                doctimestamp_count=doctimestamp_count,
                trusted_doctimestamp_count=trusted_doctimestamp_count,
                revision_problems=revision_problems,
                timestamp_problems=timestamp_problems,
                other_problems=other_problems,
            )
    except Exception as exc:
        return PadesOverall(signature_count=0, errors=[f"failed to open PDF: {exc}"])
