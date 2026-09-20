"""
The data QR on a KobSign certificate page: decode it, verify it, and
check that it describes the document it is printed on.

    base45 text  ->  COSE_Sign1  ->  CBOR map with integer keys

The QR exists so that a piece of paper can be checked without the file.
That only means something if the payload is bound to the file, so the
last step is the one that matters most: the evidence hash inside the
signed payload is compared against the ``evidence.json`` actually
embedded in the PDF. A QR that verifies beautifully and describes some
other document is worse than no QR at all, because it looks like proof.

The payload is signed with a key whose public half is archived in this
repository — see ``keys.py``. Until the production signing ceremony has
been held, that archive is empty and no real QR can be verified; the
verifier says so rather than waving it through.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..evidence import canonicalize
from . import base45, cbor
from .cose import CoseError, parse, verify_signature
from .keys import ArchivedKey, find_by_kid, load_archive
from .payload import (
    ALGORITHM_NAMES,
    LEVEL_NAMES,
    PayloadError,
    QrPayload,
    check_algorithm,
    declared_version,
    parse_version_1,
    required_algorithm,
)

__all__ = [
    "QrCheck",
    "QrResult",
    "verify_data_qr",
]


@dataclass(frozen=True)
class QrCheck:
    """One cross-check between the signed payload and the PDF.

    ``ok=None`` means the check could not be made — not that it passed.
    """

    name: str
    ok: bool | None
    detail: str


@dataclass(frozen=True)
class QrResult:
    """Outcome of decoding, verifying and cross-checking a data QR."""

    ok: bool
    reason: str | None = None  # None when ok=True
    # True when no QR payload was supplied at all. Not a failure: most
    # verifications are of a file, with nobody standing over a printout.
    not_applicable: bool = False
    payload: QrPayload | None = None
    kid: bytes | None = None
    key_source: str | None = None
    algorithm: str | None = None
    checks: list[QrCheck] = field(default_factory=list)

    @property
    def failed_checks(self) -> list[QrCheck]:
        return [check for check in self.checks if check.ok is False]


def _cross_check(payload: QrPayload, evidence: dict | None) -> list[QrCheck]:
    """Compare the signed payload against the PDF's own evidence.json."""
    if not isinstance(evidence, dict):
        return [
            QrCheck(
                "evidence.json",
                None,
                "the PDF carries no usable evidence.json to check the QR against",
            )
        ]

    checks: list[QrCheck] = []

    # The binding that makes the QR mean anything: the hash in the signed
    # payload against the evidence actually embedded in this PDF. Computed
    # from the file, not read from its ``evidence_json_hash`` field — a
    # hash that quotes itself proves nothing.
    computed = hashlib.sha256(canonicalize(evidence)).digest()
    if computed == payload.evidence_hash:
        checks.append(
            QrCheck(
                "evidence hash",
                True,
                f"the QR is signed over this PDF's evidence.json "
                f"(SHA-256 {computed.hex()})",
            )
        )
    else:
        checks.append(
            QrCheck(
                "evidence hash",
                False,
                f"the QR was signed over a different evidence.json: it names "
                f"{payload.evidence_hash.hex()}, this PDF contains "
                f"{computed.hex()}",
            )
        )

    koblink_id = evidence.get("koblink_id")
    if isinstance(koblink_id, str) and koblink_id:
        ok = koblink_id == payload.koblink_id
        checks.append(
            QrCheck(
                "koblink id",
                ok,
                f"{payload.koblink_id}"
                if ok
                else (
                    f"the QR names {payload.koblink_id}, this PDF names {koblink_id}"
                ),
            )
        )
    else:
        checks.append(
            QrCheck("koblink id", None, "evidence.json records no koblink id")
        )

    signatures = evidence.get("signatures")
    if isinstance(signatures, list):
        ok = len(signatures) == payload.signer_count
        checks.append(
            QrCheck(
                "signer count",
                ok,
                f"{payload.signer_count}"
                if ok
                else (
                    f"the QR claims {payload.signer_count} signer(s), this PDF "
                    f"records {len(signatures)}"
                ),
            )
        )

        recorded: dict[str, int] = {}
        for signer in signatures:
            level = signer.get("level") if isinstance(signer, dict) else None
            if isinstance(level, str):
                recorded[level] = recorded.get(level, 0) + 1
        unknown = set(recorded) - set(LEVEL_NAMES.values())
        if unknown:
            checks.append(
                QrCheck(
                    "signature levels",
                    None,
                    f"evidence.json records level(s) {', '.join(sorted(unknown))}, "
                    f"which the QR format has no code for",
                )
            )
        else:
            claimed = payload.levels_by_name
            ok = claimed == {name: count for name, count in recorded.items() if count}
            rendered = ", ".join(f"{name}×{count}" for name, count in claimed.items())
            checks.append(
                QrCheck(
                    "signature levels",
                    ok,
                    rendered
                    if ok
                    else (
                        f"the QR claims {rendered or 'nothing'}, this PDF records "
                        + (
                            ", ".join(
                                f"{name}×{count}" for name, count in sorted(recorded.items())
                            )
                            or "nothing"
                        )
                    ),
                )
            )
    else:
        checks.append(
            QrCheck("signer count", None, "evidence.json records no signers")
        )

    # The payload's document hash is 32 bytes; evidence.json records the
    # original document as SHA3-512. They are hashes of (presumably) the
    # same thing under different algorithms, so neither can be derived
    # from the other. Report it for the reader to compare against a
    # document in their own possession, and claim nothing further.
    checks.append(
        QrCheck(
            "document hash",
            None,
            f"the QR records SHA-256 {payload.document_hash.hex()}; "
            f"evidence.json records the original document under a different "
            f"algorithm, so the two cannot be compared here",
        )
    )

    checks.append(
        QrCheck(
            "completed",
            None,
            f"{payload.completed_at.isoformat()} (signed into the QR payload; "
            f"reported, not cross-checked)",
        )
    )
    return checks


def verify_data_qr(
    qr_text: str | None,
    evidence: dict | None = None,
    *,
    extra_public_keys: list[bytes] | None = None,
) -> QrResult:
    """Decode, verify and cross-check a data QR payload.

    ``qr_text`` is the base45 string a QR reader gives back. ``None``
    means no QR was supplied, which is reported as not-applicable.

    ``extra_public_keys`` is for tests, in the same spirit as
    ``verify_pades(extra_trust_roots=...)``: production callers rely on
    the archive that ships with the package.

    Never raises.
    """
    try:
        return _verify_data_qr(qr_text, evidence, extra_public_keys)
    except Exception as exc:  # pragma: no cover - the backstop, not a path
        # A court reads an exit code, not a traceback. Anything unforeseen
        # in here is a failure to verify, never an absence of a QR.
        return QrResult(ok=False, reason=f"the data QR could not be read: {exc}")


def _verify_data_qr(
    qr_text: str | None,
    evidence: dict | None,
    extra_public_keys: list[bytes] | None,
) -> QrResult:
    if qr_text is None or not qr_text.strip():
        return QrResult(
            ok=False,
            not_applicable=True,
            reason="no data QR supplied",
        )

    try:
        raw = base45.decode(qr_text)
    except base45.Base45Error as exc:
        return QrResult(ok=False, reason=str(exc))

    try:
        sign1 = parse(raw)
    except CoseError as exc:
        return QrResult(ok=False, reason=str(exc))

    # The version is read before anything else is decided, because the
    # version is what decides. Reading it does not mean trusting it: a
    # version this build does not implement ends here, and an unverified
    # payload of a version we DO implement is checked against that
    # version's algorithm before a signature is looked at.
    try:
        payload_item = cbor.decode(sign1.payload)
    except cbor.CborError as exc:
        return QrResult(ok=False, reason=f"the QR payload is not valid CBOR: {exc}")

    try:
        version = declared_version(payload_item)
        required_algorithm(version)
        check_algorithm(version, sign1.alg)
    except PayloadError as exc:
        return QrResult(ok=False, reason=str(exc))

    kid = sign1.kid
    if kid is None:
        return QrResult(
            ok=False,
            reason=(
                "the QR names no key (no 'kid' in the COSE header), so there "
                "is nothing to verify it against"
            ),
        )

    archive = load_archive(extra_public_keys)
    key: ArchivedKey | None = find_by_kid(kid, archive)
    if key is None:
        if not archive:
            return QrResult(
                ok=False,
                kid=kid,
                reason=(
                    f"the QR is signed by key {kid.hex()}, and this build "
                    f"carries no archived public keys at all — see "
                    f"kobsign_evidence/keys/README.md"
                ),
            )
        return QrResult(
            ok=False,
            kid=kid,
            reason=(
                f"the QR is signed by key {kid.hex()}, which is not in this "
                f"verifier's key archive ({len(archive)} key(s) archived). "
                f"Either the QR was not signed by KobSign, or this build "
                f"predates that key"
            ),
        )

    try:
        verify_signature(sign1, key)
    except CoseError as exc:
        return QrResult(ok=False, kid=kid, key_source=key.source, reason=str(exc))

    # Only now — signature verified, key identified — is the payload's
    # content worth reading in full.
    try:
        payload = parse_version_1(payload_item)
    except PayloadError as exc:
        return QrResult(ok=False, kid=kid, key_source=key.source, reason=str(exc))

    checks = _cross_check(payload, evidence)
    failed = [check for check in checks if check.ok is False]
    if failed:
        return QrResult(
            ok=False,
            kid=kid,
            key_source=key.source,
            payload=payload,
            checks=checks,
            reason="; ".join(check.detail for check in failed),
        )

    return QrResult(
        ok=True,
        kid=kid,
        key_source=key.source,
        algorithm=ALGORITHM_NAMES.get(sign1.alg, str(sign1.alg)),
        payload=payload,
        checks=checks,
    )
