"""
The data QR payload: a CBOR map with integer keys, and what each means.

    1  version           the payload format version
    2  koblink_id        the document's KobSign identifier (text)
    3  document_hash     32 bytes
    4  evidence_hash     32 bytes — SHA-256 over canonical evidence.json
    5  completed_at      unix seconds, signing completed server-side
    6  signer_count      how many people signed
    7  levels            map of level code to count: 1 = SES, 2 = AES

Integer keys, not names, because a QR has to stay small enough to print
on a page and still scan from a photocopy.

Two rules govern how this is read.

**Version binds algorithm.** Version 1 declares ES256, exactly. Not "at
least" ES256 and not "ES256 unless the header says otherwise": a
verifier that takes the algorithm from the object it is verifying can be
told which algorithm to accept by whoever wrote the object. There is no
negotiation and no downgrade — the version decides, and a mismatch is a
rejection.

**An unknown version is refused, never guessed at.** A payload from a
future format may reuse a key for something else; reading it under
version 1's rules would produce a confident, wrong answer in court. A
verifier that says "I am too old to read this, get a newer one" is worth
more than one that guesses right most of the time.

The payload carries no names, no e-mail addresses and no free text. Only
hashes, counts and an identifier — a QR is printed on paper that travels
further than the people in it ever agreed to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .cose import ALG_ES256

KEY_VERSION = 1
KEY_KOBLINK_ID = 2
KEY_DOCUMENT_HASH = 3
KEY_EVIDENCE_HASH = 4
KEY_COMPLETED_AT = 5
KEY_SIGNER_COUNT = 6
KEY_LEVELS = 7

# Every key version 1 defines. A payload carrying anything else is from a
# format this verifier does not know, whatever its version field claims.
VERSION_1_KEYS = frozenset(
    {
        KEY_VERSION,
        KEY_KOBLINK_ID,
        KEY_DOCUMENT_HASH,
        KEY_EVIDENCE_HASH,
        KEY_COMPLETED_AT,
        KEY_SIGNER_COUNT,
        KEY_LEVELS,
    }
)

# version -> the one COSE algorithm that version is signed with.
VERSION_ALGORITHMS: dict[int, int] = {1: ALG_ES256}

ALGORITHM_NAMES: dict[int, str] = {ALG_ES256: "ES256"}

# Signature level codes, as the payload encodes them.
LEVEL_NAMES: dict[int, str] = {1: "SES", 2: "AES"}

HASH_LENGTH = 32  # SHA-256


class PayloadError(ValueError):
    """The payload is malformed, or from a version this verifier cannot read."""


@dataclass(frozen=True)
class QrPayload:
    """A validated version-1 payload."""

    version: int
    koblink_id: str
    document_hash: bytes
    evidence_hash: bytes
    completed_at: datetime
    signer_count: int
    levels: dict[int, int] = field(default_factory=dict)

    @property
    def levels_by_name(self) -> dict[str, int]:
        return {LEVEL_NAMES[code]: count for code, count in sorted(self.levels.items())}


def declared_version(payload: object) -> int:
    """Read the version field before anything else is trusted about it."""
    if not isinstance(payload, dict):
        raise PayloadError("the QR payload is not a CBOR map")
    version = payload.get(KEY_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise PayloadError("the QR payload does not declare a version")
    return version


def required_algorithm(version: int) -> int:
    """The algorithm this version must be signed with. Raises if unknown."""
    try:
        return VERSION_ALGORITHMS[version]
    except KeyError:
        known = ", ".join(str(v) for v in sorted(VERSION_ALGORITHMS))
        raise PayloadError(
            f"the QR payload is version {version}; this verifier implements "
            f"version {known}. It was produced by a newer KobSign than this "
            f"tool knows about — get a newer verifier rather than trusting "
            f"this one's reading of it"
        ) from None


def check_algorithm(version: int, alg: int | None) -> None:
    """Enforce the version-to-algorithm binding. No negotiation."""
    expected = required_algorithm(version)
    if alg is None:
        raise PayloadError(
            "the COSE protected header declares no algorithm; version "
            f"{version} requires {ALGORITHM_NAMES[expected]}"
        )
    if alg != expected:
        got = ALGORITHM_NAMES.get(alg, f"COSE algorithm {alg}")
        raise PayloadError(
            f"the QR is signed with {got}, but version {version} requires "
            f"{ALGORITHM_NAMES[expected]} — a verifier that accepts the "
            f"algorithm a document asks for accepts whatever an attacker asks for"
        )


def _hash_field(payload: dict, key: int, label: str) -> bytes:
    value = payload.get(key)
    if not isinstance(value, bytes):
        raise PayloadError(f"the QR payload has no {label}")
    if len(value) != HASH_LENGTH:
        raise PayloadError(
            f"the QR payload's {label} is {len(value)} bytes, not {HASH_LENGTH}"
        )
    return value


def parse_version_1(payload: dict) -> QrPayload:
    """Validate a version-1 payload, strictly. Raises on anything unexpected."""
    unknown = set(payload) - VERSION_1_KEYS
    if unknown:
        listed = ", ".join(repr(key) for key in sorted(unknown, key=repr))
        raise PayloadError(
            f"the QR payload declares version 1 but carries key(s) {listed}, "
            f"which version 1 does not define"
        )

    koblink_id = payload.get(KEY_KOBLINK_ID)
    if not isinstance(koblink_id, str) or not koblink_id:
        raise PayloadError("the QR payload has no koblink id")

    document_hash = _hash_field(payload, KEY_DOCUMENT_HASH, "document hash")
    evidence_hash = _hash_field(payload, KEY_EVIDENCE_HASH, "evidence hash")

    completed = payload.get(KEY_COMPLETED_AT)
    if not isinstance(completed, int) or isinstance(completed, bool):
        raise PayloadError("the QR payload has no completion time")
    try:
        completed_at = datetime.fromtimestamp(completed, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise PayloadError(
            f"the QR payload's completion time ({completed}) is not a usable "
            f"unix timestamp"
        ) from None

    signer_count = payload.get(KEY_SIGNER_COUNT)
    if not isinstance(signer_count, int) or isinstance(signer_count, bool):
        raise PayloadError("the QR payload has no signer count")
    if signer_count < 1:
        raise PayloadError(
            f"the QR payload claims {signer_count} signers; a completed "
            f"document has at least one"
        )

    raw_levels = payload.get(KEY_LEVELS)
    if not isinstance(raw_levels, dict) or not raw_levels:
        raise PayloadError("the QR payload has no signature-level counts")
    levels: dict[int, int] = {}
    for code, count in raw_levels.items():
        if not isinstance(code, int) or isinstance(code, bool) or code not in LEVEL_NAMES:
            known = ", ".join(f"{k}={v}" for k, v in sorted(LEVEL_NAMES.items()))
            raise PayloadError(
                f"the QR payload uses signature level code {code!r}, which "
                f"this verifier does not know ({known})"
            )
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise PayloadError(
                f"the QR payload's count for level {LEVEL_NAMES[code]} is not "
                f"a number of signers"
            )
        levels[code] = count

    if sum(levels.values()) != signer_count:
        raise PayloadError(
            f"the QR payload's level counts add up to {sum(levels.values())} "
            f"but it claims {signer_count} signers"
        )

    return QrPayload(
        version=1,
        koblink_id=koblink_id,
        document_hash=document_hash,
        evidence_hash=evidence_hash,
        completed_at=completed_at,
        signer_count=signer_count,
        levels=levels,
    )
