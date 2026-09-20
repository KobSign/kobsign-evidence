"""
The archive of public keys the data QR is verified against.

Historical public keys live in this repository, inside the package, not
only behind a JWKS endpoint. An endpoint dies with the domain, the
company or the hosting bill; a QR printed on a signed agreement is meant
to be verifiable seventy years from now, by someone holding nothing but
the paper and a copy of this tool. So the keys ship with the tool.

Two rules follow from that, and neither is negotiable:

* **Rotation adds. It never removes.** Every key that ever signed a
  data QR stays in the archive forever. Drop one and every document it
  signed stops being verifiable — silently, and only for the people who
  come looking years later.
* **Public keys only.** Nothing in this directory is secret and nothing
  in it is sensitive; that is the point. A private key must never end up
  here.

The archive may be empty. The production signing ceremony has not been
held at the time of writing, so a build can legitimately ship with no
keys at all — in which case a QR cannot be verified, and the verifier
says exactly that rather than passing the document on a technicality.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# A key identifier is DERIVED, never assigned: the first 8 bytes of
# SHA-256 over the public key's DER SubjectPublicKeyInfo. Anyone holding
# the public key can recompute it, so a `kid` cannot point at a key that
# is not the key — there is no registry to disagree with.
KID_LENGTH = 8


@dataclass(frozen=True)
class ArchivedKey:
    """One public key from the archive, with its derived identifier."""

    kid: bytes
    public_key: ec.EllipticCurvePublicKey
    source: str  # file name inside the archive, for the report

    @property
    def kid_hex(self) -> str:
        return self.kid.hex()


def derive_kid(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Derive the key identifier the COSE header must carry."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).digest()[:KID_LENGTH]


def load_public_key(data: bytes, source: str = "supplied key") -> ArchivedKey:
    """Load one PEM or DER public key and derive its ``kid``.

    Raises ``ValueError`` when the bytes are not a public key this
    verifier can use.
    """
    key = None
    errors = []
    for loader in (
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
    ):
        try:
            key = loader(data)
            break
        except Exception as exc:  # noqa: PERF203 — two shots, both reported
            errors.append(str(exc))
    if key is None:
        raise ValueError(f"{source}: not a readable public key ({'; '.join(errors)})")
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError(
            f"{source}: not an elliptic-curve public key "
            f"({type(key).__name__}); the data QR is signed with ES256"
        )
    return ArchivedKey(kid=derive_kid(key), public_key=key, source=source)


def load_archive(extra: list[bytes] | None = None) -> list[ArchivedKey]:
    """Load every archived public key, plus any supplied by the caller.

    ``extra`` (PEM or DER bytes) is for test fixtures signed with keys
    generated on the spot — the same shape, and the same intent, as
    ``verify_pades(extra_trust_roots=...)``. Production callers leave it
    unset.

    A file that will not parse is skipped rather than raising: one
    corrupt entry must not take the whole archive — and therefore every
    other document — down with it.
    """
    archive: list[ArchivedKey] = []
    package = resources.files("kobsign_evidence.keys")
    for entry in sorted(package.iterdir(), key=lambda item: item.name):
        if not entry.name.endswith((".pem", ".der")):
            continue
        try:
            archive.append(load_public_key(entry.read_bytes(), entry.name))
        except Exception:
            continue

    for index, raw in enumerate(extra or []):
        try:
            archive.append(load_public_key(raw, f"caller-supplied key {index}"))
        except Exception:
            continue
    return archive


def find_by_kid(kid: bytes, archive: list[ArchivedKey]) -> ArchivedKey | None:
    """Look a key up by its derived identifier."""
    for key in archive:
        if key.kid == kid:
            return key
    return None
