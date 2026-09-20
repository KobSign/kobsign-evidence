"""Build data-QR payloads from scratch, for testing the verifier.

The CBOR encoder here is deliberately a second implementation, written
from RFC 8949 rather than imported from ``kobsign_evidence.qr.cbor``. If
the decoder under test and the encoder producing its input were the same
code, they would agree with each other about a mistake as happily as
about the specification.

The production signing key does not exist yet — the ceremony has not
been held — so every key here is generated on the spot.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

COSE_SIGN1_TAG = 18
ALG_ES256 = -7
ALG_ES384 = -35


def base45_encode(data: bytes) -> str:
    """RFC 9285 §4.1, the encode direction."""
    out = []
    for offset in range(0, len(data), 2):
        chunk = data[offset : offset + 2]
        if len(chunk) == 2:
            number = (chunk[0] << 8) + chunk[1]
            c, number = number % 45, number // 45
            d, e = number % 45, number // 45
            out += [BASE45_ALPHABET[c], BASE45_ALPHABET[d], BASE45_ALPHABET[e]]
        else:
            number = chunk[0]
            out += [BASE45_ALPHABET[number % 45], BASE45_ALPHABET[number // 45]]
    return "".join(out)


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    for minor, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < (1 << (8 * width)):
            return bytes([(major << 5) | minor]) + argument.to_bytes(width, "big")
    raise ValueError("too large")


def cbor_encode(value) -> bytes:
    """Canonical CBOR for the types a data QR uses."""
    if isinstance(value, bool):
        raise ValueError("no booleans in a data QR")
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        # RFC 8949 §4.2.1: sort by the encoded key bytes.
        items = sorted(
            ((cbor_encode(k), cbor_encode(v)) for k, v in value.items()),
            key=lambda pair: pair[0],
        )
        return _head(5, len(value)) + b"".join(k + v for k, v in items)
    raise ValueError(f"cannot encode {type(value).__name__}")


def cbor_tag(tag: int, payload: bytes) -> bytes:
    return _head(6, tag) + payload


@dataclass
class QrIdentity:
    """An ES256 key pair standing in for the (not yet existing) KobSign key."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls, curve: ec.EllipticCurve | None = None) -> "QrIdentity":
        return cls(ec.generate_private_key(curve or ec.SECP256R1()))

    @property
    def public_der(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def kid(self) -> bytes:
        """Derived, not assigned: SHA-256 over the DER SPKI, first 8 bytes."""
        return hashlib.sha256(self.public_der).digest()[:8]

    def sign(self, message: bytes, *, hash_algorithm=None) -> bytes:
        """Raw (r || s) signature, as COSE wants it — not DER."""
        der = self.private_key.sign(
            message, ec.ECDSA(hash_algorithm or hashes.SHA256())
        )
        r, s = utils.decode_dss_signature(der)
        size = (self.private_key.curve.key_size + 7) // 8
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def payload_map(
    *,
    version: int = 1,
    koblink_id: str = "KB-PERSON-VERIFY001-DOC-2026-00001",
    document_hash: bytes | None = None,
    evidence_hash: bytes | None = None,
    completed_at: int = 1_790_000_000,
    signer_count: int = 1,
    levels: dict[int, int] | None = None,
) -> dict:
    return {
        1: version,
        2: koblink_id,
        3: document_hash if document_hash is not None else bytes(range(32)),
        4: evidence_hash if evidence_hash is not None else bytes(range(32, 64)),
        5: completed_at,
        6: signer_count,
        7: levels if levels is not None else {2: signer_count},
    }


def make_qr(
    identity: QrIdentity,
    payload: dict | bytes,
    *,
    alg: int | None = ALG_ES256,
    alg_in_unprotected: int | None = None,
    kid: bytes | None = None,
    kid_in_unprotected: bool = False,
    tagged: bool = True,
    tamper_payload: bool = False,
    hash_algorithm=None,
) -> str:
    """Produce a base45 COSE_Sign1 data QR, with knobs for the negative tests."""
    payload_bytes = payload if isinstance(payload, bytes) else cbor_encode(payload)

    protected: dict = {}
    if alg is not None:
        protected[1] = alg
    unprotected: dict = {}
    if alg_in_unprotected is not None:
        unprotected[1] = alg_in_unprotected
    key_id = identity.kid if kid is None else kid
    if kid_in_unprotected:
        unprotected[4] = key_id
    else:
        protected[4] = key_id

    protected_bytes = cbor_encode(protected) if protected else b""
    sig_structure = cbor_encode(["Signature1", protected_bytes, b"", payload_bytes])
    signature = identity.sign(sig_structure, hash_algorithm=hash_algorithm)

    if tamper_payload:
        # Flip a bit AFTER signing: the signature is over what was signed,
        # which is no longer what is in the QR.
        mutable = bytearray(payload_bytes)
        mutable[-1] ^= 0x01
        payload_bytes = bytes(mutable)

    message = cbor_encode(
        [protected_bytes, unprotected, payload_bytes, signature]
    )
    if tagged:
        message = cbor_tag(COSE_SIGN1_TAG, message)
    return base45_encode(message)
