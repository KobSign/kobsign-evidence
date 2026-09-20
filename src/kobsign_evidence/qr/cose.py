"""
COSE_Sign1 verification (RFC 9052) for the data QR.

Scope is one shape and one algorithm: a single-signer COSE_Sign1 object
signed with ES256. There is no negotiation here — see ``payload.py`` for
why the version inside the payload, not the header, decides what is
acceptable.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import cbor
from .keys import ArchivedKey

# CBOR tag 18 marks a COSE_Sign1 object (RFC 9052 §2).
COSE_SIGN1_TAG = 18

# COSE header parameter labels (RFC 9052 §3.1).
HEADER_ALG = 1
HEADER_KID = 4

# COSE algorithm identifier for ECDSA w/ SHA-256 (RFC 9053 §2.1).
ALG_ES256 = -7

# ES256 signatures are the raw pair (r, s), 32 bytes each — not DER.
ES256_SIGNATURE_LENGTH = 64


class CoseError(ValueError):
    """The COSE structure is malformed, or the signature does not verify."""


@dataclass(frozen=True)
class CoseSign1:
    """A parsed COSE_Sign1 object, before its signature is verified."""

    protected_bytes: bytes  # the exact bytes the signature covers
    protected: dict
    unprotected: dict
    payload: bytes
    signature: bytes

    @property
    def alg(self) -> int | None:
        """Algorithm from the protected header. Never from the unprotected one.

        An algorithm a verifier would read out of the unprotected header
        is an algorithm an attacker can rewrite: those bytes are not
        covered by the signature.
        """
        value = self.protected.get(HEADER_ALG)
        return value if isinstance(value, int) else None

    @property
    def kid(self) -> bytes | None:
        """Key identifier, protected header first."""
        for source in (self.protected, self.unprotected):
            value = source.get(HEADER_KID)
            if isinstance(value, bytes) and value:
                return value
        return None


def parse(data: bytes) -> CoseSign1:
    """Parse a COSE_Sign1 object. Does not verify anything."""
    try:
        item = cbor.decode(data)
    except cbor.CborError as exc:
        raise CoseError(f"the QR payload is not valid CBOR: {exc}") from None

    if isinstance(item, cbor.Tagged):
        if item.tag != COSE_SIGN1_TAG:
            raise CoseError(
                f"the QR payload is CBOR tag {item.tag}, not a COSE_Sign1 "
                f"object (tag {COSE_SIGN1_TAG})"
            )
        item = item.value

    if not isinstance(item, list) or len(item) != 4:
        raise CoseError(
            "the QR payload is not a COSE_Sign1 object (expected an array of "
            "four elements)"
        )

    protected_bytes, unprotected, payload, signature = item
    if not isinstance(protected_bytes, bytes):
        raise CoseError("the COSE protected header is not a byte string")
    if not isinstance(unprotected, dict):
        raise CoseError("the COSE unprotected header is not a map")
    if not isinstance(payload, bytes):
        raise CoseError(
            "the COSE payload is not a byte string — a detached payload "
            "cannot be verified from the QR alone"
        )
    if not isinstance(signature, bytes):
        raise CoseError("the COSE signature is not a byte string")

    if protected_bytes:
        try:
            protected = cbor.decode(protected_bytes)
        except cbor.CborError as exc:
            raise CoseError(f"the COSE protected header is not valid CBOR: {exc}") from None
        if not isinstance(protected, dict):
            raise CoseError("the COSE protected header is not a map")
    else:
        protected = {}

    return CoseSign1(
        protected_bytes=protected_bytes,
        protected=protected,
        unprotected=unprotected,
        payload=payload,
        signature=signature,
    )


def sig_structure(sign1: CoseSign1) -> bytes:
    """Rebuild the ``Sig_structure`` the signature was computed over.

    RFC 9052 §4.4: ``["Signature1", protected, external_aad, payload]``,
    canonically encoded, with the protected header taken as the bytes
    that were in the message rather than a re-encoding of the parsed map.
    Re-encoding would verify a structure the signer never signed.
    """
    return cbor.encode(["Signature1", sign1.protected_bytes, b"", sign1.payload])


def verify_signature(sign1: CoseSign1, key: ArchivedKey) -> None:
    """Verify the ES256 signature. Returns on success, raises otherwise."""
    if not isinstance(key.public_key.curve, ec.SECP256R1):
        raise CoseError(
            f"the archived key {key.source} is on curve "
            f"{key.public_key.curve.name}; ES256 requires P-256"
        )
    if len(sign1.signature) != ES256_SIGNATURE_LENGTH:
        raise CoseError(
            f"the COSE signature is {len(sign1.signature)} bytes; ES256 is "
            f"{ES256_SIGNATURE_LENGTH} (r and s, 32 bytes each)"
        )

    half = ES256_SIGNATURE_LENGTH // 2
    r = int.from_bytes(sign1.signature[:half], "big")
    s = int.from_bytes(sign1.signature[half:], "big")
    try:
        key.public_key.verify(
            utils.encode_dss_signature(r, s),
            sig_structure(sign1),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        raise CoseError(
            "the QR signature does not verify against the archived public "
            "key it names — the payload has been altered, or it was not "
            "signed by KobSign"
        ) from None
