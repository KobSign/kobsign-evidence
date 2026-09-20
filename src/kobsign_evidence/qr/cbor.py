"""
A deliberately small, deliberately strict CBOR codec (RFC 8949).

Only what the data QR needs: unsigned and negative integers, byte
strings, text strings, arrays, maps and tags. No floats, no indefinite
lengths, no streaming. Everything else is rejected by name rather than
skipped, because a verifier that quietly ignores what it does not
understand is a verifier that can be fed something it does not
understand.

This module has NO dependencies beyond the Python standard library. The
same reasoning as ``evidence.py``: a QR printed on paper has to be
verifiable in seventy years, and every third-party package between the
specification and the answer is a bet that the package still exists and
still behaves the same way. RFC 8949 will still be readable.

Encoding is here only to rebuild COSE's ``Sig_structure`` — the exact
bytes the signature was computed over. We never produce a QR.
"""

from __future__ import annotations

from dataclasses import dataclass

# How deep a nested structure may go before we stop following it. The
# payload is two levels deep; anything approaching this is either a bug
# or someone probing the parser.
MAX_DEPTH = 16


class CborError(ValueError):
    """Malformed, non-canonical, or unsupported CBOR."""


@dataclass(frozen=True)
class Tagged:
    """A CBOR tag and the item it wraps (major type 6)."""

    tag: int
    value: object


def _read_head(data: bytes, offset: int, depth: int) -> tuple[int, int, int]:
    """Read one initial byte plus its argument.

    Returns ``(major_type, argument, new_offset)``.
    """
    if depth > MAX_DEPTH:
        raise CborError("the CBOR structure is nested deeper than this parser allows")
    if offset >= len(data):
        raise CborError("the CBOR data ends in the middle of an item")

    initial = data[offset]
    major = initial >> 5
    minor = initial & 0x1F
    offset += 1

    if minor < 24:
        return major, minor, offset
    if minor == 31:
        raise CborError(
            "the CBOR data uses an indefinite-length item, which this "
            "parser rejects"
        )
    if minor > 27:
        raise CborError(f"the CBOR data uses reserved additional information {minor}")

    width = 1 << (minor - 24)
    if offset + width > len(data):
        raise CborError("the CBOR data ends in the middle of an item's length")
    argument = int.from_bytes(data[offset : offset + width], "big")
    offset += width

    # RFC 8949 §4.2.1: the shortest form that fits is the only valid one.
    # Non-minimal encodings are two byte strings for one value, which is
    # exactly the ambiguity a hash over the payload must not have.
    minimum = (0, 24, 256, 65536, 4294967296)[minor - 23]
    if argument < minimum:
        raise CborError(
            "the CBOR data encodes a value in more bytes than necessary "
            "(non-canonical)"
        )
    return major, argument, offset


def _decode_item(data: bytes, offset: int, depth: int = 0) -> tuple[object, int]:
    major, argument, offset = _read_head(data, offset, depth)

    if major == 0:  # unsigned integer
        return argument, offset
    if major == 1:  # negative integer: -1 - n
        return -1 - argument, offset
    if major in (2, 3):  # byte string / text string
        end = offset + argument
        if end > len(data):
            raise CborError("the CBOR data ends in the middle of a string")
        raw = data[offset:end]
        if major == 2:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError:
            raise CborError("the CBOR data holds a text string that is not UTF-8") from None
    if major == 4:  # array
        items: list[object] = []
        for _ in range(argument):
            item, offset = _decode_item(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:  # map
        result: dict[object, object] = {}
        for _ in range(argument):
            key, offset = _decode_item(data, offset, depth + 1)
            if isinstance(key, (list, dict)):
                raise CborError("the CBOR data uses a composite value as a map key")
            if key in result:
                raise CborError(f"the CBOR data repeats the map key {key!r}")
            value, offset = _decode_item(data, offset, depth + 1)
            result[key] = value
        return result, offset
    if major == 6:  # tag
        value, offset = _decode_item(data, offset, depth + 1)
        return Tagged(argument, value), offset

    # major == 7: floats, true/false/null, simple values. The data QR
    # carries hashes, counts and identifiers; none of them need these,
    # and accepting them would mean accepting a float where a count
    # belongs.
    raise CborError(
        "the CBOR data holds a float or simple value, which this parser rejects"
    )


def decode(data: bytes) -> object:
    """Decode exactly one CBOR item from ``data``.

    Trailing bytes are an error, not something to ignore: they are how a
    second, unsigned item gets smuggled in behind a signed one.
    """
    value, offset = _decode_item(data, 0)
    if offset != len(data):
        raise CborError(
            f"{len(data) - offset} unexpected byte(s) follow the CBOR data"
        )
    return value


def _encode_head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    for minor, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < (1 << (8 * width)):
            return bytes([(major << 5) | minor]) + argument.to_bytes(width, "big")
    raise CborError("value too large to encode")


def encode(value: object) -> bytes:
    """Encode a value in canonical CBOR. Only the types COSE needs."""
    if isinstance(value, bool):
        # bool is an int subclass in Python; catching it here keeps a
        # stray True from silently encoding as the integer 1.
        raise CborError("booleans are not encodable by this codec")
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(0, value)
        return _encode_head(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _encode_head(4, len(value)) + b"".join(encode(item) for item in value)
    raise CborError(f"cannot encode {type(value).__name__}")
