"""
Base45 decoding — RFC 9285.

The data QR is base45 because that is the alphanumeric mode a QR code
encodes most densely; the same reason the EU Digital COVID Certificate
used it. This is the decode half only. The verifier never produces a QR.

Standard library only, like every layer a court has to be able to
re-derive from the specification alone.
"""

from __future__ import annotations

# RFC 9285 §4, table 1. Position in this string is the character's value.
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_VALUES = {char: index for index, char in enumerate(ALPHABET)}


class Base45Error(ValueError):
    """The string is not valid base45. Carries a reader-facing reason."""


# Line breaks and tabs get introduced by copying a payload through a
# terminal, an e-mail or a text file, and are never part of one. The SPACE
# character is not on this list: it is a base45 character carrying data
# (value 36), and removing it would quietly decode a different payload.
_LAYOUT_CHARACTERS = "\r\n\t\v\f"


def decode(text: str) -> bytes:
    """Decode a base45 string. Raises :class:`Base45Error` on anything else.

    Line breaks are removed first: a payload read from a file or pasted
    from a scanner arrives wrapped, and that is the reader's tooling
    talking, not a corrupted document.
    """
    compact = text.translate({ord(char): None for char in _LAYOUT_CHARACTERS})
    if not compact:
        raise Base45Error("the QR payload is empty")

    try:
        values = [_VALUES[char] for char in compact]
    except KeyError as exc:
        bad = exc.args[0]
        raise Base45Error(
            f"the QR payload contains {bad!r}, which is not a base45 character"
        ) from None

    out = bytearray()
    for offset in range(0, len(values), 3):
        chunk = values[offset : offset + 3]
        if len(chunk) == 3:
            number = chunk[0] + chunk[1] * 45 + chunk[2] * 45 * 45
            if number > 0xFFFF:
                raise Base45Error(
                    "the QR payload has a 3-character group that does not "
                    "encode two bytes"
                )
            out += number.to_bytes(2, "big")
        elif len(chunk) == 2:
            number = chunk[0] + chunk[1] * 45
            if number > 0xFF:
                raise Base45Error(
                    "the QR payload has a 2-character group that does not "
                    "encode one byte"
                )
            out.append(number)
        else:
            # RFC 9285 §6: a leftover single character cannot occur in a
            # well-formed encoding. Usually a truncated scan.
            raise Base45Error(
                "the QR payload ends in a single leftover character — the "
                "scan is incomplete"
            )
    return bytes(out)
