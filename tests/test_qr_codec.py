"""The two codecs under the data QR: base45 (RFC 9285) and CBOR (RFC 8949).

Both are implemented here from the specification rather than pulled in as
dependencies — see the module docstrings for why — which makes their own
test coverage part of the security argument rather than a nicety.
"""

from __future__ import annotations

import pytest
import qr_factory

from kobsign_evidence.qr import base45, cbor


class TestBase45:
    @pytest.mark.parametrize(
        ("decoded", "encoded"),
        [
            # RFC 9285 §4.3, the worked examples in the specification.
            (b"AB", "BB8"),
            (b"Hello!!", "%69 VD92EX0"),
            (b"base-45", "UJCLQE7W581"),
            (b"ietf!", "QED8WEX0"),
        ],
    )
    def test_rfc_9285_vectors(self, decoded, encoded):
        assert base45.decode(encoded) == decoded
        assert qr_factory.base45_encode(decoded) == encoded

    def test_round_trip(self):
        payload = bytes(range(256)) * 3
        assert base45.decode(qr_factory.base45_encode(payload)) == payload

    def test_line_breaks_from_a_scanner_are_tolerated(self):
        assert base45.decode("BB8\n") == b"AB"
        assert base45.decode("BB8\r\nBB8") == b"ABAB"

    def test_a_space_is_data_and_is_never_stripped(self):
        """SPACE is base45 character 36. Dropping it decodes another payload."""
        assert base45.decode("%69 VD92EX0") == b"Hello!!"
        with pytest.raises(base45.Base45Error):
            base45.decode("%69VD92EX0")

    def test_a_character_outside_the_alphabet_is_named(self):
        with pytest.raises(base45.Base45Error, match="'a'"):
            base45.decode("BBa")

    def test_a_truncated_scan_is_rejected(self):
        with pytest.raises(base45.Base45Error, match="incomplete"):
            base45.decode("BB8B")

    def test_an_out_of_range_group_is_rejected(self):
        # ':::' is 44 + 44*45 + 44*2025 = 90044, past two bytes.
        with pytest.raises(base45.Base45Error, match="two bytes"):
            base45.decode(":::")

    def test_empty_input_is_rejected(self):
        with pytest.raises(base45.Base45Error, match="empty"):
            base45.decode("")
        with pytest.raises(base45.Base45Error, match="empty"):
            base45.decode("\n")


class TestCborDecoder:
    def test_round_trips_the_shapes_a_payload_uses(self):
        value = {
            1: 1,
            2: "KB-PERSON-VERIFY001-DOC-2026-00001",
            3: bytes(range(32)),
            5: 1_790_000_000,
            6: 2,
            7: {1: 1, 2: 1},
            8: -7,
        }
        assert cbor.decode(qr_factory.cbor_encode(value)) == value

    def test_tags_are_preserved(self):
        item = cbor.decode(qr_factory.cbor_tag(18, qr_factory.cbor_encode([1, 2])))
        assert isinstance(item, cbor.Tagged)
        assert item.tag == 18
        assert item.value == [1, 2]

    def test_trailing_bytes_are_rejected(self):
        """Where a second, unsigned item would hide behind a signed one."""
        with pytest.raises(cbor.CborError, match="unexpected byte"):
            cbor.decode(qr_factory.cbor_encode(1) + b"\x01")

    def test_indefinite_length_is_rejected(self):
        # 0x5f: byte string of indefinite length.
        with pytest.raises(cbor.CborError, match="indefinite"):
            cbor.decode(b"\x5f\x41\x01\xff")

    def test_non_minimal_integer_encoding_is_rejected(self):
        """One value, two encodings, is one value too many under a hash."""
        assert cbor.decode(b"\x01") == 1
        with pytest.raises(cbor.CborError, match="non-canonical"):
            cbor.decode(b"\x18\x01")  # 1, written in the two-byte form

    def test_a_repeated_map_key_is_rejected(self):
        with pytest.raises(cbor.CborError, match="repeats the map key"):
            cbor.decode(b"\xa2\x01\x01\x01\x02")

    def test_floats_are_rejected(self):
        with pytest.raises(cbor.CborError, match="float"):
            cbor.decode(b"\xf9\x3c\x00")  # half-precision 1.0

    def test_a_truncated_item_is_rejected(self):
        with pytest.raises(cbor.CborError, match="ends in the middle"):
            cbor.decode(b"\x43\x01\x02")  # 3-byte string, 2 bytes present

    def test_deep_nesting_is_refused_rather_than_followed(self):
        bomb = b"\x81" * 200 + b"\x01"
        with pytest.raises(cbor.CborError, match="nested deeper"):
            cbor.decode(bomb)

    def test_a_declared_length_longer_than_the_data_cannot_allocate(self):
        # Claims a 4-gigabyte array; must fail on the data, not on memory.
        with pytest.raises(cbor.CborError):
            cbor.decode(b"\x9a\xff\xff\xff\xff")


class TestCborEncoder:
    """The encoder exists only to rebuild COSE's Sig_structure."""

    def test_matches_the_independent_test_encoder(self):
        for value in (0, 1, 23, 24, 255, 256, 65535, 65536, -1, -7, -1000):
            assert cbor.encode(value) == qr_factory.cbor_encode(value)
        for value in (b"", b"\x00" * 40, "Signature1", ["Signature1", b"", b"", b"x"]):
            assert cbor.encode(value) == qr_factory.cbor_encode(value)

    def test_booleans_are_not_silently_integers(self):
        with pytest.raises(cbor.CborError, match="[Bb]oolean"):
            cbor.encode(True)
