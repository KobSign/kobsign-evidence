"""Decoding, verifying and cross-checking the data QR.

The QR exists so a printed page can be checked without the file. Every
test here is about one of the three ways that promise fails: the payload
is not what it claims, the key is not one we archived, or the payload is
about some other document.
"""

from __future__ import annotations

import hashlib
import json

import pytest
import qr_factory
from cryptography.hazmat.primitives.asymmetric import ec

from kobsign_evidence.evidence import canonicalize
from kobsign_evidence.qr import verify_data_qr
from kobsign_evidence.qr.keys import derive_kid, load_archive, load_public_key


@pytest.fixture
def identity() -> qr_factory.QrIdentity:
    return qr_factory.QrIdentity.generate()


@pytest.fixture
def evidence() -> dict:
    """An evidence package shaped like the ones the backend emits."""
    package = {
        "document_title": "QR fixture",
        "koblink_id": "KB-PERSON-VERIFY001-DOC-2026-00001",
        "signatures": [
            {"name": "Ola Nordmann", "email": "ola@example.com", "level": "AES"},
            {"name": "Kari Nordmann", "email": "kari@example.com", "level": "SES"},
        ],
        "original_document_hash": "a" * 128,
        "evidence_json_hash": "",
        "_schema": {
            "version": "3.12.0",
            "type": "DocumentEvidencePackage",
            "canonicalization_version": "1",
        },
    }
    package["evidence_json_hash"] = hashlib.sha256(canonicalize(package)).hexdigest()
    return package


def evidence_digest(evidence: dict) -> bytes:
    return hashlib.sha256(canonicalize(evidence)).digest()


def matching_payload(evidence: dict, **overrides) -> dict:
    """A payload that agrees with ``evidence`` on every cross-checked field."""
    defaults = {
        "koblink_id": evidence["koblink_id"],
        "evidence_hash": evidence_digest(evidence),
        "signer_count": len(evidence["signatures"]),
        "levels": {1: 1, 2: 1},
    }
    defaults.update(overrides)
    return qr_factory.payload_map(**defaults)


class TestKeyIdentifiers:
    """A kid is derived from the key, never handed out by a registry."""

    def test_kid_is_the_first_eight_bytes_of_sha256_over_the_der_spki(self, identity):
        key = load_public_key(identity.public_pem, "test key")
        expected = hashlib.sha256(identity.public_der).digest()[:8]
        assert key.kid == expected
        assert len(key.kid) == 8
        assert derive_kid(identity.private_key.public_key()) == expected

    def test_pem_and_der_give_the_same_key(self, identity):
        assert (
            load_public_key(identity.public_pem).kid
            == load_public_key(identity.public_der).kid
        )

    def test_two_keys_do_not_share_an_identifier(self):
        first = qr_factory.QrIdentity.generate()
        second = qr_factory.QrIdentity.generate()
        assert first.kid != second.kid

    def test_a_private_key_is_refused(self, identity):
        from cryptography.hazmat.primitives import serialization

        private_pem = identity.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(ValueError):
            load_public_key(private_pem, "leaked key")

    def test_an_rsa_key_is_refused(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        pem = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        with pytest.raises(ValueError, match="ES256"):
            load_public_key(pem, "rsa key")


class TestArchivedKeyBundle:
    """The archive that ships inside the package."""

    def test_the_bundled_archive_loads_without_a_network(self):
        # May legitimately be empty — the production ceremony has not been
        # held — but it must never fail to load.
        assert isinstance(load_archive(), list)

    def test_every_archived_file_is_a_usable_public_key(self):
        """A file that does not load is a key that silently stopped working."""
        from importlib import resources

        package = resources.files("kobsign_evidence.keys")
        for entry in package.iterdir():
            if not entry.name.endswith((".pem", ".der")):
                continue
            key = load_public_key(entry.read_bytes(), entry.name)
            assert isinstance(key.public_key.curve, ec.SECP256R1), entry.name

    def test_no_private_key_material_is_archived(self):
        """The archive is public by design. One slip here is the whole system."""
        from importlib import resources

        package = resources.files("kobsign_evidence.keys")
        for entry in package.iterdir():
            if entry.name.endswith((".pem", ".der")):
                assert b"PRIVATE KEY" not in entry.read_bytes(), entry.name

    def test_extra_keys_join_the_archive(self, identity):
        archive = load_archive([identity.public_pem])
        assert any(key.kid == identity.kid for key in archive)

    def test_a_corrupt_entry_does_not_take_the_archive_down(self, identity):
        archive = load_archive([b"not a key at all", identity.public_pem])
        assert any(key.kid == identity.kid for key in archive)


class TestHappyPath:
    def test_a_well_formed_qr_verifies_and_matches_the_pdf(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert result.ok, result.reason
        assert result.algorithm == "ES256"
        assert result.kid == identity.kid
        assert result.payload.koblink_id == evidence["koblink_id"]
        assert result.payload.signer_count == 2
        assert result.payload.levels_by_name == {"SES": 1, "AES": 1}
        assert [check.name for check in result.checks if check.ok is False] == []

    def test_the_evidence_hash_check_is_computed_not_quoted(self, identity, evidence):
        """The check recomputes the hash; it does not read the file's own claim."""
        qr = qr_factory.make_qr(identity, matching_payload(evidence))
        # A file that lies about its own hash must not change this check's
        # outcome — the QR is bound to the content, not to the claim.
        evidence["evidence_json_hash"] = "0" * 64
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert result.ok, result.reason

    def test_an_untagged_cose_sign1_is_accepted(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence), tagged=False)
        assert verify_data_qr(
            qr, evidence, extra_public_keys=[identity.public_pem]
        ).ok

    def test_no_qr_supplied_is_not_a_failure(self, evidence):
        result = verify_data_qr(None, evidence)
        assert result.not_applicable
        assert not result.ok

    def test_the_payload_carries_no_names(self, identity, evidence):
        """Hashes and counts only. A printed QR outlives everyone's consent."""
        raw = qr_factory.cbor_encode(matching_payload(evidence))
        for signer in evidence["signatures"]:
            assert signer["name"].encode() not in raw
            assert signer["email"].encode() not in raw
        assert b"QR fixture" not in raw


class TestSignatureIsNotDecoration:
    def test_a_tampered_payload_is_rejected(self, identity, evidence):
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence), tamper_payload=True
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "does not verify" in result.reason

    def test_a_qr_signed_by_an_unarchived_key_is_rejected(self, identity, evidence):
        stranger = qr_factory.QrIdentity.generate()
        qr = qr_factory.make_qr(stranger, matching_payload(evidence))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert stranger.kid.hex() in result.reason

    def test_an_empty_archive_says_so_plainly(self, evidence):
        """Until the ceremony is held, this is what every real QR hits."""
        stranger = qr_factory.QrIdentity.generate()
        qr = qr_factory.make_qr(stranger, matching_payload(evidence))
        result = verify_data_qr(qr, evidence)
        assert not result.ok
        assert not result.not_applicable, "an unverifiable QR is not 'not applicable'"

    def test_a_qr_naming_someone_elses_key_id_is_rejected(self, identity, evidence):
        """Signed by a stranger, labelled with our kid. The label loses."""
        stranger = qr_factory.QrIdentity.generate()
        qr = qr_factory.make_qr(stranger, matching_payload(evidence), kid=identity.kid)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "does not verify" in result.reason

    def test_a_qr_with_no_key_id_is_rejected(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence), kid=b"")
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "names no key" in result.reason

    def test_the_key_id_may_travel_in_the_unprotected_header(self, identity, evidence):
        """kid is a lookup hint; the signature is what decides."""
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence), kid_in_unprotected=True
        )
        assert verify_data_qr(
            qr, evidence, extra_public_keys=[identity.public_pem]
        ).ok


class TestVersionBindsAlgorithm:
    def test_version_1_declares_es256_and_nothing_else(self, identity, evidence):
        """The algorithm comes from the version, not from the document."""
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence), alg=qr_factory.ALG_ES384
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "ES256" in result.reason

    def test_an_algorithm_in_the_unprotected_header_does_not_count(
        self, identity, evidence
    ):
        """Those bytes are not signed, so they cannot decide anything."""
        qr = qr_factory.make_qr(
            identity,
            matching_payload(evidence),
            alg=None,
            alg_in_unprotected=qr_factory.ALG_ES256,
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "no algorithm" in result.reason

    def test_an_unknown_version_is_refused_not_guessed_at(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence, version=2))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "version 2" in result.reason
        assert "newer verifier" in result.reason
        assert result.payload is None, "nothing from an unreadable version is reported"

    def test_an_unknown_version_is_refused_even_when_perfectly_signed(
        self, identity, evidence
    ):
        """Signed by an archived key is not a reason to read it optimistically."""
        qr = qr_factory.make_qr(identity, matching_payload(evidence, version=99))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "version 99" in result.reason

    def test_a_payload_without_a_version_is_refused(self, identity, evidence):
        payload = matching_payload(evidence)
        del payload[1]
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "version" in result.reason


class TestPayloadShape:
    def test_a_key_version_1_does_not_define_is_refused(self, identity, evidence):
        payload = matching_payload(evidence)
        payload[8] = "something new"
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "version 1 does not define" in result.reason

    @pytest.mark.parametrize("key", [2, 3, 4, 5, 6, 7])
    def test_every_version_1_field_is_required(self, identity, evidence, key):
        payload = matching_payload(evidence)
        del payload[key]
        qr = qr_factory.make_qr(identity, payload)
        assert not verify_data_qr(
            qr, evidence, extra_public_keys=[identity.public_pem]
        ).ok

    def test_a_short_hash_is_refused(self, identity, evidence):
        payload = matching_payload(evidence)
        payload[4] = b"\x00" * 16
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "16 bytes" in result.reason

    def test_an_unknown_signature_level_code_is_refused(self, identity, evidence):
        payload = matching_payload(evidence, levels={3: 2})
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "level code" in result.reason

    def test_level_counts_must_add_up_to_the_signer_count(self, identity, evidence):
        payload = matching_payload(evidence, levels={1: 5})
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "add up" in result.reason


class TestCrossCheckAgainstThePdf:
    """A QR that verifies and describes another document is the dangerous one."""

    def test_an_evidence_hash_for_a_different_document_is_caught(
        self, identity, evidence
    ):
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence, evidence_hash=bytes(32))
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "different evidence.json" in result.reason
        assert evidence_digest(evidence).hex() in result.reason

    def test_editing_the_pdf_evidence_breaks_the_binding(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence))
        evidence["signatures"][0]["name"] = "Mallory"
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "different evidence.json" in result.reason

    def test_a_mismatched_koblink_id_is_caught(self, identity, evidence):
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence, koblink_id="KB-OTHER-DOC")
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "KB-OTHER-DOC" in result.reason

    def test_a_mismatched_signer_count_is_caught(self, identity, evidence):
        qr = qr_factory.make_qr(
            identity, matching_payload(evidence, signer_count=3, levels={1: 1, 2: 2})
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "3 signer(s)" in result.reason

    def test_mismatched_levels_are_caught(self, identity, evidence):
        qr = qr_factory.make_qr(identity, matching_payload(evidence, levels={2: 2}))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "AES" in result.reason

    def test_without_evidence_the_binding_is_reported_as_unchecked(
        self, identity, evidence
    ):
        """No evidence.json means the QR is unverified against anything."""
        qr = qr_factory.make_qr(identity, matching_payload(evidence))
        result = verify_data_qr(qr, None, extra_public_keys=[identity.public_pem])
        binding = next(check for check in result.checks if check.name == "evidence.json")
        assert binding.ok is None

    def test_the_document_hash_is_reported_not_claimed(self, identity, evidence):
        """Different algorithms; saying more than that would be invention."""
        payload = matching_payload(evidence)
        qr = qr_factory.make_qr(identity, payload)
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        check = next(c for c in result.checks if c.name == "document hash")
        assert check.ok is None
        assert payload[3].hex() in check.detail

    def test_an_unmappable_level_in_evidence_is_reported_not_failed(
        self, identity, evidence
    ):
        evidence["signatures"][0]["level"] = "QES"
        evidence["evidence_json_hash"] = hashlib.sha256(
            canonicalize(evidence)
        ).hexdigest()
        qr = qr_factory.make_qr(
            identity,
            matching_payload(
                evidence, evidence_hash=evidence_digest(evidence), levels={1: 1, 2: 1}
            ),
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        check = next(c for c in result.checks if c.name == "signature levels")
        assert check.ok is None
        assert "QES" in check.detail
        assert result.ok, result.reason


class TestMalformedInput:
    """Nothing a QR reader can hand this function may raise."""

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "not base45!",
            "BB8",  # valid base45, not CBOR
            "QED8WEX0",
            "%69 VD92EX0",
        ],
    )
    def test_garbage_is_reported_never_raised(self, text, evidence):
        result = verify_data_qr(text, evidence)
        assert not result.ok
        assert result.reason

    def test_a_cose_object_that_is_not_an_array_is_rejected(self, identity, evidence):
        raw = qr_factory.cbor_tag(18, qr_factory.cbor_encode({1: 2}))
        result = verify_data_qr(qr_factory.base45_encode(raw), evidence)
        assert not result.ok
        assert "COSE_Sign1" in result.reason

    def test_a_different_cbor_tag_is_rejected(self, identity, evidence):
        raw = qr_factory.cbor_tag(
            98, qr_factory.cbor_encode([b"", {}, b"", b""])
        )  # tag 98 is COSE_Sign (multi-signer)
        result = verify_data_qr(qr_factory.base45_encode(raw), evidence)
        assert not result.ok
        assert "tag 98" in result.reason

    def test_a_payload_that_is_not_a_map_is_rejected(self, identity, evidence):
        qr = qr_factory.make_qr(identity, qr_factory.cbor_encode([1, 2, 3]))
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok
        assert "not a CBOR map" in result.reason

    def test_a_json_payload_is_not_mistaken_for_cbor(self, identity, evidence):
        qr = qr_factory.make_qr(
            identity, json.dumps({"version": 1}).encode("utf-8")
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert not result.ok


class TestLevelCountEdges:
    def test_an_explicit_zero_count_is_not_a_disagreement(self, identity, evidence):
        """{SES: 0, AES: 2} and {AES: 2} say the same thing."""
        evidence["signatures"] = [
            {"name": "A", "level": "AES"},
            {"name": "B", "level": "AES"},
        ]
        evidence["evidence_json_hash"] = hashlib.sha256(
            canonicalize(evidence)
        ).hexdigest()
        qr = qr_factory.make_qr(
            identity,
            matching_payload(
                evidence,
                evidence_hash=evidence_digest(evidence),
                signer_count=2,
                levels={1: 0, 2: 2},
            ),
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        assert result.ok, result.reason

    def test_a_signer_without_a_recorded_level_is_reported_not_failed(
        self, identity, evidence
    ):
        evidence["signatures"][1].pop("level")
        evidence["evidence_json_hash"] = hashlib.sha256(
            canonicalize(evidence)
        ).hexdigest()
        qr = qr_factory.make_qr(
            identity,
            matching_payload(evidence, evidence_hash=evidence_digest(evidence)),
        )
        result = verify_data_qr(qr, evidence, extra_public_keys=[identity.public_pem])
        check = next(c for c in result.checks if c.name == "signature levels")
        assert check.ok is None
        assert "no signature level" in check.detail
        assert result.ok, result.reason
