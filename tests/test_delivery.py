"""Tests for the per-signer ``delivery`` block (evidence schema 3.12.0).

Standalone — no PDF, no backend, standard library plus the verifier.

The shape under test comes from ``DELIVERY_EVENT_SEMANTICS`` and
``_group_delivery()`` in the KobSign repo. The load-bearing cases are the
two at the ends: an older document with no delivery block must still
verify green, and a block that drops its ``does_not_prove`` wording must
not.
"""

from __future__ import annotations

import pytest

from kobsign_evidence.delivery import (
    EVENTS_WITHOUT_DISCLAIMER,
    KNOWN_DELIVERY_EVENTS,
    validate_delivery,
)

NOTE = (
    "A missing event means it was not recorded — not that it did not happen. "
    "Privacy proxies suppress open tracking and provider webhooks can be lost."
)


def _event(name: str = "provider_accepted", **overrides) -> dict:
    event = {
        "event": name,
        "at": "2026-09-01T08:00:00+00:00",
        "proves": "Our e-mail provider accepted the message for delivery.",
    }
    if name not in EVENTS_WITHOUT_DISCLAIMER:
        event["does_not_prove"] = "That the message reached the recipient's mail server."
    event.update(overrides)
    return event


def _evidence(*signers: dict) -> dict:
    return {
        "document_title": "Test",
        "_schema": {"version": "3.12.0", "canonicalization_version": "1"},
        "signatures": list(signers) or [{"name": "Alice"}],
    }


def _signer_with(*events: dict, name: str = "Alice", note: str = NOTE) -> dict:
    return {"name": name, "delivery": {"events": list(events), "note": note}}


class TestOptionality:
    """Schema 3.12.0 adds the block. It does not require it."""

    def test_no_delivery_block_is_not_applicable(self):
        result = validate_delivery(_evidence({"name": "Alice"}))
        assert result.not_applicable
        assert not result.ok

    def test_older_schema_without_delivery_is_not_applicable(self):
        evidence = _evidence({"name": "Alice"})
        evidence["_schema"]["version"] = "3.11.0"
        result = validate_delivery(evidence)
        assert result.not_applicable

    def test_some_signers_with_and_some_without(self):
        result = validate_delivery(
            _evidence(_signer_with(_event()), {"name": "Bob"})
        )
        assert result.ok
        assert result.signers_with_delivery == 1

    def test_evidence_with_no_signers_at_all(self):
        result = validate_delivery({"signatures": []})
        assert result.not_applicable
        assert not result.ok


class TestEventNames:
    @pytest.mark.parametrize("name", KNOWN_DELIVERY_EVENTS)
    def test_every_known_event_validates(self, name):
        result = validate_delivery(_evidence(_signer_with(_event(name))))
        assert result.ok, result.reason
        assert result.events[0].event == name

    def test_unknown_event_name_is_reported_not_held_against_the_document(self):
        """A name from a newer schema means a newer producer, not tampering.

        evidence.json sits inside the signed byte range: nobody adds an
        event to it without breaking layers 2 and 6 first. So an
        unrecognised name says this file was sealed by something younger
        than this verifier — the case the N/A rule exists for — and the
        honest answer is to hand the reader the event as the file states
        it, not to call a sound document forged.
        """
        result = validate_delivery(_evidence(_signer_with(_event("email_opened"))))
        assert result.not_applicable, "must not count against the verdict"
        assert not result.ok
        assert "email_opened" in result.reason
        assert result.unknown_events == ["email_opened"]

    def test_an_unknown_event_is_still_carried_through_verbatim(self):
        """Nothing is hidden from the reader — it is simply not vouched for."""
        event = _event("email_opened")
        event["proves"] = "Something this verifier has no wording for."
        result = validate_delivery(_evidence(_signer_with(event)))
        carried = result.events[0]
        assert carried.event == "email_opened"
        assert carried.known is False
        assert carried.proves == "Something this verifier has no wording for."

    def test_known_events_alongside_an_unknown_one_still_validate(self):
        result = validate_delivery(
            _evidence(_signer_with(_event("provider_accepted"), _event("email_opened")))
        )
        assert result.not_applicable
        assert [e.event for e in result.events] == ["provider_accepted", "email_opened"]
        assert [e.known for e in result.events] == [True, False]

    def test_a_malformed_known_event_still_fails_even_beside_an_unknown_one(self):
        """Leniency for the unfamiliar is not leniency for the broken."""
        broken = _event("tracking_pixel_loaded")
        del broken["does_not_prove"]
        result = validate_delivery(
            _evidence(_signer_with(broken, _event("email_opened")))
        )
        assert not result.ok
        assert not result.not_applicable, "a real defect is not excused"
        assert "does_not_prove" in result.reason

    def test_an_unknown_event_needs_no_disclaimer_we_cannot_know_it_needs(self):
        """We do not know a newer event's semantics, so we demand no wording."""
        bare = {"event": "quantum_delivered", "at": "2026-09-01T08:00:00+00:00"}
        result = validate_delivery(_evidence(_signer_with(bare)))
        assert result.not_applicable
        assert not result.ok
        assert result.events[0].event == "quantum_delivered"

    def test_missing_event_name_is_rejected(self):
        event = _event()
        del event["event"]
        result = validate_delivery(_evidence(_signer_with(event)))
        assert not result.ok
        assert "no event name" in result.reason


class TestTimestamps:
    @pytest.mark.parametrize(
        "value",
        [
            "2026-09-01T08:00:00+00:00",
            "2026-09-01T08:00:00Z",
            "2026-09-01T08:00:00.123456+02:00",
            "2026-09-01T08:00:00",
        ],
    )
    def test_iso8601_forms_are_accepted(self, value):
        result = validate_delivery(_evidence(_signer_with(_event(at=value))))
        assert result.ok, result.reason

    # "20260901" is deliberately absent: ISO-8601 basic format is valid,
    # and Python parses it from 3.11 on.
    @pytest.mark.parametrize("value", ["not-a-date", "01/09/2026", "", "8 a.m."])
    def test_unparsable_timestamps_are_rejected(self, value):
        result = validate_delivery(_evidence(_signer_with(_event(at=value))))
        assert not result.ok

    def test_missing_timestamp_is_rejected(self):
        event = _event()
        del event["at"]
        result = validate_delivery(_evidence(_signer_with(event)))
        assert not result.ok
        assert "no timestamp" in result.reason


class TestSemanticStatements:
    """The proves / does_not_prove pair is the block's whole purpose."""

    def test_missing_proves_is_rejected(self):
        event = _event()
        del event["proves"]
        result = validate_delivery(_evidence(_signer_with(event)))
        assert not result.ok
        assert "proves" in result.reason

    def test_empty_proves_is_rejected(self):
        result = validate_delivery(_evidence(_signer_with(_event(proves="   "))))
        assert not result.ok

    def test_tracking_pixel_without_disclaimer_is_rejected(self):
        """Strip the disclaimer and 'pixel loaded' silently becomes 'they read it'."""
        event = _event("tracking_pixel_loaded")
        del event["does_not_prove"]
        result = validate_delivery(_evidence(_signer_with(event)))
        assert not result.ok
        assert "does_not_prove" in result.reason

    def test_bounced_needs_no_disclaimer(self):
        """A bounce is unambiguous — there is no overclaim to guard against."""
        event = _event("bounced")
        assert "does_not_prove" not in event
        result = validate_delivery(_evidence(_signer_with(event)))
        assert result.ok, result.reason
        assert result.events[0].does_not_prove is None

    def test_statements_are_carried_through_verbatim(self):
        event = _event("tracking_pixel_loaded")
        event["proves"] = "A tracking image embedded in the message was loaded."
        event["does_not_prove"] = (
            "That a human read the message — privacy proxies such as Apple Mail "
            "Privacy Protection load images automatically."
        )
        result = validate_delivery(_evidence(_signer_with(event)))
        assert result.events[0].proves == event["proves"]
        assert result.events[0].does_not_prove == event["does_not_prove"]


class TestBlockShape:
    def test_delivery_must_be_an_object(self):
        result = validate_delivery(_evidence({"name": "A", "delivery": ["nope"]}))
        assert not result.ok
        assert not result.not_applicable

    def test_empty_event_list_is_rejected(self):
        result = validate_delivery(_evidence(_signer_with()))
        assert not result.ok
        assert "no events" in result.reason

    def test_missing_note_is_rejected(self):
        result = validate_delivery(_evidence(_signer_with(_event(), note="")))
        assert not result.ok
        assert "note" in result.reason

    def test_note_is_carried_through_and_deduplicated(self):
        result = validate_delivery(
            _evidence(
                _signer_with(_event(), name="Alice"),
                _signer_with(_event(), name="Bob"),
            )
        )
        assert result.ok
        assert result.notes == [NOTE]

    def test_events_are_attributed_to_their_signer(self):
        result = validate_delivery(
            _evidence(
                _signer_with(_event(), name="Alice"),
                _signer_with(_event("link_followed"), name="Bob"),
            )
        )
        assert [(e.signer_index, e.signer_name) for e in result.events] == [
            (0, "Alice"),
            (1, "Bob"),
        ]

    def test_full_seven_event_trail(self):
        events = [_event(name) for name in KNOWN_DELIVERY_EVENTS]
        result = validate_delivery(_evidence(_signer_with(*events)))
        assert result.ok, result.reason
        assert len(result.events) == len(KNOWN_DELIVERY_EVENTS)


class TestNeverRaises:
    @pytest.mark.parametrize(
        "evidence",
        [
            {},
            {"signatures": None},
            {"signatures": ["not a dict"]},
            {"signatures": [{"delivery": {"events": [None], "note": "x"}}]},
            {"signatures": [{"delivery": {"events": [{}], "note": "x"}}]},
        ],
    )
    def test_malformed_input_returns_a_result(self, evidence):
        result = validate_delivery(evidence)
        assert result.ok is False
