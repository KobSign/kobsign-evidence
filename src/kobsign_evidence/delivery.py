"""
Validation of the per-signer ``delivery`` block in evidence.json.

Introduced in evidence schema 3.12.0. Each signer may carry a record of
what happened to the signing invitation — that an e-mail provider
accepted it, that a tracking pixel loaded, that a link was followed.

The block exists because the rows it is built from are party-linking and
are deleted on KobSign's retention ladder. Sealing the trail into the
signed PDF is what lets it outlive them.

This module validates the *shape* of that trail. It deliberately does not
interpret it. Every event in the file carries its own ``proves`` and
``does_not_prove`` statement, and a reader — this verifier included —
must repeat those rather than substitute a summary.
``tracking_pixel_loaded`` is the clearest case: Apple Mail Privacy
Protection loads images without a human ever opening the message, so
"opened" would be a claim the file itself declines to make.

The block is OPTIONAL. Documents sealed under schema 3.11.0 or earlier
carry no ``delivery`` block at all, and signers for whom nothing was
recorded omit it too. Absence is reported as not-applicable, never as a
failure.

Reference: ``DELIVERY_EVENT_SEMANTICS`` and ``_group_delivery()`` in
``src/signatures/pdf/cover_page/evidence_serializer.py`` (KobSign repo).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Delivery block landed in evidence schema 3.12.0 (fase 1 M3.1).
DELIVERY_INTRODUCED_AT = (3, 12, 0)

# Event names the serializer emits, in the order the invitation travels.
# Confirmed against ``DELIVERY_EVENT_SEMANTICS`` in the KobSign repo: these
# seven are the whole set. Completion of the signing itself is deliberately
# not among them — it is established server-side and recorded in the
# signer's ``signed_at``, not in the delivery trail.
#
# A name outside this list means the file was sealed by a producer younger
# than this verifier. It is reported, never held against the document: see
# ``_validate_event``.
KNOWN_DELIVERY_EVENTS: tuple[str, ...] = (
    "provider_accepted",
    "recipient_server_accepted",
    "tracking_pixel_loaded",
    "link_followed",
    "push_delivered",
    "bounced",
    "complained",
)

# Every event states what it proves. Every event except ``bounced`` also
# states what it does NOT prove — a bounce is unambiguous (the message was
# rejected), so there is no overclaim to guard against.
EVENTS_WITHOUT_DISCLAIMER: frozenset[str] = frozenset({"bounced"})


@dataclass(frozen=True)
class DeliveryEvent:
    """One delivery event, as recorded in the file.

    ``proves`` / ``does_not_prove`` are carried verbatim from
    evidence.json. Callers render these strings; they must not paraphrase
    them into a claim the underlying signal cannot support.

    ``known`` is False for an event name this verifier does not have in
    ``KNOWN_DELIVERY_EVENTS``. Such an event is carried through exactly as
    the file states it and vouched for by nothing: the verifier can repeat
    it, but it cannot tell a reader what the name is supposed to mean.
    """

    signer_index: int
    signer_name: str | None
    event: str
    at: str
    proves: str
    does_not_prove: str | None = None
    known: bool = True


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of delivery-block validation across all signers."""

    ok: bool
    events: list[DeliveryEvent] = field(default_factory=list)
    # The note each signer's block carries, explaining how to read a gap in
    # the trail. Kept verbatim; de-duplicated across signers.
    notes: list[str] = field(default_factory=list)
    reason: str | None = None  # None when ok=True
    # True when the trail cannot be vouched for in full, but nothing about
    # it is wrong: no signer carries a block at all (an older schema, or a
    # signer for whom nothing was recorded), or the block holds an event
    # name from a newer schema. Not a failure.
    not_applicable: bool = False
    signers_with_delivery: int = 0
    # Event names this verifier does not know, in the order encountered.
    unknown_events: list[str] = field(default_factory=list)


def _parse_iso8601(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z``.

    ``datetime.fromisoformat`` only accepts ``Z`` from Python 3.11 on, and
    this package supports 3.10.
    """
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _validate_event(
    raw: object, signer_index: int, signer_name: str | None, position: int
) -> tuple[DeliveryEvent | None, str | None]:
    """Validate one event object. Returns ``(event, error)`` — exactly one set."""
    where = f"signer {signer_index} delivery event {position}"
    if not isinstance(raw, dict):
        return None, f"{where} is not an object"

    name = raw.get("event")
    if not isinstance(name, str) or not name:
        return None, f"{where} has no event name"

    if name not in KNOWN_DELIVERY_EVENTS:
        # A newer producer. We do not know what this event is supposed to
        # prove, so we demand no wording of it and check no shape beyond
        # its name — a rule written for the seven names above would only
        # be guesswork applied to an eighth. Whatever it carries is handed
        # to the reader verbatim, and vouched for by nothing.
        at = raw.get("at")
        proves = raw.get("proves")
        does_not_prove = raw.get("does_not_prove")
        return (
            DeliveryEvent(
                signer_index=signer_index,
                signer_name=signer_name,
                event=name,
                at=at if isinstance(at, str) else "",
                proves=proves if isinstance(proves, str) else "",
                does_not_prove=(
                    does_not_prove if isinstance(does_not_prove, str) else None
                ),
                known=False,
            ),
            None,
        )

    at = raw.get("at")
    if not isinstance(at, str) or not at:
        return None, f"{where} ({name}) has no timestamp"
    if _parse_iso8601(at) is None:
        return None, f"{where} ({name}) has an unparsable timestamp {at!r}"

    proves = raw.get("proves")
    if not isinstance(proves, str) or not proves.strip():
        return None, f"{where} ({name}) is missing its 'proves' statement"

    does_not_prove = raw.get("does_not_prove")
    if name in EVENTS_WITHOUT_DISCLAIMER:
        does_not_prove = does_not_prove if isinstance(does_not_prove, str) else None
    elif not isinstance(does_not_prove, str) or not does_not_prove.strip():
        # The disclaimer is the point of the block, not decoration: without
        # it a reader is free to turn "pixel loaded" into "they read it".
        return None, f"{where} ({name}) is missing its 'does_not_prove' statement"

    return (
        DeliveryEvent(
            signer_index=signer_index,
            signer_name=signer_name,
            event=name,
            at=at,
            proves=proves,
            does_not_prove=does_not_prove,
        ),
        None,
    )


def validate_delivery(evidence: dict) -> DeliveryResult:
    """Validate every signer's ``delivery`` block in an evidence package.

    Never raises. Returns ``not_applicable=True`` when no signer carries a
    delivery block — the block is an addition in schema 3.12.0, not a new
    requirement, and documents sealed before it must still verify green.
    """
    signatures = evidence.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return DeliveryResult(
            ok=False,
            not_applicable=True,
            reason="no signers in evidence.json to carry a delivery trail",
        )

    events: list[DeliveryEvent] = []
    notes: list[str] = []
    unknown_events: list[str] = []
    signers_with_delivery = 0

    for index, signer in enumerate(signatures):
        if not isinstance(signer, dict):
            continue
        block = signer.get("delivery")
        if block is None:
            # Nothing was recorded for this signer. The serializer omits the
            # block entirely in that case — see _group_delivery().
            continue
        if not isinstance(block, dict):
            return DeliveryResult(
                ok=False,
                reason=f"signer {index} has a 'delivery' field that is not an object",
            )

        name = signer.get("name")
        signer_name = name if isinstance(name, str) else None

        raw_events = block.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            # An empty block should not exist: the serializer returns early
            # when there is nothing to record.
            return DeliveryResult(
                ok=False,
                reason=f"signer {index} has a delivery block with no events",
            )

        for position, raw in enumerate(raw_events):
            event, error = _validate_event(raw, index, signer_name, position)
            if error is not None:
                return DeliveryResult(ok=False, reason=error)
            assert event is not None  # _validate_event sets exactly one
            events.append(event)
            if not event.known and event.event not in unknown_events:
                unknown_events.append(event.event)

        note = block.get("note")
        if not isinstance(note, str) or not note.strip():
            return DeliveryResult(
                ok=False,
                reason=(
                    f"signer {index} has a delivery block without its 'note' — "
                    f"the note is what tells a reader that a missing event "
                    f"means unrecorded, not absent"
                ),
            )
        if note not in notes:
            notes.append(note)
        signers_with_delivery += 1

    if signers_with_delivery == 0:
        return DeliveryResult(
            ok=False,
            not_applicable=True,
            reason=(
                "no delivery trail recorded (schema before 3.12.0, or nothing "
                "was recorded for any signer)"
            ),
        )

    if unknown_events:
        # Everything present is well-formed as far as this verifier can
        # judge, but it cannot judge all of it. Reported, not counted
        # against the document — the same treatment a field introduced
        # after sealing gets everywhere else in this tool.
        listed = ", ".join(repr(name) for name in unknown_events)
        return DeliveryResult(
            ok=False,
            not_applicable=True,
            events=events,
            notes=notes,
            signers_with_delivery=signers_with_delivery,
            unknown_events=unknown_events,
            reason=(
                f"the delivery trail holds event name(s) {listed} from a "
                f"schema newer than this verifier knows; they are reported "
                f"as the file states them and vouched for by nothing"
            ),
        )

    return DeliveryResult(
        ok=True,
        events=events,
        notes=notes,
        signers_with_delivery=signers_with_delivery,
    )
