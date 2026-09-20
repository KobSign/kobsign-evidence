"""
Command-line interface for kobsign-evidence.

Usage:
    kobsign-evidence document.pdf              # one-line verdict
    kobsign-evidence document.pdf --verbose    # per-layer breakdown
    kobsign-evidence document.pdf --json       # machine-readable output
    kobsign-evidence document.pdf --qr "<text>"      # check a scanned data QR
    kobsign-evidence document.pdf --qr-file scan.txt # ...or one saved to a file
    kobsign-evidence --version

Exit codes:
    0 — verified
    1 — verification failed
    2 — file or argument error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import __version__
from .verifier import verify


def _format_delivery(delivery) -> list[str]:
    """Render the delivery trail using the file's own wording.

    ``proves`` and ``does_not_prove`` are printed verbatim. The tool does
    not summarise them, because every shorter phrasing overclaims: a
    loaded tracking pixel may be Apple Mail Privacy Protection rather than
    a person, and "opened" would put that in a court's hands as fact.
    """
    if delivery is None or not delivery.events:
        return []
    lines = ["", "Delivery trail:"]
    current_signer: int | None = None
    for event in delivery.events:
        if event.signer_index != current_signer:
            current_signer = event.signer_index
            who = event.signer_name or f"signer {event.signer_index}"
            lines.append(f"  {who}:")
        lines.append(f"    {event.at}  {event.event}")
        lines.append(f"      proves:         {event.proves}")
        if event.does_not_prove:
            lines.append(f"      does not prove: {event.does_not_prove}")
    for note in delivery.notes:
        lines.append(f"  Note: {note}")
    return lines


def _format_qr(qr) -> list[str]:
    """Render the data QR's findings.

    Checks the tool could not make are printed as such rather than left
    out. A reader skimming for red flags should be able to see which
    questions were asked and which went unanswered.
    """
    if qr is None or not qr.checks:
        return []
    lines = ["", "Data QR:"]
    if qr.payload is not None:
        lines.append(f"  koblink id:  {qr.payload.koblink_id}")
        lines.append(f"  completed:   {qr.payload.completed_at.isoformat()}")
        levels = ", ".join(
            f"{name}×{count}" for name, count in qr.payload.levels_by_name.items()
        )
        lines.append(f"  signers:     {qr.payload.signer_count} ({levels})")
    if qr.kid is not None:
        lines.append(f"  signed by:   key {qr.kid.hex()} ({qr.key_source or 'archived'})")
    for check in qr.checks:
        mark = "OK " if check.ok else ("-  " if check.ok is None else "BAD")
        lines.append(f"  [{mark}] {check.name}: {check.detail}")
    return lines


def _format_verbose(result) -> str:
    lines = []
    for layer in result.layers:
        if layer.na:
            mark = "N/A "
        elif layer.ok:
            mark = "OK  "
        else:
            mark = "FAIL"
        lines.append(f"  [{mark}] {layer.name}: {layer.detail}")
    lines.extend(_format_delivery(result.delivery))
    lines.extend(_format_qr(result.qr))
    verdict = "VERIFIED" if result.verified else "FAILED"
    header = (
        f"kobsign-evidence v{__version__}\n"
        f"Signatures: {result.signature_count}"
    )
    if result.evidence_schema_version:
        header += f"  |  evidence schema: {result.evidence_schema_version}"
    if result.canonicalization_version:
        header += f"  |  canonicalization: v{result.canonicalization_version}"
    return f"{header}\n\n" + "\n".join(lines) + f"\n\n{verdict}\n"


def _format_json(result) -> str:
    payload = {
        "verified": result.verified,
        "signature_count": result.signature_count,
        "evidence_schema_version": result.evidence_schema_version,
        "canonicalization_version": result.canonicalization_version,
        "layers": [asdict(layer) for layer in result.layers],
    }
    if result.qr is not None:
        qr_payload = result.qr.payload
        payload["qr"] = {
            "ok": result.qr.ok,
            "reason": result.qr.reason,
            "algorithm": result.qr.algorithm,
            "kid": result.qr.kid.hex() if result.qr.kid else None,
            "key_source": result.qr.key_source,
            "payload": None
            if qr_payload is None
            else {
                "version": qr_payload.version,
                "koblink_id": qr_payload.koblink_id,
                "document_hash": qr_payload.document_hash.hex(),
                "evidence_hash": qr_payload.evidence_hash.hex(),
                "completed_at": qr_payload.completed_at.isoformat(),
                "signer_count": qr_payload.signer_count,
                "levels": qr_payload.levels_by_name,
            },
            # ``ok: null`` on a check means the check could not be made.
            # That is not the same as passing and must not read as passing.
            "checks": [asdict(check) for check in result.qr.checks],
        }
    if result.delivery is not None and result.delivery.events:
        # Events are emitted with their own proves / does_not_prove strings
        # so a downstream consumer cannot restate the trail more strongly
        # than the file does.
        payload["delivery"] = {
            "events": [asdict(event) for event in result.delivery.events],
            "notes": result.delivery.notes,
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kobsign-evidence",
        description=(
            "Independent verifier for KobSign-signed PDFs. Verifies PAdES-LTA "
            "signatures, certificate chains, timestamps, and embedded evidence.json "
            "integrity — without KobSign infrastructure."
        ),
    )
    parser.add_argument(
        "pdf",
        nargs="?",
        help="Path to the signed PDF to verify.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-layer verification results.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report instead of the short verdict.",
    )
    parser.add_argument(
        "--qr",
        metavar="TEXT",
        help=(
            "The data QR payload from the certificate page, as a QR reader "
            "returns it. Checked against the evidence.json inside the PDF."
        ),
    )
    parser.add_argument(
        "--qr-file",
        metavar="PATH",
        help="Read the data QR payload from a file instead of the command line.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"kobsign-evidence {__version__}",
    )
    args = parser.parse_args(argv)

    if not args.pdf:
        parser.print_usage(sys.stderr)
        print("error: missing PDF path", file=sys.stderr)
        return 2

    if not os.path.isfile(args.pdf):
        print(f"error: file not found: {args.pdf}", file=sys.stderr)
        return 2

    if args.qr and args.qr_file:
        print(
            "error: pass either --qr or --qr-file, not both",
            file=sys.stderr,
        )
        return 2

    qr_payload = args.qr
    if args.qr_file:
        try:
            with open(args.qr_file, encoding="utf-8") as handle:
                qr_payload = handle.read()
        except OSError as exc:
            print(f"error: could not read {args.qr_file}: {exc}", file=sys.stderr)
            return 2

    result = verify(args.pdf, qr_payload=qr_payload)

    if args.json:
        print(_format_json(result))
    elif args.verbose:
        print(_format_verbose(result), end="")
    else:
        if result.verified:
            print("VERIFIED")
        else:
            failed = result.failed_layer
            reason = failed.detail if failed else "unknown failure"
            print(f"FAILED: {reason}")

    return 0 if result.verified else 1


if __name__ == "__main__":
    sys.exit(main())
