"""
Command-line interface for kobsign-evidence.

Usage:
    kobsign-evidence document.pdf              # one-line verdict
    kobsign-evidence document.pdf --verbose    # per-layer breakdown
    kobsign-evidence document.pdf --json       # machine-readable output
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


def _format_verbose(result) -> str:
    lines = []
    for layer in result.layers:
        mark = "OK  " if layer.ok else "FAIL"
        lines.append(f"  [{mark}] {layer.name}: {layer.detail}")
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

    result = verify(args.pdf)

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
