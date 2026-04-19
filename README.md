# kobsign-evidence

**Independent verifier for KobSign-signed PDF documents.**

Verify that a signed PDF is intact, trusted, and authentic — without
needing KobSign infrastructure, KobSign source code, or a network
connection. Designed for courts, opposing counsel, auditors, and
security researchers.

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What it checks

Six independent layers:

| # | Layer | What it proves |
|---|---|---|
| 1 | PDF structure | The file is a well-formed PDF |
| 2 | PAdES-LTA signature | The document bytes match what was signed — no modification after signing |
| 3 | Certificate chain | The signer's certificate chains to a bundled, trusted root |
| 4 | Qualified timestamp | The signature is timestamped by a qualified TSA |
| 5 | `evidence.json` integrity | The machine-readable audit trail matches its own SHA-256 hash |
| 6 | Document hashes | The original document hash is recorded, hex-well-formed, and ready for comparison |

Every layer reports `OK` or `FAIL` with a specific reason. The overall
verdict is the single bit courts care about.

## Install

```bash
pip install kobsign-evidence
```

Pre-built binaries for Windows and macOS are attached to each
[GitHub release](https://github.com/KobSign/kobsign-evidence/releases)
— no Python required.

## Usage

```bash
# One-line verdict
kobsign-evidence signed-document.pdf
# → VERIFIED
#   or
# → FAILED: <specific reason>

# Per-layer breakdown
kobsign-evidence signed-document.pdf --verbose

# Machine-readable JSON
kobsign-evidence signed-document.pdf --json
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Verified — all layers pass |
| 1 | Verification failed — see output for which layer failed and why |
| 2 | File or argument error (path not found, etc.) |

## Why this tool exists

A KobSign signature rests on three promises:

1. **The document has not been modified** — cryptographic signatures
   over the document bytes.
2. **The signer is who the signature claims** — certificates chained to
   DigiCert's public trust root.
3. **The evidence is not editable after the fact** — `evidence.json` is
   embedded in the signed PDF and hashed into the signature.

This tool verifies all three without trusting KobSign. A judge or
opposing counsel can download the tool, run it, and get a binary answer
that does not rely on our word.

## Dependencies

- [`pyhanko`](https://github.com/MatthiasValvekens/pyHanko) — PAdES-LTA
  signature validation
- [`pikepdf`](https://github.com/pikepdf/pikepdf) — PDF attachment
  extraction
- [`cryptography`](https://github.com/pyca/cryptography) — certificate
  parsing

All dependencies are open-source and widely audited. The trust roots
(`trust/*.pem`) are bundled inside the package so no network access is
needed during verification.

## Reproducibility — the evidence hash

The `evidence_json_hash` field inside `evidence.json` is a SHA-256 over
a canonical form of the evidence itself. You can reproduce it from the
PDF alone using the
[standalone reference implementation](docs/reference-implementation.md)
— no KobSign code required, just the Python standard library.

## License

MIT — see [LICENSE](LICENSE).

## Status

This repository is published alongside each release of the verifier.
It is **archived read-only** between releases: no issues, no pull
requests, no community management. If you find a bug, see
[kobsign.com/trust/verify](https://kobsign.com/trust/verify) for the
reporting channel.
