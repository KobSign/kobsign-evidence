# kobsign-evidence

**Independent verifier for KobSign-signed PDF documents.**

Verify that a signed PDF is intact, trusted, and authentic — without
needing KobSign infrastructure, KobSign source code, or a network
connection. Designed for courts, opposing counsel, auditors, and
security researchers.

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What it checks

Eight independent layers:

| # | Layer | What it proves |
|---|---|---|
| 1 | PDF structure | The file is a well-formed PDF |
| 2 | PAdES-LTA signature | The bytes the signature covers still hash to the signed value |
| 3 | Certificate chain | The signer's certificate chains to a bundled, trusted root |
| 4 | Qualified timestamp | The document is timestamped, and the TSA's own certificate chains to a bundled, trusted root |
| 5 | Post-signature revisions | Nothing of substance was appended after the last signature |
| 6 | `evidence.json` integrity | The machine-readable audit trail matches its own SHA-256 hash |
| 7 | Document hashes | The original document hash is recorded, hex-well-formed, and ready for comparison |
| 8 | Delivery trail | The recorded delivery events are well-formed, and each states its own limits |

Every layer reports `OK`, `FAIL` or `N/A` with a specific reason. The
overall verdict is the single bit courts care about.

Layers 3 and 4 make the same demand of two different parties. A
timestamp token proves only that someone held a key; it carries weight
because the authority behind it chains to a root the reader already
trusts. A token from an authority this tool cannot chain is reported as
what it is — someone stamped this, and we cannot tell you who — and
never as a timestamp. That covers the archival DocTimeStamps PAdES-LTA
is built out of, which is where a document's date usually comes from.

Layers 2 and 5 are separate on purpose. A PDF grows by incremental
update: new bytes are appended and the original bytes stay exactly as
they were. A signature over the original byte range therefore keeps
verifying after someone has appended a revision that adds a page, an
annotation or a different visible value. The reader sees the last
revision; the signature covers the first. Layer 5 is what closes that
gap — legitimate archival timestamps and later signers are allowed
through, anything else is reported.

A layer marked `N/A` does not apply to the document in hand — typically
a feature added in an evidence schema newer than the one the document
was sealed under. `N/A` never turns a verdict red: a signature made in
2026 is not retroactively weakened by a field introduced in 2027.

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

### Reading the delivery trail

When a document carries one, `--verbose` and `--json` print what was
recorded about the signing invitation — that a provider accepted it,
that a tracking pixel loaded, that a link was followed.

Each event is printed with the `proves` and `does_not_prove` statement
the file itself carries, verbatim. This tool does not summarise them,
and neither should a report built on it. `tracking_pixel_loaded` is the
case that matters: privacy proxies such as Apple Mail Privacy Protection
load images automatically, so a loaded pixel is not a person reading
anything.

A missing event means it was not recorded, not that it did not happen.
That the signature was completed is established server-side and recorded
in the signer's `signed_at` — it does not depend on e-mail at all.

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
