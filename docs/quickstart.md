# kobsign-evidence quickstart

A 60-second guide to verifying a KobSign-signed PDF.

## Windows

1. Download `kobsign-evidence-windows-x64.exe` from the
   [latest release](https://github.com/KobSign/kobsign-evidence/releases).
2. Open PowerShell or Command Prompt in the folder containing the
   downloaded `.exe` and the PDF you want to check.
3. Run:

   ```
   kobsign-evidence-windows-x64.exe signed-document.pdf
   ```

Windows SmartScreen may warn that the binary is unsigned. Click
**More info → Run anyway**. To verify the binary itself:

```
certutil -hashfile kobsign-evidence-windows-x64.exe SHA256
```

Compare the output against the SHA-256 published on the release page.

## macOS (Apple Silicon — M1/M2/M3/M4)

1. Download `kobsign-evidence-macos-arm64` from the
   [latest release](https://github.com/KobSign/kobsign-evidence/releases).
2. Open Terminal in the download folder.
3. Make it executable and run:

   ```bash
   chmod +x kobsign-evidence-macos-arm64
   ./kobsign-evidence-macos-arm64 signed-document.pdf
   ```

macOS Gatekeeper may block the binary. Allow it via **System Settings
→ Privacy & Security → Allow anyway**. Hash verification:

```bash
shasum -a 256 kobsign-evidence-macos-arm64
```

**Intel Mac (pre-2020)?** Use the pip-install path below instead — the
binary is Apple-Silicon-only.

## Linux / any Python 3.10+ environment

```bash
pip install kobsign-evidence
kobsign-evidence signed-document.pdf
```

## Reading the output

```
VERIFIED
```

All eight verification layers passed. The document is intact, nothing
was appended after signing, the certificate chain is trusted, the
timestamp is valid, and the embedded evidence record is unmodified.

```
FAILED: <specific reason>
```

The tool identifies the first failing layer. Common reasons:

- `the signed bytes have been altered` — layer 2
- `signer certificate does not chain to a trusted root` — layer 3
- `no qualified timestamp present` — layer 4
- `content was changed after this signature` — layer 5
- `evidence.json hash mismatch — content has been modified` — layer 6

Run with `--verbose` for a breakdown of all eight layers, including the
delivery trail if the document carries one. Run with `--json` for a
machine-readable report.

A layer shown as `N/A` rather than `OK` or `FAIL` does not apply to this
document — usually a field introduced in a newer evidence schema than
the one it was sealed under. It does not count against the verdict.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Verified |
| 1 | Verification failed |
| 2 | File or argument error |

## Questions

For issues or questions, see
[kobsign.com/trust/verify](https://kobsign.com/trust/verify). This
repository is archived read-only between releases — no GitHub issues.
