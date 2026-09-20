# The data-QR public key archive

Every public key that has ever signed a KobSign data QR lives in this
directory, and ships inside the installed package.

A JWKS endpoint is not enough. An endpoint dies with the domain, the
company, or the hosting bill; the QR printed on a signed agreement is
meant to be checkable in seventy years by someone holding the paper, a
copy of this tool, and no network. So the keys travel with the tool.

## The rules

1. **Rotation adds a key. It never removes one.** Every key stays here
   forever, including keys that were rotated out, keys whose private
   half was destroyed in a ceremony, and keys nobody will ever sign with
   again. Delete one and every document it signed stops being
   verifiable — quietly, and only for the people who come looking years
   later, which is precisely who this archive is for.

2. **Public halves only.** Nothing here is secret; that is the point. A
   private key must never be committed to this directory, and
   `tests/test_qr.py` fails the build if one ever is.

3. **A key is identified by what it is, not by what it is called.** The
   `kid` in a QR's COSE header is the first 8 bytes of SHA-256 over the
   key's DER `SubjectPublicKeyInfo`. It is derived, never assigned, so
   the file name here carries no authority — rename a file and nothing
   about verification changes.

## Adding a key

Drop the public half in as PEM (`-----BEGIN PUBLIC KEY-----`) or DER,
named for when it entered service, e.g. `kobsign-qr-2026-01.pem`. It is
picked up automatically; there is no index to update and no
registration step. Keys must be NIST P-256, because version 1 of the
payload is signed with ES256 and nothing else.

## Why this directory may be empty

The production signing ceremony has not been held. Until it is, there is
no production key to archive, and a build legitimately ships with an
empty archive. A data QR presented to such a build cannot be verified,
and the verifier says exactly that — it does not treat "I have no keys"
as "nothing to check here".
