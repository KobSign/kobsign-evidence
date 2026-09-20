# The data QR, byte by byte

This document describes the payload the verifier reads out of a KobSign
certificate page's data QR, in enough detail to re-implement the check
from scratch. Nothing here depends on KobSign source code.

## The wrapping

```
QR image  ->  base45 text  ->  COSE_Sign1  ->  CBOR map, integer keys
```

* **base45** — RFC 9285. The alphanumeric mode a QR encodes most
  densely. Note that SPACE (value 36) is a data character: a decoder that
  strips whitespace decodes a different payload.
* **COSE_Sign1** — RFC 9052, CBOR tag 18 (untagged is also accepted).
  The array is `[protected, unprotected, payload, signature]`.
  * `protected` carries `alg` (label 1) and usually `kid` (label 4). The
    algorithm is read from here and nowhere else: the unprotected header
    is not covered by the signature, so anything read from it is a value
    the attacker chose.
  * `signature` is the raw ECDSA pair `r || s`, 32 bytes each — not DER.
  * The signature is over `Sig_structure` = canonical CBOR of
    `["Signature1", protected_bytes, external_aad (empty), payload]`,
    where `protected_bytes` is the byte string as it appeared in the
    message, never a re-encoding of the parsed map.

## The payload

A CBOR map with integer keys — names would not fit on a page that has to
scan from a photocopy.

| Key | Meaning | Type |
|---|---|---|
| 1 | payload version | unsigned integer |
| 2 | koblink id | text |
| 3 | document hash | 32 bytes |
| 4 | evidence hash | 32 bytes — SHA-256 over canonical `evidence.json` |
| 5 | completed | unix seconds, server-side completion |
| 6 | signer count | unsigned integer |
| 7 | levels | map of level code to count: `1` = SES, `2` = AES |

There are no names, no e-mail addresses and no document title in the
payload. A QR printed on paper outlives the consent of the people in it.

## Version binds algorithm

| Version | Algorithm |
|---|---|
| 1 | ES256 (COSE `alg` = -7), and nothing else |

Two rules follow, and the verifier applies both before it looks at a
signature:

* **No negotiation, no downgrade.** The version decides the algorithm. A
  verifier that accepts the algorithm named in the object it is
  verifying accepts whatever the writer of that object chose.
* **An unknown version is refused, not guessed at.** A future format may
  reuse key 3 for something else; reading it under version 1's rules
  produces a confident wrong answer in a courtroom. The verifier says it
  is too old and asks to be replaced.

Within version 1 the payload is read strictly: every key must be
present, hashes must be exactly 32 bytes, level counts must add up to
the signer count, and a key version 1 does not define is a rejection
rather than something to skip past.

## Key identifiers are derived

```
kid = SHA-256(public key DER SubjectPublicKeyInfo)[:8]
```

Derived, never assigned. Anyone holding the public key can recompute it,
so there is no registry to be out of date and no name to be wrong about.
The file name a key is archived under carries no authority.

The public keys are archived in `src/kobsign_evidence/keys/`, inside the
installed package. Rotation adds keys; it never removes one, because a
removed key silently unverifies every document it ever signed. See that
directory's README.

## Cross-checking against the PDF

Verifying the signature only proves the payload is KobSign's. What makes
the QR evidence is the binding to the document:

| Check | Against |
|---|---|
| evidence hash | SHA-256 over the canonical form of the `evidence.json` embedded in this PDF, recomputed from the file — not read from its own `evidence_json_hash` field |
| koblink id | `koblink_id` in `evidence.json` |
| signer count | number of entries in `signatures` |
| levels | the `level` of each signer (`SES`, `AES`) |
| document hash | `original_document_hash` in `evidence.json` — **when the two are the same width** (see below) |

Both the payload's key 3 and `evidence.json`'s
`original_document_hash` are taken over the user's original upload, and
the signing pipeline writes 32 bytes in both places — the QR builder
refuses to issue a code for anything else. But this package spent a long
time documenting that field as SHA3-512, and the sample bundled with the
repository holds a hand-written placeholder 64 bytes wide, so a file in
hand is not guaranteed to hold what the format says it holds.

The comparison is therefore driven by what the file actually contains.
Equal widths are compared and can fail the layer; unequal widths are
printed for a reader holding the original document to hash themselves,
and nothing is claimed.

Note that **`evidence.json` does not record which algorithm produced
either digest.** Its `hash_algorithm` field is a compliance label for the
signature and timestamp — it renders on the cover page as one item in
"PAdES-LTA (ETSI) · PDF/A-3 (ISO) · SHA-256 · RFC 3161 TSA" — and this
verifier does not read it as a label on the document hash. A reader
comparing digests themselves should use SHA-256, which is what KobSign's
pipeline records here; that is the producer's word, not the document's.

One value is only ever reported:

* **completed** — as it stands in the signed payload. It cannot be
  altered without breaking the signature; it is not checked against
  anything else, and no consistency claim is made from it.

A check that could not be made is printed as `-`, never as `OK`.

## Reproducing the evidence hash

`evidence_json_hash` is SHA-256 over a canonical form of
`evidence.json`. The canonicalization is implemented in
`kobsign_evidence/evidence.py`, in about forty lines using the standard
library alone, and its docstring lists the seven steps. The same digest,
in raw bytes, is what key 4 of the QR payload carries — so reproducing
one reproduces the other.
