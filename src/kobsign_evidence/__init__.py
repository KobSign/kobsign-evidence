"""
kobsign-evidence — independent verifier for KobSign-signed PDFs.

Verifies a signed PDF document without any KobSign infrastructure:
    1. PDF structural integrity
    2. PAdES-LTA signature over the signed byte range
    3. Certificate chain to a trusted root
    4. Qualified timestamp
    5. No content appended after the last signature
    6. evidence.json hash (reproducible canonicalization)
    7. Document hashes in evidence.json match the actual document
    8. Delivery trail, reported in the file's own words
    9. Data QR from the certificate page, cross-checked against this PDF

Public API:
    verify(pdf_path) -> VerificationResult
"""

from .verifier import VerificationResult, verify

__version__ = "0.3.0"
__all__ = ["verify", "VerificationResult", "__version__"]
