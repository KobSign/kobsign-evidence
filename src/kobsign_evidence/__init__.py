"""
kobsign-evidence — independent verifier for KobSign-signed PDFs.

Verifies a signed PDF document without any KobSign infrastructure:
    1. PDF structural integrity
    2. PAdES-LTA signature
    3. Certificate chain to a trusted root
    4. Qualified timestamp
    5. evidence.json hash (reproducible canonicalization)
    6. Document hashes in evidence.json match the actual document

Public API:
    verify(pdf_path) -> VerificationResult
"""

from .verifier import VerificationResult, verify

__version__ = "0.1.1"
__all__ = ["verify", "VerificationResult", "__version__"]
