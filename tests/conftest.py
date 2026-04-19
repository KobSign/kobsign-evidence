"""Shared fixtures — including signed-PDF generation for end-to-end tests.

These fixtures reach into the KobSign backend (src/) to produce
realistic signed PDFs. The backend isn't installed as a package, so we
add it to sys.path on demand. End-to-end tests are automatically skipped
if the backend isn't available (e.g. when the verifier is installed on
a fresh machine with only the PyPI dependencies).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The verifier package lives at ../kobsign-evidence — add ../src for
# backend imports when running tests from the monorepo.
_MONOREPO_SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture(scope="session")
def backend_available() -> bool:
    """True when the KobSign backend is importable (monorepo checkout)."""
    if not _MONOREPO_SRC.is_dir():
        return False
    if str(_MONOREPO_SRC) not in sys.path:
        sys.path.insert(0, str(_MONOREPO_SRC))
    try:
        import django  # noqa: F401

        return True
    except Exception:
        return False


@pytest.fixture
def signed_pdf_pair(tmp_path, backend_available):
    """Produce a (valid.pdf, tampered.pdf) pair signed with a self-signed cert.

    Skipped when the KobSign backend is not available.
    """
    if not backend_available:
        pytest.skip("KobSign backend not available (not running inside monorepo)")

    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kobsign.settings")
    import django
    from django.apps import apps as django_apps

    if not django_apps.ready:
        django.setup()

    from datetime import UTC, datetime
    from io import BytesIO

    import pikepdf
    from django.conf import settings
    from signatures.pdf.cover_page.evidence_serializer import embed_evidence_json
    from signatures.pdf.cover_page.generator import (
        DocumentEvidencePackage,
        SignerEvidencePackage,
    )
    import signatures.pdf.signing.pades as pades_module

    # Minimal PDF with some content (self-signed signing requires non-blank content)
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(595, 842))
    page.Contents = pdf.make_stream(b"BT /F1 12 Tf 100 700 Td (Test Document) Tj ET")
    buf = BytesIO()
    pdf.save(buf)
    input_bytes = buf.getvalue()

    # Build an evidence package + compute its hash
    signer = SignerEvidencePackage(
        name="Test Signer",
        email="test@example.com",
        method="passkey",
        level="AES",
        signed_at=datetime.now(UTC),
    )
    package = DocumentEvidencePackage(
        document_title="Verifier fixture",
        koblink_id="KB-PERSON-VERIFY001-DOC-2026-00001",
        original_document_hash="a" * 128,  # SHA3-512 hex length
        signature_standard="PAdES-LTA",
        signatures=[signer],
    )
    # Compute + write the evidence_json_hash so the verifier can check it.
    # Round-trip through evidence_to_json to collapse datetime → ISO strings
    # before hashing — the same shape that ends up in the embedded file.
    import json as _json

    from signatures.pdf.cover_page.evidence_serializer import (
        compute_evidence_json_hash,
        evidence_to_json,
    )

    evidence_dict = _json.loads(evidence_to_json(package))
    package.evidence_json_hash = compute_evidence_json_hash(evidence_dict)

    with_evidence = embed_evidence_json(input_bytes, package)

    # Sign using the self-signed provider (no Key Vault required)
    settings.KOBSIGN_SIGNING_PROVIDER = "self_signed"
    settings.KOBSIGN_USE_TSA = False
    pades_module._provider_instance = None
    try:
        result = pades_module.sign_pdf(
            pdf_input=with_evidence,
            signer_name="Test Signer",
            reason="Verifier fixture",
            signature_level="SES",
            use_tsa=False,
        )
    finally:
        pades_module._provider_instance = None

    if not result.success:
        pytest.skip(f"Could not sign test fixture: {result.error_message}")

    valid_pdf = tmp_path / "valid.pdf"
    valid_pdf.write_bytes(result.signed_pdf_bytes)

    # Build a tampered version by flipping a byte in the middle of the PDF
    tampered_bytes = bytearray(result.signed_pdf_bytes)
    mid = len(tampered_bytes) // 2
    tampered_bytes[mid] = tampered_bytes[mid] ^ 0xFF
    tampered_pdf = tmp_path / "tampered.pdf"
    tampered_pdf.write_bytes(bytes(tampered_bytes))

    return valid_pdf, tampered_pdf


@pytest.fixture
def self_signed_trust_root(backend_available) -> bytes | None:
    """DER-encoded self-signed provider cert for trust-chain tests."""
    if not backend_available:
        return None
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kobsign.settings")
    import django
    from django.apps import apps as django_apps

    if not django_apps.ready:
        django.setup()
    import signatures.pdf.signing.pades as pades_module

    from django.conf import settings

    settings.KOBSIGN_SIGNING_PROVIDER = "self_signed"
    pades_module._provider_instance = None
    try:
        provider = pades_module.get_signing_provider()
        cert_pem, _key_pem = provider._get_or_create_cert("Test Signer")
    finally:
        pades_module._provider_instance = None
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_bytes(serialization.Encoding.DER)
