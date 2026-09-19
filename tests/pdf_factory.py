"""Build signed PDFs from scratch, offline, with no KobSign code.

The end-to-end fixtures in ``conftest.py`` reach into the KobSign backend
and skip when it is absent. That is fine for checking the verifier against
what production actually emits, but it means the negative tests — the ones
that prove a forged or tampered document is rejected — silently do not run
on a machine that only has this package installed.

The security properties this tool claims must be testable by the same
people the tool is aimed at: a court, opposing counsel, a researcher with
a pip install and no access to our source. Everything here uses pyHanko,
pikepdf and ``cryptography`` only.

Nothing in this module reaches the network.
"""

from __future__ import annotations

import datetime
from io import BytesIO

import pikepdf
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore


class TestIdentity:
    """A self-signed key pair, in the several shapes the libraries want."""

    def __init__(self, common_name: str, *, timestamping: bool = False) -> None:
        self.common_name = common_name
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        is_ca = not timestamping
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=is_ca,
                    crl_sign=is_ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if timestamping:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=False,
            )
        self._cert = builder.sign(self._key, hashes.SHA256())

    @property
    def cert_der(self) -> bytes:
        """DER bytes, the shape ``verify_pades(extra_trust_roots=...)`` takes."""
        return self._cert.public_bytes(serialization.Encoding.DER)

    @property
    def asn1_cert(self) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(self.cert_der)

    @property
    def _asn1_key(self) -> asn1_keys.PrivateKeyInfo:
        return asn1_keys.PrivateKeyInfo.load(
            self._key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    def pdf_signer(self) -> signers.SimpleSigner:
        return signers.SimpleSigner(
            signing_cert=self.asn1_cert,
            signing_key=self._asn1_key,
            cert_registry=SimpleCertificateStore.from_certs([self.asn1_cert]),
        )

    def timestamper(self) -> DummyTimeStamper:
        return DummyTimeStamper(
            tsa_cert=self.asn1_cert,
            tsa_key=self._asn1_key,
            certs_to_embed=SimpleCertificateStore.from_certs([self.asn1_cert]),
        )


def blank_pdf(text: str = "Test Document") -> bytes:
    """A one-page PDF with a little content — enough to sign."""
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(595, 842))
    page.Contents = pdf.make_stream(
        f"BT /F1 12 Tf 100 700 Td ({text}) Tj ET".encode("ascii")
    )
    buf = BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def attach_evidence_json(pdf_bytes: bytes, evidence_bytes: bytes) -> bytes:
    """Embed ``evidence.json`` as a PDF/A-3 attachment, as KobSign does."""
    with pikepdf.open(BytesIO(pdf_bytes)) as pdf:
        stream = pikepdf.Stream(pdf, evidence_bytes)
        stream["/Type"] = pikepdf.Name("/EmbeddedFile")
        stream["/Subtype"] = pikepdf.Name("/application/json")
        stream["/Params"] = pikepdf.Dictionary({"/Size": len(evidence_bytes)})
        filespec = pikepdf.Dictionary(
            {
                "/Type": pikepdf.Name("/Filespec"),
                "/F": "evidence.json",
                "/UF": "evidence.json",
                "/EF": pikepdf.Dictionary({"/F": pdf.make_indirect(stream)}),
                "/AFRelationship": pikepdf.Name("/Source"),
            }
        )
        pdf.Root["/Names"] = pikepdf.Dictionary(
            {
                "/EmbeddedFiles": pikepdf.Dictionary(
                    {"/Names": pikepdf.Array(["evidence.json", pdf.make_indirect(filespec)])}
                )
            }
        )
        out = BytesIO()
        pdf.save(out)
        return out.getvalue()


def sign(pdf_bytes: bytes, identity: TestIdentity, field_name: str = "Sig1") -> bytes:
    """Apply one approval signature."""
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
    return signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name=field_name),
        signer=identity.pdf_signer(),
    ).getvalue()


def add_second_signature(
    pdf_bytes: bytes, identity: TestIdentity, field_name: str = "Sig2"
) -> bytes:
    """Append a second signer — a legitimate incremental update."""
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
    fields.append_signature_field(
        writer, fields.SigFieldSpec(sig_field_name=field_name, box=(60, 60, 200, 100))
    )
    return signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name=field_name),
        signer=identity.pdf_signer(),
    ).getvalue()


def add_archival_timestamp(
    pdf_bytes: bytes, tsa: TestIdentity, trust_roots: list[asn1_x509.Certificate]
) -> bytes:
    """Append a DocTimeStamp — the incremental update PAdES-LTA is made of."""
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
    validation_context = ValidationContext(
        trust_roots=trust_roots, allow_fetching=False, revocation_mode="soft-fail"
    )
    out = BytesIO()
    signers.PdfTimeStamper(tsa.timestamper()).timestamp_pdf(
        writer, "sha256", validation_context, in_place=False, output=out
    )
    return out.getvalue()


def append_annotation_after_signing(pdf_bytes: bytes) -> bytes:
    """Smuggle content in via a genuine incremental update.

    This is the attack the ``intact`` bit alone does not catch: every byte
    of the signed revision is left exactly as it was, so the signature
    still hashes correctly. The reader sees the last revision; the
    signature covers the first.
    """
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
    page = writer.root["/Pages"]["/Kids"][0].get_object()
    annotation = generic.DictionaryObject(
        {
            generic.pdf_name("/Type"): generic.pdf_name("/Annot"),
            generic.pdf_name("/Subtype"): generic.pdf_name("/Text"),
            generic.pdf_name("/Rect"): generic.ArrayObject(
                [generic.NumberObject(v) for v in (10, 10, 50, 50)]
            ),
            generic.pdf_name("/Contents"): generic.TextStringObject(
                "added after the signature"
            ),
        }
    )
    page[generic.pdf_name("/Annots")] = generic.ArrayObject(
        [writer.add_object(annotation)]
    )
    writer.update_container(page)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def flip_a_byte(pdf_bytes: bytes) -> bytes:
    """Corrupt the signed byte range outright."""
    mutated = bytearray(pdf_bytes)
    middle = len(mutated) // 2
    mutated[middle] ^= 0xFF
    return bytes(mutated)
