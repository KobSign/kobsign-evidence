"""
Extract embedded files (PDF/A-3 attachments) from a signed PDF.

KobSign embeds these attachments in every signed PDF:
    - evidence.json — machine-readable audit trail
    - admissibility.pdf (or admissibility-1.pdf, ...) — human-readable
      legal admissibility report, one per AES signer in multi-signer docs

Reading goes through the ``/Names /EmbeddedFiles`` name tree directly so
it works regardless of which writer produced the PDF.
"""

from __future__ import annotations

import pikepdf


def _iter_name_tree_entries(name_tree):
    """Yield (name_string, filespec) pairs from a PDF name tree.

    The name tree may be flat (a /Names array) or nested (/Kids with
    recursive /Names). We flatten it here — KobSign writes the flat
    form but other writers may produce nested trees.
    """
    if "/Names" in name_tree:
        pairs = name_tree["/Names"]
        for i in range(0, len(pairs), 2):
            yield str(pairs[i]), pairs[i + 1]
    if "/Kids" in name_tree:
        for kid in name_tree["/Kids"]:
            yield from _iter_name_tree_entries(kid)


def _read_embedded_bytes(filespec) -> bytes | None:
    """Pull raw bytes out of a /Filespec dictionary's /EF /F stream."""
    ef = filespec.get("/EF")
    if ef is None:
        return None
    stream = ef.get("/F") or ef.get("/UF")
    if stream is None:
        return None
    return bytes(stream.read_bytes())


def extract_attachment(pdf_path: str, name: str) -> bytes | None:
    """Return the raw bytes of a named PDF/A-3 attachment, or None if absent."""
    with pikepdf.open(pdf_path) as pdf:
        root = pdf.Root
        names = root.get("/Names")
        if names is None:
            return None
        ef_tree = names.get("/EmbeddedFiles")
        if ef_tree is None:
            return None
        for entry_name, filespec in _iter_name_tree_entries(ef_tree):
            if entry_name == name:
                return _read_embedded_bytes(filespec)
    return None


def list_attachments(pdf_path: str) -> list[str]:
    """List all embedded attachment filenames in a PDF (flat, de-duplicated)."""
    names: list[str] = []
    with pikepdf.open(pdf_path) as pdf:
        names_obj = pdf.Root.get("/Names")
        if names_obj is None:
            return names
        ef_tree = names_obj.get("/EmbeddedFiles")
        if ef_tree is None:
            return names
        for entry_name, _ in _iter_name_tree_entries(ef_tree):
            if entry_name not in names:
                names.append(entry_name)
    return names
