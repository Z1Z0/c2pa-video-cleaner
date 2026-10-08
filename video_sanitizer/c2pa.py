"""Detection and validation utilities for C2PA, Content Credentials, and JUMBF provenance."""

from pathlib import Path
from typing import List, Tuple, Union

# Official standard C2PA UUID (16 bytes)
C2PA_UUID_BYTES = bytes.fromhex("d8fec3d61b0e483c92975828877aae48")

# Prohibited C2PA & Generative AI binary signatures
PROHIBITED_C2PA_TERMS = [
    b"c2pa",
    b"jumbf",
    b"jumd",
    b"c2cl",
    b"c2as",
    b"application/c2pa",
    b"claim generator",
    b"claim_generator",
    b"digital source type",
    b"digitalsourcetype",
    b"trainedalgorithmicmedia",
    b"google generative ai",
    b"google synthetic",
    b"synthid",
    b"urn:c2pa",
    b"c2pa.manifest",
    b"c2pa.claim",
    b"c2pa.opened",
    b"c2pa.resized",
    C2PA_UUID_BYTES,
]


def scan_binary_for_c2pa(data: bytes) -> List[str]:
    """Scans binary data for any C2PA, JUMBF, or AI provenance markers."""
    detected = []
    lower_data = data.lower()
    for term in PROHIBITED_C2PA_TERMS:
        if term == C2PA_UUID_BYTES:
            if C2PA_UUID_BYTES in data:
                detected.append("Standard C2PA UUID (d8fec3d6-1b0e-483c-9297-5828877aae48)")
        else:
            if term in lower_data:
                term_str = term.decode("latin1", errors="replace")
                detected.append(f"C2PA provenance term '{term_str}'")
    return detected


def verify_no_c2pa(target: Union[Path, bytes]) -> Tuple[bool, List[str]]:
    """Verifies that the target file or bytes contain no C2PA manifests or provenance.

    Returns (is_clean, issues).
    """
    if isinstance(target, Path):
        try:
            with open(target, "rb") as f:
                data = f.read()
        except Exception as e:
            return False, [f"Failed to read file for C2PA check: {e}"]
    else:
        data = target

    issues = scan_binary_for_c2pa(data)
    return len(issues) == 0, issues
