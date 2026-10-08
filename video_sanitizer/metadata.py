"""Metadata rules, box whitelists, and forbidden term definitions."""

import time
from typing import Any, Optional, Set, Tuple

# MP4 Epoch offset: Seconds between 1904-01-01 00:00:00 UTC and 1970-01-01 00:00:00 UTC
MP4_EPOCH_OFFSET = 2082844800

# Strict Box Whitelists by Hierarchy Level (Whitelisting approach)
ALLOWED_ROOT_BOXES: Set[bytes] = {
    b"ftyp",
    b"moov",
    b"mdat",
}

ALLOWED_MOOV_BOXES: Set[bytes] = {
    b"mvhd",
    b"trak",
}

ALLOWED_TRAK_BOXES: Set[bytes] = {
    b"tkhd",
    b"edts",
    b"mdia",
}

ALLOWED_EDTS_BOXES: Set[bytes] = {
    b"elst",
}

ALLOWED_MDIA_BOXES: Set[bytes] = {
    b"mdhd",
    b"hdlr",
    b"minf",
}

ALLOWED_MINF_BOXES: Set[bytes] = {
    b"vmhd",
    b"smhd",
    b"dinf",
    b"stbl",
}

ALLOWED_DINF_BOXES: Set[bytes] = {
    b"dref",
}

ALLOWED_STBL_BOXES: Set[bytes] = {
    b"stsd",
    b"stts",
    b"ctts",
    b"cslg",
    b"stss",
    b"sdtp",
    b"stsc",
    b"stsz",
    b"stco",
    b"co64",
    b"sgpd",
    b"sbgp",
}

ALLOWED_VISUAL_SAMPLE_BOXES: Set[bytes] = {
    b"avcC",
    b"hvcC",
    b"vpcC",
    b"av1C",
    b"colr",
    b"pasp",
    b"btrt",
}

ALLOWED_AUDIO_SAMPLE_BOXES: Set[bytes] = {
    b"esds",
    b"wave",
    b"btrt",
    b"dOps",
}

# Known Prohibited UUIDs in MP4 files
PROHIBITED_UUIDS: Set[bytes] = {
    # Standard Adobe XMP UUID: be7acfcb-97a9-42e8-9c71-999491e3afac
    bytes.fromhex("be7acfcb97a942e89c71999491e3afac"),
    # Standard C2PA UUID: d8fec3d6-1b0e-483c-9297-5828877aae48
    bytes.fromhex("d8fec3d61b0e483c92975828877aae48"),
}

# Prohibited binary terms and signatures in container headers / metadata
PROHIBITED_METADATA_STRINGS = [
    "xmp",
    "c2pa",
    "jumbf",
    "manifest",
    "assertion",
    "claim",
    "ingredient",
    "pantry",
    "history",
    "provenance",
    "instance",
    "documentid",
    "derivedfrom",
    "project",
    "adobe",
    "premiere",
    "photoshop",
    "aftereffects",
    "mediaencoder",
    "davinci",
    "finalcut",
    "capcut",
    "filmora",
    "canva",
    "digitalsource",
    "generative",
    "synthid",
    "gemini",
    "prproj",
    "windowsatom",
    "macatom",
    "creatortool",
    "metadatadate",
    "softwareagent",
    "lavf",
]

# ExifTool Whitelisted technical tags that are expected and required for playback/format
ALLOWED_TECHNICAL_TAG_PREFIXES = (
    "ExifTool:",
    "System:",
    "File:",
    "Composite:",
)


def get_neutral_mp4_timestamp(reference_time: Optional[float] = None) -> int:
    """Returns a fresh neutral timestamp in MP4 epoch seconds (since 1904-01-01).

    If reference_time is None, uses current time.
    """
    unix_time = reference_time if reference_time is not None else time.time()
    return int(unix_time) + MP4_EPOCH_OFFSET


def is_forbidden_exiftool_tag(tag_key: str, tag_val: Any) -> Tuple[bool, str]:
    """Inspects an ExifTool tag key and value against forbidden provenance/editing terms.

    Returns (is_forbidden, reason).
    """
    k_lower = tag_key.lower()
    val_str = str(tag_val).lower()

    # Disallow entire XMP family tags
    if tag_key.startswith("XMP"):
        return True, f"XMP metadata tag present: {tag_key}"

    # Disallow UserData / QuickTime metadata with editing or software tags
    if "userdata" in k_lower or "itemlist" in k_lower:
        return True, f"UserData / ItemList metadata tag present: {tag_key}"

    # Filesystem tags representing the physical file being inspected
    fs_file_tags = (
        "sourcefile",
        "file:filename",
        "system:filename",
        "file:directory",
        "system:directory",
        "file:filepath",
        "system:filepath",
    )

    # Check key and value for prohibited terms
    for term in PROHIBITED_METADATA_STRINGS:
        if term in k_lower:
            return True, f"Tag key contains prohibited term '{term}': {tag_key}"
        # Check tag value for prohibited term, unless it is the physical file path tag itself
        if k_lower not in fs_file_tags:
            if term in val_str:
                return True, f"Tag value in {tag_key} contains prohibited term '{term}': {tag_val}"

    # Check for file paths or project extensions in tag values (outside physical file tags)
    if k_lower not in fs_file_tags:
        if any(ext in val_str for ext in [".prproj", ".psd", ".aep", "\\nouwaar\\"]):
            return True, f"Tag {tag_key} contains local project/file path: {tag_val}"

    return False, ""
