"""Video Metadata Sanitizer.

A whitelist-based media sanitizer that eliminates editing history, provenance,
Adobe/Photoshop/Premiere metadata, XMP, C2PA, JUMBF, and file references
while preserving audiovisual streams without re-encoding.
"""

from .models import (
    MediaStreamInfo,
    InspectionResult,
    VerificationResult,
    SanitizeResult,
)
from .sanitizer import sanitize_video, batch_sanitize
from .verifier import verify_video
from .inspector import inspect_video

__version__ = "1.0.0"

__all__ = [
    "MediaStreamInfo",
    "InspectionResult",
    "VerificationResult",
    "SanitizeResult",
    "sanitize_video",
    "batch_sanitize",
    "verify_video",
    "inspect_video",
]
