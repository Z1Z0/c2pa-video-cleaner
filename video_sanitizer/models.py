"""Data models for video metadata sanitization, inspection, and verification."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MediaStreamInfo:
    """Represents technical audio or video stream attributes."""

    index: int
    codec_type: str  # 'video' or 'audio'
    codec_name: str  # 'h264', 'aac', etc.
    codec_tag: str  # 'avc1', 'mp4a', etc.
    profile: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    sample_rate: Optional[int] = None
    channels: Optional[int] = None
    duration: Optional[float] = None
    bit_rate: Optional[int] = None
    color_primaries: Optional[str] = None
    color_transfer: Optional[str] = None
    color_space: Optional[str] = None
    color_range: Optional[str] = None

    @property
    def resolution_str(self) -> str:
        if self.width and self.height:
            return f"{self.width}x{self.height}"
        return "N/A"

    @property
    def frame_rate_str(self) -> str:
        if self.frame_rate is not None:
            return f"{self.frame_rate:.2f}".rstrip("0").rstrip(".")
        return "N/A"

    @property
    def sample_rate_str(self) -> str:
        if self.sample_rate:
            return f"{self.sample_rate} Hz"
        return "N/A"


@dataclass
class InspectionResult:
    """Represents pre-sanitization findings on container and streams."""

    file_path: Path
    file_size: int
    format_name: str
    duration: float
    streams: List[MediaStreamInfo] = field(default_factory=list)
    has_video: bool = False
    has_audio: bool = False
    has_xmp: bool = False
    has_c2pa: bool = False
    has_adobe: bool = False
    has_premiere: bool = False
    has_photoshop: bool = False
    has_source_references: bool = False
    has_ai_references: bool = False
    metadata_tags_count: int = 0
    forbidden_tags: List[str] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    box_types_found: List[str] = field(default_factory=list)

    @property
    def video_stream(self) -> Optional[MediaStreamInfo]:
        for s in self.streams:
            if s.codec_type == "video":
                return s
        return None

    @property
    def audio_stream(self) -> Optional[MediaStreamInfo]:
        for s in self.streams:
            if s.codec_type == "audio":
                return s
        return None


@dataclass
class VerificationResult:
    """Represents post-sanitization audit and integrity results."""

    is_valid: bool = False
    is_clean: bool = False
    media_integrity_passed: bool = False
    decoding_passed: bool = False
    issues: List[str] = field(default_factory=list)
    exiftool_tags: Dict[str, Any] = field(default_factory=dict)
    streams: List[MediaStreamInfo] = field(default_factory=list)
    duration: float = 0.0
    container_boxes: List[str] = field(default_factory=list)

    @property
    def video_stream(self) -> Optional[MediaStreamInfo]:
        for s in self.streams:
            if s.codec_type == "video":
                return s
        return None

    @property
    def audio_stream(self) -> Optional[MediaStreamInfo]:
        for s in self.streams:
            if s.codec_type == "audio":
                return s
        return None


@dataclass
class SanitizeResult:
    """Overall outcome of a video sanitization run."""

    success: bool
    input_path: Path
    output_path: Optional[Path] = None
    message: str = ""
    before_inspection: Optional[InspectionResult] = None
    after_verification: Optional[VerificationResult] = None
    re_encoded: bool = False
