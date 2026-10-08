"""Unit tests for models and formatting helpers."""

from pathlib import Path
from video_sanitizer.models import MediaStreamInfo, InspectionResult, VerificationResult, SanitizeResult


def test_media_stream_info():
    v = MediaStreamInfo(
        index=0,
        codec_type="video",
        codec_name="h264",
        codec_tag="avc1",
        width=1920,
        height=1080,
        frame_rate=23.976,
    )
    assert v.resolution_str == "1920x1080"
    assert "23.98" in v.frame_rate_str

    a = MediaStreamInfo(
        index=1,
        codec_type="audio",
        codec_name="aac",
        codec_tag="mp4a",
        sample_rate=48000,
        channels=2,
    )
    assert a.sample_rate_str == "48000 Hz"


def test_inspection_result_helpers():
    insp = InspectionResult(
        file_path=Path("test.mp4"),
        file_size=1024,
        format_name="mov,mp4",
        duration=10.0,
        streams=[
            MediaStreamInfo(index=0, codec_type="video", codec_name="h264", codec_tag="avc1"),
            MediaStreamInfo(index=1, codec_type="audio", codec_name="aac", codec_tag="mp4a"),
        ],
    )
    assert insp.video_stream is not None
    assert insp.video_stream.codec_name == "h264"
    assert insp.audio_stream is not None
    assert insp.audio_stream.codec_name == "aac"
