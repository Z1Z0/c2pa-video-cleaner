"""Unit tests for verifier module."""

from video_sanitizer.metadata import is_forbidden_exiftool_tag
from video_sanitizer.verifier import verify_media_integrity
from video_sanitizer.models import MediaStreamInfo


def test_is_forbidden_exiftool_tag():
    # Technical tags should be allowed
    bad, _ = is_forbidden_exiftool_tag("File:MIMEType", "video/mp4")
    assert bad is False

    bad, _ = is_forbidden_exiftool_tag("QuickTime:MajorBrand", "MP4 Base Media v1")
    assert bad is False

    bad, _ = is_forbidden_exiftool_tag("Track1:VideoFrameRate", 24)
    assert bad is False

    # Forbidden tags should be flagged
    bad, _ = is_forbidden_exiftool_tag("XMP-xmp:CreatorTool", "Adobe Premiere Pro")
    assert bad is True

    bad, _ = is_forbidden_exiftool_tag("QuickTime:UserData", "Some data")
    assert bad is True

    bad, _ = is_forbidden_exiftool_tag("Track1:HandlerDescription", "Adobe Premiere")
    assert bad is True

    bad, _ = is_forbidden_exiftool_tag("QuickTime:Description", "gemini_generated_video.mp4")
    assert bad is True


def test_verify_media_integrity():
    stream1 = [
        MediaStreamInfo(index=0, codec_type="video", codec_name="h264", codec_tag="avc1", width=1280, height=720, frame_rate=30.0),
        MediaStreamInfo(index=1, codec_type="audio", codec_name="aac", codec_tag="mp4a", sample_rate=48000, channels=2),
    ]
    stream2 = [
        MediaStreamInfo(index=0, codec_type="video", codec_name="h264", codec_tag="avc1", width=1280, height=720, frame_rate=30.0),
        MediaStreamInfo(index=1, codec_type="audio", codec_name="aac", codec_tag="mp4a", sample_rate=48000, channels=2),
    ]

    ok, issues = verify_media_integrity(stream1, 10.0, stream2, 10.0)
    assert ok is True
    assert len(issues) == 0

    # Modify codec in clean stream
    stream2_bad = [
        MediaStreamInfo(index=0, codec_type="video", codec_name="hevc", codec_tag="hvc1", width=1280, height=720, frame_rate=30.0),
    ]
    ok, issues = verify_media_integrity(stream1, 10.0, stream2_bad, 10.0)
    assert ok is False
    assert len(issues) > 0
