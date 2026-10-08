"""End-to-end integration tests for video sanitization using the primary test case."""

from pathlib import Path
import pytest
from video_sanitizer.sanitizer import sanitize_video

PRIMARY_TEST_FILE = Path(r"D:\Nouwaar\Videos\azureplume01.mp4")


@pytest.mark.skipif(not PRIMARY_TEST_FILE.exists(), reason="Primary test video not found on disk")
def test_sanitize_primary_video(tmp_path):
    out_file = tmp_path / "sanitized_azureplume01.mp4"

    res = sanitize_video(
        input_path=PRIMARY_TEST_FILE,
        output_path=out_file,
    )

    # 1. Pipeline success
    assert res.success is True, f"Sanitization failed: {res.message}"
    assert out_file.exists()
    assert out_file.stat().st_size > 0

    # 2. Before Inspection Audit
    before = res.before_inspection
    assert before is not None
    assert before.has_xmp is True
    assert before.has_adobe is True
    assert before.has_premiere is True
    assert before.has_photoshop is True
    assert before.has_source_references is True

    # 3. After Verification Audit
    after = res.after_verification
    assert after is not None
    assert after.is_valid is True
    assert after.is_clean is True
    assert after.decoding_passed is True
    assert after.media_integrity_passed is True
    assert len(after.issues) == 0

    # 4. Container Structure Audit
    assert after.container_boxes == ["ftyp", "moov", "mdat"]

    # 5. Media Integrity
    assert res.re_encoded is False
    assert after.video_stream is not None
    assert after.video_stream.codec_name == "h264"
    assert after.video_stream.width == 720
    assert after.video_stream.height == 1280
    assert after.audio_stream is not None
    assert after.audio_stream.codec_name == "aac"
    assert after.audio_stream.channels == 2
    assert after.audio_stream.sample_rate == 48000
