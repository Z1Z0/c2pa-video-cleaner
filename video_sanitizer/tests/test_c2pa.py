"""Unit tests for C2PA and provenance detection."""

from video_sanitizer.c2pa import C2PA_UUID_BYTES, scan_binary_for_c2pa, verify_no_c2pa


def test_scan_binary_for_c2pa_clean():
    clean_data = b"Some innocent video binary data with no provenance tags."
    issues = scan_binary_for_c2pa(clean_data)
    assert len(issues) == 0


def test_scan_binary_for_c2pa_detected():
    bad_data = b"prefix " + C2PA_UUID_BYTES + b" suffix c2pa.manifest application/c2pa"
    issues = scan_binary_for_c2pa(bad_data)
    assert len(issues) >= 3


def test_verify_no_c2pa():
    clean = b"\x00\x00\x00\x1cftypisom"
    ok, issues = verify_no_c2pa(clean)
    assert ok is True
    assert len(issues) == 0

    dirty = b"\x00\x00\x00\x28uuid" + C2PA_UUID_BYTES
    ok, issues = verify_no_c2pa(dirty)
    assert ok is False
    assert len(issues) > 0
