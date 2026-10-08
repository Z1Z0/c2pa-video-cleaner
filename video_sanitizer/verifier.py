"""Verification engine for strict container audit, ExifTool inspection, and media integrity."""

import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .c2pa import scan_binary_for_c2pa
from .inspector import find_tool, probe_media_streams
from .metadata import (
    ALLOWED_ROOT_BOXES,
    PROHIBITED_METADATA_STRINGS,
    PROHIBITED_UUIDS,
    is_forbidden_exiftool_tag,
)
from .models import MediaStreamInfo, VerificationResult
from .mp4_rebuilder import parse_raw_boxes


def verify_container_boxes(file_path: Path) -> Tuple[bool, List[str], List[str]]:
    """Strictly audits top-level and container boxes against whitelist.

    Returns (is_clean, issues, box_names).
    """
    issues = []
    box_names = []

    try:
        with open(file_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            flen = f.tell()
            f.seek(0)

            boxes = parse_raw_boxes(f, 0, flen)
            for bt, pos, sz, hsz in boxes:
                bt_str = bt.decode("latin1", errors="replace")
                box_names.append(bt_str)

                # Check root box against whitelist
                if bt not in ALLOWED_ROOT_BOXES:
                    issues.append(f"Detected forbidden root box '{bt_str}' (pos={pos}, size={sz})")

                # If UUID box is detected
                if bt == b"uuid":
                    f.seek(pos + hsz)
                    uuid_val = f.read(16)
                    if uuid_val in PROHIBITED_UUIDS:
                        issues.append(f"Detected forbidden UUID box ({uuid_val.hex()})")

                # If moov box, check children
                if bt == b"moov":
                    f.seek(pos + hsz)
                    moov_raw = f.read(sz - hsz)
                    m_stream = io.BytesIO(moov_raw)
                    m_children = parse_raw_boxes(m_stream, 0, len(moov_raw))
                    for mbt, _, msz, _ in m_children:
                        mbt_str = mbt.decode("latin1", errors="replace")
                        if mbt in (b"udta", b"uuid", b"meta"):
                            issues.append(f"Detected forbidden box 'moov/{mbt_str}' (size={msz})")

    except Exception as e:
        return False, [f"Failed to inspect MP4 boxes: {e}"], []

    return len(issues) == 0, issues, box_names


def verify_decoding(file_path: Path) -> Tuple[bool, List[str]]:
    """Verifies that the video and audio streams decode completely with zero errors."""
    ffmpeg_exe = find_tool("ffmpeg")
    if not ffmpeg_exe:
        return True, []  # Skip if ffmpeg binary unavailable

    cmd = [
        ffmpeg_exe,
        "-v",
        "error",
        "-i",
        str(file_path),
        "-f",
        "null",
        "-",
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            err = res.stderr.strip()
            return False, [f"Playback decoding error: {err}"]
        if res.stderr.strip():
            # Any warning or error on -v error
            return False, [f"Decoder reported warnings/errors: {res.stderr.strip()}"]
    except Exception as e:
        return False, [f"Decoding test exception: {e}"]

    return True, []


def verify_media_integrity(
    orig_streams: List[MediaStreamInfo],
    orig_duration: float,
    clean_streams: List[MediaStreamInfo],
    clean_duration: float,
) -> Tuple[bool, List[str]]:
    """Checks that all video frames, audio channels, durations, and resolutions are preserved."""
    issues = []

    # Check duration (tolerance 0.25s for container/audio packet padding differences)
    if orig_duration > 0 and clean_duration > 0:
        if abs(orig_duration - clean_duration) > 0.25:
            issues.append(
                f"Duration mismatch: original {orig_duration:.2f}s vs cleaned {clean_duration:.2f}s"
            )

    # Video stream check
    orig_v = next((s for s in orig_streams if s.codec_type == "video"), None)
    clean_v = next((s for s in clean_streams if s.codec_type == "video"), None)

    if orig_v:
        if not clean_v:
            issues.append("Missing video stream in sanitized output")
        else:
            if orig_v.codec_name != clean_v.codec_name:
                issues.append(
                    f"Video codec altered: {orig_v.codec_name} -> {clean_v.codec_name}"
                )
            if orig_v.width != clean_v.width or orig_v.height != clean_v.height:
                issues.append(
                    f"Resolution altered: {orig_v.resolution_str} -> {clean_v.resolution_str}"
                )
            if orig_v.frame_rate and clean_v.frame_rate:
                if abs(orig_v.frame_rate - clean_v.frame_rate) > 0.1:
                    issues.append(
                        f"Frame rate altered: {orig_v.frame_rate_str} -> {clean_v.frame_rate_str}"
                    )

    # Audio stream check
    orig_a = next((s for s in orig_streams if s.codec_type == "audio"), None)
    clean_a = next((s for s in clean_streams if s.codec_type == "audio"), None)

    if orig_a:
        if not clean_a:
            issues.append("Missing audio stream in sanitized output")
        else:
            if orig_a.codec_name != clean_a.codec_name:
                issues.append(
                    f"Audio codec altered: {orig_a.codec_name} -> {clean_a.codec_name}"
                )
            if orig_a.channels != clean_a.channels:
                issues.append(
                    f"Audio channels altered: {orig_a.channels} -> {clean_a.channels}"
                )
            if orig_a.sample_rate != clean_a.sample_rate:
                issues.append(
                    f"Audio sample rate altered: {orig_a.sample_rate} -> {clean_a.sample_rate}"
                )

    return len(issues) == 0, issues


def verify_video(
    file_path: Path,
    expected_streams: Optional[List[MediaStreamInfo]] = None,
    expected_duration: Optional[float] = None,
    exiftool_path: Optional[str] = None,
) -> VerificationResult:
    """Performs full automated verification:

    1. Native MP4 container box audit (whitelist enforcement)
    2. Deep binary scan for prohibited C2PA, JUMBF, and editing signatures
    3. Decoding & playability verification via FFmpeg
    4. Stream and media preservation integrity audit
    5. ExifTool audit: zero forbidden metadata tags
    """
    all_issues = []

    # 1. Box structure audit
    box_clean, box_issues, box_names = verify_container_boxes(file_path)
    all_issues.extend(box_issues)

    # 2. Binary scan
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            c2pa_issues = scan_binary_for_c2pa(data)
            all_issues.extend(c2pa_issues)
            lower_d = data.lower()
            for kw in [b"prproj", b"adobe xmp", b"mainconcept"]:
                if kw in lower_d:
                    all_issues.append(f"Binary contains prohibited string '{kw.decode()}'")
    except Exception as e:
        all_issues.append(f"Failed to scan binary data: {e}")

    # 3. Decoding check
    dec_clean, dec_issues = verify_decoding(file_path)
    all_issues.extend(dec_issues)

    # 4. Stream integrity check
    duration, _, streams = probe_media_streams(file_path)
    integrity_clean = True
    if expected_streams is not None and expected_duration is not None:
        integrity_clean, integ_issues = verify_media_integrity(
            expected_streams, expected_duration, streams, duration
        )
        all_issues.extend(integ_issues)

    # 5. ExifTool verification
    exiftool_exe = find_tool("exiftool", exiftool_path)
    exiftool_tags: Dict[str, Any] = {}
    if exiftool_exe:
        try:
            cmd = [
                exiftool_exe,
                "-json",
                "-G",
                "-a",
                "-u",
                "-s",
                str(file_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            tags_list = json.loads(res.stdout)
            if tags_list:
                exiftool_tags = tags_list[0]
                for k, v in exiftool_tags.items():
                    is_forbid, reason = is_forbidden_exiftool_tag(k, v)
                    if is_forbid:
                        all_issues.append(f"ExifTool detected forbidden tag: {reason}")
        except Exception as e:
            all_issues.append(f"ExifTool execution failure: {e}")

    is_clean = len(all_issues) == 0
    is_valid = dec_clean and box_clean

    return VerificationResult(
        is_valid=is_valid,
        is_clean=is_clean,
        media_integrity_passed=integrity_clean,
        decoding_passed=dec_clean,
        issues=all_issues,
        exiftool_tags=exiftool_tags,
        streams=streams,
        duration=duration,
        container_boxes=box_names,
    )
