"""Orchestrates the lossless video metadata sanitization pipeline."""

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from .inspector import find_tool, inspect_video
from .models import InspectionResult, SanitizeResult, VerificationResult
from .mp4_rebuilder import rebuild_mp4
from .verifier import verify_video


def resolve_collision(
    dest_path: Path, collision_policy: str
) -> Tuple[Optional[Path], bool]:
    """Resolves output filename collisions based on policy:

    - 'rename': adds ' (1)', ' (2)', etc.
    - 'overwrite': overwrites destination
    - 'skip': skips processing
    Returns (resolved_path, should_skip).
    """
    if not dest_path.exists():
        return dest_path, False

    if collision_policy == "skip":
        return None, True

    if collision_policy == "overwrite":
        return dest_path, False

    # Default: rename
    stem = dest_path.stem
    suffix = dest_path.suffix
    parent = dest_path.parent
    counter = 1
    while True:
        candidate = parent / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate, False
        counter += 1


def sanitize_video(
    input_path: Path,
    output_path: Path,
    neutral_timestamp: Optional[int] = None,
    exiftool_path: Optional[str] = None,
) -> SanitizeResult:
    """Sanitizes a single video file without re-encoding:

    1. Inspects input container, streams, and metadata.
    2. Performs lossless stream-copy remuxing via FFmpeg.
    3. Rebuilds container via MP4 rebuilder applying strict box whitelist.
    4. Audits and verifies output with container parser, decoder, and ExifTool.
    5. Atomically delivers clean MP4.
    """
    if not input_path.is_file():
        return SanitizeResult(
            success=False,
            input_path=input_path,
            output_path=output_path,
            message=f"Input file does not exist: {input_path}",
        )

    # 1. Pre-inspection
    before_insp = inspect_video(input_path, exiftool_path=exiftool_path)
    if not before_insp.has_video:
        return SanitizeResult(
            success=False,
            input_path=input_path,
            output_path=output_path,
            message="No video stream detected in input file",
            before_inspection=before_insp,
        )

    temp_dir = output_path.parent
    temp_streamcopy = temp_dir / f".tmp_remux_{output_path.name}"
    temp_clean = temp_dir / f".tmp_clean_{output_path.name}"

    try:
        # 2. Lossless stream copy with FFmpeg
        ffmpeg_exe = find_tool("ffmpeg")
        if not ffmpeg_exe:
            return SanitizeResult(
                success=False,
                input_path=input_path,
                output_path=output_path,
                message="ffmpeg executable not found on system PATH",
                before_inspection=before_insp,
            )

        cmd = [
            ffmpeg_exe,
            "-y",
            "-i",
            str(input_path),
            "-c",
            "copy",
            "-map",
            "0:v:0",
            "-map",
            "0:a?",
            "-map_metadata",
            "-1",
            "-map_chapters",
            "-1",
            "-bitexact",
            str(temp_streamcopy),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return SanitizeResult(
                success=False,
                input_path=input_path,
                output_path=output_path,
                message=f"FFmpeg stream copy remuxing failed: {res.stderr.strip()}",
                before_inspection=before_insp,
            )

        # 3. Controlled MP4 container rebuilding & metadata stripping
        rebuild_ok = rebuild_mp4(
            input_path=temp_streamcopy,
            output_path=temp_clean,
            neutral_timestamp=neutral_timestamp,
        )
        if not rebuild_ok:
            return SanitizeResult(
                success=False,
                input_path=input_path,
                output_path=output_path,
                message="MP4 rebuilder failed to process container",
                before_inspection=before_insp,
            )

        # 4. Independent Verification
        verification = verify_video(
            file_path=temp_clean,
            expected_streams=before_insp.streams,
            expected_duration=before_insp.duration,
            exiftool_path=exiftool_path,
        )

        if not verification.is_clean or not verification.is_valid:
            issue_msg = "; ".join(verification.issues[:3])
            return SanitizeResult(
                success=False,
                input_path=input_path,
                output_path=output_path,
                message=f"Verification failed: {issue_msg}",
                before_inspection=before_insp,
                after_verification=verification,
                re_encoded=False,
            )

        # 5. Atomic file promotion
        if output_path.exists():
            output_path.unlink()
        temp_clean.replace(output_path)

        return SanitizeResult(
            success=True,
            input_path=input_path,
            output_path=output_path,
            message="Metadata and provenance eliminated successfully",
            before_inspection=before_insp,
            after_verification=verification,
            re_encoded=False,
        )

    except Exception as e:
        return SanitizeResult(
            success=False,
            input_path=input_path,
            output_path=output_path,
            message=f"Sanitization error: {str(e)}",
            before_inspection=before_insp,
        )
    finally:
        # Cleanup temporary files
        for p in (temp_streamcopy, temp_clean):
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass


def batch_sanitize(
    input_dir: Path,
    output_dir: Path,
    collision_policy: str = "rename",
    exiftool_path: Optional[str] = None,
    extensions: Tuple[str, ...] = (".mp4", ".mov", ".m4v"),
) -> List[SanitizeResult]:
    """Batch sanitizes all supported video files in a directory."""
    results: List[SanitizeResult] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    target_files = sorted(
        [
            p
            for p in input_dir.iterdir()
            if p.is_file() and p.suffix.lower() in extensions
        ]
    )

    for f in target_files:
        dest_target = output_dir / f"{f.stem}.mp4"
        resolved_dest, should_skip = resolve_collision(dest_target, collision_policy)
        if should_skip or resolved_dest is None:
            results.append(
                SanitizeResult(
                    success=False,
                    input_path=f,
                    output_path=None,
                    message="Skipped (file exists)",
                )
            )
            continue

        res = sanitize_video(
            input_path=f,
            output_path=resolved_dest,
            exiftool_path=exiftool_path,
        )
        results.append(res)

    return results
