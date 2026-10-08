"""Inspection module for probing container structures, media streams, and metadata."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .c2pa import scan_binary_for_c2pa
from .metadata import is_forbidden_exiftool_tag
from .models import InspectionResult, MediaStreamInfo
from .mp4_rebuilder import parse_raw_boxes


def find_tool(tool_name: str, explicit_path: Optional[str] = None) -> Optional[str]:
    """Finds an executable tool on system PATH, script directory, or common locations."""
    if explicit_path and os.path.isfile(explicit_path):
        return explicit_path

    found = shutil.which(tool_name) or shutil.which(f"{tool_name}.exe")
    if found and os.path.isfile(found):
        return found

    # Script directory & workspace
    script_dir = Path(__file__).resolve().parent.parent
    for candidate in [
        script_dir / f"{tool_name}.exe",
        script_dir / tool_name,
        Path.cwd() / f"{tool_name}.exe",
        Path(r"D:\Projects\Video metadata sanitization") / f"{tool_name}.exe",
        Path(r"D:\Projects\metadata sanitization") / f"{tool_name}.exe",
    ]:
        if candidate.is_file():
            return str(candidate)

    return None


def probe_media_streams(file_path: Path) -> Tuple[float, str, List[MediaStreamInfo]]:
    """Probes audiovisual streams using ffprobe."""
    ffprobe_exe = find_tool("ffprobe")
    if not ffprobe_exe:
        return 0.0, "unknown", []

    cmd = [
        ffprobe_exe,
        "-v",
        "quiet",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        str(file_path),
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
    except Exception:
        return 0.0, "unknown", []

    format_data = data.get("format", {})
    duration = float(format_data.get("duration", 0.0))
    format_name = format_data.get("format_name", "mp4")

    streams = []
    for s in data.get("streams", []):
        ctype = s.get("codec_type")
        if ctype not in ("video", "audio"):
            continue

        cname = s.get("codec_name", "")
        ctag = s.get("codec_tag_string", "")
        idx = int(s.get("index", 0))

        # Parse frame rate
        fps = None
        r_fps = s.get("r_frame_rate", "")
        if "/" in r_fps:
            num, den = r_fps.split("/")
            if float(den) > 0:
                fps = float(num) / float(den)

        # Parse duration
        st_duration = None
        if "duration" in s:
            try:
                st_duration = float(s["duration"])
            except (ValueError, TypeError):
                st_duration = duration

        # Parse bit rate
        bit_rate = None
        if "bit_rate" in s:
            try:
                bit_rate = int(s["bit_rate"])
            except (ValueError, TypeError):
                pass

        stream_info = MediaStreamInfo(
            index=idx,
            codec_type=ctype,
            codec_name=cname,
            codec_tag=ctag,
            profile=s.get("profile"),
            width=int(s["width"]) if "width" in s else None,
            height=int(s["height"]) if "height" in s else None,
            frame_rate=fps,
            sample_rate=int(s["sample_rate"]) if "sample_rate" in s else None,
            channels=int(s["channels"]) if "channels" in s else None,
            duration=st_duration,
            bit_rate=bit_rate,
            color_primaries=s.get("color_primaries"),
            color_transfer=s.get("color_transfer"),
            color_space=s.get("color_space"),
            color_range=s.get("color_range"),
        )
        streams.append(stream_info)

    return duration, format_name, streams


def inspect_video(
    file_path: Path, exiftool_path: Optional[str] = None
) -> InspectionResult:
    """Performs deep pre-sanitization inspection of video file."""
    duration, fmt_name, streams = probe_media_streams(file_path)

    has_video = any(s.codec_type == "video" for s in streams)
    has_audio = any(s.codec_type == "audio" for s in streams)

    # Inspect native top-level boxes
    box_types = []
    has_uuid = False
    try:
        with open(file_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            flen = f.tell()
            f.seek(0)
            boxes = parse_raw_boxes(f, 0, flen)
            for bt, _, _, _ in boxes:
                bt_str = bt.decode("latin1", errors="replace")
                box_types.append(bt_str)
                if bt == b"uuid":
                    has_uuid = True
    except Exception:
        pass

    # ExifTool inspection
    exiftool_exe = find_tool("exiftool", exiftool_path)
    raw_meta: Dict[str, Any] = {}
    forbidden_tags: List[str] = []
    has_xmp = False
    has_c2pa = False
    has_adobe = False
    has_premiere = False
    has_photoshop = False
    has_source_references = False
    has_ai_references = False

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
                raw_meta = tags_list[0]
                for k, v in raw_meta.items():
                    k_lower = k.lower()
                    v_str = str(v).lower()

                    if k.startswith("XMP") or "xmp" in k_lower or "xmp" in v_str:
                        has_xmp = True
                    if "c2pa" in k_lower or "c2pa" in v_str or "jumbf" in v_str:
                        has_c2pa = True
                    if "adobe" in k_lower or "adobe" in v_str:
                        has_adobe = True
                    if "premiere" in k_lower or "premiere" in v_str:
                        has_premiere = True
                    if "photoshop" in k_lower or "photoshop" in v_str:
                        has_photoshop = True
                    if any(
                        p in v_str
                        for p in [".prproj", ".psd", "gemini_generated", "\\videos\\"]
                    ):
                        has_source_references = True
                    if any(
                        ai in v_str
                        for ai in ["gemini", "synthid", "generative ai", "generative"]
                    ):
                        has_ai_references = True

                    is_forbid, _ = is_forbidden_exiftool_tag(k, v)
                    if is_forbid:
                        forbidden_tags.append(f"{k} = {v}")
        except Exception:
            pass

    # Binary check fallback
    try:
        with open(file_path, "rb") as f:
            sample = f.read(1024 * 1024)
            c2pa_issues = scan_binary_for_c2pa(sample)
            if c2pa_issues:
                has_c2pa = True
    except Exception:
        pass

    file_size = file_path.stat().st_size if file_path.exists() else 0

    return InspectionResult(
        file_path=file_path,
        file_size=file_size,
        format_name=fmt_name,
        duration=duration,
        streams=streams,
        has_video=has_video,
        has_audio=has_audio,
        has_xmp=has_xmp,
        has_c2pa=has_c2pa,
        has_adobe=has_adobe,
        has_premiere=has_premiere,
        has_photoshop=has_photoshop,
        has_source_references=has_source_references,
        has_ai_references=has_ai_references,
        metadata_tags_count=len(raw_meta),
        forbidden_tags=forbidden_tags,
        raw_metadata=raw_meta,
        box_types_found=box_types,
    )
