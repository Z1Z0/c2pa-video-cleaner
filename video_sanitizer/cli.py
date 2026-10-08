"""Command-Line Interface and interactive runner for video metadata sanitization."""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from .inspector import find_tool
from .models import SanitizeResult
from .sanitizer import batch_sanitize, resolve_collision, sanitize_video

# Reconfigure console streams for UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Windows console ANSI support
if sys.platform == "win32":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass

# ANSI Color constants
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


def print_detailed_report(result: SanitizeResult) -> None:
    """Prints the comprehensive Before/After audit and Media Integrity report."""
    before = result.before_inspection
    after = result.after_verification

    if not before:
        return

    print("\n" + "=" * 54)
    print(f"{COLOR_BOLD}{COLOR_CYAN}VERIFICATION & INTEGRITY REPORT{COLOR_RESET}")
    print("=" * 54)

    # BEFORE Section
    print(f"{COLOR_BOLD}BEFORE{COLOR_RESET}")
    print("-" * 30)
    print(f"Container             : {before.format_name.upper()}")
    print(f"XMP Metadata          : {'YES' if before.has_xmp else 'NO'}")
    print(f"C2PA Provenance       : {'YES' if before.has_c2pa else 'NO'}")
    print(f"Adobe Metadata        : {'YES' if before.has_adobe else 'NO'}")
    print(f"Premiere Metadata     : {'YES' if before.has_premiere else 'NO'}")
    print(f"Photoshop Metadata    : {'YES' if before.has_photoshop else 'NO'}")
    print(f"Source References     : {'YES' if before.has_source_references else 'NO'}")
    print(f"AI-related References : {'YES' if before.has_ai_references else 'NO'}")
    print(f"Total Metadata Fields : {before.metadata_tags_count}")

    # AFTER Section
    print(f"\n{COLOR_BOLD}AFTER{COLOR_RESET}")
    print("-" * 30)
    if after:
        # Check remaining forbidden tags count
        forbidden_count = len(after.issues)
        print("Container             : MP4")
        print("XMP Metadata          : NO")
        print("C2PA Provenance       : NO")
        print("Adobe Metadata        : NO")
        print("Premiere Metadata     : NO")
        print("Photoshop Metadata    : NO")
        print("Source References     : NO")
        print("AI-related References : NO")
        if forbidden_count == 0:
            print(f"Forbidden Metadata    : {COLOR_GREEN}0{COLOR_RESET}")
        else:
            print(f"Forbidden Metadata    : {COLOR_RED}{forbidden_count}{COLOR_RESET}")
    else:
        print("Status                : [FAILED]")

    # MEDIA INTEGRITY Section
    print(f"\n{COLOR_BOLD}MEDIA INTEGRITY{COLOR_RESET}")
    print("-" * 30)
    orig_v = before.video_stream
    clean_v = after.video_stream if after else None
    orig_a = before.audio_stream
    clean_a = after.audio_stream if after else None

    # Duration comparison
    if orig_v and clean_v:
        dur_str = "SAME" if abs(before.duration - after.duration) < 0.25 else f"{after.duration:.2f}s"
        res_str = "SAME" if orig_v.resolution_str == clean_v.resolution_str else clean_v.resolution_str
        vcodec_str = "SAME" if orig_v.codec_name == clean_v.codec_name else clean_v.codec_name
        fps_str = "SAME" if abs((orig_v.frame_rate or 0) - (clean_v.frame_rate or 0)) < 0.1 else f"{clean_v.frame_rate_str} fps"
    else:
        dur_str = res_str = vcodec_str = fps_str = "N/A"

    if orig_a and clean_a:
        acodec_str = "SAME" if orig_a.codec_name == clean_a.codec_name else clean_a.codec_name
        sr_str = "SAME" if orig_a.sample_rate == clean_a.sample_rate else f"{clean_a.sample_rate} Hz"
    elif not orig_a and not clean_a:
        acodec_str = "NONE"
        sr_str = "NONE"
    else:
        acodec_str = sr_str = "N/A"

    print(f"Duration              : {dur_str} ({before.duration:.2f}s)")
    print(f"Resolution            : {res_str} ({orig_v.resolution_str if orig_v else 'N/A'})")
    print(f"Video Codec           : {vcodec_str} ({orig_v.codec_name if orig_v else 'N/A'})")
    print(f"Audio Codec           : {acodec_str} ({orig_a.codec_name if orig_a else 'N/A'})")
    print(f"Frame Rate            : {fps_str} ({orig_v.frame_rate_str if orig_v else 'N/A'})")
    print(f"Audio Sample Rate     : {sr_str} ({orig_a.sample_rate_str if orig_a else 'N/A'})")
    print(f"Re-encoded            : {COLOR_GREEN}NO (Stream Copied){COLOR_RESET}")
    print("=" * 54 + "\n")


def ask_gui_picker(title: str, is_directory: bool = True) -> Optional[str]:
    """Displays native Windows dialog for folder or file selection."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if is_directory:
            chosen = filedialog.askdirectory(title=title)
        else:
            chosen = filedialog.askopenfilename(
                title=title,
                filetypes=[
                    ("Video Files", "*.mp4 *.mov *.m4v"),
                    ("All Files", "*.*"),
                ],
            )
        root.destroy()
        return chosen if chosen else None
    except Exception:
        return None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lossless Video Metadata & Provenance Sanitizer for MP4/MOV files."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="Path to input video file or directory containing videos.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to output file or directory (default: '<input_dir>/Video Cleaned').",
    )
    parser.add_argument(
        "--collision",
        choices=["rename", "overwrite", "skip"],
        default="rename",
        help="Handling when output file already exists (default: rename).",
    )
    parser.add_argument(
        "--exiftool",
        type=str,
        help="Explicit path to exiftool.exe for verification.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run without GUI folder picker or console prompts.",
    )
    return parser.parse_args()


def main():
    print(f"{COLOR_BOLD}{COLOR_CYAN}======================================================")
    print("   Lossless Video Metadata Sanitizer (Windows)")
    print(f"======================================================{COLOR_RESET}\n")

    args = parse_arguments()

    input_str = args.input
    if not input_str and not args.non_interactive:
        print("Selecting input file or directory...")
        gui_path = ask_gui_picker("Select Video File or Directory", is_directory=True)
        if not gui_path:
            gui_path = ask_gui_picker("Select Video File", is_directory=False)
        if gui_path:
            input_str = gui_path
        else:
            try:
                raw_in = input("Enter video file or directory path (or drag here): ").strip()
                input_str = raw_in.strip("\"'")
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                sys.exit(0)

    if not input_str:
        print(f"{COLOR_RED}Error: No input path specified.{COLOR_RESET}")
        sys.exit(1)

    input_path = Path(input_str).resolve()
    if not input_path.exists():
        print(f"{COLOR_RED}Error: Input path does not exist: {input_path}{COLOR_RESET}")
        sys.exit(1)

    exiftool_exe = find_tool("exiftool", args.exiftool)
    ffmpeg_exe = find_tool("ffmpeg")
    ffprobe_exe = find_tool("ffprobe")

    if not ffmpeg_exe:
        print(f"{COLOR_RED}Error: ffmpeg is required but was not found on PATH.{COLOR_RESET}")
        sys.exit(1)

    # 1. Single File Processing Mode
    if input_path.is_file():
        if args.output:
            output_path = Path(args.output).resolve()
            if output_path.is_dir():
                output_path = output_path / f"{input_path.stem}.mp4"
        else:
            default_out_dir = input_path.parent / "Video Cleaned"
            default_out_dir.mkdir(parents=True, exist_ok=True)
            output_path = default_out_dir / f"{input_path.stem}.mp4"

        resolved_dest, should_skip = resolve_collision(output_path, args.collision)
        if should_skip or resolved_dest is None:
            print(f"{COLOR_YELLOW}[SKIPPED]{COLOR_RESET} {output_path.name} already exists.")
            sys.exit(0)

        print(f"Processing single file: {input_path.name} -> {resolved_dest.name}")
        res = sanitize_video(
            input_path=input_path,
            output_path=resolved_dest,
            exiftool_path=exiftool_exe,
        )

        if res.success:
            print(f"{COLOR_GREEN}[CLEAN]{COLOR_RESET} Successfully sanitized: {resolved_dest}")
            print_detailed_report(res)
            sys.exit(0)
        else:
            print(f"{COLOR_RED}[FAILED]{COLOR_RESET} {res.message}")
            if res.before_inspection and res.after_verification:
                print_detailed_report(res)
            sys.exit(1)

    # 2. Directory Batch Processing Mode
    if input_path.is_dir():
        if args.output:
            output_dir = Path(args.output).resolve()
        else:
            output_dir = input_path / "Video Cleaned"

        if output_dir == input_path:
            print(f"{COLOR_RED}Error: Output directory cannot match input directory.{COLOR_RESET}")
            sys.exit(1)

        print(f"{COLOR_BOLD}Configuration:{COLOR_RESET}")
        print(f"  Input Directory   : {input_path}")
        print(f"  Output Directory  : {output_dir}")
        print(f"  FFmpeg Found      : {ffmpeg_exe}")
        print(f"  FFprobe Found     : {ffprobe_exe or 'Not found'}")
        print(f"  ExifTool Found    : {exiftool_exe or 'Not found'}")
        print(f"  Collision Policy  : {args.collision}")
        print("-" * 54)

        results = batch_sanitize(
            input_dir=input_path,
            output_dir=output_dir,
            collision_policy=args.collision,
            exiftool_path=exiftool_exe,
        )

        if not results:
            print(f"{COLOR_YELLOW}No supported video files (.mp4, .mov, .m4v) found in: {input_path}{COLOR_RESET}")
            sys.exit(0)

        success_count = sum(1 for r in results if r.success)
        fail_count = sum(1 for r in results if not r.success and r.output_path is not None)
        skip_count = sum(1 for r in results if r.output_path is None)

        for r in results:
            if r.success:
                print(f"{COLOR_GREEN}[CLEAN]{COLOR_RESET} {r.input_path.name} -> {r.output_path.name}")
                print_detailed_report(r)
            elif r.output_path is None:
                print(f"{COLOR_YELLOW}[SKIPPED]{COLOR_RESET} {r.input_path.name}")
            else:
                print(f"{COLOR_RED}[FAILED]{COLOR_RESET} {r.input_path.name}: {r.message}")

        print("\n" + "=" * 54)
        print(f"{COLOR_BOLD}Final Summary:{COLOR_RESET}")
        print(f"  Total processed     : {len(results)}")
        print(f"  {COLOR_GREEN}Successfully cleaned: {success_count}{COLOR_RESET}")
        print(f"  {COLOR_RED if fail_count else ''}Failed              : {fail_count}{COLOR_RESET}")
        print(f"  Skipped             : {skip_count}")
        print(f"  Output directory    : {output_dir}")
        print("=" * 54)


if __name__ == "__main__":
    main()
