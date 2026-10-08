#!/usr/bin/env python3
"""clean_video.py — Top-level entrypoint for Lossless Video Metadata & Provenance Sanitizer."""

import sys
from pathlib import Path

# Ensure video_sanitizer is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from video_sanitizer.cli import main

if __name__ == "__main__":
    main()
