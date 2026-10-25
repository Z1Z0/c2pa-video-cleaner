# C2PA Video Cleaner & Metadata Stripper

A cross-platform (Windows, Linux, macOS), high-performance media sanitization utility and container-rebuilding engine engineered to eliminate all C2PA manifests, Content Credentials, digital provenance, editing history, software signatures, camera tags, and forensic tracking identifiers from video containers while preserving original audiovisual streams with 100% bitstream fidelity (lossless stream-copy, zero re-encoding).

Specifically engineered to target and strip:
- **C2PA Manifests & Content Credentials:** JUMBF boxes, claim generators, digital source type assertions, and signed manifest stores (`urn:c2pa`, `d8fec3d6-1b0e-483c-9297-5828877aae48`).
- **XMP & Adobe History:** Adobe XMP Core packets (`uuid: be7acfcb-97a9-42e8-9c71-999491e3afac`), Premiere Pro project paths (`.prproj`), Photoshop document IDs, editing history software agents, and ingredient file references (`.psd`, `.png`, `.mp4`).
- **Generative AI & Watermark Provenance:** Markers indicating synthetic generation (e.g. Gemini, SynthID, Generative AI tags).
- **Internal Production Metadata:** User Data atoms (`udta`, `meta`, `ilst`), QuickTime item lists, software encoding tags (`Lavf`, compressor names), and original editing timeline timestamps.

---

## Supported Operating Systems

The sanitizer is fully cross-platform and tested across:
- **Linux:** Ubuntu, Debian, Fedora, Arch Linux, Alpine, and headless server environments.
- **macOS:** Apple Silicon (M1/M2/M3/M4) and Intel (x86_64) running macOS 11+.
- **Windows:** Windows 10, Windows 11, and Windows Server (x64/ARM64).

---

## Architectural Philosophy: Strict Whitelist vs. Blacklist

Conventional metadata strippers rely on a **blacklist** pattern: they search for known metadata keys or regex patterns (e.g., `adobe`, `c2pa`, `xmp`) and attempt to delete them. This approach is inherently flawed in digital forensics because:
1. Proprietary software frequently invents custom container atoms or nests tracking metadata inside codec configuration structures where blacklists fail to look.
2. Partial deletion often leaves orphan atoms or corrupts container offset tables (`stco`/`co64`), breaking streaming compliance.

### The Strict Whitelist Architecture
This utility implements an **inversion of control** using a strict structural whitelist:

```
                          ┌───────────────────────────┐
                          │   Contaminated Source     │
                          │   (MP4 / MOV / M4V)       │
                          └─────────────┬─────────────┘
                                        │
                         [Stage 1: Pre-Sanitization Probe]
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │   FFmpeg Lossless Remux   │
                          │   -c copy -map 0:v:0      │
                          │   -map 0:a? -bitexact     │
                          └─────────────┬─────────────┘
                                        │
                       [Stage 2: Low-Level ISOBMFF Rebuild]
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │   Custom Box Rebuilder    │
                          │   • Whitelist-only atoms  │
                          │   • Timestamp neutralizer │
                          │   • Recalibrate stco/co64 │
                          └─────────────┬─────────────┘
                                        │
                     [Stage 3: Dual-Engine Verification Audit]
                                        │
                     ┌──────────────────┴──────────────────┐
                     │                                     │
                     ▼                                     ▼
       ┌──────────────────────────┐          ┌──────────────────────────┐
       │   Automated Container    │          │     Deep ExifTool &      │
       │   & Playback Audit       │          │   Binary Signature Audit │
       │   • Validates box tree   │          │   • 0 forbidden tags     │
       │   • Decodes all frames   │          │   • 0 C2PA/XMP remnants  │
       └─────────────┬────────────┘          └─────────────┬────────────┘
                     │                                     │
                     └──────────────────┬──────────────────┘
                                        │ (Both Pass)
                                        ▼
                          ┌───────────────────────────┐
                          │   Pristine Standard MP4   │
                          │   (Neutralized ISO Media) │
                          └───────────────────────────┘
```

1. **Lossless Stream Extraction:** Video NALUs (H.264/AVC, H.265/HEVC) and audio frames (AAC, etc.) are extracted directly via lossless stream copying (`-c copy`). No transcoding occurs; every frame remains identical bit-for-bit.
2. **Container Reconstruction from Scratch:** A clean ISO/IEC 14496-12 MP4 container is constructed retaining **only** essential structural boxes:
   - `ftyp`: File Type Box (`isom` major brand, `isom, avc1, mp41` compatible brands).
   - `moov`: Movie Box containing only sanitized `mvhd` (neutralized timestamps) and `trak` atoms for `vide` and `soun` media.
   - `stsd`: Sample description table keeping only verified codec configuration records (`avcC`, `hvcC`, `colr`, `pasp`, `esds`) while scrubbing compressor names and private extensions.
   - `mdat`: Media data box copied via memory-safe 1 MB buffered streaming.
3. **Chunk Offset Recalibration:** All chunk offsets (`stco` 32-bit and `co64` 64-bit) are re-indexed to reflect the exact byte offset shift of the newly constructed container.
4. **Zero-Tolerance Audit & Atomic Delivery:** The sanitized file is verified by container box parsers, full FFmpeg frame decoding, and ExifTool tag auditing. The file is delivered atomically only when all audits pass with zero issues.

---

## Allowed Box Whitelist Hierarchy

Any box not explicitly listed below is stripped unconditionally at container rebuild time:

| Level | Allowed Box Types | Sanitization / Handling Behavior |
|---|---|---|
| **Root** | `ftyp`, `moov`, `mdat` | All `uuid`, `udta`, `meta`, `free`, `skip` atoms are permanently eliminated. |
| **`moov`** | `mvhd`, `trak` | `mvhd` creation and modification timestamps are reset to neutral MP4 epoch timestamps. |
| **`trak`** | `tkhd`, `edts`, `mdia` | Only tracks with handlers `vide` or `soun` are permitted. Subtitle, timecode, and data tracks are dropped. |
| **`edts`** | `elst` | Preserves edit list timing alignment; strips non-standard edit entries. |
| **`mdia`** | `mdhd`, `hdlr`, `minf` | `mdhd` timestamps reset to neutral; `hdlr` names reset to neutral `VideoHandler`/`SoundHandler`. |
| **`minf`** | `vmhd`, `smhd`, `dinf`, `stbl` | Strips all data handler extensions except standard data references (`dref`). |
| **`stbl`** | `stsd`, `stts`, `ctts`, `cslg`, `stss`, `sdtp`, `stsc`, `stsz`, `stco`, `co64`, `sgpd`, `sbgp` | Sample entries in `stsd` scrub compressor names. Offset tables (`stco`/`co64`) are mathematically adjusted by delta. |
| **`stsd` Video** | `avcC`, `hvcC`, `vpcC`, `av1C`, `colr`, `pasp`, `btrt` | Visual sample entries retain only necessary bitstream decodability headers. |
| **`stsd` Audio** | `esds`, `wave`, `btrt`, `dOps` | Audio sample entries retain only codec parameters. |

---

## Before / After Forensic Audit Matrix

| Metric / Parameter | Contaminated Source (e.g. Premiere / Photoshop / AI) | Sanitized Output |
|---|---|---|
| **Container Format** | MP4 / MOV / QuickTime container with extensions | Standard ISO Base Media File (`isom`) |
| **Major Brand / Brands** | `mp42`, `qt  `, `M4V `, etc. | Major: `isom` \| Compatible: `isom, avc1, mp41` |
| **C2PA Content Credentials** | Embedded JUMBF manifest, digital source type, assertions | **None (0 bytes)** |
| **Adobe XMP Packets** | Full XMP packet (`uuid: be7acfcb...`) with edit history | **None (0 bytes)** |
| **Project File References** | Full paths (`Project.prproj`, `asset.psd`, timeline clips) | **None (0 references)** |
| **Software Identifiers** | `Adobe Premiere Pro`, `Photoshop`, `Lavf...` | **None (Neutralized to standard handler names)** |
| **Creation / Modify Dates** | Original production and export timestamps | **Neutralized MP4 Epoch Timestamps** |
| **Video Codec & Stream** | e.g. H.264 / AVC (`avc1`) | **Identical (100% bit-exact stream copy)** |
| **Video Resolution & FPS** | e.g. 1920x1080 @ 24.00 fps | **Identical** |
| **Audio Codec & Channels** | e.g. AAC 48000 Hz Stereo | **Identical** |
| **Color Matrix & Primaries** | Preserved (e.g. BT.709, Limited range) | **Identical** |
| **Decoding Playability** | Variable (often flagged by privacy auditors) | **100% Clean Pass (`ffmpeg -f null -`)** |
| **Forbidden Metadata Tags** | 10 to 50+ tracking tags | **0** |

---

## Repository Structure

```
├── clean_video.py                  # Standalone CLI entrypoint runner
├── requirements.txt                # Python environment requirements (pytest)
├── .gitignore                      # Git exclusion rules
├── README.md                       # Documentation
│
└── video_sanitizer/                # Core Python package
    ├── __init__.py                 # Public package API exports
    ├── models.py                   # Dataclasses: MediaStreamInfo, InspectionResult, etc.
    ├── metadata.py                 # Box whitelist sets, forbidden string rules, epoch math
    ├── c2pa.py                     # C2PA UUID and JUMBF binary scanner
    ├── mp4_rebuilder.py            # Low-level ISOBMFF binary parser, rebuilder & stco patcher
    ├── inspector.py                # Pre-sanitization inspector (ffprobe, exiftool, binary)
    ├── verifier.py                 # Multi-engine post-sanitization verification auditor
    ├── sanitizer.py                # Pipeline orchestrator: remux -> rebuild -> verify -> promote
    ├── cli.py                      # Interactive GUI picker, CLI runner & terminal reporter
    │
    └── tests/                      # Automated test suite
        ├── test_c2pa.py            # C2PA binary signature detection tests
        ├── test_models.py          # Data model and property unit tests
        ├── test_mp4_rebuilder.py   # Low-level box parser, ftyp, and timestamp tests
        ├── test_sanitizer.py       # End-to-end integration tests with synthetic media
        └── test_verifier.py        # Tag validation and media preservation tests
```

---

## Installation & Prerequisites

### 1. Python Environment
Python 3.8 or higher is required. Clone the repository and install test dependencies:

```bash
pip install -r requirements.txt
```

> [!NOTE]
> On desktop systems, `tkinter` is used for the interactive GUI file picker. It is included by default with standard Windows and macOS Python distributions. On Linux, if not already installed, it can be added via your package manager (e.g., `sudo apt install python3-tk`). For headless or server use, run with `--non-interactive`.

### 2. External Dependencies

The sanitizer requires two standard multimedia utilities installed on your system:

#### A. FFmpeg & FFprobe
Required for lossless stream-copy remuxing and decode verification.
- **Linux (Debian/Ubuntu):** `sudo apt update && sudo apt install ffmpeg`
- **Linux (Fedora/RHEL):** `sudo dnf install ffmpeg`
- **macOS (Homebrew):** `brew install ffmpeg`
- **Windows:** `winget install Gyan.FFmpeg` or `choco install ffmpeg`

#### B. ExifTool
Required for the deep metadata tag audit.
- **Linux (Debian/Ubuntu):** `sudo apt update && sudo apt install libimage-exiftool-perl`
- **Linux (Fedora/RHEL):** `sudo dnf install perl-Image-ExifTool`
- **Linux (Arch):** `sudo pacman -S perl-image-exiftool`
- **macOS (Homebrew):** `brew install exiftool`
- **Windows:** `winget install OliverBetz.ExifTool` or download from [exiftool.org](https://exiftool.org/)

> [!TIP]
> The sanitizer resolves `exiftool` automatically by checking your system `PATH`, the script directory, or via the `--exiftool` CLI flag.

---

## CLI & Interactive Usage

### 1. Interactive GUI Mode (Default)
Running the entrypoint without arguments opens native file/folder picker dialogs:

```bash
python clean_video.py
```
*(On Linux/macOS, use `python3 clean_video.py`)*

If GUI dialogs are unavailable or cancelled, the runner provides an interactive console fallback supporting **drag-and-drop** file paths.

### 2. Single Video Processing
Sanitize a single video file. By default, output is placed in `<input_dir>/Video Cleaned/<filename>.mp4`:

```bash
# Default destination (<input_dir>/Video Cleaned/sample.mp4)
python clean_video.py -i "sample.mp4"

# Explicit destination path
python clean_video.py -i "sample.mp4" -o "clean_sample.mp4"
```

### 3. Directory Batch Processing
Sanitize all supported video containers (`.mp4`, `.mov`, `.m4v`) within a folder:

```bash
python clean_video.py -i "source_videos/" -o "sanitized_videos/" --collision rename
```

### 4. Headless & Automated CI/CD Pipelines
Use `--non-interactive` to disable GUI dialogs and console prompts:

```bash
python clean_video.py -i "input.mp4" -o "output.mp4" --non-interactive --collision overwrite
```

### CLI Flag Reference

| Flag | Long Option | Description | Default |
|---|---|---|---|
| `-i` | `--input` | Path to target video file or folder | Interactive Picker |
| `-o` | `--output` | Destination file or directory | `<input_dir>/Video Cleaned` |
| | `--collision` | Policy when output file exists: `rename`, `overwrite`, `skip` | `rename` |
| | `--exiftool` | Explicit path to custom `exiftool` executable | Auto-detected |
| | `--non-interactive` | Disables GUI file dialogs and interactive prompts | `False` |

---

## Programmatic Python API

The `video_sanitizer` package can be imported directly into Python applications.

### Single File Sanitization

```python
from pathlib import Path
from video_sanitizer import sanitize_video

input_file = Path("contaminated.mp4")
output_file = Path("clean.mp4")

result = sanitize_video(
    input_path=input_file,
    output_path=output_file,
)

if result.success:
    print(f"[OK] Clean file written to: {result.output_path}")
    print(f"     Re-encoded: {result.re_encoded}")  # Always False
else:
    print(f"[FAIL] Error: {result.message}")
```

### Batch Directory Processing

```python
from pathlib import Path
from video_sanitizer import batch_sanitize

results = batch_sanitize(
    input_dir=Path("source_directory"),
    output_dir=Path("sanitized_directory"),
    collision_policy="rename",  # "rename", "overwrite", or "skip"
)

for res in results:
    status = "CLEAN" if res.success else "SKIPPED/FAILED"
    print(f"[{status}] {res.input_path.name} -> {res.output_path}")
```

### Deep Pre-Sanitization Inspection

```python
from pathlib import Path
from video_sanitizer import inspect_video

report = inspect_video(Path("suspicious.mp4"))

print(f"Duration: {report.duration}s | Container: {report.format_name}")
print(f"C2PA Detected:      {report.has_c2pa}")
print(f"XMP Detected:       {report.has_xmp}")
print(f"Adobe Detected:     {report.has_adobe}")
print(f"Source References:  {report.has_source_references}")
print(f"Forbidden Tags:     {len(report.forbidden_tags)}")

for tag in report.forbidden_tags:
    print(f" - {tag}")
```

### Independent Post-Sanitization Verification

```python
from pathlib import Path
from video_sanitizer import verify_video

audit = verify_video(Path("sanitized_output.mp4"))

print(f"Valid MP4 Structure:     {audit.is_valid}")
print(f"Clean (Zero Metadata):    {audit.is_clean}")
print(f"Decodes Without Errors:   {audit.decoding_passed}")
print(f"Top-level Boxes Found:    {audit.container_boxes}")

if not audit.is_clean:
    print("Issues identified:")
    for issue in audit.issues:
        print(f" - {issue}")
```

---

## Technical Data Models Reference

### `SanitizeResult`
| Attribute | Type | Description |
|---|---|---|
| `success` | `bool` | `True` only if container rebuilt and all verification stages pass. |
| `input_path` | `Path` | Source file path. |
| `output_path` | `Optional[Path]` | Final destination path (or `None` if skipped). |
| `message` | `str` | Diagnostic outcome message or failure reason. |
| `before_inspection` | `Optional[InspectionResult]` | Forensic audit findings prior to sanitization. |
| `after_verification` | `Optional[VerificationResult]` | Multi-engine audit results of sanitized file. |
| `re_encoded` | `bool` | Guarantee flag (strictly `False`). |

### `InspectionResult`
| Attribute | Type | Description |
|---|---|---|
| `has_c2pa` | `bool` | Detects C2PA UUIDs, JUMBF boxes, claims, or digital source tags. |
| `has_xmp` | `bool` | Detects Adobe XMP packets and RDF namespaces. |
| `has_adobe` | `bool` | Detects Adobe Premiere, Photoshop, or After Effects tags. |
| `has_source_references` | `bool` | Detects local project files (`.prproj`, `.psd`, asset paths). |
| `has_ai_references` | `bool` | Detects AI indicators (`gemini`, `synthid`, `generative`). |
| `forbidden_tags` | `List[str]` | List of all prohibited key-value metadata pairs found. |

---

## Dual-Engine Automated Verification

The sanitizer enforces a strict fail-closed contract. If any check fails, the intermediate output is wiped and the process exits with an error.

```
       Sanitized File
             │
             ├──► 1. Native Box Audit ──────► Top-level must be {ftyp, moov, mdat} only.
             │                                Zero uuid, udta, meta, or free boxes allowed.
             │
             ├──► 2. Deep Binary Scan ──────► Scans file for standard C2PA UUIDs,
             │                                JUMBF signatures, and Adobe project strings.
             │
             ├──► 3. Decoder Test ──────────► Executes `ffmpeg -v error -i <file> -f null -`
             │                                to confirm every video/audio frame decodes cleanly.
             │
             ├──► 4. Integrity Comparison ──► Compares input vs. output: codec, resolution,
             │                                framerate, duration (±0.25s), sample rate.
             │
             └──► 5. ExifTool Deep Audit ───► Executes `exiftool -json -G -a -u -s`
                                              to ensure ZERO non-whitelisted metadata remains.
```

---

## Stream Handling Invariants & Limitations

1. **Track Filtering Policy:**
   - The sanitizer strictly extracts the **primary video stream** (`0:v:0`) and **primary audio streams** (`0:a?`).
   - Timelines containing secondary data tracks, timecode tracks (`tmcd`), subtitle tracks, or chapter markers (`-map_chapters -1`) have those tracks deliberately omitted because they routinely carry embedded project history and software timestamps.
2. **Supported Input Containers:**
   - `.mp4`, `.mov`, `.m4v` (H.264/AVC, H.265/HEVC video with AAC, MP3, or PCM audio).
3. **64-bit Large File Support:**
   - Full 64-bit chunk offset (`co64`) and large `mdat` container support ensures seamless operation on media files exceeding 4 GB.
4. **Memory Footprint:**
   - Container rewriting streams media frames in memory-safe 1 MB chunks without buffering entire multi-gigabyte videos in RAM.

---

## Automated Test Suite

The test suite validates both unit components and full end-to-end processing:

```bash
pytest -v
```

### Test Coverage Overview
- `video_sanitizer/tests/test_c2pa.py`: Binary validation for C2PA UUID bytes, JUMBF markers, and synthetic media signatures.
- `video_sanitizer/tests/test_mp4_rebuilder.py`: Box header reading, `ftyp` serialization, `mvhd`/`tkhd`/`mdhd` timestamp zeroing, and `hdlr` creation.
- `video_sanitizer/tests/test_verifier.py`: Tag whitelist enforcement and media stream integrity comparison logic.
- `video_sanitizer/tests/test_models.py`: Helper properties (`resolution_str`, `frame_rate_str`, stream accessors).
- `video_sanitizer/tests/test_sanitizer.py`: Dynamic end-to-end test that synthesizes an MP4 video with embedded contaminated metadata, runs the full pipeline, and verifies that the output passes all verification stages.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
