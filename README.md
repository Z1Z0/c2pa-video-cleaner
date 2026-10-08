# Lossless Video Metadata & Provenance Sanitizer

A high-performance, Windows-compatible Python utility that transforms heavily contaminated video files (containing Adobe Premiere Pro, Photoshop, XMP history, C2PA manifests, Content Credentials, JUMBF provenance, camera tags, editing dates, and source file references) into clean, standard MP4 containers resembling freshly exported technical media files.

---

## Architectural Philosophy: Strict Whitelist Approach

Unlike conventional metadata cleaners that attempt a **blacklist** approach (searching for and deleting known keywords like `adobe`, `c2pa`, `gemini`), this sanitizer implements a **strict whitelist architecture**:

1. **Media Stream Preservation:** The actual video frames (NALUs) and audio packets are extracted and preserved with 100% bitstream fidelity via lossless stream copy (`-c copy`) without re-encoding.
2. **Container Reconstruction:** A brand-new MP4 container is built containing **only** the strictly required ISO/IEC 14496-12 structural boxes:
   - `ftyp`: File Type Box (`isom`, compatible brands `isom, avc1, mp41`)
   - `moov`: Movie Box
     - `mvhd`: Movie Header Box (with regenerated neutral timestamps)
     - `trak`: Track Box (strictly `vide` and `soun` media tracks only)
       - `tkhd`: Track Header Box (with neutral timestamps)
       - `edts`: Edit Box (`elst` edit lists for timing alignment)
       - `mdia`: Media Box
         - `mdhd`: Media Header Box (neutral timestamps)
         - `hdlr`: Handler Reference Box (neutralized to standard `VideoHandler` and `SoundHandler`)
         - `minf`: Media Information Box (`vmhd`, `smhd`, `dinf`, `stbl`)
           - `stbl`: Sample Table Box (`stsd`, `stts`, `ctts`, `cslg`, `stss`, `sdtp`, `stsc`, `stsz`, `stco`/`co64`, `sgpd`, `sbgp`)
             - In `stsd`: Sample descriptions keep codec config (`avcC`, `hvcC`, `colr`, `pasp`, `esds`) while stripping all private extensions and sanitizing compressor names.
   - `mdat`: Media Data Box (stream-copied in memory-safe 1MB chunks)
3. **Complete Elimination:** All non-whitelisted boxes are structurally omitted:
   - Embedded XMP metadata boxes (`uuid: be7acfcb-97a9-42e8-9c71-999491e3afac`)
   - C2PA manifest stores and JUMBF boxes (`uuid: d8fec3d6-1b0e-483c-9297-5828877aae48`, `jumb`, `c2pa`)
   - User Data boxes (`udta`, `©too: Lavf...`, `©TIM`, `©TSC`, `meta`, `ilst`)
   - Free space padding (`free`, `skip`)
   - Data, subtitle, and timecode tracks carrying project history
4. **Accurate Recalibration:** Chunk offset tables (`stco` / `co64`) are mathematically adjusted to precisely match the new `mdat` position in the container.

---

## Exact Before / After State

### Typical Contaminated Input (e.g. Adobe Premiere / Photoshop / AI-generated):
- **XMP Toolkit:** Adobe XMP Core 7.1
- **Creator Tool:** Adobe Premiere Pro 2023.0 (Windows)
- **History Software Agent:** Adobe Premiere Pro, Adobe Photoshop
- **Ingredients File Path:** `gemini_generated_video_2ccb7745.mp4`, `Website-logo-black.png`
- **Pantry Creator Tool:** Adobe Photoshop 26.9 (Windows)
- **Windows Atom Project Path:** `\\?\D:\Nouwaar\Videos\720p.prproj`
- **Document / Instance IDs:** `xmp.iid:...`, `adobe:docid:photoshop:...`
- **Internal Timestamps:** Export and editing timeline timestamps
- **C2PA / Content Credentials:** Embedded manifests and assertions

### Sanitized Output:
- **File Type:** MP4
- **MIME Type:** `video/mp4`
- **Major Brand:** MP4 Base Media v1 (`isom`)
- **Compatible Brands:** `isom, avc1, mp41`
- **Movie Header Version:** 0
- **Create Date / Modify Date:** Fresh neutral timestamp
- **Video Dimensions:** Identical to input (e.g. `720x1280`)
- **Duration:** Identical to input (e.g. `15.00 s`)
- **Video Codec:** Identical to input (`avc1`, H.264)
- **Video Frame Rate:** Identical to input (`24 fps`)
- **Audio Codec:** Identical to input (`mp4a`, AAC)
- **Audio Channels / Sample Rate:** Identical to input (`2 channels`, `48000 Hz`)
- **Color Information:** Preserved (`BT.709`, `Limited range`)
- **Forbidden Metadata Fields:** **0**

---

## Dual-Engine Independent Verification

The sanitizer enforces a zero-tolerance automated verification stage:

1. **Native Container Box Audit:** Verifies that top-level boxes consist strictly of `ftyp`, `moov`, and `mdat`, with zero `uuid`, `udta`, `free`, or `meta` boxes.
2. **Deep Binary Audit:** Scans the full binary file for prohibited C2PA UUIDs, JUMBF markers, and software keywords.
3. **Full Stream Decoding Verification:** Executes `ffmpeg -v error -i <output> -f null -` to verify that 100% of video frames and audio packets decode with zero errors.
4. **Media Integrity Comparison:** Verifies that video/audio codecs, resolution, frame rate, duration, and channel counts are preserved.
5. **Deep ExifTool Audit:** Runs `exiftool -json -G -a -u -s <output>` and checks all tags to guarantee zero remaining provenance, XMP, Adobe, Premiere, Photoshop, project references, or AI keywords.

If any check fails, the sanitizer marks the operation as `[FAILED]`, purges the temporary files, and refuses to report success.

---

## Requirements & Windows Installation

### 1. Python Environment
Python 3.8 or newer is required.

### 2. External Tools
- **FFmpeg & FFprobe:** Must be available on your Windows `PATH`.
- **ExifTool:** Automatically detected if placed in the project folder (`exiftool.exe`) or on your `PATH`.

---

## Usage

### Interactive Mode (Default)
Run without arguments to launch the Windows file/folder picker:

```powershell
python clean_video.py
```

### Single File Processing
Sanitize a single video file:

```powershell
# Default output to '<input_dir>/Video Cleaned/<filename>.mp4'
python clean_video.py -i "D:\Nouwaar\Videos\azureplume01.mp4"

# Custom output destination
python clean_video.py -i "D:\Nouwaar\Videos\azureplume01.mp4" -o "D:\CleanVideos\azureplume01_clean.mp4"
```

### Directory Batch Processing
Sanitize an entire directory of videos (`.mp4`, `.mov`, `.m4v`):

```powershell
python clean_video.py -i "D:\Nouwaar\Videos" -o "D:\Nouwaar\Videos\Sanitized" --collision rename
```

### Available CLI Flags
| Flag | Description | Default |
|---|---|---|
| `-i`, `--input` | Path to input file or directory | Interactive Picker |
| `-o`, `--output` | Destination file or directory | `<input_dir>/Video Cleaned` |
| `--collision` | Action if destination exists: `rename`, `overwrite`, `skip` | `rename` |
| `--exiftool` | Explicit path to `exiftool.exe` | Auto-detected |
| `--non-interactive` | Disable GUI dialogs and interactive console prompts | `False` |

---

## Python Package Integration

You can also use the sanitizer as a Python module in your own scripts:

```python
from pathlib import Path
from video_sanitizer import sanitize_video, inspect_video, verify_video

# Inspect input
before = inspect_video(Path("dirty_video.mp4"))
print(f"XMP present: {before.has_xmp}, Adobe present: {before.has_adobe}")

# Sanitize
result = sanitize_video(
    input_path=Path("dirty_video.mp4"),
    output_path=Path("clean_video.mp4"),
)

if result.success:
    print("Video sanitized successfully!")
    print(f"Re-encoded: {result.re_encoded}")
```

---

## Test Suite

Run the full automated test suite:

```powershell
pytest -v
```
