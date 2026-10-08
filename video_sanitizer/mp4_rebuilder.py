"""Low-level ISO Base Media File Format (MP4/ISOBMFF) parser and whitelist rebuilder.

Constructs a pristine MP4 container retaining strictly required structural,
codec configuration, timing, and stream boxes while discarding all metadata,
XMP, C2PA, editing history, and secondary non-media tracks.
"""

import io
import struct
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

from .c2pa import C2PA_UUID_BYTES
from .metadata import (
    ALLOWED_AUDIO_SAMPLE_BOXES,
    ALLOWED_DINF_BOXES,
    ALLOWED_EDTS_BOXES,
    ALLOWED_MDIA_BOXES,
    ALLOWED_MINF_BOXES,
    ALLOWED_MOOV_BOXES,
    ALLOWED_ROOT_BOXES,
    ALLOWED_STBL_BOXES,
    ALLOWED_TRAK_BOXES,
    ALLOWED_VISUAL_SAMPLE_BOXES,
    PROHIBITED_UUIDS,
    get_neutral_mp4_timestamp,
)


class MP4Box:
    """Represents an ISOBMFF Box / Atom."""

    def __init__(
        self,
        box_type: bytes,
        payload: bytes = b"",
        children: Optional[List["MP4Box"]] = None,
        large_size: bool = False,
    ):
        self.box_type = box_type  # 4-byte ASCII
        self.payload = payload
        self.children = children if children is not None else []
        self.large_size = large_size

    def pack(self) -> bytes:
        """Serializes the box and all its children to bytes."""
        if self.children:
            body = b"".join(child.pack() for child in self.children)
        else:
            body = self.payload

        total_size = len(body) + 8
        if total_size > 0xFFFFFFFF or self.large_size:
            total_size_64 = len(body) + 16
            return struct.pack(">I4sQ", 1, self.box_type, total_size_64) + body
        else:
            return struct.pack(">I4s", total_size, self.box_type) + body


def read_box_header(stream: BinaryIO) -> Optional[Tuple[int, bytes, int]]:
    """Reads a box header from stream.

    Returns (total_size, box_type, header_size) or None at EOF.
    """
    pos = stream.tell()
    raw = stream.read(8)
    if len(raw) < 8:
        return None

    size, box_type = struct.unpack(">I4s", raw)
    if size == 1:
        large_raw = stream.read(8)
        if len(large_raw) < 8:
            return None
        large_size = struct.unpack(">Q", large_raw)[0]
        return large_size, box_type, 16
    elif size == 0:
        # Extends to EOF
        stream.seek(0, io.SEEK_END)
        end_pos = stream.tell()
        stream.seek(pos + 8)
        return (end_pos - pos), box_type, 8
    else:
        return size, box_type, 8


def parse_raw_boxes(stream: BinaryIO, start: int, end: int) -> List[Tuple[bytes, int, int, int]]:
    """Parses raw boxes in a range without deep child unpacking.

    Returns list of (box_type, pos, total_size, header_size).
    """
    stream.seek(start)
    boxes = []
    while stream.tell() < end:
        pos = stream.tell()
        hdr = read_box_header(stream)
        if not hdr:
            break
        sz, bt, hsz = hdr
        if sz < hsz:
            break
        boxes.append((bt, pos, sz, hsz))
        stream.seek(pos + sz)
    return boxes


def make_clean_ftyp() -> bytes:
    """Builds a standardized MP4 Base Media v1 ftyp box.

    Major Brand: isom (MP4 Base Media v1)
    Minor Version: 0x00000200
    Compatible Brands: isom, avc1, mp41
    """
    return struct.pack(
        ">I4s4sI4s4s4s",
        28,
        b"ftyp",
        b"isom",
        0x00000200,
        b"isom",
        b"avc1",
        b"mp41",
    )


def sanitize_mvhd(payload: bytearray, neutral_ts: int) -> bytearray:
    """Neutralizes creation and modification timestamps in mvhd."""
    if len(payload) < 24:
        return payload
    version = payload[0]
    if version == 0:
        # offset 4: creation_time (uint32), offset 8: modification_time (uint32)
        struct.pack_into(">II", payload, 4, neutral_ts, neutral_ts)
    elif version == 1:
        # offset 4: creation_time (uint64), offset 12: modification_time (uint64)
        if len(payload) >= 32:
            struct.pack_into(">QQ", payload, 4, neutral_ts, neutral_ts)
    return payload


def sanitize_tkhd(payload: bytearray, neutral_ts: int) -> bytearray:
    """Neutralizes creation and modification timestamps in tkhd."""
    if len(payload) < 24:
        return payload
    version = payload[0]
    if version == 0:
        struct.pack_into(">II", payload, 4, neutral_ts, neutral_ts)
    elif version == 1:
        if len(payload) >= 32:
            struct.pack_into(">QQ", payload, 4, neutral_ts, neutral_ts)
    return payload


def sanitize_mdhd(payload: bytearray, neutral_ts: int) -> bytearray:
    """Neutralizes creation and modification timestamps in mdhd."""
    if len(payload) < 20:
        return payload
    version = payload[0]
    if version == 0:
        struct.pack_into(">II", payload, 4, neutral_ts, neutral_ts)
    elif version == 1:
        if len(payload) >= 28:
            struct.pack_into(">QQ", payload, 4, neutral_ts, neutral_ts)
    return payload


def make_clean_hdlr(handler_type: bytes, neutral_name: str) -> bytes:
    """Constructs a clean handler box with standard neutral description."""
    name_bytes = neutral_name.encode("utf-8") + b"\x00"
    # version=0, flags=0 (4 bytes), pre_defined=0 (4 bytes), handler_type (4 bytes), reserved (12 bytes)
    payload = struct.pack(">II4s12s", 0, 0, handler_type, b"\x00" * 12) + name_bytes
    total_sz = len(payload) + 8
    return struct.pack(">I4s", total_sz, b"hdlr") + payload


def sanitize_visual_sample_entry(entry_bytes: bytearray) -> bytearray:
    """Sanitizes visual sample entry (avc1, hvc1, etc.):

    - Neutralizes compressor name to clean standard name or zero
    - Whitelists child boxes: only avcC, hvcC, vpcC, av1C, colr, pasp, btrt
    """
    if len(entry_bytes) < 78:
        return entry_bytes

    # VisualSampleEntry header:
    # 6 bytes reserved, 2 bytes data_ref_idx, 16 bytes pre_defined/reserved,
    # 2 bytes width, 2 bytes height, 4 horizres, 4 vertres, 4 reserved, 2 frame_count,
    # 32 bytes compressorname (offset 42..74)
    # 2 bytes depth, 2 bytes pre_defined
    # Set compressor name to standard "AVC Coding" (Pascal string: len 10 + "AVC Coding" + zeros)
    comp_name = b"\x0aAVC Coding" + b"\x00" * 21
    entry_bytes[42:74] = comp_name

    # Inspect and whitelist child boxes starting at offset 78
    pos = 78
    child_boxes = []
    while pos < len(entry_bytes):
        if pos + 8 > len(entry_bytes):
            break
        sz, bt = struct.unpack(">I4s", entry_bytes[pos : pos + 8])
        if sz < 8 or pos + sz > len(entry_bytes):
            break
        if bt in ALLOWED_VISUAL_SAMPLE_BOXES:
            child_boxes.append(entry_bytes[pos : pos + sz])
        pos += sz

    base_header = entry_bytes[:78]
    rebuilt = bytearray(base_header)
    for cb in child_boxes:
        rebuilt.extend(cb)
    return rebuilt


def sanitize_audio_sample_entry(entry_bytes: bytearray) -> bytearray:
    """Sanitizes audio sample entry (mp4a, etc.):

    - Whitelists child boxes: only esds, wave, btrt, dOps
    """
    if len(entry_bytes) < 28:
        return entry_bytes

    # AudioSampleEntry header is 28 bytes
    pos = 28
    child_boxes = []
    while pos < len(entry_bytes):
        if pos + 8 > len(entry_bytes):
            break
        sz, bt = struct.unpack(">I4s", entry_bytes[pos : pos + 8])
        if sz < 8 or pos + sz > len(entry_bytes):
            break
        if bt in ALLOWED_AUDIO_SAMPLE_BOXES:
            child_boxes.append(entry_bytes[pos : pos + sz])
        pos += sz

    base_header = entry_bytes[:28]
    rebuilt = bytearray(base_header)
    for cb in child_boxes:
        rebuilt.extend(cb)
    return rebuilt


def sanitize_stsd(payload: bytearray, handler_type: bytes) -> bytearray:
    """Sanitizes stsd box payload containing sample entries."""
    if len(payload) < 8:
        return payload

    # stsd payload: 1 byte version, 3 bytes flags, 4 bytes entry_count
    entry_count = struct.unpack(">I", payload[4:8])[0]
    pos = 8
    clean_entries = []

    for _ in range(entry_count):
        if pos + 8 > len(payload):
            break
        sz, fmt = struct.unpack(">I4s", payload[pos : pos + 8])
        if sz < 8 or pos + sz > len(payload):
            break
        entry_data = bytearray(payload[pos + 8 : pos + sz])

        if handler_type == b"vide":
            clean_body = sanitize_visual_sample_entry(entry_data)
        elif handler_type == b"soun":
            clean_body = sanitize_audio_sample_entry(entry_data)
        else:
            clean_body = entry_data

        clean_entry_box = struct.pack(">I4s", len(clean_body) + 8, fmt) + clean_body
        clean_entries.append(clean_entry_box)
        pos += sz

    rebuilt = bytearray(payload[:4])  # version + flags
    rebuilt.extend(struct.pack(">I", len(clean_entries)))
    for ce in clean_entries:
        rebuilt.extend(ce)
    return rebuilt


def rebuild_trak(
    trak_raw: bytes,
    neutral_ts: int,
) -> Optional[bytearray]:
    """Applies strict whitelist and timestamp sanitization to a single track box.

    Returns rebuilt track bytearray or None if track is not video/audio.
    """
    stream = io.BytesIO(trak_raw)
    hdr = read_box_header(stream)
    if not hdr or hdr[1] != b"trak":
        return None

    # Parse top children of trak
    trak_len = len(trak_raw)
    children = parse_raw_boxes(stream, 8, trak_len)

    # 1. First locate mdia/hdlr to determine handler_type
    handler_type = None
    for bt, pos, sz, hsz in children:
        if bt == b"mdia":
            mdia_children = parse_raw_boxes(stream, pos + hsz, pos + sz)
            for mbt, mpos, msz, mhsz in mdia_children:
                if mbt == b"hdlr":
                    stream.seek(mpos + mhsz)
                    hdlr_pay = stream.read(msz - mhsz)
                    if len(hdlr_pay) >= 12:
                        # hdlr: 4 ver/flags, 4 pre_defined, 4 handler_type
                        handler_type = hdlr_pay[8:12]
                    break
            break

    # Strictly only allow 'vide' and 'soun' tracks
    if handler_type not in (b"vide", b"soun"):
        return None

    rebuilt_trak_children = bytearray()

    for bt, pos, sz, hsz in children:
        if bt not in ALLOWED_TRAK_BOXES:
            continue

        stream.seek(pos + hsz)
        payload = bytearray(stream.read(sz - hsz))

        if bt == b"tkhd":
            clean_pay = sanitize_tkhd(payload, neutral_ts)
            rebuilt_trak_children.extend(
                struct.pack(">I4s", len(clean_pay) + 8, b"tkhd") + clean_pay
            )

        elif bt == b"edts":
            # Filter edts children: keep only elst
            edts_stream = io.BytesIO(payload)
            edts_ch = parse_raw_boxes(edts_stream, 0, len(payload))
            clean_edts_pay = bytearray()
            for ebt, epos, esz, ehsz in edts_ch:
                if ebt in ALLOWED_EDTS_BOXES:
                    clean_edts_pay.extend(payload[epos : epos + esz])
            if clean_edts_pay:
                rebuilt_trak_children.extend(
                    struct.pack(">I4s", len(clean_edts_pay) + 8, b"edts")
                    + clean_edts_pay
                )

        elif bt == b"mdia":
            mdia_stream = io.BytesIO(payload)
            mdia_ch = parse_raw_boxes(mdia_stream, 0, len(payload))
            rebuilt_mdia_pay = bytearray()

            for mbt, mpos, msz, mhsz in mdia_ch:
                if mbt not in ALLOWED_MDIA_BOXES:
                    continue

                stream.seek(pos + hsz + mpos + mhsz)
                mpayload = bytearray(stream.read(msz - mhsz))

                if mbt == b"mdhd":
                    clean_mdhd = sanitize_mdhd(mpayload, neutral_ts)
                    rebuilt_mdia_pay.extend(
                        struct.pack(">I4s", len(clean_mdhd) + 8, b"mdhd") + clean_mdhd
                    )

                elif mbt == b"hdlr":
                    name = "VideoHandler" if handler_type == b"vide" else "SoundHandler"
                    clean_hdlr_box = make_clean_hdlr(handler_type, name)
                    rebuilt_mdia_pay.extend(clean_hdlr_box)

                elif mbt == b"minf":
                    minf_stream = io.BytesIO(mpayload)
                    minf_ch = parse_raw_boxes(minf_stream, 0, len(mpayload))
                    rebuilt_minf_pay = bytearray()

                    for ibt, ipos, isz, ihsz in minf_ch:
                        if ibt not in ALLOWED_MINF_BOXES:
                            continue

                        stream.seek(pos + hsz + mpos + mhsz + ipos + ihsz)
                        ipayload = bytearray(stream.read(isz - ihsz))

                        if ibt in (b"vmhd", b"smhd"):
                            rebuilt_minf_pay.extend(
                                struct.pack(">I4s", len(ipayload) + 8, ibt) + ipayload
                            )

                        elif ibt == b"dinf":
                            dinf_stream = io.BytesIO(ipayload)
                            dinf_ch = parse_raw_boxes(dinf_stream, 0, len(ipayload))
                            rebuilt_dinf_pay = bytearray()
                            for dbt, dpos, dsz, dhsz in dinf_ch:
                                if dbt in ALLOWED_DINF_BOXES:
                                    rebuilt_dinf_pay.extend(ipayload[dpos : dpos + dsz])
                            rebuilt_minf_pay.extend(
                                struct.pack(">I4s", len(rebuilt_dinf_pay) + 8, b"dinf")
                                + rebuilt_dinf_pay
                            )

                        elif ibt == b"stbl":
                            stbl_stream = io.BytesIO(ipayload)
                            stbl_ch = parse_raw_boxes(stbl_stream, 0, len(ipayload))
                            rebuilt_stbl_pay = bytearray()

                            for sbt, spos, ssz, shsz in stbl_ch:
                                if sbt not in ALLOWED_STBL_BOXES:
                                    continue

                                stream.seek(
                                    pos + hsz + mpos + mhsz + ipos + ihsz + spos + shsz
                                )
                                spayload = bytearray(stream.read(ssz - shsz))

                                if sbt == b"stsd":
                                    clean_stsd = sanitize_stsd(spayload, handler_type)
                                    rebuilt_stbl_pay.extend(
                                        struct.pack(">I4s", len(clean_stsd) + 8, b"stsd")
                                        + clean_stsd
                                    )
                                else:
                                    # Timing, sample sizes, chunks, and offset tables
                                    rebuilt_stbl_pay.extend(
                                        struct.pack(">I4s", len(spayload) + 8, sbt)
                                        + spayload
                                    )

                            rebuilt_minf_pay.extend(
                                struct.pack(">I4s", len(rebuilt_stbl_pay) + 8, b"stbl")
                                + rebuilt_stbl_pay
                            )

                    rebuilt_mdia_pay.extend(
                        struct.pack(">I4s", len(rebuilt_minf_pay) + 8, b"minf")
                        + rebuilt_minf_pay
                    )

            rebuilt_trak_children.extend(
                struct.pack(">I4s", len(rebuilt_mdia_pay) + 8, b"mdia")
                + rebuilt_mdia_pay
            )

    return (
        struct.pack(">I4s", len(rebuilt_trak_children) + 8, b"trak")
        + rebuilt_trak_children
    )


def patch_chunk_offsets(moov_bytes: bytearray, delta: int) -> bytearray:
    """Adjusts all chunk offsets in stco and co64 boxes by delta."""
    stream = io.BytesIO(moov_bytes)
    moov_ch = parse_raw_boxes(stream, 8, len(moov_bytes))

    for bt, pos, sz, hsz in moov_ch:
        if bt == b"trak":
            trak_ch = parse_raw_boxes(stream, pos + hsz, pos + sz)
            for tbt, tpos, tsz, thsz in trak_ch:
                if tbt == b"mdia":
                    mdia_ch = parse_raw_boxes(stream, tpos + thsz, tpos + tsz)
                    for mbt, mpos, msz, mhsz in mdia_ch:
                        if mbt == b"minf":
                            minf_ch = parse_raw_boxes(stream, mpos + mhsz, mpos + msz)
                            for ibt, ipos, isz, ihsz in minf_ch:
                                if ibt == b"stbl":
                                    stbl_ch = parse_raw_boxes(
                                        stream, ipos + ihsz, ipos + isz
                                    )
                                    for sbt, spos, ssz, shsz in stbl_ch:
                                        if sbt == b"stco":
                                            entry_count = struct.unpack(
                                                ">I",
                                                moov_bytes[
                                                    spos + shsz + 4 : spos + shsz + 8
                                                ],
                                            )[0]
                                            for i in range(entry_count):
                                                off_idx = spos + shsz + 8 + i * 4
                                                old_off = struct.unpack(
                                                    ">I",
                                                    moov_bytes[off_idx : off_idx + 4],
                                                )[0]
                                                new_off = old_off + delta
                                                struct.pack_into(
                                                    ">I", moov_bytes, off_idx, new_off
                                                )
                                        elif sbt == b"co64":
                                            entry_count = struct.unpack(
                                                ">I",
                                                moov_bytes[
                                                    spos + shsz + 4 : spos + shsz + 8
                                                ],
                                            )[0]
                                            for i in range(entry_count):
                                                off_idx = spos + shsz + 8 + i * 8
                                                old_off = struct.unpack(
                                                    ">Q",
                                                    moov_bytes[off_idx : off_idx + 8],
                                                )[0]
                                                new_off = old_off + delta
                                                struct.pack_into(
                                                    ">Q", moov_bytes, off_idx, new_off
                                                )
    return moov_bytes


def rebuild_mp4(
    input_path: Path,
    output_path: Path,
    neutral_timestamp: Optional[int] = None,
) -> bool:
    """Rebuilds an MP4 container strictly adhering to the whitelist architecture:

    - Keeps only ftyp, moov, mdat
    - Neutralizes internal container timestamps
    - Strips all udta, uuid, free, meta, C2PA, and XMP boxes
    - Sanitizes handler names and compressor names
    - Accurately recalibrates stco / co64 chunk offsets
    - Streams mdat in chunks for fast, memory-safe execution
    """
    if neutral_timestamp is None:
        neutral_timestamp = get_neutral_mp4_timestamp()

    clean_ftyp = make_clean_ftyp()

    with open(input_path, "rb") as fin:
        fin.seek(0, io.SEEK_END)
        file_len = fin.tell()
        fin.seek(0)

        top_boxes = parse_raw_boxes(fin, 0, file_len)

        # Locate source moov and mdat
        source_moov_raw = None
        source_mdat_pos = None
        source_mdat_size = None
        source_mdat_hsz = None

        for bt, pos, sz, hsz in top_boxes:
            if bt == b"moov":
                fin.seek(pos)
                source_moov_raw = fin.read(sz)
            elif bt == b"mdat":
                source_mdat_pos = pos
                source_mdat_size = sz
                source_mdat_hsz = hsz

        if not source_moov_raw or source_mdat_pos is None:
            return False

        # Parse source moov children
        moov_stream = io.BytesIO(source_moov_raw)
        moov_children = parse_raw_boxes(moov_stream, 8, len(source_moov_raw))

        rebuilt_moov_payload = bytearray()

        for bt, pos, sz, hsz in moov_children:
            if bt not in ALLOWED_MOOV_BOXES:
                continue

            if bt == b"mvhd":
                moov_stream.seek(pos + hsz)
                mvhd_payload = bytearray(moov_stream.read(sz - hsz))
                clean_mvhd = sanitize_mvhd(mvhd_payload, neutral_timestamp)
                rebuilt_moov_payload.extend(
                    struct.pack(">I4s", len(clean_mvhd) + 8, b"mvhd") + clean_mvhd
                )

            elif bt == b"trak":
                trak_raw = source_moov_raw[pos : pos + sz]
                clean_trak = rebuild_trak(trak_raw, neutral_timestamp)
                if clean_trak:
                    rebuilt_moov_payload.extend(clean_trak)

        # Assemble clean moov box
        clean_moov = bytearray(
            struct.pack(">I4s", len(rebuilt_moov_payload) + 8, b"moov")
            + rebuilt_moov_payload
        )

        # Calculate chunk offset delta
        source_mdat_payload_pos = source_mdat_pos + source_mdat_hsz
        source_mdat_payload_len = source_mdat_size - source_mdat_hsz

        # Determine new mdat header
        if source_mdat_size > 0xFFFFFFFF:
            new_mdat_hsz = 16
            new_mdat_header = struct.pack(">I4sQ", 1, b"mdat", source_mdat_size)
        else:
            new_mdat_hsz = 8
            new_mdat_header = struct.pack(">I4s", source_mdat_size, b"mdat")

        new_mdat_pos = len(clean_ftyp) + len(clean_moov)
        new_mdat_payload_pos = new_mdat_pos + new_mdat_hsz

        delta = new_mdat_payload_pos - source_mdat_payload_pos

        # Patch stco/co64 entries in clean_moov
        clean_moov = patch_chunk_offsets(clean_moov, delta)

        # Stream write to destination
        with open(output_path, "wb") as fout:
            fout.write(clean_ftyp)
            fout.write(clean_moov)
            fout.write(new_mdat_header)

            # Stream copy mdat payload in 1MB chunks
            fin.seek(source_mdat_payload_pos)
            bytes_left = source_mdat_payload_len
            chunk_size = 1024 * 1024
            while bytes_left > 0:
                read_amount = min(chunk_size, bytes_left)
                buf = fin.read(read_amount)
                if not buf:
                    break
                fout.write(buf)
                bytes_left -= len(buf)

    return True
