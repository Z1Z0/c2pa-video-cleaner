"""Unit tests for low-level MP4 container parsing and rewriting."""

import io
import struct
from pathlib import Path
from video_sanitizer.mp4_rebuilder import (
    make_clean_ftyp,
    make_clean_hdlr,
    parse_raw_boxes,
    read_box_header,
    sanitize_mvhd,
    sanitize_tkhd,
    sanitize_mdhd,
)


def test_box_header_reading():
    raw = struct.pack(">I4s", 24, b"test") + b"1234567890123456"
    stream = io.BytesIO(raw)
    hdr = read_box_header(stream)
    assert hdr is not None
    size, btype, hsz = hdr
    assert size == 24
    assert btype == b"test"
    assert hsz == 8


def test_make_clean_ftyp():
    ftyp = make_clean_ftyp()
    assert len(ftyp) == 28
    sz, bt, mb, mv = struct.unpack(">I4s4sI", ftyp[:16])
    assert sz == 28
    assert bt == b"ftyp"
    assert mb == b"isom"
    assert mv == 0x200


def test_sanitize_mvhd():
    # version 0 mvhd
    raw = bytearray(100)
    raw[0] = 0  # version 0
    # set old timestamps
    struct.pack_into(">II", raw, 4, 1111, 2222)
    sanitized = sanitize_mvhd(raw, neutral_ts=9999)
    c_ts, m_ts = struct.unpack(">II", sanitized[4:12])
    assert c_ts == 9999
    assert m_ts == 9999


def test_make_clean_hdlr():
    box = make_clean_hdlr(b"vide", "VideoHandler")
    sz, bt, ver_flags, pre_def, ht = struct.unpack(">I4sII4s", box[:20])
    assert bt == b"hdlr"
    assert ht == b"vide"
    assert b"VideoHandler\x00" in box
