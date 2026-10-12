"""Media & document probing: cheap header parsing that sharpens media verdicts.

Not strictly needed to *place* a file, but it distinguishes things that look
alike (mp4 video vs m4a audio, ebook pdf vs document pdf) and it fills the
report with useful facts (resolution, tags, page count).
"""
from __future__ import annotations

import re
import struct
from typing import Dict, Optional, Tuple


def image_info(head: bytes) -> Dict[str, object]:
    """Width/height for the common raster formats, from the header alone."""
    try:
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", head[16:24])
            return {"format": "png", "width": w, "height": h}
        if head[:2] == b"\xff\xd8":
            i = 2
            while i + 9 < len(head):
                if head[i] != 0xFF:
                    i += 1
                    continue
                marker = head[i + 1]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB):
                    h, w = struct.unpack(">HH", head[i + 5 : i + 9])
                    return {"format": "jpeg", "width": w, "height": h}
                seg_len = struct.unpack(">H", head[i + 2 : i + 4])[0]
                i += 2 + seg_len
            return {"format": "jpeg"}
        if head[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", head[6:10])
            return {"format": "gif", "width": w, "height": h}
        if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            return {"format": "webp"}
        if head[:2] == b"BM":
            w, h = struct.unpack("<ii", head[18:26])
            return {"format": "bmp", "width": abs(w), "height": abs(h)}
        if head[:4] == b"8BPS":
            h, w = struct.unpack(">II", head[14:22])
            return {"format": "psd", "width": w, "height": h}
    except Exception:
        return {}
    return {}


def iso_bmff_brand(head: bytes) -> Dict[str, object]:
    """ISO base media file format (mp4/m4a/mov): brand + basic track hint."""
    out: Dict[str, object] = {}
    if len(head) < 12 or head[4:8] != b"ftyp":
        return out
    try:
        major = head[8:12].decode("latin-1").strip()
        compat = head[16 : 16 + 4 * 4].decode("latin-1", "ignore") if len(head) > 16 else ""
        out["brand"] = major
        out["compatible"] = compat.replace("\x00", " ").strip()
        sample = head[:4096]
        out["has_video_track"] = b"vide" in sample or major in ("isom", "mp42", "avc1", "iso6", "M4V ")
        out["has_audio_track"] = b"soun" in sample or major in ("M4A ", "M4B ")
    except Exception:
        pass
    return out


def id3_tags(head: bytes) -> Dict[str, str]:
    """Read ID3v2 text frames (title/artist/album) from the first bytes."""
    tags: Dict[str, str] = {}
    if head[:3] != b"ID3" or len(head) < 20:
        return tags
    try:
        size = ((head[6] & 0x7F) << 21) | ((head[7] & 0x7F) << 14) | ((head[8] & 0x7F) << 7) | (head[9] & 0x7F)
        body = head[10 : 10 + min(size, 20000)]
        names = {"TIT2": "title", "TPE1": "artist", "TALB": "album", "TRCK": "track", "TCON": "genre"}
        i = 0
        while i + 10 <= len(body):
            fid = body[i : i + 4].decode("latin-1")
            fsize = struct.unpack(">I", body[i + 4 : i + 8])[0]
            if fsize <= 0 or i + 10 + fsize > len(body):
                break
            payload = body[i + 10 : i + 10 + fsize]
            if fid in names and payload:
                enc = payload[0]
                raw = payload[1:]
                if enc == 0:
                    text = raw.decode("latin-1", "replace")
                elif enc == 3:
                    text = raw.decode("utf-8", "replace")
                else:
                    text = raw.decode("utf-16", "replace")
                text = text.strip("\x00").strip()
                if text:
                    tags[names[fid]] = text[:80]
            i += 10 + fsize
    except Exception:
        return tags
    return tags


def matroska_info(head: bytes) -> Dict[str, object]:
    """Very small MKV/WebM probe: doctype is enough to split video vs audio."""
    out: Dict[str, object] = {}
    if head[:4] != b"\x1a\x45\xdf\xa3":
        return out
    for needle, value in ((b"matroska", "matroska"), (b"webm", "webm")):
        if needle in head[:4096]:
            out["doctype"] = value
    return out


def pdf_info(head: bytes) -> Dict[str, object]:
    out: Dict[str, object] = {}
    m = re.match(rb"%PDF-(\d\.\d)", head)
    if m:
        out["version"] = m.group(1).decode()
    if b"/Encrypt" in head:
        out["encrypted"] = True
    if b"/Linearized" in head:
        out["linearized"] = True
    return out


def ebook_hint(ext: str, head: bytes) -> Optional[str]:
    if ext in (".epub", ".mobi", ".azw3", ".djvu"):
        return "ebook"
    if ext == ".pdf":
        return "document"
    return None


def probe(ctx) -> Dict[str, object]:
    """One call the detectors use: everything media-ish about this file."""
    ext = ctx.suffix
    head = ctx.head(65536)
    info: Dict[str, object] = {}
    img = image_info(head)
    if img:
        info["image"] = img
    bmff = iso_bmff_brand(head)
    if bmff:
        info["iso_bmff"] = bmff
    tags = id3_tags(head)
    if tags:
        info["id3"] = tags
    mkv = matroska_info(head)
    if mkv:
        info["matroska"] = mkv
    pdf = pdf_info(head)
    if pdf:
        info["pdf"] = pdf
    if ext in (".zip", ".jar") and b"mimetypeapplication/epub+zip" in head:
        info["epub"] = True
    return info
