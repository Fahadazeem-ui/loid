"""Format sniffing: magic bytes, container subtypes, and PE/binary metadata.

Deep candidates (Windows executables, Java bytecode, Unity/Electron/NSIS
installers) are identified from bytes, not from the file extension. This is one
of the biggest accuracy wins: a *misnamed* file no longer fools the sorter.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HEAD_SIZE = 4096

TEXT_KINDS = {"text", "json", "yaml", "xml", "html", "script", "code"}
ARCHIVE_KINDS = {"archive"}
BINARY_KINDS = {"executable", "binary", "image", "audio", "video", "document", "font", "database"}

_TRUTHY = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@dataclass
class MagicInfo:
    kind: str = "unknown"          # archive|executable|image|audio|video|document|text|binary|font|database
    subtype: str = ""              # zip|rar|pe|elf|pdf|ogg|...
    note: str = ""
    details: Dict[str, object] = field(default_factory=dict)

    @property
    def is_archive(self) -> bool:
        return self.kind == "archive"

    def describe(self) -> str:
        return f"{self.kind}/{self.subtype}" if self.subtype else self.kind


def sniff_head(head: bytes, size: int = 0) -> MagicInfo:
    """Classify a file from its first bytes (plus optional total size)."""
    h = head
    if not h:
        return MagicInfo("unknown", "", "empty file")

    # -- archives ---------------------------------------------------------
    if h[:4] in _TRUTHY:
        return MagicInfo("archive", "zip", "PKZIP container")
    if h[:4] == b"PK\x01\x02":
        return MagicInfo("archive", "zip", "zip central directory")
    if h[:7] == b"Rar!\x1a\x07\x00" or h[:8] == b"Rar!\x1a\x07\x01\x00":
        return MagicInfo("archive", "rar", "RAR (cannot be read without rarfile)")
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return MagicInfo("archive", "7z", "7-Zip container")
    if h[:2] == b"\x1f\x8b":
        return MagicInfo("archive", "gzip", "gzip stream")
    if h[:3] == b"BZh":
        return MagicInfo("archive", "bzip2", "bzip2 stream")
    if h[:6] == b"\xfd7zXZ\x00":
        return MagicInfo("archive", "xz", "xz stream")
    if len(h) > 262 and h[257:262] == b"ustar":
        return MagicInfo("archive", "tar", "POSIX tar")
    if h[:4] == b"MSCF":
        return MagicInfo("archive", "cab", "Microsoft Cabinet")
    if h[:4] == b"KDMV":
        return MagicInfo("archive", "vmdk", "VMware disk")
    if h[:4] == b"\x37\x7a\xbc\xaf":
        return MagicInfo("archive", "7z", "7-Zip container")

    # -- executables ------------------------------------------------------
    if h[:2] == b"MZ":
        return MagicInfo("executable", "pe", "Windows PE (MZ)", {"size": size})
    if h[:4] == b"\x7fELF":
        bits = "64-bit" if h[4] == 2 else "32-bit"
        etype = {1: "relocatable", 2: "executable", 3: "shared-library"}.get(
            int.from_bytes(h[16:18], "little"), "?"
        )
        return MagicInfo("executable", "elf", f"ELF {bits} {etype}")
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return MagicInfo("executable", "macho", "Mach-O binary")
    if h[:4] == b"\xca\xfe\xba\xbe":
        # 0xCAFEBABE is shared by Java .class and Mach-O fat binaries.
        nfat = int.from_bytes(h[4:8], "big")
        if 1 <= nfat <= 40:
            return MagicInfo("executable", "macho-fat", f"Mach-O universal ({nfat} arch)")
        major = int.from_bytes(h[6:8], "big")
        if 40 <= major <= 80:
            return MagicInfo("executable", "java-class", f"Java bytecode (major {major})")
        return MagicInfo("executable", "java-class", "Java bytecode")
    if h[:4] == b"\xd0\xcf\x11\xe0":
        return MagicInfo("document", "ole", "OLE compound file (MSI/DOC/XLS)")
    if h[:3] == b"ID3" or h[:2] == b"\xff\xfb" or h[:2] == b"\xff\xf3":
        return MagicInfo("audio", "mp3", "MP3")
    if h[:9] == b"%PDF-":
        return MagicInfo("document", "pdf", "PDF")
    if h[:5] == b"{\\rtf":
        return MagicInfo("document", "rtf", "RTF")

    # -- images / media ---------------------------------------------------
    images = {
        b"\x89PNG\r\n\x1a\n": ("png", "PNG image"),
        b"\xff\xd8\xff": ("jpeg", "JPEG image"),
        b"GIF87a": ("gif", "GIF image"),
        b"GIF89a": ("gif", "GIF image"),
        b"BM": ("bmp", "BMP image"),
        b"II*\x00": ("tiff", "TIFF image"),
        b"MM\x00*": ("tiff", "TIFF image"),
        b"8BPS": ("psd", "Photoshop document"),
        b"\x00\x00\x01\x00": ("ico", "Windows icon"),
    }
    for sig, (sub, note) in images.items():
        if h.startswith(sig):
            return MagicInfo("image", sub, note)
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return MagicInfo("image", "webp", "WebP image")
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return MagicInfo("audio", "wav", "WAV audio")
    if h[:4] == b"RIFF" and h[8:12] == b"AVI ":
        return MagicInfo("video", "avi", "AVI video")
    if h[:4] == b"OggS":
        return MagicInfo("audio", "ogg", "Ogg stream")
    if h[:4] == b"fLaC":
        return MagicInfo("audio", "flac", "FLAC audio")
    if h[:4] == b"\x1a\x45\xdf\xa3":
        return MagicInfo("video", "matroska", "Matroska/WebM")
    if h[4:8] == b"ftyp":
        brand = h[8:12].decode("latin-1", "replace").strip()
        sub = "mp4"
        if brand.startswith("M4A"):
            sub = "m4a"
        elif brand in ("qt  ",):
            sub = "mov"
        elif brand.startswith("3g"):
            sub = "3gp"
        return MagicInfo("video" if sub in ("mp4", "mov", "3gp") else "audio", sub, f"ISO-BMFF ({brand})")
    if h[:3] == b"FLV":
        return MagicInfo("video", "flv", "Flash video")

    # -- fonts / databases ------------------------------------------------
    if h[:4] in (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf"):
        return MagicInfo("font", "ttf" if h[:4] != b"OTTO" else "otf", "TrueType/OpenType font")
    if h[:4] in (b"wOFF", b"wOF2"):
        return MagicInfo("font", "woff", "Web font")
    if h[:15] == b"SQLite format 3":
        return MagicInfo("database", "sqlite", "SQLite database")


    # -- text-ish ---------------------------------------------------------
    text_info = sniff_text(h)
    if text_info:
        return text_info
    return MagicInfo("binary", "", "unknown binary")


_JSON_RE = re.compile(rb"^\s*[\{\[]")
_YAML_RE = re.compile(rb"^\s*(---|[\w.-]+\s*:)", re.M)
_XML_RE = re.compile(rb"^\s*<\?xml", re.M)
_HTML_RE = re.compile(rb"<(!doctype|html|head|body)", re.I)


def sniff_text(head: bytes) -> Optional[MagicInfo]:
    """Return a MagicInfo for text-ish payloads (json/yaml/xml/source)."""
    sample = head[:2048]
    if b"\x00" in sample and not (sample[:2] in (b"\xff\xfe", b"\xfe\xff")):
        # UTF-16 text contains NULs; check the alternating pattern.
        if not _looks_utf16(sample):
            return None
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = sample.decode("utf-16")
        except UnicodeDecodeError:
            return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if text and printable / max(1, len(text)) < 0.85:
        return None
    if _HTML_RE.search(sample):
        return MagicInfo("text", "html", "HTML document")
    if _XML_RE.search(sample):
        return MagicInfo("text", "xml", "XML document")
    if _JSON_RE.match(sample):
        return MagicInfo("text", "json", "JSON document")
    if _YAML_RE.match(sample):
        return MagicInfo("text", "yaml", "YAML document")
    if re.match(rb"^\s*(package|import|public|class|#!)", sample):
        return MagicInfo("text", "source", "source code")
    return MagicInfo("text", "", "plain text")


def _looks_utf16(sample: bytes) -> bool:
    even = sample[0::2]
    odd = sample[1::2]
    if not odd:
        return False
    return odd.count(0) / max(1, len(odd)) > 0.6 or even.count(0) / max(1, len(even)) > 0.6


# ---------------------------------------------------------------------------
# PE analysis (Windows executables) — installer/application identification
# ---------------------------------------------------------------------------

_INSTALLER_MARKERS: List[Tuple[bytes, str]] = [
    (b"Nullsoft", "NSIS installer"),
    (b"NSIS Error", "NSIS installer"),
    (b"Inno Setup", "Inno Setup installer"),
    (b"InstallShield", "InstallShield installer"),
    (b"WixBundle", "WiX Burn bundle"),
    (b"WiX Toolset", "WiX installer"),
    (b"Setup Factory", "Setup Factory installer"),
    (b"Qt Installer Framework", "Qt Installer Framework"),
    (b"Squirrel", "Squirrel updater app"),
    (b"pyi-", "PyInstaller bundle"),
    (b"python3", "Python-embedded app"),
    (b"UnityPlayer", "Unity engine"),
    (b"Unity Technologies", "Unity engine"),
    (b"UnrealEngine", "Unreal engine"),
    (b"Godot", "Godot engine"),
    (b"libgdx", "libGDX app"),
    (b"electron", "Electron app shell"),
    (b"nwjs", "NW.js app"),
    (b"Adobe AIR", "Adobe AIR app"),
    (b"Java Virtual Machine", "Java launcher"),
    (b"javaw", "Java launcher"),
    (b"7-Zip", "7-Zip SFX"),
    (b"WinRAR", "WinRAR SFX"),
    (b"AutoIt", "AutoIt script"),
    (b"AutoHotkey", "AutoHotkey script"),
    (b"MonoBundle", "Mono/.NET app"),
    (b"mscoree.dll", ".NET assembly"),
]

_VERSION_KEYS = [
    "ProductName",
    "FileDescription",
    "CompanyName",
    "OriginalFilename",
    "InternalName",
    "ProductVersion",
    "FileVersion",
    "LegalCopyright",
]


def pe_header_info(head: bytes) -> Dict[str, object]:
    """Parse enough of the PE header to know what kind of binary this is."""
    info: Dict[str, object] = {}
    try:
        if head[:2] != b"MZ" or len(head) < 0x40:
            return info
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if e_lfanew + 24 > len(head) or head[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return info
        machine = struct.unpack_from("<H", head, e_lfanew + 4)[0]
        n_sections = struct.unpack_from("<H", head, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", head, e_lfanew + 20)[0]
        characteristics = struct.unpack_from("<H", head, e_lfanew + 22)[0]
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", head, opt_off)[0]
        info["machine"] = {
            0x014C: "x86",
            0x8664: "x86-64",
            0xAA64: "arm64",
            0x01C4: "arm",
        }.get(machine, hex(machine))
        info["pe"] = "PE32+" if magic == 0x20B else "PE32"
        info["dll"] = bool(characteristics & 0x2000)
        info["sections"] = n_sections
        subsystem_off = opt_off + (0x5C if magic == 0x20B else 0x44)
        if subsystem_off + 2 <= len(head):
            subsystem = struct.unpack_from("<H", head, subsystem_off)[0]
            info["subsystem"] = {2: "GUI", 3: "console", 1: "native"}.get(subsystem, str(subsystem))
        # CLR (data directory 14) -> .NET
        dd_off = opt_off + (0x70 if magic == 0x20B else 0x60)
        clr_off = dd_off + 14 * 8
        if clr_off + 8 <= len(head):
            rva, sz = struct.unpack_from("<II", head, clr_off)
            info["dotnet"] = bool(rva) and bool(sz)
        info["sections_list"] = _pe_sections(head, e_lfanew, opt_size, n_sections)
    except Exception:  # pragma: no cover - malformed PE
        return info
    return info


def _pe_sections(head: bytes, e_lfanew: int, opt_size: int, n_sections: int) -> List[str]:
    names: List[str] = []
    off = e_lfanew + 24 + opt_size
    for i in range(min(n_sections, 40)):
        base = off + i * 40
        if base + 8 > len(head):
            break
        raw = head[base : base + 8].rstrip(b"\x00")
        names.append(raw.decode("latin-1", "replace"))
    return names


def pe_markers(data: bytes) -> List[str]:
    """Framework / installer markers found anywhere in the sample bytes."""
    found: List[str] = []
    for marker, label in _INSTALLER_MARKERS:
        if marker in data and label not in found:
            found.append(label)
    return found


class PeVersionInfo(dict):
    """ProductName / CompanyName / FileDescription and friends."""


def pe_version_info(data: bytes) -> PeVersionInfo:
    """Extract VS_VERSION_INFO fields from a raw byte sample.

    Rather than walking the resource directory (fragile across packers), we look
    for the UTF-16LE keys of the StringFileInfo block and take the following
    UTF-16 string. This survives most packers and is cheap.
    """
    out = PeVersionInfo()
    if not data:
        return out
    for key in _VERSION_KEYS:
        patterns = [key.encode("utf-16-le"), key.encode("ascii")]
        for pat in patterns:
            idx = data.find(pat)
            if idx < 0:
                continue
            start = idx + len(pat)
            # skip NULs / padding, then read a UTF-16LE string
            while start < len(data) and data[start] in (0, 32):
                start += 1
            if start + 4 > len(data):
                continue
            end = start
            while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
                if end - start > 512:
                    break
                end += 2
            raw = data[start:end]
            try:
                value = raw.decode("utf-16-le").strip("\x00").strip()
            except UnicodeDecodeError:
                continue
            if value and _printable_ratio(value) > 0.9 and key not in out:
                out[key] = value
                break
    return out


def utf16_strings(data: bytes, min_len: int = 5, limit: int = 60) -> List[str]:
    """Cheap UTF-16LE printable-string extractor (used by AI-free heuristics)."""
    out: List[str] = []
    cur = bytearray()
    i = 0
    while i + 1 < len(data) and len(out) < limit:
        ch = data[i : i + 2]
        if ch[1] == 0 and 32 <= ch[0] < 127:
            cur += ch
            i += 2
            continue
        if len(cur) >= min_len * 2:
            out.append(cur.decode("utf-16-le"))
        cur = bytearray()
        i += 2
    if len(cur) >= min_len * 2:
        out.append(cur.decode("utf-16-le"))
    return out


def ascii_strings(data: bytes, min_len: int = 5, limit: int = 400) -> List[str]:
    out: List[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin-1"))
                if len(out) >= limit:
                    return out
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("latin-1"))
    return out


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in " \t")
    return good / len(text)
