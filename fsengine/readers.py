"""Bounded content reading: text decoding, signature grepping, bytecode scanning.

This module is the reason the engine can *look inside* things instead of trusting
names. Everything is capped by the :class:`Budget` and nothing is ever written to
disk.
"""
from __future__ import annotations

import codecs
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .budget import Budget
from .listing import CODE_EXTS, TEXTUAL_EXTS, Container, Entry, Listing

CHUNK = 128 * 1024


def decode_text(data: Optional[bytes]) -> str:
    """Tolerant decoding: BOM, UTF-8, UTF-16, CP1252 — in that order."""
    if not data:
        return ""
    for bom, enc in (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if data.startswith(bom):
            try:
                return data.decode(enc, "replace")
            except Exception:
                break
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if b"\x00" in data[:4096]:
        try:
            text = data.decode("utf-16", "replace")
            if text.count("\ufffd") < len(text) * 0.1:
                return text
        except Exception:
            pass
    return data.decode("cp1252", "replace")


def json_like(data: Optional[bytes]) -> Optional[dict]:
    """Parse JSON tolerating a UTF-8 BOM, CRLF and a leading comment."""
    if not data:
        return None
    import json

    text = decode_text(data).lstrip("\ufeff \t\r\n")
    # strip // or # comments some configs carry
    text = re.sub(r"^\s*(//|#).*$", "", text, flags=re.M)
    for candidate in (text, _strip_trailing_commas(text)):
        try:
            out = json.loads(candidate)
            return out if isinstance(out, dict) else {"__value__": out}
        except Exception:
            continue
    return None


def _strip_trailing_commas(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", text)


def read_text_member(
    container: Container, names: Sequence[str], limit: int = 65536
) -> Tuple[Optional[str], str]:
    """Read the first existent member from *names* and decode it."""
    name, data = container.read_first(names, limit=limit)
    if data is None:
        return None, ""
    return name, decode_text(data)


def grep_members(
    container: Container,
    listing: Listing,
    signatures: Dict[str, Sequence[str]],
    budget: Budget,
    exts: Optional[Set[str]] = None,
    max_members: Optional[int] = None,
    per_member_bytes: Optional[int] = None,
) -> Dict[str, List[str]]:
    """Scan bounded member contents for signature strings.

    ``signatures`` maps a signature id -> list of plain substrings (OR-ed).
    Returns signature id -> up to 3 member names where it was found.
    """
    found: Dict[str, List[str]] = {}
    remaining = {k: [s.lower() for s in v] for k, v in signatures.items()}
    if not remaining:
        return found
    exts = exts or (TEXTUAL_EXTS | CODE_EXTS)
    cap = max_members or budget.max_scan_members
    per_member = per_member_bytes or min(16384, budget.max_read_bytes)

    # Prefer source/config files, then small files, then the rest.
    def rank(e: Entry) -> Tuple[int, int]:
        textual = 0 if e.suffix in exts else 1
        if e.basename.lower() in ("package.json", "build.gradle", "pom.xml", "cargo.toml"):
            textual = -1
        return (textual, min(e.size, 200_000))

    scanned = 0
    for entry in sorted(listing.files, key=rank):
        if not remaining or scanned >= cap or budget.exhausted():
            break
        if entry.suffix not in exts and entry.size > 2_000_000:
            continue
        data = container.read_member(entry.name, limit=per_member)
        if not data:
            continue
        scanned += 1
        budget.members_scanned += 1
        text = decode_text(data).lower()
        if not text:
            continue
        for sig, needles in list(remaining.items()):
            if any(n in text for n in needles):
                found.setdefault(sig, [])
                if len(found[sig]) < 3:
                    found[sig].append(listing.rel_name(entry.name))
                remaining.pop(sig, None)
    return found


def member_head(container: Container, name: str, limit: int) -> bytes:
    data = container.read_member(name, limit=limit)
    return data or b""


def class_markers(data: bytes, markers: Sequence[str]) -> Set[str]:
    """Find package/plugin markers inside Java bytecode.

    Constant-pool strings are stored as modified UTF-8 with '/' separators, so a
    plain byte search for ``org/bukkit`` works and costs microseconds. We search
    for both ``a/b`` and ``a.b`` spellings plus the class-name-only form.
    """
    hits: Set[str] = set()
    if not data:
        return hits
    for marker in markers:
        variants = {marker, marker.replace("/", "."), marker.replace(".", "/")}
        leaf = marker.replace("/", ".").split(".")[-1]
        variants.add(leaf)
        for v in variants:
            if v and v.encode("utf-8", "ignore") in data:
                hits.add(marker)
                break
    return hits


def classify_member_head(data: bytes) -> str:
    """Quick magic check for a member's first bytes."""
    from .magic import sniff_head

    return sniff_head(data[:4096]).describe()


def text_stats(data: bytes) -> Dict[str, int]:
    """Rough stats used by heuristics (no decoding cost beyond one pass)."""
    if not data:
        return {"lines": 0, "bytes": 0}
    return {"lines": data.count(b"\n") + 1, "bytes": len(data)}
