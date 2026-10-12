"""The analysis context: everything a detector may look at, plus helper lookups."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .budget import Budget
from .knowledge import SECRET_PATTERNS
from .listing import Container, Listing, suffix_of
from .magic import MagicInfo, sniff_head
from .model import Config, Evidence, normalize_name


@dataclass
class AnalysisContext:
    """One file (or nested member) under analysis."""

    path: Path
    config: Config
    budget: Budget
    container: Optional[Container] = None
    listing: Optional[Listing] = None
    magic: MagicInfo = field(default_factory=MagicInfo)
    nested_depth: int = 0
    parent: Optional["AnalysisContext"] = None
    cache: Dict[str, Any] = field(default_factory=dict)
    extras: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    nested_results: List[Any] = field(default_factory=list)
    child_analyzer: Optional[Callable[[bytes, str, float], Optional[Any]]] = None

    # -- identity ---------------------------------------------------------
    @property
    def name(self) -> str:
        return self.path.name

    @property
    def base_name(self) -> str:
        return normalize_name(self.name)[0]

    @property
    def modifiers(self) -> List[str]:
        return normalize_name(self.name)[1]

    @property
    def suffix(self) -> str:
        return suffix_of(self.base_name)

    @property
    def size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    @property
    def kind(self) -> str:
        if self.container is None:
            return "file"
        return self.container.kind

    @property
    def is_archive(self) -> bool:
        return self.kind in ("zip", "tar", "zip-unreadable")

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"

    @property
    def readable(self) -> bool:
        return self.listing is not None and bool(self.listing.files)

    @property
    def names(self) -> List[str]:
        return self.listing.name_lower if self.listing else []

    # -- lookups ----------------------------------------------------------
    def has(self, *basenames: str) -> bool:
        return bool(self.listing and self.listing.has_basename(*basenames))

    def find(self, *basenames: str) -> Optional[str]:
        return self.listing.find_basename(*basenames) if self.listing else None

    def read(self, name: str, limit: Optional[int] = None) -> Optional[bytes]:
        if self.container is None or not name:
            return None
        if self.budget.exhausted():
            return None
        data = self.container.read_member(name, limit=limit)
        if data:
            self.budget.note("inspected-files")
        return data

    def read_first(self, names: Sequence[str], limit: Optional[int] = None) -> Tuple[Optional[str], Optional[bytes]]:
        """Find + read the first existent member among *names*."""
        if self.container is None:
            return None, None
        for want in names:
            hit = self.find(want)
            if hit is None and "/" in want and self.listing:
                for cand in self.listing.names(rel=False):
                    if cand.lower().endswith("/" + want.lower()):
                        hit = cand
                        break
            if hit:
                data = self.read(hit, limit=limit)
                if data is not None:
                    return want, data
        return None, None

    def head(self, limit: int = 4096) -> bytes:
        if self.container is not None:
            return self.container.head_bytes(limit)
        try:
            with open(self.path, "rb") as fh:
                return fh.read(limit)
        except OSError:
            return b""

    def tail(self, limit: int = 4096) -> bytes:
        if self.container is not None:
            return self.container.tail_bytes(limit)
        try:
            size = self.path.stat().st_size
            with open(self.path, "rb") as fh:
                fh.seek(max(0, size - limit))
                return fh.read(limit)
        except OSError:
            return b""

    # -- bookkeeping ------------------------------------------------------
    def note(self, key: str, value: Any = None) -> None:
        if value is None:
            self.extras.setdefault(key, True)
        else:
            self.extras[key] = value

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
        self.budget.warn(message)

    def set_finding(self, kind: str, detail: str, member: str = "") -> None:
        findings = self.extras.setdefault("findings", [])
        for f in findings:
            if f.get("type") == kind and f.get("detail") == detail and f.get("member") == member:
                return
        findings.append({"type": kind, "detail": detail, "member": member})

    def child(self, data: bytes, display_name: str, discount: float = 0.6) -> Optional[Any]:
        if self.child_analyzer is None:
            return None
        if self.budget.soft_exhausted() or self.budget.exhausted():
            self.note("nested-skipped-budget")
            return None
        return self.child_analyzer(data, display_name, discount)

    def desc(self) -> str:
        parts = [f"{self.name} ({self.kind}"]
        if self.listing:
            parts.append(f", {len(self.listing.files)} files")
        parts.append(")")
        if self.modifiers:
            parts.append(f" modifiers={','.join(self.modifiers)}")
        return "".join(parts)


def make_context(
    path: Path,
    config: Config,
    budget: Budget,
    nested_depth: int = 0,
    parent: Optional[AnalysisContext] = None,
) -> AnalysisContext:
    """Build a context for a path, opening its container if it has one."""
    from .listing import open_container

    ctx = AnalysisContext(path=path, config=config, budget=budget, nested_depth=nested_depth, parent=parent)
    container = open_container(path, budget, display_name=path.name)
    if container is not None:
        ctx.container = container
        ctx.magic = container.magic
        if container.kind in ("zip", "tar", "dir"):
            ctx.listing = container.listing
            # record listing warnings/safety notes
            if ctx.listing:
                if ctx.listing.truncated:
                    ctx.note("listing_truncated", True)
                bomb = ctx.listing.bomb_warning()
                if bomb:
                    ctx.note("archive_warning", bomb)
                traversal = ctx.listing.traversal_members()
                if traversal:
                    ctx.note("unsafe_member_paths", traversal)
    else:
        ctx.magic = sniff_head(ctx.head(4096), ctx.size)
    return ctx
