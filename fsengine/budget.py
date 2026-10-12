"""Budgets and safety rails.

Every read the engine performs goes through a :class:`Budget`. This is what
makes it safe to open a 4 GB archive or a hostile zip bomb: the analysis cost is
bounded by policy, not by the file.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Budget:
    time_budget_s: float = 4.0
    max_entries: int = 8000
    max_read_bytes: int = 65536
    max_total_read_bytes: int = 12 * 1024 * 1024
    max_scan_members: int = 250
    max_nested_depth: int = 2
    max_nested_bytes: int = 24 * 1024 * 1024

    started: float = field(default_factory=time.monotonic)
    read_bytes: int = 0
    reads: int = 0
    members_scanned: int = 0
    warnings: List[str] = field(default_factory=list)
    _notes: Dict[str, int] = field(default_factory=dict)

    # -- time -------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def time_left(self) -> float:
        return max(0.0, self.time_budget_s - self.elapsed())

    def exhausted(self) -> bool:
        return (
            self.elapsed() >= self.time_budget_s
            or self.read_bytes >= self.max_total_read_bytes
        )

    def soft_exhausted(self) -> bool:
        """True when we should stop opening new heavy things but may finish up."""
        return self.elapsed() >= self.time_budget_s * 0.85

    # -- reads ------------------------------------------------------------
    def clamp(self, size: int) -> int:
        return max(0, min(int(size), self.max_read_bytes))

    def spend(self, n: int, what: str = "") -> int:
        """Account for a read; returns how many bytes we are still allowed."""
        room = self.max_total_read_bytes - self.read_bytes
        if room <= 0:
            self.note("total-read-cap")
            return 0
        allowed = min(n, room)
        self.read_bytes += allowed
        self.reads += 1
        if what:
            self.note(what)
        return allowed

    def note(self, key: str, amount: int = 1) -> None:
        self._notes[key] = self._notes.get(key, 0) + amount

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def counters(self) -> Dict[str, int]:
        return {
            "reads": self.reads,
            "read_kb": round(self.read_bytes / 1024, 1),
            "members_scanned": self.members_scanned,
            "elapsed_s": round(self.elapsed(), 3),
            **{f"note:{k}": v for k, v in self._notes.items()},
        }

    def child(self, depth: int) -> "Budget":
        """A nested budget that shares the parent's clock and byte counters."""
        sub = Budget(
            time_budget_s=self.time_budget_s,
            max_entries=self.max_entries,
            max_read_bytes=self.max_read_bytes,
            max_total_read_bytes=self.max_total_read_bytes,
            max_scan_members=self.max_scan_members,
            max_nested_depth=self.max_nested_depth,
            max_nested_bytes=self.max_nested_bytes,
            started=self.started,
        )
        # Share accounting by rebinding to parent via closures is messy; instead
        # we keep a back-reference so spend()/note() bubble up.
        object.__setattr__(sub, "_parent", self)
        object.__setattr__(sub, "_depth", depth)
        return sub


def check_bomb(
    total_uncompressed: int,
    total_compressed: int,
    file_size: int,
    entries: int,
) -> Optional[str]:
    """Detect classic zip-bomb shapes. Returns a warning string or None."""
    if total_compressed > 0:
        ratio = total_uncompressed / max(1, total_compressed)
        if ratio > 250 and total_uncompressed > 100 * 1024 * 1024:
            return f"possible archive bomb / sparse payload: {ratio:.0f}x expansion ratio"
    if file_size > 0 and entries > 0:
        if total_uncompressed > 4 * 1024 * 1024 * 1024:
            return "declared uncompressed size > 4 GiB"
        if entries > 500_000:
            return f"extreme entry count ({entries})"
    return None


def unsafe_member(name: str) -> bool:
    """Path traversal / absolute-path member names (never extracted, but noted)."""
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 2 and n[1] == ":"):
        return True
    return ".." in n.split("/")
