"""Container handles and listings.

A *listing* is what we read most of the time: the names/sizes inside an archive
cost almost nothing (the zip central directory is a few KB), and they carry a
surprising amount of identity — `assets/minecraft/models/`, `.class`, `cogs/`,
`*.fsh`, `runtimeconfig.json`, `project.godot`.

Nothing here ever extracts to disk. Members are read into bounded memory only.
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .budget import Budget, check_bomb, unsafe_member
from .magic import MagicInfo, sniff_head

TEXTUAL_EXTS = {
    ".txt", ".md", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".html", ".htm", ".js", ".cjs", ".mjs", ".ts", ".tsx",
    ".jsx", ".py", ".java", ".kt", ".kts", ".rs", ".go", ".php", ".rb", ".cs",
    ".sh", ".bat", ".cmd", ".ps1", ".gradle", ".env", ".mcmeta", ".mcfunction",
    ".fsh", ".vsh", ".glsl", ".frag", ".vert", ".gitignore", ".editorconfig",
    ".lua", ".sql", ".css", ".scss", ".vue", ".svelte", ".dockerfile", ".lock",
}

CODE_EXTS = {
    ".js", ".cjs", ".mjs", ".ts", ".py", ".java", ".kt", ".rs", ".go", ".php",
    ".rb", ".cs", ".sh", ".bat", ".cmd", ".ps1", ".gradle",
}


def suffix_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1]


def parts_of(name: str) -> List[str]:
    return [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]


@dataclass
class Entry:
    name: str
    size: int = 0
    compressed: int = 0
    is_dir: bool = False
    mode: int = 0

    @property
    def clean(self) -> str:
        return self.name.replace("\\", "/")

    @property
    def basename(self) -> str:
        return self.clean.rsplit("/", 1)[-1]

    @property
    def suffix(self) -> str:
        return suffix_of(self.clean)

    @property
    def parts(self) -> List[str]:
        return parts_of(self.clean)

    @property
    def depth(self) -> int:
        return len(self.parts)

    @property
    def lower(self) -> str:
        return self.clean.lower()


class Listing:
    """Names inside one container, with fast lookup helpers."""

    def __init__(
        self,
        entries: Sequence[Entry],
        comment: str = "",
        kind: str = "zip",
        file_size: int = 0,
        truncated: bool = False,
        extra_dirs: Optional[Iterable[str]] = None,
    ):
        self.all_entries: List[Entry] = list(entries)
        self.comment = comment
        self.kind = kind
        self.file_size = file_size
        self.truncated = truncated
        self.extra_dirs = list(extra_dirs or [])
        self.files: List[Entry] = [e for e in self.all_entries if not e.is_dir]
        self.dirs: List[str] = sorted(set(extra_dirs or []) | {e.clean for e in self.all_entries if e.is_dir})
        self.wrapper = self._detect_wrapper()
        self._name_lower: Optional[List[str]] = None
        self._basenames: Optional[Dict[str, str]] = None
        self._ext_counter: Optional[Counter] = None

    # -- basic views ------------------------------------------------------
    def _detect_wrapper(self) -> str:
        """If every entry lives under one top folder, remember that prefix.

        This is *informational only*. An earlier version stripped the wrapper
        before matching, which destroyed real content roots: a resource pack
        whose every file starts with ``assets/`` looked like an archive wrapped
        in an "assets" folder, and the pack signatures stopped matching.
        """
        tops: Set[str] = set()
        for e in self.files:
            parts = e.parts
            if len(parts) < 2:
                return ""
            tops.add(parts[0])
            if len(tops) > 1:
                return ""
        return tops.pop() if len(tops) == 1 else ""

    def rel_name(self, name: str) -> str:
        """Display helper: drop the wrapper prefix when there is one."""
        if self.wrapper and name.startswith(self.wrapper + "/"):
            return name[len(self.wrapper) + 1 :]
        return name

    def names(self, rel: bool = True, lower: bool = False) -> List[str]:
        """Member paths. Matching always uses the *full* path: signatures are
        segment-aware, so 'shaders/*.fsh' means a shaders folder with one level,
        not 'anything that ends in .fsh'."""
        out = [e.clean for e in self.files]
        return [n.lower() for n in out] if lower else out

    @property
    def name_lower(self) -> List[str]:
        if self._name_lower is None:
            self._name_lower = self.names(lower=True)
        return self._name_lower

    @property
    def name_lower_raw(self) -> List[str]:
        return [e.lower for e in self.files]

    @property
    def basename_map(self) -> Dict[str, str]:
        if self._basenames is None:
            m: Dict[str, str] = {}
            for e in self.files:
                m.setdefault(e.basename.lower(), e.clean)
            self._basenames = m
        return self._basenames

    @property
    def ext_counts(self) -> Counter:
        if self._ext_counter is None:
            self._ext_counter = Counter(e.suffix for e in self.files)
        return self._ext_counter

    def find_basename(self, *names: str) -> Optional[str]:
        for n in names:
            hit = self.basename_map.get(n.lower())
            if hit:
                return hit
        return None

    def has_basename(self, *names: str) -> bool:
        return self.find_basename(*names) is not None

    def has_dir(self, *dir_names: str) -> bool:
        """Directory present at any depth (or matching the tail of a path)."""
        want = {d.lower().strip("/") for d in dir_names}
        if want & {d.lower().strip("/") for d in self.dirs}:
            return True
        for n in self.name_lower:
            segs = n.split("/")[:-1]
            if want & set(segs):
                return True
        return False

    def dir_hits(self, *dir_names: str) -> int:
        want = {d.lower().strip("/") for d in dir_names}
        hits = 0
        for n in self.name_lower:
            if want & set(n.split("/")[:-1]):
                hits += 1
        return hits

    def matching(self, *patterns: str, regex=None) -> List[str]:
        import fnmatch

        out: List[str] = []
        pats = [p.lower() for p in patterns]
        for n in self.name_lower:
            for p in pats:
                if fnmatch.fnmatchcase(n, p) or fnmatch.fnmatchcase(n, "*/" + p):
                    out.append(n)
                    break
            else:
                if regex is not None and regex.search(n):
                    out.append(n)
        return out

    def contain(self, *substrings: str, limit: int = 6) -> List[str]:
        subs = [s.lower() for s in substrings]
        out: List[str] = []
        for n in self.name_lower:
            if any(s in n for s in subs):
                out.append(n)
                if len(out) >= limit:
                    break
        return out

    def top_roots(self) -> List[str]:
        roots: List[str] = []
        seen: Set[str] = set()
        for e in self.files:
            top = e.parts[0] if e.parts else e.clean
            if len(e.parts) == 1:
                top = "(file)" if top else top
            if top not in seen:
                seen.add(top)
                roots.append(top)
        return roots

    def multi_root_score(self) -> Tuple[int, float]:
        """(distinct project roots, fraction of files inside the largest root)."""
        counts: Counter = Counter()
        for e in self.files:
            counts[e.parts[0] if len(e.parts) > 1 else e.basename] += 1
        if not counts:
            return 0, 0.0
        top = counts.most_common(1)[0]
        return len(counts), top[1] / max(1, len(self.files))

    def total_uncompressed(self) -> int:
        return sum(e.size for e in self.files)

    def total_compressed(self) -> int:
        return sum(e.compressed for e in self.files)

    def bomb_warning(self) -> Optional[str]:
        return check_bomb(
            self.total_uncompressed(), self.total_compressed(), self.file_size, len(self.files)
        )

    def traversal_members(self, limit: int = 5) -> List[str]:
        return [e.clean for e in self.files if unsafe_member(e.clean)][:limit]

    # -- output helpers ---------------------------------------------------
    def summary_text(self, max_names: int = 60, max_line: int = 160) -> str:
        exts = ", ".join(f"{k or '(none)'}x{v}" for k, v in self.ext_counts.most_common(10))
        roots = self.top_roots()
        lines = [
            f"format={self.kind} files={len(self.files)} dirs={len(self.dirs)} "
            f"uncompressed={self.total_uncompressed()}",
            f"top-level: {', '.join(roots[:12])}{' ...' if len(roots) > 12 else ''}",
            f"extensions: {exts}",
        ]
        if self.wrapper:
            lines.append(f"single wrapper folder: {self.wrapper}/")
        names = self.names(rel=True)
        sample = sorted(names, key=lambda n: (n.count('/'), len(n)))[:max_names]
        lines.append("sample: " + " | ".join(sample))
        return "\n".join(line[:max_line] for line in lines)


# ---------------------------------------------------------------------------
# Container handles
# ---------------------------------------------------------------------------


class Container:
    """Uniform access to a zip / tar / directory / single file."""

    def __init__(
        self,
        path: Optional[Path] = None,
        data: Optional[bytes] = None,
        budget: Optional[Budget] = None,
        display_name: Optional[str] = None,
    ):
        self.path = Path(path) if path else None
        self.data = data
        self.budget = budget or Budget()
        self.display_name = display_name or (self.path.name if self.path else "<memory>")
        self.kind = "file"
        self.magic: MagicInfo = MagicInfo()
        self._listing: Optional[Listing] = None
        self._zip: Optional[zipfile.ZipFile] = None
        self._tar: Optional[tarfile.TarFile] = None
        self._bytes_io: Optional[io.BytesIO] = None
        self.file_size = 0
        self._closed = False
        self._open_error: Optional[str] = None
        self._open()

    # -- opening ----------------------------------------------------------
    def _open(self) -> None:
        try:
            if self.path is not None:
                self.file_size = self.path.stat().st_size
            elif self.data is not None:
                self.file_size = len(self.data)
        except OSError:
            self.file_size = 0
        head = self.head_bytes(4096)
        self.magic = sniff_head(head, self.file_size)
        if self.path is not None and self.path.is_dir():
            self.kind = "dir"
            return
        if self.data is not None and self.path is None:
            self._bytes_io = io.BytesIO(self.data)
        if self.magic.is_archive:
            if self.magic.subtype == "zip":
                self._open_zip()
            elif self.magic.subtype in ("tar", "gzip", "bzip2", "xz"):
                self._open_tar()
            else:
                self.kind = self.magic.subtype
        elif self._looks_like_zip_without_signature():
            self._open_zip()

    def _source(self):
        if self._bytes_io is not None:
            self._bytes_io.seek(0)
            return self._bytes_io
        if self.path is not None:
            return str(self.path)
        return None

    def _open_zip(self) -> None:
        src = self._source()
        if src is None:
            return
        try:
            self._zip = zipfile.ZipFile(src)
            self.kind = "zip"
        except Exception as exc:  # corrupt / encrypted central dir
            self._open_error = f"zip open failed: {exc}"
            self.kind = "zip-unreadable"
            self.budget.warn(f"{self.display_name}: {self._open_error}")

    def _open_tar(self) -> None:
        src = self._source()
        if src is None:
            return
        try:
            if isinstance(src, io.BytesIO):
                src.seek(0)
            self._tar = tarfile.open(fileobj=src if isinstance(src, io.BytesIO) else None,
                                     name=None if isinstance(src, io.BytesIO) else src,
                                     mode="r:*")
            self.kind = "tar"
        except Exception:
            self.kind = "file"  # bare .gz of a single file

    def _looks_like_zip_without_signature(self) -> bool:
        """Some zips start with a self-extractor stub or SFX header."""
        if self.kind == "dir":
            return False
        if self.magic.subtype == "pe":
            # SFX archives (7-Zip/WinRAR self-extractors) carry a real zip inside.
            data = self.head_bytes(1_500_000)
            idx = data.find(b"PK\x03\x04")
            if idx > 0:
                self.budget.note("sfx-archive")
                return True
        return False

    def _is_sfx(self) -> bool:
        return self.magic.subtype == "pe" and self.head_bytes(1_500_000).find(b"PK\x03\x04") > 0

    # -- reading ----------------------------------------------------------
    def head_bytes(self, n: int) -> bytes:
        n = max(0, n)
        try:
            if self.data is not None:
                return self.data[:n]
            if self.path is None or self.path.is_dir():
                return b""
            with open(self.path, "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def tail_bytes(self, n: int) -> bytes:
        try:
            if self.data is not None:
                return self.data[-n:]
            if self.path is None or self.path.is_dir():
                return b""
            size = self.path.stat().st_size
            with open(self.path, "rb") as fh:
                fh.seek(max(0, size - n))
                return fh.read(n)
        except OSError:
            return b""

    @property
    def is_sfx(self) -> bool:
        return self.magic.subtype == "pe" and b"PK\x03\x04" in self.head_bytes(1_500_000)

    # -- listing ----------------------------------------------------------
    @property
    def listing(self) -> Optional[Listing]:
        if self._listing is not None:
            return self._listing
        if self.kind == "dir":
            self._listing = self._list_dir()
        elif self.kind == "zip":
            self._listing = self._list_zip()
        elif self.kind == "tar":
            self._listing = self._list_tar()
        return self._listing

    def _list_zip(self) -> Optional[Listing]:
        assert self._zip is not None
        entries: List[Entry] = []
        truncated = False
        try:
            infos = self._zip.infolist()
        except Exception as exc:
            self.budget.warn(f"{self.display_name}: listing failed ({exc})")
            return None
        if len(infos) > self.budget.max_entries:
            truncated = True
            self.budget.note("listing-truncated")
            infos = infos[: self.budget.max_entries]
        for info in infos:
            entries.append(
                Entry(
                    name=info.filename,
                    size=info.file_size,
                    compressed=info.compress_size,
                    is_dir=info.is_dir(),
                    mode=info.external_attr >> 16,
                )
            )
        comment = ""
        try:
            comment = (self._zip.comment or b"").decode("utf-8", "replace")
        except Exception:
            comment = ""
        return Listing(entries, comment=comment, kind="zip", file_size=self.file_size, truncated=truncated)

    def _list_tar(self) -> Optional[Listing]:
        assert self._tar is not None
        entries: List[Entry] = []
        truncated = False
        try:
            for i, member in enumerate(self._tar):
                if i >= self.budget.max_entries:
                    truncated = True
                    self.budget.note("listing-truncated")
                    break
                entries.append(
                    Entry(
                        name=member.name,
                        size=member.size,
                        compressed=0,
                        is_dir=member.isdir(),
                        mode=member.mode,
                    )
                )
        except Exception as exc:
            self.budget.warn(f"{self.display_name}: tar listing failed ({exc})")
        return Listing(entries, kind="tar", file_size=self.file_size, truncated=truncated)

    def _list_dir(self) -> Listing:
        entries: List[Entry] = []
        truncated = False
        assert self.path is not None
        count = 0
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")][:200]
            rel = os.path.relpath(root, self.path)
            rel = "" if rel == "." else rel.replace(os.sep, "/") + "/"
            for d in dirs:
                entries.append(Entry(name=rel + d, is_dir=True))
            for f in files:
                count += 1
                if count > self.budget.max_entries:
                    truncated = True
                    break
                try:
                    size = os.path.getsize(os.path.join(root, f))
                except OSError:
                    size = 0
                entries.append(Entry(name=rel + f, size=size))
            if truncated:
                self.budget.note("listing-truncated")
                break
        return Listing(entries, kind="dir", file_size=self.file_size, truncated=truncated)

    # -- member reads -----------------------------------------------------
    def read_member(self, name: str, limit: Optional[int] = None) -> Optional[bytes]:
        limit = self.budget.clamp(limit or self.budget.max_read_bytes)
        try:
            if self.kind == "zip" and self._zip is not None:
                with self._zip.open(name) as fh:
                    allowed = self.budget.spend(limit, "member-read")
                    return fh.read(allowed) if allowed else b""
            if self.kind == "tar" and self._tar is not None:
                member = self._tar.getmember(name)
                fh = self._tar.extractfile(member)
                if fh is None:
                    return None
                allowed = self.budget.spend(min(limit, max(0, member.size)), "member-read")
                return fh.read(allowed) if allowed else b""
            if self.kind == "dir" and self.path is not None:
                fpath = self.path / name
                if not fpath.is_file():
                    return None
                with open(fpath, "rb") as fh:
                    allowed = self.budget.spend(limit, "member-read")
                    return fh.read(allowed) if allowed else b""
        except (KeyError, zipfile.BadZipFile, RuntimeError, OSError) as exc:
            self.budget.warn(f"{self.display_name}: cannot read {name} ({exc})")
            return None
        return None

    def read_first(self, names: Sequence[str], limit: Optional[int] = None) -> Tuple[Optional[str], Optional[bytes]]:
        listing = self.listing
        if listing is None:
            return None, None
        for want in names:
            hit = listing.find_basename(want) if "/" not in want else None
            if hit is None:
                for cand in listing.names(rel=False):
                    if cand.lower().endswith("/" + want.lower()) or cand.lower() == want.lower():
                        hit = cand
                        break
            if hit:
                data = self.read_member(hit, limit)
                if data is not None:
                    return want, data
        return None, None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in (self._zip, self._tar):
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
        if self._bytes_io is not None:
            try:
                self._bytes_io.close()
            except Exception:
                pass

    def __enter__(self) -> "Container":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def open_container(
    path: Path,
    budget: Budget,
    display_name: Optional[str] = None,
) -> Optional[Container]:
    try:
        return Container(path=path, budget=budget, display_name=display_name)
    except Exception as exc:  # pragma: no cover - defensive
        budget.warn(f"cannot open {path}: {exc}")
        return None


def open_bytes(data: bytes, budget: Budget, display_name: str) -> Optional[Container]:
    try:
        return Container(data=data, budget=budget, display_name=display_name)
    except Exception as exc:  # pragma: no cover - defensive
        budget.warn(f"cannot open nested {display_name}: {exc}")
        return None
