"""Core data structures, taxonomy and configuration."""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Archive name modifiers: ".jar.disabled", "mod.jar.old", "pack.zip.bak"
# The engine always judges a file by its *base* name first, then falls back.
# --------------------------------------------------------------------------
MODIFIER_SUFFIXES = (
    "disabled", "old", "bak", "backup", "orig", "original", "save", "tmp",
    "part", "download", "crdownload", "bak2", "1", "2", "3", "copy", "unused",
)
_MODIFIER_RE = re.compile(r"\.(" + "|".join(MODIFIER_SUFFIXES) + r")$", re.IGNORECASE)


def normalize_name(name: str) -> Tuple[str, List[str]]:
    """Return (base_name, stripped_modifiers).

    "MyMod-1.20.jar.disabled" -> ("MyMod-1.20.jar", ["disabled"])
    """
    stripped: List[str] = []
    cur = os.path.basename(name)
    while True:
        m = _MODIFIER_RE.search(cur)
        if not m:
            break
        stripped.append(m.group(1).lower())
        cur = cur[: m.start()]
    return cur, stripped


def name_tokens(name: str) -> List[str]:
    """Split a file name into lowercase tokens ('MyPack_v1.2-1.20.x' -> [...])."""
    stem = os.path.splitext(normalize_name(name)[0])[0]
    return [t for t in re.split(r"[^a-z0-9]+", stem.lower()) if t]


def slugify(text: str, fallback: str = "file") -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-._")
    return out or fallback


# --------------------------------------------------------------------------
# Taxonomy: label -> destination folder (relative to the sorted root).
# Archives are routed by *content identity*; they only land in "Archives" when
# their content truly cannot be identified (rar/7z/encrypted/mixed junk).
# --------------------------------------------------------------------------
TAXONOMY: Dict[str, str] = {
    # --- Minecraft -------------------------------------------------------
    "mc.mod":            "Minecraft/Mods",
    "mc.plugin":         "Minecraft/Plugins",
    "mc.shaderpack":     "Minecraft/Shaderpacks",
    "mc.resourcepack":   "Minecraft/Resourcepacks",
    "mc.datapack":       "Minecraft/Datapacks",
    "mc.modpack":        "Minecraft/Modpacks",
    "mc.world":          "Minecraft/Worlds",
    "mc.server":         "Minecraft/Servers",
    "mc.other":          "Minecraft/Other",
    # --- Developer -------------------------------------------------------
    "dev.discordbot":    "Developer/Discord-Bots",
    "dev.telegrambot":   "Developer/Bots/Telegram",
    "dev.gamebot":       "Developer/Bots/Minecraft-AFK",
    "dev.vscodeext":     "Developer/Editors/VSCode-Extensions",
    "dev.obsidianplugin": "Developer/Editors/Obsidian-Plugins",
    "dev.browserext":    "Developer/Browsers/Extensions",
    "dev.wordpressplugin": "Developer/Web/WordPress",
    "dev.python":        "Developer/Python",
    "dev.node":          "Developer/Node",
    "dev.java":          "Developer/Java",
    "dev.rust":          "Developer/Rust",
    "dev.go":            "Developer/Go",
    "dev.dotnet":        "Developer/DotNet",
    "dev.web":           "Developer/Web",
    "dev.shell":         "Developer/Scripts",
    "dev.other":         "Developer/Other",
    # --- Software --------------------------------------------------------
    "sw.installer":      "Software/Installers",
    "sw.portable":       "Software/Portable",
    "sw.android":        "Software/Android",
    "sw.game":           "Games",
    "sw.library":        "Software/Libraries",
    # --- Media / documents ----------------------------------------------
    "media.video":       "Media/Video",
    "media.audio":       "Media/Audio",
    "media.image":       "Media/Images",
    "media.font":        "Media/Fonts",
    "media.ebook":       "Media/Ebooks",
    "media.other":       "Media/Other",
    "doc.pdf":           "Documents/PDF",
    "doc.office":        "Documents/Office",
    "doc.text":          "Documents/Text",
    "doc.data":          "Documents/Data",
    "doc.code":          "Documents/Code",
    # --- Fallbacks -------------------------------------------------------
    "misc.collection":   "Collections",
    "misc.other":        "Other",
    "misc.review":       "_Review",
}

LABEL_TITLES: Dict[str, str] = {
    "mc.mod": "Minecraft Mod",
    "mc.plugin": "Minecraft Server Plugin",
    "mc.shaderpack": "Minecraft Shaderpack (Iris/OptiFine)",
    "mc.resourcepack": "Minecraft Resource Pack",
    "mc.datapack": "Minecraft Data Pack",
    "mc.modpack": "Minecraft Modpack",
    "mc.world": "Minecraft World Save",
    "mc.server": "Minecraft Server Bundle",
    "mc.other": "Minecraft Item",
    "dev.discordbot": "Discord Bot (source)",
    "dev.telegrambot": "Telegram Bot (source)",
    "dev.gamebot": "Game/AFK Bot (source)",
    "dev.vscodeext": "VS Code Extension",
    "dev.obsidianplugin": "Obsidian Plugin",
    "dev.browserext": "Browser Extension",
    "dev.wordpressplugin": "WordPress Plugin",
    "dev.python": "Python Project",
    "dev.node": "Node/JS Project",
    "dev.java": "Java Project",
    "dev.rust": "Rust Project",
    "dev.go": "Go Project",
    "dev.dotnet": "C#/.NET Project",
    "dev.web": "Web Project",
    "dev.shell": "Script / Batch File",
    "dev.other": "Source Project",
    "sw.installer": "Installer",
    "sw.portable": "Application / Portable Program",
    "sw.android": "Android Package",
    "sw.game": "Game / Game Data",
    "sw.library": "Library / Runtime",
    "media.video": "Video",
    "media.audio": "Audio",
    "media.image": "Image",
    "media.font": "Font",
    "media.ebook": "Ebook",
    "media.other": "Media",
    "doc.pdf": "PDF Document",
    "doc.office": "Office Document",
    "doc.text": "Text Document",
    "doc.data": "Data File",
    "doc.code": "Source File",
    "misc.collection": "Mixed Collection",
    "misc.other": "Other",
    "misc.review": "Needs Review",
}

# Coarse family used when a bundle contains several *different* kinds of thing.
FAMILY: Dict[str, str] = {
    "mc.mod": "Minecraft", "mc.plugin": "Minecraft", "mc.shaderpack": "Minecraft",
    "mc.resourcepack": "Minecraft", "mc.datapack": "Minecraft",
    "mc.modpack": "Minecraft", "mc.world": "Minecraft", "mc.server": "Minecraft",
    "mc.other": "Minecraft",
    "dev.discordbot": "Developer", "dev.telegrambot": "Developer",
    "dev.gamebot": "Developer", "dev.vscodeext": "Developer",
    "dev.obsidianplugin": "Developer", "dev.browserext": "Developer",
    "dev.wordpressplugin": "Developer", "dev.python": "Developer",
    "dev.node": "Developer", "dev.java": "Developer", "dev.rust": "Developer",
    "dev.go": "Developer", "dev.dotnet": "Developer", "dev.web": "Developer",
    "dev.shell": "Developer", "dev.other": "Developer",
    "sw.installer": "Software", "sw.portable": "Software", "sw.android": "Software",
    "sw.game": "Software", "sw.library": "Software",
}


def family_of(label: str) -> str:
    return FAMILY.get(label, label.split(".")[0] or "misc")


@dataclass(frozen=True)
class Evidence:
    """A single weighed observation produced by a detector."""

    rule: str
    label: str
    weight: float
    note: str
    stage: int = 0

    def __str__(self) -> str:  # pragma: no cover - debug helper
        sign = "+" if self.weight >= 0 else ""
        return f"{sign}{self.weight:g} {self.label} <- {self.rule}: {self.note}"


@dataclass
class Candidate:
    label: str
    score: float
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def title(self) -> str:
        return LABEL_TITLES.get(self.label, self.label)


@dataclass
class Decision:
    """Final verdict for one path."""

    path: Path
    label: str
    confidence: float
    margin: float
    candidates: List[Candidate]
    facts: Optional["Facts"] = None
    review: bool = False
    reason: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return LABEL_TITLES.get(self.label, self.label)

    @property
    def folder(self) -> str:
        # Anything the engine is not sure about goes to _Review — never to a
        # guessed folder. Being wrong is more expensive than being undecided.
        if self.review:
            return TAXONOMY["misc.review"]
        return TAXONOMY.get(self.label, TAXONOMY["misc.other"])

    @property
    def is_confident(self) -> bool:
        return not self.review

    @property
    def warnings(self) -> List[str]:
        return list(self.facts.warnings) if self.facts is not None else []

    def explain(self, max_evidence: int = 6) -> List[str]:
        lines = [
            f"{self.path.name} -> {self.title}  [{self.label}]",
            f"  confidence {self.confidence:.0%}   margin {self.margin:.2f}   folder {self.folder}",
        ]
        if self.reason:
            lines.append(f"  reason: {self.reason}")
        if self.candidates:
            ranked = ", ".join(f"{c.label}={c.score:.1f}" for c in self.candidates[:4])
            lines.append(f"  scores: {ranked}")
        for ev in (self.candidates[0].evidence if self.candidates else [])[:max_evidence]:
            lines.append(f"    {ev}")
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "name": self.path.name,
            "label": self.label,
            "title": self.title,
            "folder": self.folder,
            "confidence": round(self.confidence, 4),
            "margin": round(self.margin, 4),
            "review": self.review,
            "reason": self.reason,
            "candidates": [
                {"label": c.label, "score": round(c.score, 3)} for c in self.candidates[:5]
            ],
            "evidence": [
                {
                    "rule": e.rule,
                    "label": e.label,
                    "weight": e.weight,
                    "note": e.note,
                    "stage": e.stage,
                }
                for e in (self.candidates[0].evidence if self.candidates else [])
            ],
            "extras": _jsonable(self.extras),
        }


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


class Taxonomy:
    """Label <-> folder mapping with the ability to learn new folders."""

    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self.mapping: Dict[str, str] = dict(mapping or TAXONOMY)

    def folder(self, label: str) -> str:
        return self.mapping.get(label, self.mapping.get("misc.other", "Other"))

    def label_for_folder(self, folder: str) -> Optional[str]:
        folder = folder.replace("\\", "/").strip("/")
        for label, path in self.mapping.items():
            if path.lower() == folder.lower():
                return label
        return None

    def labels(self) -> Iterable[str]:
        return self.mapping.keys()

    def folders(self) -> List[str]:
        return sorted(set(self.mapping.values()))


@dataclass
class Config:
    """Runtime knobs. Everything is local & offline unless explicitly enabled."""

    # Where the sorted tree is written (None -> skip planning, analysis only).
    output_root: Optional[Path] = None
    # Analysis depth cap (0..6). "auto" stops early when evidence is clear.
    max_stage: int = 6
    deep: bool = False             # force the full ladder even when confident
    # Budget / safety
    time_budget_s: float = 4.0
    max_entries: int = 8000
    max_read_bytes: int = 65536    # per member
    max_total_read_bytes: int = 12 * 1024 * 1024
    max_nested_depth: int = 2
    max_nested_bytes: int = 24 * 1024 * 1024
    max_scan_members: int = 250
    # Confidence gates
    strong_score: float = 6.0
    min_score: float = 2.6
    min_margin: float = 1.2
    review_below: float = 3.4
    # Optional features (both OFF by default)
    internet: bool = False
    ai_assist: bool = False
    ai_model: str = "claude-sonnet-4-5"
    ai_max_calls: int = 25
    cache_dir: Optional[Path] = None
    # Output behaviour
    move: bool = True
    dry_run: bool = False
    write_manifests: bool = True
    verbose: bool = False

    def cache_path(self) -> Path:
        base = self.cache_dir
        if base is None:
            base = Path(os.environ.get("FILESORTER_CACHE", Path.home() / ".filesorter"))
        return Path(base)


def glob_any(names: Sequence[str], *patterns: str) -> List[str]:
    """Return names matching any of the glob patterns (case-insensitive)."""
    hits: List[str] = []
    pats = [p.lower() for p in patterns]
    for n in names:
        low = n.lower()
        for p in pats:
            if fnmatch.fnmatchcase(low, p):
                hits.append(n)
                break
    return hits


def count_suffix(names: Sequence[str], *suffixes: str) -> int:
    sufs = tuple(s.lower() for s in suffixes)
    return sum(1 for n in names if n.lower().endswith(sufs))
