"""Stage 4-6 detectors: content grepping, bytecode, binaries and nested archives.

This is the "read deeper until you actually know what it is" part. It is bounded
by the budget: the number of members scanned, bytes read and time are all capped.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .context import AnalysisContext
from .knowledge import (
    BYTECODE_MARKERS,
    SECRET_PATTERNS,
    TEXT_SIG_BY_ID,
    TEXT_SIG_NEEDLES,
)
from .model import Evidence
from .readers import class_markers, decode_text, grep_members

# Members worth reading for text evidence (config/source), in priority order.
TEXT_PRIORITY_EXTS = (
    ".js", ".cjs", ".mjs", ".ts", ".py", ".java", ".kt", ".rs", ".go", ".php",
    ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".properties", ".env",
    ".txt", ".md", ".sh", ".bat", ".gradle", ".xml", ".mcmeta", ".sk", ".fsh", ".vsh",
)

BINARY_MARKERS: List[Tuple[bytes, str, float, str]] = [
    (b"UnityFS", "sw.game", 5.2, "Unity asset bundle"),
    (b"UnityWebData", "sw.game", 5.0, "Unity web data"),
    (b"UnityPlayer", "sw.game", 4.6, "Unity player reference"),
    (b"il2cpp", "sw.game", 4.4, "IL2CPP runtime"),
    (b"Godot Engine", "sw.game", 5.0, "Godot engine string"),
    (b"UnrealEngine", "sw.game", 4.8, "Unreal engine string"),
    (b"UE4", "sw.game", 1.6, "Unreal 4 marker (weak)"),
    (b"AndroidManifest", "sw.android", 4.0, "Android manifest reference"),
    (b"classes.dex", "sw.android", 4.8, "dex reference"),
    (b"Nullsoft", "sw.installer", 5.2, "NSIS installer stub"),
    (b"Inno Setup", "sw.installer", 5.2, "Inno Setup stub"),
    (b"InstallShield", "sw.installer", 5.0, "InstallShield stub"),
    (b"Electron", "sw.portable", 3.6, "Electron reference"),
    (b"minecraft", "mc.other", 1.0, "Minecraft string (weak)"),
    (b"MinecraftForge", "mc.mod", 4.6, "Forge string"),
    (b"net.fabricmc", "mc.mod", 4.8, "Fabric string"),
    (b"org.bukkit", "mc.plugin", 4.8, "Bukkit string"),
]


def d_text_signatures(ctx: AnalysisContext) -> List[Evidence]:
    """Grep member contents for framework signatures (the deep content read)."""
    ev: List[Evidence] = []
    if not ctx.listing or ctx.container is None:
        return ev
    if ctx.budget.exhausted() or ctx.budget.soft_exhausted():
        ctx.note("content-scan-skipped", "budget")
        return ev
    if not ctx.listing.files:
        return ev

    # Only run the needle set that is plausible for this listing shape, to keep
    # the read budget for the likely winner.
    hits = grep_members(
        ctx.container,
        ctx.listing,
        TEXT_SIG_NEEDLES,
        ctx.budget,
        exts=set(TEXT_PRIORITY_EXTS),
    )
    for sid, members in hits.items():
        sig = TEXT_SIG_BY_ID[sid]
        weight, extra = _location_adjust(sig.label, members, sig.weight)
        note = f"{sig.note} (in {', '.join(shorten(m) for m in members)}){extra}"
        ev.append(Evidence(f"text:{sid}", sig.label, weight, note, 4))
    if hits:
        ctx.note("text_signatures", sorted(hits.keys()))
    return ev


def _location_adjust(label: str, members: Sequence[str], weight: float) -> Tuple[float, str]:
    """Where a signature was found matters as much as what it says.

    GLSL inside ``assets/minecraft/shaders`` is a *resource pack* (core shaders),
    not an OptiFine/Iris shaderpack, so the shader signal is heavily discounted.
    """
    if label == "mc.shaderpack":
        if members and all("assets/" in m for m in members):
            return round(weight * 0.2, 3), " — inside assets/, i.e. core shaders (resource-pack side)"
        if members and any("assets/" in m for m in members) and not any(
            "assets/" not in m for m in members
        ):
            return round(weight * 0.4, 3), " — mostly under assets/"
    if label == "mc.resourcepack":
        if members and all(m.startswith("data/") for m in members):
            return round(weight * 0.3, 3), " — found under data/ (datapack side)"
    return weight, ""


def d_secret_scan(ctx: AnalysisContext) -> List[Evidence]:
    """Look for leaked credentials. We report the *shape*, never the value."""
    ev: List[Evidence] = []
    if not ctx.listing or ctx.container is None:
        return ev
    if ctx.budget.exhausted() or ctx.budget.soft_exhausted():
        return ev
    patterns = [(k, re.compile(p), note) for k, p, note in SECRET_PATTERNS]
    candidates: List[str] = []
    for name in ctx.listing.names(rel=False):
        low = name.lower()
        base = low.rsplit("/", 1)[-1]
        if base in (".env", ".env.local", ".env.example", "config.json", "config.yml", "config.py",
                    "settings.py", "settings.json", "secrets.json", "credentials.json", ".npmrc",
                    "application.yml", "application.properties"):
            candidates.append(name)
        elif low.endswith((".env", ".pem", ".key", ".p12")) and "node_modules/" not in low:
            candidates.append(name)
    candidates = candidates[:12]
    found: List[Dict[str, str]] = []
    for name in candidates:
        data = ctx.read(name, limit=32768)
        if not data:
            continue
        text = decode_text(data)
        for key, rx, note in patterns:
            m = rx.search(text)
            if rx.search(text):
                found.append({"type": key, "member": name, "note": note})
                if len(found) >= 6:
                    break
    if found:
        ctx.note("credential_findings", found)
        kinds = ", ".join(sorted({f["note"] for f in found}))
        ctx.warn(f"{ctx.name}: possible credential material in {len(found)} file(s): {kinds}")
        ctx.set_finding("credential", kinds, found[0]["member"])
    return ev


def d_class_scan(ctx: AnalysisContext) -> List[Evidence]:
    """Read Java bytecode constant pools — the definitive plugin/mod discriminator."""
    ev: List[Evidence] = []
    if not ctx.listing or ctx.container is None:
        return ev
    class_members = [e for e in ctx.listing.files if e.suffix == ".class"]
    if not class_members:
        return ev
    if ctx.budget.exhausted() or ctx.budget.soft_exhausted():
        return ev
    class_members.sort(key=lambda e: e.size)
    # Prefer classes with promising names first (Main, Plugin, Mod, listeners)
    def prio(e):
        b = e.basename.lower()
        score = 0
        if any(k in b for k in ("main", "plugin", "mod", "listener", "command", "bootstrap", "api")):
            score -= 1
        return (score, e.size)

    class_members.sort(key=prio)
    limit = min(28, max(6, len(class_members)))
    marker_hits: Counter = Counter()
    marker_examples: Dict[str, str] = {}
    read_classes = 0
    for entry in class_members[:limit]:
        if ctx.budget.exhausted():
            break
        data = ctx.read(entry.name, limit=98304)
        if not data:
            continue
        read_classes += 1
        for label, rows in BYTECODE_MARKERS.items():
            marks = []
            for marker, weight, note in rows:
                variants = {marker, marker.replace("/", ".")}
                for v in variants:
                    if v.encode("utf-8", "ignore") in data:
                        marks.append((marker, weight, note))
                        break
            for marker, weight, note in marks:
                marker_hits[marker] += 1
                marker_examples.setdefault(marker, entry.clean)
    if not marker_hits:
        return ev
    ctx.note("bytecode_classes_read", read_classes)
    ctx.note("bytecode_markers", {m: c for m, c in marker_hits.most_common(12)})

    by_label: Dict[str, List[Tuple[str, float, str, int]]] = {}
    for label, rows in BYTECODE_MARKERS.items():
        for marker, weight, note in rows:
            k = marker_hits.get(marker, 0)
            if k:
                by_label.setdefault(label, []).append((marker, weight, note, k))
    for label, rows in by_label.items():
        rows.sort(key=lambda r: (-r[1], -r[3]))
        for rank, (marker, weight, note, count) in enumerate(rows):
            factor = 1.0 if rank == 0 else (0.5 if rank == 1 else 0.25)
            coverage = 1.0 if count >= 2 else 0.85
            w = weight * factor * coverage
            ev.append(
                Evidence(
                    f"bytecode:{marker}",
                    label,
                    round(w, 3),
                    f"{note} used in {count} class file(s) (e.g. {shorten(marker_examples.get(marker, ''))})",
                    5,
                )
            )
            if rank >= 4:
                break
    return ev


def d_jar_library(ctx: AnalysisContext) -> List[Evidence]:
    """A jar that is *not* a plugin/mod: a plain Java library or desktop app.

    Runs after the bytecode scan, so it can stay silent whenever loader
    markers were found — the "it's a mod/plugin" verdict always wins over this.
    """
    ev: List[Evidence] = []
    if not ctx.listing or ctx.container is None or not ctx.is_archive:
        return ev
    classes = [e for e in ctx.listing.files if e.suffix == ".class"]
    if len(classes) < 5:
        return ev
    markers = ctx.extras.get("bytecode_markers") or {}
    loader_prefixes = ("org/bukkit", "io/papermc", "net/md_5", "com/velocitypowered",
                       "net/minecraftforge", "net/neoforged", "net/fabricmc",
                       "org/quiltmc", "cn/nukkit", "org/spongepowered")
    if any(str(m).startswith(loader_prefixes) for m in markers):
        return ev  # it is a plugin/mod; leave it alone
    names = ctx.listing.name_lower
    has_maven = any("meta-inf/maven/" in n for n in names) or ctx.listing.has_basename("pom.properties")
    has_main = bool(ctx.extras.get("main_class"))
    note = f"{len(classes)} compiled classes, no mod/plugin loader markers"
    if has_maven:
        ev.append(Evidence("jar:maven-artifact", "sw.library", 5.0,
                           f"published Maven artefact: {note}", 5))
    elif has_main:
        ev.append(Evidence("jar:application", "dev.java", 3.2,
                           f"standalone Java application ({note}, Main-Class set)", 5))
    else:
        ev.append(Evidence("jar:library", "sw.library", 3.6, f"plain Java archive: {note}", 5))
    return ev


def d_binary_probe(ctx: AnalysisContext) -> List[Evidence]:
    """Scan strings inside unidentified binaries (asset bundles, SFX stubs, ...)."""
    ev: List[Evidence] = []
    if ctx.is_archive or ctx.is_dir:
        return ev
    if ctx.magic.kind in ("text", "unknown") or ctx.magic.kind == "archive":
        return ev
    if ctx.budget.exhausted():
        return ev
    sample = ctx.head(524288) + ctx.tail(131072)
    if not sample:
        return ev
    hits: List[Tuple[str, float, str]] = []
    for marker, label, weight, note in BINARY_MARKERS:
        if marker in sample:
            hits.append((label, weight, note))
    if hits:
        ctx.note("binary_markers", sorted({h[2] for h in hits}))
        for label, weight, note in hits[:6]:
            ev.append(Evidence("binary-string", label, weight, note, 5))
    return ev


def d_media_collection(ctx: AnalysisContext) -> List[Evidence]:
    """A zip full of wallpapers is an image collection, not 'Archives'."""
    ev: List[Evidence] = []
    if not ctx.listing or not ctx.listing.files or not ctx.is_archive:
        return ev
    total = len(ctx.listing.files)
    if total < 4:
        return ev
    c = Counter(e.suffix for e in ctx.listing.files)
    families = {
        "media.image": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff"),
        "media.video": (".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v"),
        "media.audio": (".mp3", ".flac", ".wav", ".m4a", ".ogg", ".opus"),
        "media.ebook": (".epub", ".mobi", ".azw3", ".pdf"),
        "doc.office": (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".pdf"),
    }
    for label, exts in families.items():
        count = sum(c.get(e, 0) for e in exts)
        if count >= 4 and count / total > 0.7:
            ctx.note("collection_kind", label)
            ev.append(Evidence("collection:homogeneous", label, 5.4,
                               f"{count}/{total} files are {label.split('.')[1]} files", 4))
            break
    return ev


def d_nested_archives(ctx: AnalysisContext) -> List[Evidence]:
    """Open nested archives (bounded) — this is how we see inside a mods/ folder."""
    ev: List[Evidence] = []
    if not ctx.listing or ctx.container is None:
        return ev
    if ctx.nested_depth >= ctx.budget.max_nested_depth:
        return ev
    if ctx.budget.exhausted() or ctx.budget.soft_exhausted():
        ctx.note("nested-skipped", "budget")
        return ev

    nested = [e for e in ctx.listing.files if e.suffix in (".zip", ".jar", ".mrpack", ".litemod")]
    if not nested:
        return ev
    ctx.note("nested_archive_count", len(nested))

    # A folder of jars is itself a strong signal (mods/plugins/instance).
    jar_dirs = Counter()
    for e in nested:
        parts = e.parts
        if len(parts) >= 2:
            jar_dirs[parts[-2]] += 1
    if nested and len(nested) >= 3:
        top_dirs = ", ".join(f"{d}/ ({c})" for d, c in jar_dirs.most_common(3))
        if any("mod" in d.lower() for d in jar_dirs):
            ev.append(Evidence("nested:mods-folder", "mc.modpack", 4.6,
                               f"{len(nested)} jars, mods-like layout: {top_dirs}", 2))
        elif any("plugin" in d.lower() for d in jar_dirs):
            ev.append(Evidence("nested:plugins-folder", "mc.server", 4.4,
                               f"{len(nested)} jars under plugins/: {top_dirs}", 2))
        else:
            ev.append(Evidence("nested:jar-bundle", "misc.collection", 2.2,
                               f"{len(nested)} nested archives ({top_dirs})", 2))

    # Deep-dive a few nested archives (prefer a mods/ folder, then smallest).
    budget_left = ctx.budget.max_nested_bytes
    candidates = sorted(
        nested,
        key=lambda e: (0 if "/mods/" in e.lower or "mods/" in e.lower else 1,
                       0 if "/plugins/" in e.lower else 1, e.size),
    )[:3]
    analyzed: List[Tuple[str, str, float]] = []
    for entry in candidates:
        if budget_left <= 0 or ctx.budget.exhausted():
            break
        want = min(entry.size, 6 * 1024 * 1024, budget_left)
        data = ctx.read(entry.name, limit=want)
        if not data:
            continue
        budget_left -= len(data)
        child = ctx.child(data, entry.basename, discount=0.55)
        if child is None:
            continue
        ctx.nested_results.append(child)
        analyzed.append((entry.basename, child.label, child.confidence))
        ev.append(
            Evidence(
                "nested:file",
                child.label,
                round(5.0 * max(0.2, child.confidence), 2),
                f"nested archive {shorten(entry.clean)} identified as {child.title} "
                f"({child.confidence:.0%})",
                6,
            )
        )
    if analyzed:
        ctx.note("nested_identities", [{"name": n, "label": l, "confidence": round(c, 2)} for n, l, c in analyzed])
    return ev


DEEP_DETECTORS: List["object"] = []


def _register() -> None:
    from .detectors import Detector

    DEEP_DETECTORS.extend(
        [
            Detector("text-signatures", 4, d_text_signatures),
            Detector("secret-scan", 4, d_secret_scan, always=True),
            Detector("media-collection", 4, d_media_collection),
            Detector("class-scan", 5, d_class_scan),
            Detector("jar-library", 5, d_jar_library),
            Detector("binary-probe", 5, d_binary_probe),
            Detector("nested-archives", 6, d_nested_archives),
        ]
    )


_register()


def shorten(text: str, limit: int = 60) -> str:
    text = str(text).replace("\\", "/")
    return text if len(text) <= limit else "…" + text[-limit:]
