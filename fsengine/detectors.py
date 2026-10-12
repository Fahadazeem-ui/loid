"""Stage 0-2 detectors: names, headers, listings and structural statistics.

A detector never decides anything. It emits :class:`~fsengine.model.Evidence`
and the fusion layer decides. This is what removes the "first rule that matches
wins" failure mode that dumped everything into *Archives*.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .context import AnalysisContext
from .knowledge import (
    ARCHIVE_EXTS,
    BYTECODE_MARKERS,
    EXT_LABELS,
    NAME_HINTS,
    PATH_SIGS,
    Sig,
)
from .listing import suffix_of
from .magic import (
    ascii_strings,
    pe_header_info,
    pe_markers,
    pe_version_info,
    sniff_head,
)
from .model import Evidence, MODIFIER_SUFFIXES, name_tokens

# ===========================================================================
# Detector framework
# ===========================================================================


@dataclass
class Detector:
    id: str
    stage: int
    run: object  # Callable[[AnalysisContext], List[Evidence]]
    note: str = ""
    always: bool = False  # run even when the classifier already settled (safety checks)

    def __call__(self, ctx: AnalysisContext) -> List[Evidence]:
        try:
            return list(self.run(ctx))  # type: ignore[misc]
        except Exception as exc:  # a detector must never kill the run
            ctx.warn(f"detector {self.id} failed: {exc}")
            return []


# ===========================================================================
# Stage 0 — names
# ===========================================================================


def d_user_corrections(ctx: AnalysisContext) -> List[Evidence]:
    """A file the user has already corrected once is classified from that note.

    Runs first and outranks everything: the human knows better than the rules.
    """
    from .corrections import match as _match

    row = _match(ctx.name, ctx.config)
    if not row:
        return []
    return [
        Evidence(
            "user:correction",
            str(row["label"]),
            9.0,
            f"you taught me this ({row.get('note') or row['pattern']})",
            0,
        )
    ]


def d_extension(ctx: AnalysisContext) -> List[Evidence]:
    """File extensions are strong evidence for *media/documents*, weak for code."""
    ev: List[Evidence] = []
    ext = ctx.suffix
    if not ext:
        return ev
    if ctx.is_archive or ctx.is_dir:
        return ev
    row = EXT_LABELS.get(ext)
    if row and row[1] > 0:
        label, weight = row
        ev.append(Evidence("ext", label, weight, f"extension {ext}", 0))
    return ev


def d_archive_extension(ctx: AnalysisContext) -> List[Evidence]:
    """Special container extensions that carry meaning by themselves."""
    ev: List[Evidence] = []
    ext = ctx.suffix
    special = {
        ".mrpack": ("mc.modpack", 6.5, "Modrinth modpack container"),
        ".litemod": ("mc.mod", 6.0, "LiteLoader mod container"),
        ".mcworld": ("mc.world", 6.5, "Minecraft Bedrock world"),
        ".mcpack": ("mc.resourcepack", 4.5, "Bedrock resource pack/addon"),
        ".mcaddon": ("mc.modpack", 4.0, "Bedrock addon bundle"),
        ".vsix": ("dev.vscodeext", 7.0, "VSIX package"),
        ".crx": ("dev.browserext", 7.0, "Chrome package"),
        ".xpi": ("dev.browserext", 7.0, "Firefox extension package"),
        ".whl": ("dev.python", 6.5, "Python wheel"),
        ".nupkg": ("dev.dotnet", 6.0, "NuGet package"),
        ".apkg": ("sw.library", 2.0, "Anki deck/package"),
        ".aar": ("sw.library", 4.0, "Android library archive"),
        ".deb": ("sw.portable", 5.0, "Debian package"),
        ".rpm": ("sw.portable", 5.0, "RPM package"),
        ".dmg": ("sw.installer", 5.5, "macOS disk image"),
        ".iso": ("sw.portable", 5.0, "disk image"),
        ".msi": ("sw.installer", 6.0, "Windows Installer"),
        ".apk": ("sw.android", 7.0, "Android package"),
        ".aab": ("sw.android", 7.0, "Android app bundle"),
        ".xapk": ("sw.android", 6.5, "Android split package"),
        ".jar": ("dev.java", 0.6, "JAR container (Java)"),
        ".zip": ("misc.other", 0.0, "generic zip"),
    }
    if ext in special:
        label, weight, note = special[ext]
        if weight > 0:
            ev.append(Evidence("archive-ext", label, weight, note, 0))
    if ctx.modifiers:
        ev.append(
            Evidence(
                "modifier",
                "misc.other",
                0.0,
                f"name carries modifier(s): {', '.join(ctx.modifiers)} — judged by base name",
                0,
            )
        )
    return ev


def d_name_hints(ctx: AnalysisContext) -> List[Evidence]:
    """Words in the file name. Never decisive on its own (max ~3 points)."""
    ev: List[Evidence] = []
    tokens = set(name_tokens(ctx.base_name))
    raw = ctx.base_name.lower()
    for label, rows in NAME_HINTS.items():
        total = 0.0
        notes: List[str] = []
        for needle, weight, note in rows:
            hit = needle in tokens
            if not hit and ("-" in needle or " " in needle):
                hit = needle in raw
            if hit:
                total += weight
                notes.append(note)
                if len(notes) >= 3:
                    break
        if total:
            # A single word in a file name can never prove identity.
            capped = max(-3.0, min(3.0, total))
            ev.append(Evidence("name", label, capped, "; ".join(notes) or "name hint", 0))
    return ev


# ===========================================================================
# Stage 1 — magic bytes / container header
# ===========================================================================


def d_magic_kind(ctx: AnalysisContext) -> List[Evidence]:
    """What the bytes say the file *is* (independent of the extension)."""
    ev: List[Evidence] = []
    magic = ctx.magic
    ext = ctx.suffix

    if magic.is_archive:
        ev.append(Evidence("magic", "misc.other", 0.0, f"container: {magic.describe()}", 1))
        if magic.subtype in ("rar", "7z"):
            ctx.note("unreadable_container", magic.subtype)
            ctx.warn(f"{ctx.name}: {magic.note}; contents cannot be inspected")
        return ev

    kind_map = {
        ("image", "png"): "media.image", ("image", "jpeg"): "media.image",
        ("image", "gif"): "media.image", ("image", "webp"): "media.image",
        ("image", "bmp"): "media.image", ("image", "tiff"): "media.image",
        ("image", "psd"): "media.image", ("image", "ico"): "media.image",
        ("audio", "mp3"): "media.audio", ("audio", "ogg"): "media.audio",
        ("audio", "flac"): "media.audio", ("audio", "wav"): "media.audio",
        ("audio", "m4a"): "media.audio",
        ("video", "mp4"): "media.video", ("video", "matroska"): "media.video",
        ("video", "avi"): "media.video", ("video", "flv"): "media.video",
        ("document", "pdf"): "doc.pdf", ("document", "ole"): "doc.office",
        ("document", "rtf"): "doc.office",
        ("font", "ttf"): "media.font", ("font", "otf"): "media.font",
        ("font", "woff"): "media.font",
        ("database", "sqlite"): "doc.data",
        ("executable", "java-class"): "dev.java",
    }
    key = (magic.kind, magic.subtype)
    if key in kind_map:
        label = kind_map[key]
        weight = 8.0 if magic.kind in ("image", "audio", "video", "font") else 7.0
        ev.append(Evidence("magic", label, weight, f"magic bytes: {magic.describe()}", 1))

    if magic.subtype == "elf":
        ev.append(Evidence("magic", "sw.portable", 5.0, f"ELF binary ({magic.note})", 1))
    if magic.subtype == "macho":
        ev.append(Evidence("magic", "sw.portable", 5.0, "Mach-O binary", 1))
    if magic.kind == "text":
        ev.append(Evidence("magic", "doc.text", 1.0, f"text content ({magic.subtype or 'plain'})", 1))
    if magic.kind == "binary" and not ext:
        ev.append(Evidence("magic", "misc.review", 1.0, "unidentified binary", 1))
    return ev


def d_extension_mismatch(ctx: AnalysisContext) -> List[Evidence]:
    """A misnamed file is a real signal: trust the bytes, note the lie."""
    ev: List[Evidence] = []
    ext = ctx.suffix
    if not ext or ctx.is_archive:
        return ev
    row = EXT_LABELS.get(ext)
    if not row:
        return ev
    ext_label = row[0]
    magic = ctx.magic
    expected_family = {
        "media.image": ("image",), "media.video": ("video",), "media.audio": ("audio",),
        "doc.pdf": ("document",), "doc.office": ("document",),
    }.get(ext_label)
    if expected_family and magic.kind not in expected_family and magic.kind not in ("unknown",):
        ctx.note("extension_mismatch", f"extension {ext} but content is {magic.describe()}")
        # Counter-evidence against the label the *extension* suggested, plus a
        # nudge towards review: a .png that is actually text must not be filed
        # into Images just because of its name.
        penalty = 6.0 if magic.kind in ("text",) else 4.0
        ev.append(
            Evidence(
                "mismatch",
                ext_label,
                -penalty,
                f"extension claims {ext_label} but the bytes are {magic.describe()}",
                1,
            )
        )
        ev.append(
            Evidence(
                "mismatch",
                "misc.review",
                3.0,
                f"extension says {ext_label} but bytes are {magic.describe()}",
                1,
            )
        )
    if ext_label.startswith("sw.") and magic.kind == "text":
        ctx.note("extension_mismatch", f"extension {ext} but content is text")
        ev.append(Evidence("mismatch", ext_label, -6.0, f"{ext} file that is actually text", 1))
        ev.append(Evidence("mismatch", "misc.review", 3.2, f"{ext} file that is actually text", 1))
    return ev


def d_content_mix(ctx: AnalysisContext) -> List[Evidence]:
    """An archive of many *unrelated* kinds (a drive dump) is a Collection.

    This exists because the old engine treated "one .exe somewhere inside" as
    proof of an installer and dumped the whole archive into Software.
    """
    ev: List[Evidence] = []
    if not ctx.listing or not ctx.is_archive or len(ctx.listing.files) < 4:
        return ev
    family_exts = {
        "image": (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".psd", ".svg"),
        "video": (".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".wmv"),
        "audio": (".mp3", ".flac", ".wav", ".m4a", ".ogg", ".opus", ".aac"),
        "document": (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".csv",
                     ".rtf", ".odt", ".epub"),
        "executable": (".exe", ".msi", ".dll", ".so", ".dylib"),
        "java-archive": (".jar", ".class", ".litemod"),
        "source": (".py", ".js", ".ts", ".java", ".kt", ".rs", ".go", ".cs", ".php", ".rb",
                   ".cpp", ".c", ".h", ".sh", ".bat", ".cmd", ".ps1"),
        "data": (".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".xml", ".properties",
                 ".db", ".sqlite"),
    }
    # Readmes, licences and checksums exist in *every* archive; counting them as
    # a family turned normal projects into "Collections".
    metadata_exts = {".txt", ".md", ".nfo", ".sfv", ".log", ".url", ".lnk", ".html",
                     ".gitignore", ".license", ".news", ".rst"}
    counts: Counter = Counter()
    for entry in ctx.listing.files:
        ext = entry.suffix
        if ext in metadata_exts:
            continue
        for family, exts in family_exts.items():
            if ext in exts:
                counts[family] += 1
                break
        else:
            counts["other"] += 1
    total = sum(counts.values())
    if total < 4:
        return ev
    dominant, dom_count = counts.most_common(1)[0]
    significant = [f for f, c in counts.items() if c / total >= 0.12 and f != "other"]
    dom_share = dom_count / total
    if len(significant) >= 3 and dom_share <= 0.6:
        ctx.note("content_mix", {f: c for f, c in counts.most_common()})
        ev.append(
            Evidence(
                "mix:unrelated",
                "misc.collection",
                7.0,
                f"archive mixes {len(significant)} unrelated kinds of files "
                f"({', '.join(f'{f}={c}' for f, c in counts.most_common(4))})",
                2,
            )
        )
    return ev


def d_pe_details(ctx: AnalysisContext) -> List[Evidence]:
    """Windows executable analysis: installer? app? game? library?"""
    ev: List[Evidence] = []
    if ctx.magic.subtype not in ("pe",):
        return ev
    head = ctx.head(262144)
    tail = ctx.tail(65536)
    info = pe_header_info(head)
    ctx.note("pe", data_safe(info))
    sample = head + tail

    markers = pe_markers(sample)
    if markers:
        ctx.note("pe_markers", markers)
    installer_hit = False
    for m in markers:
        if "installer" in m.lower() or "nsis" in m.lower() or "inno" in m.lower() or "wiX" in m.lower() or "setup" in m.lower():
            installer_hit = True
        if m in ("Unity engine", "Unreal engine", "Godot engine"):
            ev.append(Evidence("pe", "sw.game", 5.0, f"PE marker: {m}", 1))
        elif m in ("Electron app shell", "NW.js app"):
            ev.append(Evidence("pe", "sw.portable", 4.0, f"PE marker: {m}", 1))
        elif m == "7-Zip SFX":
            ev.append(Evidence("pe", "sw.installer", 3.0, "self-extracting archive stub", 1))
        else:
            ev.append(Evidence("pe", "sw.installer", 5.0, f"PE marker: {m}", 1))
            installer_hit = True

    if installer_hit:
        pass  # the evidence above already carries the verdict

    version = pe_version_info(sample)
    if version:
        ctx.note("pe_version_info", dict(version))
        product = str(version.get("ProductName") or version.get("FileDescription") or "")
        company = str(version.get("CompanyName") or "")
        if product:
            ctx.note("product_name", product)
        if company:
            ctx.note("company", company)
        ev.append(Evidence("pe", "sw.portable", 2.0,
                           f"version info: {product or company or 'present'}", 1))
    if info.get("dll"):
        ev.append(Evidence("pe", "sw.library", 3.5, "PE is a DLL (library)", 1))
    if info.get("dotnet"):
        ev.append(Evidence("pe", "sw.portable", 1.5, ".NET assembly", 1))
    if info.get("subsystem") == "console" and not installer_hit:
        ev.append(Evidence("pe", "sw.portable", 1.0, "console application", 1))
    if ctx.is_sfx:
        ctx.note("self_extracting", True)
        ev.append(Evidence("pe", "sw.installer", 2.0, "contains an embedded ZIP (SFX)", 1))
    return ev


def d_container_capability(ctx: AnalysisContext) -> List[Evidence]:
    """Record what we could and could not open (feeds the review decision)."""
    ev: List[Evidence] = []
    if ctx.container is not None and ctx.container.kind == "zip-unreadable":
        ctx.note("unreadable_container", "corrupt-zip")
        ev.append(Evidence("container", "misc.review", 1.5, "zip could not be opened", 1))
    if ctx.listing and not ctx.listing.files and ctx.is_archive:
        ev.append(Evidence("container", "misc.review", 1.2, "archive is empty", 1))
    return ev


# ===========================================================================
# Stage 2 — listing structure
# ===========================================================================


def _match_sig(names: Sequence[str], sig: Sig) -> List[str]:
    return [n for n in names if sig.matches(n)]


def d_path_signatures(ctx: AnalysisContext) -> List[Evidence]:
    """The workhorse: match every path signature against the member list."""
    ev: List[Evidence] = []
    if not ctx.listing or not ctx.listing.files:
        return ev
    names = ctx.listing.name_lower
    per_label: Dict[str, List[Tuple[Sig, List[str]]]] = {}
    for label, sigs in PATH_SIGS.items():
        for sig in sigs:
            hits = _match_sig(names, sig)
            if hits:
                per_label.setdefault(label, []).append((sig, hits))

    for label, rows in per_label.items():
        rows.sort(key=lambda r: -abs(r[0].weight))
        for rank, (sig, hits) in enumerate(rows):
            factor = 1.0 if rank == 0 else (0.5 if rank == 1 else 0.25)
            weight = sig.weight * factor
            note = sig.note
            if len(hits) > 1:
                note += f" ({len(hits)} matches, e.g. {shorten(hits[0])})"
            else:
                note += f" ({shorten(hits[0])})"
            ev.append(Evidence(f"path:{sig.needle}", label, round(weight, 3), note, 2))
            if rank >= 5:
                break

    # Core shaders are *resource pack* content, not an OptiFine shaderpack.
    core = _match_sig(names, Sig("assets/minecraft/shaders/core/", 0, "", contains=True))
    if core:
        ev.append(Evidence("guard:core-shaders", "mc.shaderpack", -4.0,
                           f"vanilla core shader tree present ({len(core)} files) — this is "
                           f"resource-pack content, not an OptiFine/Iris shaderpack", 2))
        ev.append(Evidence("guard:core-shaders", "mc.resourcepack", 4.0,
                           f"core shader tree under assets/ ({len(core)} files) — modern resource pack",
                           2))
    return ev


def _counts(ctx: AnalysisContext) -> Counter:
    """Suffix -> file count (cached). Basenames live in ctx.cache separately so
    this counter stays a plain numeric Counter."""
    cached = ctx.cache.get("ext_counts")
    if cached is not None:
        return cached
    counter: Counter = Counter()
    if ctx.listing:
        for e in ctx.listing.files:
            counter[e.suffix] += 1
        ctx.cache["basename_counts"] = Counter(e.basename.lower() for e in ctx.listing.files)
    ctx.cache["ext_counts"] = counter
    return counter


def d_structure_stats(ctx: AnalysisContext) -> List[Evidence]:
    """Population statistics that shift the odds inside a family."""
    ev: List[Evidence] = []
    if not ctx.listing or not ctx.listing.files:
        return ev
    c = _counts(ctx)
    total = max(1, len(ctx.listing.files))
    ctx.note("file_count", len(ctx.listing.files))
    ctx.note("extension_counts", dict(c.most_common(12)))

    def n(*exts: str) -> int:
        return sum(c.get(e, 0) for e in exts)

    jars = n(".jar", ".litemod")
    classes = n(".class")
    fsh = n(".fsh", ".vsh", ".gsh", ".csh", ".glsl", ".frag", ".vert")
    mcfunction = n(".mcfunction")
    mca = n(".mca", ".mcr")
    exes = n(".exe", ".msi")
    dlls = n(".dll", ".so", ".dylib")
    pngs = n(".png")
    oggs = n(".ogg")
    javas = n(".java")
    pys = n(".py")
    jss = n(".js", ".ts", ".mjs", ".cjs")
    jsons = n(".json")
    langs = n(".lang")
    zips = n(".zip")
    dexes = n(".dex")
    so = n(".so")

    if jars >= 3 and jars / total > 0.2:
        ev.append(Evidence("stats:many-jars", "mc.modpack", 3.4,
                           f"{jars} jar files (mod/plugin collection)", 2))
        ev.append(Evidence("stats:many-jars", "sw.library", 1.2,
                           f"{jars} java archives", 2))
    if classes >= 5:
        ev.append(Evidence("stats:classes", "dev.java", 2.6,
                           f"{classes} .class files (compiled Java)", 2))
    if fsh >= 3:
        ev.append(Evidence("stats:glsl", "mc.shaderpack", 4.0,
                           f"{fsh} GLSL shader sources", 2))
        ev.append(Evidence("stats:glsl", "mc.resourcepack", 0.8,
                           f"{fsh} GLSL sources could also be core shaders", 2))
    if mcfunction >= 3:
        ev.append(Evidence("stats:mcfunction", "mc.datapack", 4.4,
                           f"{mcfunction} .mcfunction files", 2))
    if mca >= 1:
        ev.append(Evidence("stats:region", "mc.world", 5.6,
                           f"{mca} region files (world save)", 2))
    if dexes >= 1:
        ev.append(Evidence("stats:dex", "sw.android", 6.0,
                           f"{dexes} dex files (Android bytecode)", 2))
    if so >= 3 and ctx.listing.has_dir("lib"):
        ev.append(Evidence("stats:so", "sw.android", 2.0,
                           "lib/ + .so native libraries", 2))
    if pngs >= 30 and oggs >= 5:
        ev.append(Evidence("stats:assets", "mc.resourcepack", 1.6,
                           f"{pngs} textures + {oggs} sounds (pack-like asset ratio)", 2))
    if pngs >= 10 and fsh >= 3:
        ev.append(Evidence("stats:assets", "mc.resourcepack", 1.4,
                           "textures alongside GLSL (hybrid pack)", 2))
    if javas >= 5 and pys == 0:
        ev.append(Evidence("stats:java-src", "dev.java", 1.6, f"{javas} .java sources", 2))
    if pys >= 3:
        ev.append(Evidence("stats:py-src", "dev.python", 1.4, f"{pys} .py files", 2))
    if jss >= 3:
        ev.append(Evidence("stats:js-src", "dev.node", 1.2, f"{jss} .js/.ts files", 2))
    if exes >= 1 and dlls >= 3 and jars == 0:
        ev.append(Evidence("stats:winapp", "sw.portable", 3.0,
                           f"{exes} executables + {dlls} libraries (Windows app layout)", 2))
    if zips >= 3 and jars >= 0 and exes >= 1:
        ev.append(Evidence("stats:nested-zips", "sw.portable", 1.2,
                           f"{zips} nested archives", 2))
    if langs >= 2 and fsh >= 1:
        ev.append(Evidence("stats:lang", "mc.shaderpack", 1.2,
                           "shaderpack language files", 2))

    # Ratio-based dev-project signals
    code_files = pys + jss + javas + n(".rs", ".go", ".php", ".rb", ".cs", ".kt")
    if total >= 5 and code_files / total > 0.5:
        ev.append(Evidence("stats:source-heavy", "dev.other", 1.8,
                           f"{code_files}/{total} files are source code", 2))

    roots, largest_share = ctx.listing.multi_root_score()
    if roots >= 3 and largest_share < 0.6 and total > 40:
        ctx.note("multi_root", {"roots": roots, "largest_share": round(largest_share, 2)})
    return ev


def d_script_ratio(ctx: AnalysisContext) -> List[Evidence]:
    """Script files only mean "Scripts" when the project *is* scripts.

    A `.bat` launcher inside a Python/Node/Java project is one file out of many;
    treating it as the project's identity put whole repos into Developer/Scripts.
    """
    ev: List[Evidence] = []
    if not ctx.listing or len(ctx.listing.files) < 2:
        return ev
    script_exts = (".bat", ".cmd", ".ps1", ".sh", ".bash", ".zsh")
    scripts = [e for e in ctx.listing.files if e.suffix in script_exts]
    if not scripts:
        return ev
    total = len(ctx.listing.files)
    ratio = len(scripts) / total
    if ratio >= 0.7 and total <= 40:
        ev.append(Evidence("scripts:dominant", "dev.shell", 4.2,
                           f"{len(scripts)}/{total} files are shell/batch scripts", 2))
    elif ratio <= 0.25 or total >= 6:
        ev.append(Evidence("scripts:minor", "dev.shell", -3.4,
                           f"scripts are only {len(scripts)}/{total} of the project — "
                           f"launcher scripts, not the identity", 2))
        ev.append(Evidence("scripts:minor", "dev.other", 1.0,
                           f"project ships {len(scripts)} launcher script(s)", 2))
    return ev


GAME_MOD_EXTS = {
    ".esp": "Bethesda plugin", ".esm": "Bethesda master", ".esl": "Bethesda light plugin",
    ".bsa": "Bethesda archive", ".ba2": "Bethesda archive (v2)",
    ".pk3": "id Tech package", ".pk4": "id Tech package", ".wad": "Doom WAD", ".iwad": "Doom IWAD",
    ".ucas": "Unreal IoStore container", ".utoc": "Unreal IoStore table",
    ".osu": "osu! beatmap", ".bpk": "BepInEx package",
    ".assets": "Unity mod asset", ".resource": "Unity mod asset",
}

GAME_MOD_PATHS = [
    ("BepInEx/plugins", 5.8, "BepInEx plugin folder (Unity mod loader)"),
    ("MelonLoader/Mods", 5.8, "MelonLoader mods folder (Unity mod loader)"),
    ("CustomLevels/", 5.2, "Beat Saber custom levels"),
    ("CustomSongs/", 4.8, "custom song folder"),
    ("UserData/", 2.6, "mod user data folder"),
    ("mods/*/data/song", 5.0, "chart/song data (rhythm-game mod)"),
    ("song-chart.json", 4.6, "rhythm-game chart file"),
    ("pack.json", 2.8, "mod pack manifest"),
    ("data/song/", 4.4, "song folder inside a mod package"),
    ("content/", 0.8, "content folder (very weak)"),
]


def d_game_mod(ctx: AnalysisContext) -> List[Evidence]:
    """Game mod packages (Bethesda, id Tech, Unreal, Unity loaders, rhythm games).

    These live in Downloads folders constantly and have nothing to do with
    Minecraft/Minecraft-server content — they belong in Games.
    """
    ev: List[Evidence] = []
    if not ctx.listing or not ctx.listing.files:
        return ev
    counts = _counts(ctx)
    hits = sorted(
        ((ext, note) for ext, note in GAME_MOD_EXTS.items() if counts.get(ext, 0)),
        key=lambda row: -counts[row[0]],
    )
    total = len(ctx.listing.files)
    for ext, note in hits[:2]:
        count = counts[ext]
        ev.append(Evidence("gamemod:ext", "sw.game", 4.6 if count < 3 else 5.2,
                           f"{count}x {ext} — {note}", 2))
    for needle, weight, note in GAME_MOD_PATHS:
        if any(Sig(needle, 0, "", glob=True).matches(n) for n in ctx.listing.name_lower):
            ev.append(Evidence(f"gamemod:path:{needle}", "sw.game", weight, note, 2))
    if counts.get(".esp") and any(n.startswith("data/") for n in ctx.listing.name_lower):
        ev.append(Evidence("gamemod:bethesda", "sw.game", 5.4,
                           "Data/ + .esp layout (Bethesda mod)", 2))
    if total and counts.get(".dll") and any("plugins/" in n for n in ctx.listing.name_lower):
        ev.append(Evidence("gamemod:plugin-dll", "sw.game", 3.2,
                           "Plugins/ folder with .dll (game mod loader layout)", 2))
    return ev


def d_language_profile(ctx: AnalysisContext) -> List[Evidence]:
    """When one language dominates the file list, that *is* the ecosystem.

    The old engine needed a package.json/pom.xml to see a project at all, so a
    folder of .py files (or a repo with the descriptor one level too deep) had
    nothing to match on. Counting is cheap and works without any descriptor.
    """
    ev: List[Evidence] = []
    if not ctx.listing or len(ctx.listing.files) < 4:
        return ev
    lang_map = {
        "dev.python": (".py", ".pyw", ".ipynb"),
        "dev.node": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"),
        "dev.java": (".java", ".kt", ".kts", ".scala", ".groovy"),
        "dev.rust": (".rs",),
        "dev.go": (".go",),
        "dev.dotnet": (".cs", ".vb", ".fs"),
        "dev.web": (".html", ".htm", ".css", ".scss", ".less", ".php"),
        "dev.other": (".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".swift", ".dart", ".lua", ".rb"),
    }
    counts: Counter = Counter()
    for entry in ctx.listing.files:
        for label, exts in lang_map.items():
            if entry.suffix in exts:
                counts[label] += 1
                break
    total = len(ctx.listing.files)
    if not counts:
        return ev
    label, count = counts.most_common(1)[0]
    share = count / total
    if count >= 8 or share >= 0.4:
        # Scale with both absolute count and dominance, capped so that a
        # "language" guess can never outrank a real descriptor.
        weight = min(5.0, 1.6 + 2.0 * min(1.0, count / 12) + 1.6 * min(1.0, share))
        ev.append(Evidence("lang:dominant", label, round(weight, 2),
                           f"{count}/{total} files are {label.split('.')[1]} sources "
                           f"({share:.0%} of the archive)", 2))
        ctx.note("language_profile", {k: v for k, v in counts.most_common(4)})
        rival = counts.most_common(2)
        if len(rival) > 1 and rival[1][1] / total >= 0.3:
            ev.append(Evidence("lang:mixed", rival[1][0], 1.4,
                               f"also {rival[1][1]} {rival[1][0].split('.')[1]} sources (mixed project)", 2))
    return ev


def d_manifest_only(ctx: AnalysisContext) -> List[Evidence]:
    """Single-executable / trivial containers (a zip that is just one file)."""
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    files = ctx.listing.files
    if len(files) == 1:
        only = files[0]
        ev.append(Evidence("single-member", "misc.other", 0.0,
                           f"archive holds a single file: {shorten(only.clean)}", 2))
        if only.suffix == ".exe":
            base = only.basename.lower()
            installerish = any(k in base for k in ("setup", "install", "installer", "update"))
            ev.append(Evidence("single-exe", "sw.installer" if installerish else "sw.portable",
                               4.0 if installerish else 3.4,
                               f"wraps a single executable ({only.basename})", 2))
        elif only.suffix == ".apk":
            ev.append(Evidence("single-apk", "sw.android", 5.0, "wraps an APK", 2))
        elif only.suffix == ".jar":
            ev.append(Evidence("single-jar", "dev.java", 1.4, "wraps a single jar", 2))
    return ev


def shorten(text: str, limit: int = 60) -> str:
    text = text.replace("\\", "/")
    if len(text) <= limit:
        return text
    return "…" + text[-limit:]


def data_safe(value: object) -> object:
    if isinstance(value, dict):
        return {k: data_safe(v) for k, v in list(value.items())[:20]}
    if isinstance(value, (list, tuple)):
        return [data_safe(v) for v in value[:20]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# ===========================================================================
# Registry
# ===========================================================================

from .descriptors import DESCRIPTORS  # noqa: E402
from .deepscan import DEEP_DETECTORS  # noqa: E402

DETECTORS: List[Detector] = [
    Detector("user-corrections", 0, d_user_corrections),
    Detector("extension", 0, d_extension),
    Detector("archive-extension", 0, d_archive_extension),
    Detector("name-hints", 0, d_name_hints),
    Detector("magic", 1, d_magic_kind),
    Detector("mismatch", 1, d_extension_mismatch),
    Detector("pe", 1, d_pe_details),
    Detector("container", 1, d_container_capability),
    Detector("paths", 2, d_path_signatures),
    Detector("stats", 2, d_structure_stats),
    Detector("game-mod", 2, d_game_mod),
    Detector("content-mix", 2, d_content_mix),
    Detector("language-profile", 2, d_language_profile),
    Detector("script-ratio", 2, d_script_ratio),
    Detector("trivial", 2, d_manifest_only),
] + DESCRIPTORS + DEEP_DETECTORS


def detectors_up_to(stage: int, max_stage: int) -> List[Detector]:
    return [d for d in DETECTORS if d.stage <= stage and d.stage <= max_stage]
