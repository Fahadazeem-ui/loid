"""Stage 3 detectors: read the descriptor files that *name* what a thing is.

Descriptors are the cheapest high-precision evidence available. They are also
where the old engine was weakest: it only looked in the archive root. Here we
look at any path in the listing (`src/main/resources/plugin.yml`,
`repo-main/package.json`, `overrides/...`, nested `mods/...`) and we tolerate
BOMs, CRLF, trailing commas, comments and non-standard key layouts.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .context import AnalysisContext
from .knowledge import RE_PACK_FORMAT
from .model import Evidence
from .readers import decode_text, json_like

JAR_DESCRIPTORS = (
    "plugin.yml", "bungee.yml", "paper-plugin.yml", "velocity-plugin.json",
    "nukkit.yml", "sponge_plugins.json", "fabric.mod.json", "quilt.mod.json",
    "mcmod.info", "META-INF/mods.toml", "META-INF/neoforge.mods.toml",
    "META-INF/MANIFEST.MF", "pack.mcmeta", "modrinth.index.json",
)


# ---------------------------------------------------------------------------
# small parsers
# ---------------------------------------------------------------------------


def parse_simple_yaml(text: str) -> Dict[str, str]:
    """Line-based YAML reader. Enough for plugin.yml / bukkit.yml headers."""
    out: Dict[str, str] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.lstrip().startswith("- "):
            if current:
                out.setdefault(current + "[]", line.strip()[2:].strip())
            continue
        m = re.match(r"^(\s*)([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", line)
        if not m:
            continue
        indent, key, value = m.group(1), m.group(2).strip(), m.group(3).strip()
        if indent == "":
            current = key.lower()
            out[current] = value.strip("'\"")
        elif current:
            out.setdefault(current + "." + key.lower(), value.strip("'\""))
    return out


def parse_simple_toml(text: str) -> Dict[str, Any]:
    """Grab top-level keys and array values without a full TOML parser."""
    out: Dict[str, Any] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip().strip('"').lower()
            value = value.strip().rstrip(",").strip('"')
            out[f"{section}.{key}" if section else key] = value
    return out


def _read_json_member(ctx: AnalysisContext, names: Sequence[str], limit: int = 131072) -> Tuple[Optional[str], Optional[dict]]:
    name, data = ctx.read_first(list(names), limit=limit)
    if data is None:
        return None, None
    parsed = json_like(data)
    return name, parsed


def _read_text_member(ctx: AnalysisContext, names: Sequence[str], limit: int = 131072) -> Tuple[Optional[str], str]:
    name, data = ctx.read_first(list(names), limit=limit)
    if data is None:
        return None, ""
    return name, decode_text(data)


def _norm_keys(obj: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        out[str(k).strip().lower()] = v
    return out


def _dep_names(obj: dict) -> List[str]:
    deps: List[str] = []
    for key in ("dependencies", "devdependencies", "peerDependencies", "optionalDependencies"):
        block = obj.get(key) or obj.get(key.lower())
        if isinstance(block, dict):
            deps.extend(str(k).lower() for k in block.keys())
        elif isinstance(block, list):
            deps.extend(str(k).lower() for k in block)
    return deps


def _req_names(text: str) -> List[str]:
    names: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            line = line.lstrip("- ").strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)", line)
        if m:
            names.append(m.group(1).lower().replace("_", "-"))
    return names


def _pyproject_names(text: str) -> List[str]:
    names: List[str] = []
    for m in re.finditer(r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*(?:[<>=!~]=|$)', text, re.M):
        names.append(m.group(1).lower().replace("_", "-"))
    for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*[<>=!~]", text, re.M):
        names.append(m.group(1).lower().replace("_", "-"))
    return names


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------


def d_java_descriptors(ctx: AnalysisContext) -> List[Evidence]:
    """plugin.yml / fabric.mod.json / mods.toml / velocity descriptor and friends."""
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev

    # ---- Bukkit-family plugin descriptors
    name, data = ctx.read_first(
        ["plugin.yml", "paper-plugin.yml", "bungee.yml", "nukkit.yml", "sponge_plugins.json"],
        limit=65536,
    )
    if data is not None:
        text = decode_text(data)
        info = parse_simple_yaml(text) if name.endswith((".yml", ".yaml")) else (_read_json_bytes(data) or {})
        if name.endswith((".yml", ".yaml")):
            platform = {
                "bungee.yml": "BungeeCord",
                "nukkit.yml": "Nukkit",
                "paper-plugin.yml": "Paper",
            }.get(name, "Bukkit/Spigot/Paper")
            weight = 6.6
            note = f"{platform} plugin descriptor found"
            if info.get("main"):
                note += f" (main: {short(info['main'])})"
            if info.get("name"):
                ctx.note("plugin_name", info.get("name"))
            if info.get("api-version") or info.get("apiversion"):
                ctx.note("plugin_api_version", info.get("api-version") or info.get("apiversion"))
                weight += 0.4
            if info.get("author") or info.get("authors"):
                ctx.note("plugin_author", info.get("author") or info.get("authors"))
            ev.append(Evidence("descriptor:plugin.yml", "mc.plugin", weight, note, 3))
            ctx.note("mc_java_artifact", "plugin")

    # ---- Velocity descriptor
    vname, vdata = ctx.read_first(["velocity-plugin.json", "META-INF/velocity-plugin.json"], limit=32768)
    if vdata is not None:
        parsed = json_like(vdata) or {}
        note = "Velocity plugin descriptor"
        if parsed.get("id"):
            note += f" (id: {parsed['id']})"
            ctx.note("plugin_name", parsed.get("id"))
        ev.append(Evidence("descriptor:velocity-plugin.json", "mc.plugin", 6.8, note, 3))
        ctx.note("mc_java_artifact", "plugin")

    # ---- Mod descriptors
    fname, fdata = ctx.read_first(["fabric.mod.json", "quilt.mod.json"], limit=131072)
    if fdata is not None:
        parsed = json_like(fdata) or {}
        loader = "Quilt" if "quilt" in (fname or "") else "Fabric"
        note = f"{loader} mod descriptor"
        if parsed.get("id"):
            ctx.note("mod_id", parsed.get("id"))
            note += f" (id: {parsed['id']})"
        version = parsed.get("version")
        if isinstance(version, str):
            note += f" v{version}"
        deps = parsed.get("depends") or {}
        dep_note = ""
        if isinstance(deps, dict):
            interesting = [k for k in deps if k in ("minecraft", "fabricloader", "fabric-api", "forge", "neoforge")]
            if interesting:
                dep_note = ", ".join(interesting)
        ev.append(Evidence("descriptor:fabric.mod.json", "mc.mod", 6.8, note + (f" [deps: {dep_note}]" if dep_note else ""), 3))
        if parsed.get("entrypoints"):
            ctx.note("has_entrypoints", True)
        ctx.note("mc_java_artifact", "mod")
        _texture_size(ctx, parsed)

    # ---- Forge / NeoForge TOML
    for cand in ("META-INF/neoforge.mods.toml", "META-INF/mods.toml", "mods.toml"):
        tname, tdata = ctx.read_first([cand], limit=131072)
        if tdata is None:
            continue
        text = decode_text(tdata)
        loader = "NeoForge" if "neoforge" in text.lower() or "neoforge" in cand else "Forge"
        toml = parse_simple_toml(text)
        modid = toml.get("modid") or toml.get("modid") or _find_first(text, r'modId\s*=\s*"?([A-Za-z0-9_.\-]+)')
        note = f"{loader} mod descriptor ({tname})"
        if modid:
            ctx.note("mod_id", modid)
            note += f" (modId: {modid})"
        if "loaderVersion" in text or "loader_version" in text.lower():
            note += " with loaderVersion"
        ev.append(Evidence("descriptor:mods.toml", "mc.mod", 6.8, note, 3))
        ctx.note("mc_java_artifact", "mod")

    # ---- Legacy mcmod.info
    lname, ldata = ctx.read_first(["mcmod.info"], limit=65536)
    if ldata is not None:
        parsed = json_like(ldata)
        modid = ""
        if isinstance(parsed, dict):
            arr = parsed.get("modList") or parsed.get("__value__") or []
            if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                modid = str(arr[0].get("modid", ""))
        ctx.note("mod_id", modid or None)
        ev.append(Evidence("descriptor:mcmod.info", "mc.mod", 5.6,
                           f"legacy Forge mod info{(' (modid: ' + modid + ')') if modid else ''}", 3))
        ctx.note("mc_java_artifact", "mod")

    # ---- pack.mcmeta (resource pack vs data pack)
    pname, pdata = ctx.read_first(["pack.mcmeta"], limit=32768)
    if pdata is not None:
        text = decode_text(pdata)
        fmt = ""
        m = RE_PACK_FORMAT.search(text)
        if m:
            fmt = m.group(1)
            ctx.note("pack_format", int(fmt))
        has_data = ctx.listing.has_dir("data")
        has_assets = ctx.listing.has_dir("assets")
        desc = _pack_description(text)
        if desc:
            ctx.note("pack_description", desc)
        if has_data and not has_assets:
            ev.append(Evidence("descriptor:pack.mcmeta", "mc.datapack", 5.6,
                               f"pack.mcmeta (format {fmt or '?'}) + data/ tree and no assets/", 3))
        elif has_assets:
            ev.append(Evidence("descriptor:pack.mcmeta", "mc.resourcepack", 5.0,
                               f"pack.mcmeta (format {fmt or '?'}) + assets/ tree", 3))
        elif ctx.listing.has_dir("shaders"):
            ev.append(Evidence("descriptor:pack.mcmeta", "mc.shaderpack", 2.4,
                               f"pack.mcmeta (format {fmt or '?'}) + shaders/ tree (hybrid pack)", 3))
        else:
            ev.append(Evidence("descriptor:pack.mcmeta", "mc.resourcepack", 2.8,
                               f"pack.mcmeta (format {fmt or '?'})", 3))
        if fmt:
            ctx.note("pack_format_hint", f"pack_format {fmt}")

    # ---- MANIFEST.MF
    mname, mdata = ctx.read_first(["META-INF/MANIFEST.MF", "MANIFEST.MF"], limit=65536)
    if mdata is not None:
        text = decode_text(mdata)
        attrs = _manifest_attrs(text)
        if attrs:
            ctx.note("jar_manifest", {k: v for k, v in list(attrs.items())[:12]})
        main = attrs.get("main-class", "")
        title = attrs.get("implementation-title", "")
        tweak = attrs.get("tweak-class", "")
        fml = any(k for k in attrs if "fml" in k.lower()) or "FMLModType" in text
        if fml:
            ev.append(Evidence("manifest:fml", "mc.mod", 4.2, "FML attributes in MANIFEST.MF", 3))
        if tweak:
            ev.append(Evidence("manifest:tweak", "mc.mod", 4.4, f"TweakClass: {short(tweak)}", 3))
        if main:
            ctx.note("main_class", main)
            if any(k in main.lower() for k in ("bukkit", "spigot", "paper", "bungee", "velocity")):
                ev.append(Evidence("manifest:main", "mc.plugin", 3.0,
                                   f"Main-Class references a server platform: {short(main)}", 3))
            if "forge" in main.lower() or "mod" in main.lower():
                ev.append(Evidence("manifest:main", "mc.mod", 2.2,
                                   f"Main-Class looks mod-like: {short(main)}", 3))
        if title:
            ctx.note("jar_title", title)
        if not ev or all(e.rule.startswith("manifest:fml") for e in ev):
            if attrs:
                ev.append(Evidence("manifest:generic", "dev.java", 1.4,
                                   "META-INF/MANIFEST.MF present (jar layout)", 3))
    return ev


def _texture_size(ctx: AnalysisContext, parsed: dict) -> None:
    """Push fabric mod context (client-only mods are still mods, but note it)."""
    if parsed.get("environment") == "client":
        ctx.note("mod_environment", "client-only")


def _read_json_bytes(data: bytes) -> Optional[dict]:
    return json_like(data)


def _find_first(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.I)
    return m.group(1) if m else ""


def _pack_description(text: str) -> str:
    m = re.search(r'"description"\s*:\s*(?:"([^"]{0,80})"|\{[^}]{0,200}\})', text, re.S)
    if not m:
        return ""
    return (m.group(1) or "").strip()


def _manifest_attrs(text: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    current_key: Optional[str] = None
    for raw in text.splitlines():
        if raw.startswith(" ") and current_key:
            attrs[current_key] += raw.strip()
            continue
        if ":" in raw:
            key, _, value = raw.partition(":")
            current_key = key.strip().lower()
            attrs[current_key] = value.strip()
    return attrs


def d_package_json(ctx: AnalysisContext) -> List[Evidence]:
    """package.json is the single most informative file in the JS world."""
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    name, obj = _read_json_member(
        ctx,
        ["package.json", "src/package.json", "bot/package.json", "app/package.json",
         "client/package.json", "server/package.json", "web/package.json"],
    )
    if obj is None:
        return ev
    obj = _norm_keys(obj)
    deps = _dep_names(obj)
    ctx.note("package_json_name", obj.get("name"))
    ctx.note("package_dependencies", deps[:20])

    engines = obj.get("engines") or {}
    if isinstance(engines, dict) and any("vscode" in str(k).lower() for k in engines):
        ev.append(Evidence("pkg:vscode", "dev.vscodeext", 6.6,
                           f"package.json declares VS Code engine ({engines})", 3))
    if any(d in ("obsidian",) or d.startswith("obsidian-") for d in deps):
        ev.append(Evidence("pkg:obsidian", "dev.obsidianplugin", 6.0,
                           "package.json depends on the Obsidian API", 3))
    if any(d == "discord.js" or d.startswith("@discordjs/") or d in ("eris", "oceanic.js", "discordeno") for d in deps):
        ev.append(Evidence("pkg:discord", "dev.discordbot", 6.4,
                           f"discord library dependency ({_pick(deps, ('discord.js', 'eris', 'oceanic.js', 'discordeno'))})", 3))
    if any(d in ("telegraf", "node-telegram-bot-api", "grammy", "telebot", "telegram") for d in deps):
        ev.append(Evidence("pkg:telegram", "dev.telegrambot", 6.4,
                           f"telegram bot library ({_pick(deps, ('telegraf', 'grammy', 'node-telegram-bot-api'))})", 3))
    if any(d == "mineflayer" or d.startswith("mineflayer-") or d == "minecraft-protocol" for d in deps):
        ev.append(Evidence("pkg:mineflayer", "dev.gamebot", 6.2,
                           "mineflayer dependency (game bot)", 3))
    if any(d in ("electron", "electron-builder", "electron-packager") for d in deps):
        ev.append(Evidence("pkg:electron", "sw.portable", 4.6, "electron app dependency", 3))
    if any(d in ("next", "nuxt", "react", "react-dom", "vue", "svelte", "angular", "@angular/core", "astro") for d in deps):
        ev.append(Evidence("pkg:web", "dev.web", 4.2, "front-end framework dependency", 3))
    if any(d in ("express", "fastify", "koa", "hapi", "@nestjs/core") for d in deps):
        ev.append(Evidence("pkg:web", "dev.web", 3.4, "server-side web framework dependency", 3))
    if any(d in ("typescript",) for d in deps) or "tsconfig.json" in (ctx.names or []):
        ev.append(Evidence("pkg:ts", "dev.other", 2.0, "TypeScript toolchain", 3))
    if not deps:
        ev.append(Evidence("pkg:empty", "misc.review", 0.6, "package.json with no dependencies", 3))
    return ev


def _pick(deps: Sequence[str], wanted: Sequence[str]) -> str:
    hits = [d for d in deps if d in wanted]
    return ", ".join(hits[:3]) if hits else ", ".join(deps[:3])


def d_python_descriptors(ctx: AnalysisContext) -> List[Evidence]:
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    names = ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"]
    collected: List[str] = []
    found_any = False
    for cand in names:
        member = ctx.find(cand)
        if not member:
            continue
        found_any = True
        data = ctx.read(member, limit=65536)
        text = decode_text(data) if data else ""
        if cand.endswith(".txt"):
            collected += _req_names(text)
        elif cand == "pyproject.toml":
            collected += _pyproject_names(text)
        elif cand == "setup.py":
            collected += re.findall(r"['\"]([A-Za-z0-9_.\-]{2,40})['\"]", text)[:20]
            if "install_requires" in text:
                collected += re.findall(r"['\"]([A-Za-z0-9_.\-]{2,40})['\"]", text)
    if found_any:
        collected = [c.lower().replace("_", "-") for c in collected]
        ctx.note("python_dependencies", sorted(set(collected))[:20])
        if any(c in ("discord.py", "nextcord", "disnake", "py-cord", "discord") for c in collected):
            ev.append(Evidence("py:discord", "dev.discordbot", 6.4,
                               f"discord.py-family dependency ({_pick(collected, ('discord.py', 'nextcord', 'disnake', 'py-cord'))})", 3))
        if any(c in ("python-telegram-bot", "aiogram", "pytelegrambotapi", "telebot", "telethon", "pyrogram") for c in collected):
            ev.append(Evidence("py:telegram", "dev.telegrambot", 6.4,
                               f"telegram bot dependency ({_pick(collected, ('python-telegram-bot', 'aiogram', 'telebot'))})", 3))
        if any(c in ("mineflayer", "javascript", "pycraft", "minecraft") for c in collected):
            ev.append(Evidence("py:mcbot", "dev.gamebot", 4.0, "Minecraft-related python dependency", 3))
        if any(c in ("django", "flask", "fastapi", "starlette", "aiohttp", "uvicorn", "gunicorn") for c in collected):
            ev.append(Evidence("py:webframework", "dev.web", 3.4, "python web framework dependency", 3))
        if any(c in ("pandas", "numpy", "scipy", "matplotlib", "scikit-learn", "torch", "tensorflow") for c in collected):
            ev.append(Evidence("py:datasci", "dev.python", 2.4, "data-science dependency stack", 3))
        if any(c in ("pygame", "arcade", "pyglet") for c in collected):
            ev.append(Evidence("py:game", "sw.game", 3.0, "python game framework dependency", 3))
    return ev


def d_build_files(ctx: AnalysisContext) -> List[Evidence]:
    """Maven/Gradle builds tell us plugin vs mod vs plain library."""
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    mname, mdata = ctx.read_first(["pom.xml"], limit=131072)
    if mdata is not None:
        text = decode_text(mdata).lower()
        note = "Maven project"
        weight = 4.8
        if "spigot-api" in text or "bukkit" in text or "spigotmc" in text:
            ev.append(Evidence("maven:spigot", "mc.plugin", 5.6, "Maven build against the Spigot/Bukkit API", 3))
            ctx.note("mc_java_artifact", "plugin")
        if "paper-api" in text or "papermc" in text:
            ev.append(Evidence("maven:paper", "mc.plugin", 5.8, "Maven build against the Paper API", 3))
            ctx.note("mc_java_artifact", "plugin")
        if "velocity" in text and "api" in text:
            ev.append(Evidence("maven:velocity", "mc.plugin", 5.2, "Maven build against the Velocity API", 3))
        if "minecraftforge" in text or "forge" in text and "minecraft" in text:
            ev.append(Evidence("maven:forge", "mc.mod", 5.0, "Maven build against the Forge API", 3))
            ctx.note("mc_java_artifact", "mod")
        if "neoforge" in text:
            ev.append(Evidence("maven:neoforge", "mc.mod", 5.2, "Maven build against the NeoForge API", 3))
        if "fabric" in text and "loader" in text:
            ev.append(Evidence("maven:fabric", "mc.mod", 5.0, "Maven build against the Fabric loader", 3))
        artifact = _find_first(text, r"<artifactId>\s*([a-z0-9_.\-]+)\s*</artifactId>")
        if artifact:
            ctx.note("maven_artifact", artifact)
            note += f" (artifact: {artifact})"
        ev.append(Evidence("maven", "dev.java", weight, note, 3))

    for cand in ("build.gradle", "build.gradle.kts"):
        gname, gdata = ctx.read_first([cand], limit=131072)
        if gdata is None:
            continue
        text = decode_text(gdata)
        low = text.lower()
        note = f"Gradle build ({cand})"
        if "fabric-loom" in low or "net.fabricmc" in low:
            ev.append(Evidence("gradle:fabric", "mc.mod", 6.4, "Gradle uses fabric-loom (Fabric mod)", 3))
            ctx.note("mc_java_artifact", "mod")
        if "net.minecraftforge" in low or "minecraftforge" in low or "fg.deobf" in low or "net.minecraftforge.gradle" in low:
            ev.append(Evidence("gradle:forge", "mc.mod", 6.2, "Gradle uses the ForgeGradle plugin (mod)", 3))
            ctx.note("mc_java_artifact", "mod")
        if "net.neoforged" in low or "neoforge" in low or "neo-forge" in low:
            ev.append(Evidence("gradle:neoforge", "mc.mod", 6.4, "Gradle uses NeoGradle/NeoForge (mod)", 3))
            ctx.note("mc_java_artifact", "mod")
        if "io.papermc.paper" in low or "paper-api" in low or "papermc" in low:
            ev.append(Evidence("gradle:paper", "mc.plugin", 6.0, "Gradle depends on the Paper API (plugin)", 3))
            ctx.note("mc_java_artifact", "plugin")
        if "spigot-api" in low or "org.spigotmc" in low or "bukkit" in low:
            ev.append(Evidence("gradle:spigot", "mc.plugin", 5.8, "Gradle depends on Spigot/Bukkit (plugin)", 3))
            ctx.note("mc_java_artifact", "plugin")
        if "velocity-api" in low or "com.velocitypowered" in low:
            ev.append(Evidence("gradle:velocity", "mc.plugin", 6.0, "Gradle depends on Velocity (proxy plugin)", 3))
        if "com.destroystokyo.paper" in low or "paperspigot" in low:
            ev.append(Evidence("gradle:paper-legacy", "mc.plugin", 5.6, "Gradle depends on legacy Paper", 3))
        if "application {" in low or "mainclass" in low:
            note += ", application plugin"
        ev.append(Evidence("gradle", "dev.java", 4.6, note, 3))
        break

    sname, sdata = ctx.read_first(["settings.gradle", "settings.gradle.kts"], limit=32768)
    if sdata is not None:
        text = decode_text(sdata)
        root = _find_first(text, r"rootProject\.name\s*=\s*['\"]([^'\"]+)['\"]")
        if root:
            ctx.note("gradle_root_project", root)
        ev.append(Evidence("gradle:settings", "dev.java", 3.6, "Gradle settings file (multi-module Java project)", 3))
    return ev


def d_other_project_files(ctx: AnalysisContext) -> List[Evidence]:
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    cname, cdata = ctx.read_first(["Cargo.toml"], limit=65536)
    if cdata is not None:
        toml = parse_simple_toml(decode_text(cdata))
        pkg = toml.get("package.name", "")
        if pkg:
            ctx.note("crate_name", pkg)
        ev.append(Evidence("cargo", "dev.rust", 5.6, f"Cargo manifest{(' (crate ' + pkg + ')') if pkg else ''}", 3))
    gname, gdata = ctx.read_first(["go.mod"], limit=32768)
    if gdata is not None:
        mod = _find_first(decode_text(gdata), r"module\s+(\S+)")
        if mod:
            ctx.note("go_module", mod)
        ev.append(Evidence("go.mod", "dev.go", 5.6, f"Go module{(' (' + mod + ')') if mod else ''}", 3))
    for cand in ("*.csproj", "*.sln", "*.vbproj"):
        if not cand.startswith("*"):
            continue
        hits = ctx.listing.matching(cand) if ctx.listing else []
        if hits:
            ctx.note("dotnet_project", hits[0])
            ev.append(Evidence("csproj", "dev.dotnet", 5.6, f".NET project file ({hits[0]})", 3))
            break
    # WordPress / PHP
    php_files = [n for n in (ctx.names or []) if n.endswith(".php")][:12]
    if php_files:
        for member in [m for m in ctx.listing.names(rel=False) if m.lower().endswith(".php")][:6]:
            data = ctx.read(member, limit=16384)
            text = decode_text(data).lower() if data else ""
            if "plugin name:" in text and ("version:" in text or "description:" in text):
                ctx.note("wordpress_plugin", _find_first(text, r"plugin name:\s*([^\n*]{2,60})"))
                ev.append(Evidence("wp:header", "dev.wordpressplugin", 6.4,
                                   "PHP file with a WordPress plugin header", 3))
                break
    return ev


def d_minecraft_extra(ctx: AnalysisContext) -> List[Evidence]:
    """Minecraft-specific odds and ends (Skript, Bedrock, server bundles)."""
    ev: List[Evidence] = []
    if not ctx.listing:
        return ev
    names = ctx.names or []
    sk = [n for n in names if n.endswith(".sk")]
    if sk:
        ev.append(Evidence("skript", "mc.plugin", 5.0, f"{len(sk)} Skript .sk scripts (server-side plugin content)", 3))
    # Bedrock addon manifests
    bname, bdata = ctx.read_first(["manifest.json"], limit=65536)
    if bdata is not None:
        obj = json_like(bdata)
        if obj and any(k in _norm_keys(obj) for k in ("format_version",)) and "modules" in _norm_keys(obj):
            ob = _norm_keys(obj)
            modules = ob.get("modules") or []
            mtype = ""
            if isinstance(modules, list) and modules and isinstance(modules[0], dict):
                mtype = str(modules[0].get("type", ""))
            header = ob.get("header") if isinstance(ob.get("header"), dict) else {}
            if isinstance(header, dict) and header.get("name"):
                ctx.note("bedrock_pack_name", header.get("name"))
            if "resources" in mtype:
                ev.append(Evidence("bedrock:manifest", "mc.resourcepack", 5.8,
                                   "Bedrock manifest with a resources module", 3))
            elif "data" in mtype or "script" in mtype:
                ev.append(Evidence("bedrock:manifest", "mc.datapack", 5.2,
                                   "Bedrock manifest with a data/script module (behavior pack)", 3))
            else:
                ev.append(Evidence("bedrock:manifest", "mc.other", 3.0, "Bedrock add-on manifest", 3))
    # server bundle heuristics
    if ctx.listing.has_dir("plugins") and any(n.endswith(".jar") for n in names):
        ev.append(Evidence("server:plugins-dir", "mc.server", 4.2,
                           "plugins/ folder with jars (server deployment bundle)", 3))
    if ctx.find("server.properties") and (ctx.listing.has_dir("world") or any(n.startswith("world/") for n in names)):
        ev.append(Evidence("server:world", "mc.server", 3.6,
                           "server.properties next to a world/ folder", 3))
    return ev


DESCRIPTORS: List[Detector] = []


def _register() -> None:
    from .detectors import Detector  # local import to avoid cycle at module use

    DESCRIPTORS.extend(
        [
            Detector("java-descriptors", 3, d_java_descriptors),
            Detector("package-json", 3, d_package_json),
            Detector("python-descriptors", 3, d_python_descriptors),
            Detector("build-files", 3, d_build_files),
            Detector("other-project-files", 3, d_other_project_files),
            Detector("minecraft-extra", 3, d_minecraft_extra),
        ]
    )


_register()


def short(text: str, limit: int = 50) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
