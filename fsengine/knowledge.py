"""Knowledge base: signatures, marker tables and name hints.

Everything the engine "knows" about file families is data in this module, so
learning a new ecosystem = adding rows here, not touching the algorithm.

Weights are calibrated roughly as:
    6+  provable, spec-level evidence (fabric.mod.json, AndroidManifest.xml)
    4-5 strong structural evidence (assets/minecraft/, shaders/*.fsh)
    2-3 structural hints that in isolation prove nothing (package.json)
    0-2 statistical nudges (folder names, token counts)
   <0   counter-evidence that actively argues against a label
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Sig:
    """A path/name signature. ``glob=True`` matches the whole path pattern."""

    needle: str
    weight: float
    note: str
    glob: bool = False
    contains: bool = False

    def matches(self, path: str) -> bool:
        p = path.lower().rstrip("/")
        n = self.needle.lower().rstrip("/")
        if self.glob:
            if any(ch in n for ch in "*?["):
                return _glob_match(p, n)
            # Wildcard-free "glob" = prefix/folder pattern ("assets/minecraft/textures")
            return p == n or p.startswith(n + "/") or ("/" + n + "/") in (p + "/") or p.endswith("/" + n)
        if self.contains:
            return n in p
        return p == n or p.endswith("/" + n) or p.startswith(n + "/") or ("/" + n + "/") in (p + "/")


def _glob_match(path: str, pattern: str) -> bool:
    """Segment-aware glob matching.

    ``shaders/*.fsh`` must match ``shaders/composite.fsh`` and
    ``world/region/x.mca`` must match ``region/*.mca`` — but *must not* match
    ``assets/minecraft/shaders/core/rendertype_solid.fsh``. Python's fnmatch
    lets ``*`` cross ``/``, which is exactly how a resource pack gets mistaken
    for a shaderpack, so we build our own regex where ``*`` stops at ``/``.
    """
    import re as _re

    rx = _re.escape(pattern).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    try:
        full = _re.compile(r"^(?:.*/)?" + rx + r"$")
    except _re.error:
        return False
    if full.match(path):
        return True
    segments = path.split("/")
    for i in range(len(segments)):
        if full.match("/".join(segments[: i + 1])):
            return True
    return False


# ---------------------------------------------------------------------------
# Path signatures (matched against archive member paths)
# ---------------------------------------------------------------------------

PATH_SIGS: Dict[str, List[Sig]] = {
    # --- Minecraft: shaderpacks -----------------------------------------
    "mc.shaderpack": [
        Sig("shaders/shaders.properties", 6.0, "OptiFine shaderpack root descriptor", glob=True),
        Sig("shaders/*/shaders.properties", 6.0, "dimensional shaderpack descriptor", glob=True),
        Sig("shaders/*.fsh", 5.0, "GLSL fragment shader source", glob=True),
        Sig("shaders/*.vsh", 5.0, "GLSL vertex shader source", glob=True),
        Sig("shaders/*.gsh", 4.7, "GLSL geometry shader source", glob=True),
        Sig("shaders/*.csh", 4.7, "GLSL compute shader source", glob=True),
        Sig("shaders/lang/en_us.lang", 4.0, "shaderpack language file", glob=True),
        Sig("shaders/world0", 5.2, "per-dimension shader pack (OptiFine/Iris)", glob=True),
        Sig("shaders/world-1", 5.0, "nether shader program set", glob=True),
        Sig("shaders/dimension.properties", 5.0, "Iris dimension config", glob=True),
        Sig("shaders/lib/*.glsl", 4.8, "shader include library", glob=True),
        Sig("shaders/*.glsl", 4.5, "GLSL program", glob=True),
        Sig("shaders/program/*.glsl", 5.0, "shader program directory", glob=True),
        Sig("shaders/program/*.fsh", 5.0, "shader program directory", glob=True),
        Sig("shaders/*.properties", 5.5, "shader program settings", glob=True),
        Sig("shaders/block.properties", 5.5, "OptiFine block->program mapping", glob=True),
        Sig("shaders/item.properties", 5.2, "OptiFine item->program mapping", glob=True),
        Sig("shaders/entity.properties", 5.2, "OptiFine entity->program mapping", glob=True),
        Sig("iris.properties", 4.0, "Iris shader config", glob=True),
        Sig("shaders/composite*.fsh", 5.0, "composite shader stage", glob=True),
    ],
    # --- Minecraft: resource packs --------------------------------------
    "mc.resourcepack": [
        Sig("assets/minecraft/textures", 5.6, "vanilla texture tree", glob=True),
        Sig("assets/minecraft/models", 5.4, "vanilla model tree", glob=True),
        Sig("assets/minecraft/blockstates", 5.4, "vanilla blockstate tree", glob=True),
        Sig("assets/minecraft/lang/en_us.json", 5.0, "vanilla language file", glob=True),
        Sig("assets/minecraft/font", 4.4, "vanilla font tree", glob=True),
        Sig("assets/minecraft/sounds.json", 4.6, "vanilla sound registry", glob=True),
        Sig("assets/minecraft/optifine", 5.6, "OptiFine resource pack extras (CIT/CTM)", glob=True),
        Sig("assets/minecraft/textures/gui", 4.4, "vanilla GUI textures", glob=True),
        Sig("assets/minecraft/shaders", 4.2, "vanilla core shader tree", glob=True),
        Sig("assets/minecraft/textures/gui/container", 4.2, "vanilla container GUI sheet", glob=True),
        Sig("assets/minecraft/font/default.json", 4.5, "vanilla font provider", glob=True),
        Sig("assets/minecraft/atlases", 4.5, "atlas definition (pack format 19+)", glob=True),
        Sig("assets/*/textures", 4.0, "namespaced texture tree", glob=True),
        Sig("assets/*/lang/en_us.json", 3.8, "namespaced language file", glob=True),
        Sig("assets/*/models", 3.8, "namespaced model tree", glob=True),
        Sig("assets/*/blockstates", 3.6, "namespaced blockstate tree", glob=True),
        Sig("assets/*/sounds.json", 3.6, "namespaced sound registry", glob=True),
        Sig("assets/*/font", 3.4, "namespaced font tree", glob=True),
        Sig("pack.png", 3.2, "pack icon (resource/datapack convention)"),
        Sig("assets/minecraft/textures/font", 4.2, "bitmap font sheet", glob=True),
        Sig("assets/minecraft/textures/environment", 4.2, "sky/environment textures", glob=True),
        Sig("assets/minecraft/textures/gui/title", 4.2, "title screen textures", glob=True),
        Sig("assets/realms", 3.4, "realms textures", glob=True),
        Sig("assets/minecraft/shaders/core", 5.0, "vanilla core shader tree (resource-pack content)", glob=True),
        Sig("assets/minecraft/shaders/post", 4.6, "vanilla post-processing shader", glob=True),
        Sig("assets/minecraft/shaders/include", 4.6, "vanilla shader include", glob=True),
        Sig("assets/*/shaders/core", 4.4, "mod-provided core shader (resource-pack side)", glob=True),
        Sig("assets/minecraft/textures/painting", 3.8, "painting textures", glob=True),
        Sig("assets/minecraft/textures/particle", 3.6, "particle textures", glob=True),
    ],
    # NOTE: core shaders (assets/minecraft/shaders/...) are *resource pack*
    # content. They are listed here, not as a separate label, and the path
    # detector additionally emits counter-evidence against "shaderpack".
    # --- Minecraft: datapacks -------------------------------------------
    "mc.datapack": [
        Sig("data/minecraft/tags", 5.4, "vanilla tag overrides", glob=True),
        Sig("data/*/function/", 5.6, "function tree (1.21+ layout)", contains=True),
        Sig("data/*/functions/", 5.6, "function tree (legacy layout)", contains=True),
        Sig("data/*/advancement/", 5.2, "advancement tree (1.21+ layout)", contains=True),
        Sig("data/*/advancements/", 5.2, "advancement tree (legacy)", contains=True),
        Sig("data/*/loot_table/", 4.8, "loot table tree (1.21+ layout)", contains=True),
        Sig("data/*/loot_tables/", 4.8, "loot table tree (legacy)", contains=True),
        Sig("data/*/recipe/", 4.6, "recipe tree (1.21+ layout)", contains=True),
        Sig("data/*/recipes/", 4.6, "recipe tree (legacy)", contains=True),
        Sig("data/*/predicate/", 4.4, "predicate tree", contains=True),
        Sig("data/*/predicates/", 4.4, "predicate tree", contains=True),
        Sig("data/*/structure/", 4.2, "structure tree", contains=True),
        Sig("data/*/worldgen/", 4.4, "worldgen tree", contains=True),
        Sig("data/minecraft/worldgen", 4.8, "vanilla worldgen overrides", glob=True),
        Sig("data/*/tags/", 4.4, "tag tree", contains=True),
        Sig("data/*/damage_type/", 4.6, "damage type tree", contains=True),
        Sig("data/*/enchantment/", 4.6, "enchantment tree", contains=True),
        Sig("data/*/dimension_type/", 4.4, "dimension type tree", contains=True),
        Sig("data/*/datapacks", 3.0, "packed datapack inside a world", glob=True),
    ],
    # --- Minecraft: worlds ----------------------------------------------
    "mc.world": [
        Sig("level.dat", 6.0, "world save descriptor"),
        Sig("level.dat_old", 5.0, "world save backup descriptor"),
        Sig("region/r.0.0.mca", 5.2, "anvil region file", glob=True),
        Sig("region/*.mca", 5.0, "anvil region file", glob=True),
        Sig("region/*.mcr", 4.6, "mcregion file (legacy world)", glob=True),
        Sig("playerdata/*.dat", 4.6, "player data directory", glob=True),
        Sig("data/map_*.dat", 4.4, "map data", glob=True),
        Sig("levelname.txt", 4.6, "world display name"),
        Sig("session.lock", 4.4, "world lock file"),
        Sig("DIM-1/region", 4.8, "nether dimension folder", glob=True),
        Sig("DIM1/region", 4.8, "end dimension folder", glob=True),
        Sig("dimensions/minecraft/overworld", 5.0, "custom dimension layout", glob=True),
        Sig("world/level.dat", 6.0, "world save inside a wrapper folder", glob=True),
        Sig("server.properties", 3.4, "server config (world bundles often ship one)"),
    ],
    # --- Minecraft: server bundles --------------------------------------
    "mc.server": [
        Sig("spigot.yml", 5.6, "Spigot server config"),
        Sig("bukkit.yml", 5.4, "Bukkit server config"),
        Sig("paper.yml", 5.4, "Paper server config (legacy)"),
        Sig("paper-global.yml", 5.6, "Paper server config"),
        Sig("server.properties", 4.6, "Minecraft server properties"),
        Sig("eula.txt", 4.6, "Minecraft EULA file"),
        Sig("ops.json", 4.0, "operator list"),
        Sig("whitelist.json", 3.8, "whitelist"),
        Sig("banned-players.json", 3.6, "ban list"),
        Sig("plugins/", 4.6, "plugins directory", contains=True),
        Sig("mods/", 3.4, "mods directory", contains=True),
        Sig("crash-reports/", 4.0, "server crash reports", contains=True),
        Sig("logs/latest.log", 4.4, "server log", glob=True),
        Sig("usercache.json", 3.6, "usercache"),
        Sig("server.jar", 3.0, "server jar"),
    ],
    # --- Minecraft: modpacks --------------------------------------------
    "mc.modpack": [
        Sig("modrinth.index.json", 6.5, "Modrinth .mrpack manifest"),
        Sig("mmc-pack.json", 6.0, "MultiMC/Prism instance descriptor"),
        Sig("instance.cfg", 5.4, "MultiMC/Prism instance config"),
        Sig("overrides/", 4.2, "CurseForge/SKP overrides folder", contains=True),
        Sig("client-overrides/", 4.4, ".mrpack client overrides", contains=True),
        Sig("config/", 1.6, "mod config folder (also used by mods)", contains=True),
        Sig(".minecraft/mods/", 5.0, "instance mods folder", contains=True),
        Sig(".minecraft/config/", 4.4, "instance config folder", contains=True),
        Sig("instance.cfg.disabled", 2.0, "disabled instance config"),
        Sig("manifest.json", 2.6, "may be a CurseForge manifest (needs key check)"),
    ],
    # --- Minecraft: plugins (archives) ----------------------------------
    "mc.plugin": [
        Sig("plugin.yml", 6.2, "Bukkit/Spigot/Paper plugin descriptor"),
        Sig("plugin.yml.disabled", 3.0, "disabled plugin descriptor"),
        Sig("bungee.yml", 6.2, "BungeeCord plugin descriptor"),
        Sig("velocity-plugin.json", 6.4, "Velocity plugin descriptor"),
        Sig("sponge_plugins.json", 6.0, "Sponge plugin descriptor"),
        Sig("META-INF/velocity-plugin.json", 6.2, "Velocity descriptor (META-INF)", glob=True),
        Sig("nukkit.yml", 5.8, "Nukkit plugin descriptor"),
        Sig("paper-plugin.yml", 6.2, "Paper plugin descriptor"),
        Sig("fabric.mod.json", -1.2, "mod descriptor (argues against plugin)"),
        Sig("META-INF/mods.toml", -1.2, "forge descriptor (argues against plugin)"),
    ],
    # --- Minecraft: mods -------------------------------------------------
    "mc.mod": [
        Sig("fabric.mod.json", 6.6, "Fabric mod descriptor"),
        Sig("quilt.mod.json", 6.2, "Quilt mod descriptor"),
        Sig("META-INF/mods.toml", 6.4, "Forge mod descriptor", glob=True),
        Sig("META-INF/neoforge.mods.toml", 6.6, "NeoForge mod descriptor", glob=True),
        Sig("mcmod.info", 5.4, "legacy Forge mod info"),
        Sig("META-INF/MANIFEST.MF", 1.6, "manifest (FML/tweak class hints)"),
        Sig("mixins.json", 3.6, "mixin config"),
        Sig("*mixins.json", 3.8, "mixin config", glob=True),
        Sig("mixins.*.json", 3.8, "mixin config", glob=True),
        Sig("assets/fabric", 3.4, "fabric resources", glob=True),
        Sig("fabric.mod.json.disabled", 2.6, "disabled Fabric descriptor"),
        Sig("META-INF/jarjar", 2.0, "nested dependency jars", glob=True),
        Sig("META-INF/MANIFEST.MF.MF", 0.0, "manifest oddity"),
    ],
    # --- Discord bots ----------------------------------------------------
    "dev.discordbot": [
        Sig("cogs/", 3.6, "discord.py cogs package", contains=True),
        Sig("commands/", 2.0, "command package (common in bots)", contains=True),
        Sig("events/", 1.6, "event handlers package", contains=True),
        Sig("slashcommands/", 2.6, "slash command package", contains=True),
        Sig(".env", 1.0, "dotenv file (may hold a token)"),
        Sig("deploy-commands.js", 3.4, "discord.js slash command deployer"),
        Sig("deploy_commands.js", 3.2, "discord.js slash command deployer"),
        Sig("register-commands.js", 3.0, "discord.js command registrar"),
        Sig("commands.js", 1.2, "command module"),
        Sig("handlers.js", 0.8, "handlers module"),
        Sig("lavalink/", 2.0, "music node config", contains=True),
        Sig("application.yml", 0.8, "config file"),
        Sig("src/commands/", 2.2, "bot command tree", contains=True),
        Sig("src/events/", 2.0, "bot event tree", contains=True),
        Sig("src/handlers/", 1.6, "bot handler tree", contains=True),
        Sig("bot.js", 1.6, "likely bot entry point"),
        Sig("bot.py", 1.6, "likely bot entry point"),
        Sig("docker-compose.yml", 0.6, "deployment file"),
    ],
    # --- Telegram bots ---------------------------------------------------
    "dev.telegrambot": [
        Sig("handlers/", 1.4, "handlers package", contains=True),
        Sig("handlers/*.py", 1.6, "python bot handlers", glob=True),
        Sig("bot.py", 1.2, "likely bot entry point"),
        Sig("plugins/", 1.0, "plugin folder", contains=True),
    ],
    # --- Game / AFK bots -------------------------------------------------
    "dev.gamebot": [
        Sig("bot.js", 1.4, "likely bot entry point"),
        Sig("afk.js", 2.6, "AFK keeper script"),
        Sig("config.json", 0.8, "bot config"),
        Sig("accounts.json", 2.4, "bot account list"),
        Sig("aternos.js", 3.4, "Aternos integration"),
        Sig("mineflayer", 3.0, "mineflayer reference in path", contains=True),
    ],
    # --- Developer projects ---------------------------------------------
    "dev.vscodeext": [
        Sig(".vscode/launch.json", 2.0, "VS Code launch config", glob=True),
        Sig("extension.js", 3.4, "VS Code extension entry point"),
        Sig("extension.ts", 3.4, "VS Code extension entry point"),
        Sig(".vscodeignore", 4.6, "VS Code extension packaging file"),
        Sig(".vsixmanifest", 5.0, "VSIX manifest"),
        Sig("extension.vsixmanifest", 5.0, "VSIX manifest"),
        Sig("node_modules/", 1.0, "bundled dependencies", contains=True),
    ],
    "dev.obsidianplugin": [
        Sig("main.js", 1.6, "Obsidian plugin bundle"),
        Sig("manifest.json", 1.2, "Obsidian plugin manifest (needs key check)"),
        Sig("styles.css", 1.6, "Obsidian plugin styles"),
        Sig("versions.json", 2.4, "Obsidian plugin version map"),
        Sig(".hotreload", 3.0, "Obsidian hot-reload marker"),
    ],
    "dev.browserext": [
        Sig("manifest.json", 2.4, "web extension manifest (needs key check)"),
        Sig("_locales/", 3.6, "web extension locales", contains=True),
        Sig("background.js", 2.6, "extension background script"),
        Sig("content.js", 2.4, "extension content script"),
        Sig("popup.html", 2.6, "extension popup"),
        Sig("service_worker.js", 2.4, "MV3 service worker"),
        Sig("icons/icon128.png", 1.6, "extension icon set", glob=True),
        Sig("_metadata/", 3.0, "crx metadata", contains=True),
    ],
    "dev.wordpressplugin": [
        Sig("uninstall.php", 3.6, "WordPress uninstall hook"),
        Sig("readme.txt", 1.4, "WordPress plugin readme (needs header check)"),
        Sig("includes/", 1.4, "WordPress includes folder", contains=True),
        Sig("admin/", 1.2, "WordPress admin folder (weak)", contains=True),
        Sig("wp-content/", 4.2, "WordPress content root", contains=True),
    ],
    # --- Ecosystems ------------------------------------------------------
    "dev.python": [
        Sig("setup.py", 4.2, "Python packaging script"),
        Sig("pyproject.toml", 4.4, "Python project metadata"),
        Sig("requirements.txt", 3.6, "Python dependencies"),
        Sig("__init__.py", 2.4, "Python package marker"),
        Sig("__main__.py", 3.2, "Python entry module"),
        Sig("Pipfile", 4.0, "Pipenv project"),
        Sig("poetry.lock", 4.2, "Poetry lockfile"),
        Sig(".venv/", 3.6, "virtualenv", contains=True),
        Sig("venv/", 3.0, "virtualenv", contains=True),
        Sig("tox.ini", 3.6, "tox config"),
        Sig("manage.py", 4.4, "Django manage script"),
        Sig("*.py", 1.8, "python source files", glob=True),
        Sig("*.ipynb", 3.0, "Jupyter notebook", glob=True),
    ],
    "dev.node": [
        Sig("package.json", 3.6, "Node package metadata"),
        Sig("package-lock.json", 3.8, "npm lockfile"),
        Sig("yarn.lock", 3.8, "yarn lockfile"),
        Sig("pnpm-lock.yaml", 3.8, "pnpm lockfile"),
        Sig("node_modules/", 4.2, "installed dependencies", contains=True),
        Sig("next.config.js", 3.8, "Next.js config"),
        Sig("vite.config.js", 3.8, "Vite config"),
        Sig("vite.config.ts", 3.8, "Vite config"),
        Sig("webpack.config.js", 4.0, "webpack config"),
        Sig("tsconfig.json", 3.2, "TypeScript config"),
        Sig("eslint.config.js", 3.0, "ESLint flat config"),
        Sig(".npmrc", 2.6, "npm config"),
    ],
    "dev.java": [
        Sig("pom.xml", 4.6, "Maven project"),
        Sig("build.gradle", 4.4, "Gradle build script"),
        Sig("build.gradle.kts", 4.4, "Gradle build script"),
        Sig("settings.gradle", 4.0, "Gradle settings"),
        Sig("gradlew", 4.0, "Gradle wrapper"),
        Sig("gradlew.bat", 4.0, "Gradle wrapper"),
        Sig("gradle/wrapper/gradle-wrapper.properties", 4.2, "Gradle wrapper config", glob=True),
        Sig("src/main/java/", 4.2, "Maven/Gradle source layout", contains=True),
        Sig("src/test/java/", 3.6, "Maven/Gradle test layout", contains=True),
        Sig("mvnw", 3.8, "Maven wrapper"),
    ],
    "dev.rust": [
        Sig("Cargo.toml", 5.6, "Rust manifest"),
        Sig("Cargo.lock", 5.0, "Rust lockfile"),
        Sig("src/main.rs", 4.6, "Rust entry point", glob=True),
        Sig("src/lib.rs", 4.4, "Rust library root", glob=True),
    ],
    "dev.go": [
        Sig("go.mod", 5.6, "Go module"),
        Sig("go.sum", 5.0, "Go checksum file"),
        Sig("main.go", 4.4, "Go entry point"),
    ],
    "dev.dotnet": [
        Sig("*.csproj", 5.4, "C# project file", glob=True),
        Sig("*.sln", 4.8, "Visual Studio solution", glob=True),
        Sig("Program.cs", 4.2, "C# entry point"),
        Sig("*.vbproj", 5.2, "VB.NET project file", glob=True),
        Sig("packages.config", 3.2, "NuGet config"),
        Sig("obj/", 2.2, ".NET build objects", contains=True),
        Sig("bin/Debug/", 3.0, ".NET build output", contains=True),
    ],
    "dev.web": [
        Sig("index.html", 3.4, "web entry page"),
        Sig("public/index.html", 3.6, "web entry page", glob=True),
        Sig("src/App.jsx", 3.6, "React app root", glob=True),
        Sig("src/App.tsx", 3.6, "React app root", glob=True),
        Sig("src/app/page.tsx", 3.6, "Next.js app router page", glob=True),
        Sig("styles.css", 1.4, "stylesheet"),
        Sig("assets/css/", 1.6, "css assets", contains=True),
        Sig("favicon.ico", 2.0, "site icon"),
        Sig("angular.json", 3.6, "Angular workspace"),
        Sig("svelte.config.js", 3.6, "Svelte config"),
        Sig("nuxt.config.ts", 3.6, "Nuxt config"),
        Sig("index.php", 3.4, "PHP entry page"),
    ],
    "dev.shell": [
        Sig("*.bat", 2.2, "Windows batch script", glob=True),
        Sig("*.cmd", 2.2, "Windows command script", glob=True),
        Sig("*.ps1", 2.4, "PowerShell script", glob=True),
        Sig("*.sh", 2.0, "shell script", glob=True),
    ],
    # --- Software --------------------------------------------------------
    "sw.installer": [
        Sig("setup.exe", 4.6, "installer executable"),
        Sig("*setup*.exe", 4.0, "installer executable", glob=True),
        Sig("*installer*.exe", 4.0, "installer executable", glob=True),
        Sig("install.exe", 4.0, "installer executable"),
        Sig("*.msi", 5.4, "Windows Installer package", glob=True),
        Sig("*.msix", 5.4, "MSIX package", glob=True),
        Sig("*.appx", 5.2, "AppX package", glob=True),
        Sig("*.msixbundle", 5.4, "MSIX bundle", glob=True),
        Sig("installer.exe", 4.4, "installer executable"),
        Sig("unins000.exe", 5.0, "Inno Setup uninstaller"),
        Sig("uninstall.exe", 4.0, "uninstaller"),
        Sig("[Content_Types].xml", 3.4, "OPC/MSIX package marker"),
        Sig("[$]PLUGINSDIR/", 4.6, "NSIS plugin payload", contains=True),
        Sig("$PLUGINSDIR/", 4.6, "NSIS plugin payload", contains=True),
        Sig("inno setup", 4.0, "Inno Setup string in path", contains=True),
        Sig("msitools", 2.0, "msi tooling", contains=True),
    ],
    "sw.portable": [
        Sig("*.exe", 2.8, "Windows executable", glob=True),
        Sig("*.dll", 1.2, "Windows library", glob=True),
        Sig("resources/app.asar", 5.0, "Electron app payload", glob=True),
        Sig("resources/app/", 3.6, "Electron app resources", contains=True),
        Sig("locales/en-us.pak", 3.4, "Chromium locale pak", glob=True),
        Sig("*.pak", 2.2, "resource pak", glob=True),
        Sig("lib/", 1.0, "library folder (very weak)", contains=True),
        Sig("portable", 1.4, "portable in name/path", contains=True),
        Sig("app/", 1.2, "app folder (weak)", contains=True),
    ],
    "sw.android": [
        Sig("AndroidManifest.xml", 5.6, "Android manifest (binary or text)"),
        Sig("classes.dex", 6.2, "Dalvik bytecode"),
        Sig("classes2.dex", 5.8, "Dalvik bytecode (multidex)"),
        Sig("resources.arsc", 5.6, "compiled Android resources"),
        Sig("res/layout/", 4.6, "compiled layout tree", contains=True),
        Sig("META-INF/CERT.RSA", 4.8, "APK signature block", glob=True),
        Sig("META-INF/CERT.SF", 4.6, "APK signature manifest", glob=True),
        Sig("lib/arm64-v8a/", 4.4, "Android native libs", contains=True),
        Sig("lib/armeabi-v7a/", 4.4, "Android native libs", contains=True),
        Sig("lib/x86_64/", 3.6, "Android native libs", contains=True),
        Sig("assets/flutter_assets/", 5.0, "Flutter app payload", contains=True),
        Sig("res/xml/", 4.0, "Android xml resources", contains=True),
        Sig("res/drawable/", 4.0, "Android drawable resources", contains=True),
        Sig("bundleconfig.pb", 5.6, "Android App Bundle config", glob=True),
        Sig("base/manifest/AndroidManifest.xml", 5.8, "AAB base manifest", glob=True),
    ],
    "sw.game": [
        Sig("UnityPlayer.dll", 6.2, "Unity runtime"),
        Sig("*_Data/", 4.6, "Unity data folder", glob=True),
        Sig("*/Managed/Assembly-CSharp.dll", 5.2, "Unity managed assemblies", glob=True),
        Sig("*_Data/Managed/", 5.0, "Unity managed code", contains=True),
        Sig("*_Data/il2cpp_data/", 5.2, "Unity IL2CPP payload", contains=True),
        Sig("globalgamemanagers", 5.6, "Unity asset database"),
        Sig("level0", 3.6, "Unity scene bundle"),
        Sig("resources.assets", 5.0, "Unity resource bundle"),
        Sig("Engine/Binaries/", 4.6, "Unreal engine folder", contains=True),
        Sig("*.pak", 2.6, "game data pak", glob=True),
        Sig("project.godot", 5.6, "Godot project file"),
        Sig("*.pck", 4.6, "Godot/Aurora data pack", glob=True),
        Sig("*.gcb", 3.0, "Godot compiled bytecode", glob=True),
        Sig("*.dll.config", 1.6, "Mono config", glob=True),
        Sig("data/", 0.6, "data folder (very weak)", contains=True),
        Sig("_CommonRedist/", 5.4, "Steam redists (game release)", contains=True),
        Sig("steam_api64.dll", 5.6, "Steamworks library"),
        Sig("steamapps/", 3.6, "Steam library layout", contains=True),
    ],
    "sw.library": [
        Sig("*.dll", 3.2, "Windows library", glob=True),
        Sig("*.so", 2.4, "Linux shared object", glob=True),
        Sig("*.dylib", 2.6, "macOS dynamic library", glob=True),
        Sig("lib/*.jar", 2.2, "bundled java libraries", glob=True),
        Sig("Commons/", 1.6, "shared commons folder", contains=True),
        Sig("runtime/", 1.2, "runtime folder (weak)", contains=True),
        Sig("META-INF/maven", 4.2, "Maven metadata (published library jar)", glob=True),
        Sig("pom.properties", 3.4, "Maven descriptor (library artefact)"),
        Sig("META-INF/services", 2.0, "service-loader registrations", glob=True),
        Sig("licenses/", 1.2, "bundled licenses (very weak)", contains=True),
    ],
}

# ---------------------------------------------------------------------------
# Secret / token shapes (privacy note: any match is reported, never uploaded)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("discord_token", r"\b[A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}\b",
     "Discord bot token"),
    ("discord_client_secret", r"\b[A-Za-z0-9_\-]{32}\b(?=.*discord)", "Discord client secret (possible)"),
    ("telegram_token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{30,40}\b", "Telegram bot token"),
    ("openai_key", r"\bsk-[A-Za-z0-9]{20,60}\b", "OpenAI API key"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,80}\b", "Anthropic API key"),
    ("google_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    ("github_token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "GitHub token"),
    ("private_key", r"-----BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----", "private key block"),
    ("stripe_key", r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b", "Stripe secret key"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    ("mongodb_uri", r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@", "MongoDB connection string with credentials"),
    ("mysql_uri", r"mysql://[^:\s]+:[^@\s]+@", "MySQL connection string with credentials"),
    ("generic_password", r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]", "hardcoded password"),
]


# ---------------------------------------------------------------------------
# Text signatures (grepped inside member contents, bounded)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TextSig:
    sid: str
    label: str
    weight: float
    note: str
    needles: Tuple[str, ...]


TEXT_SIGS: List[TextSig] = [
    # --- bot frameworks --------------------------------------------------
    TextSig("discordjs", "dev.discordbot", 6.0, "discord.js dependency",
            ("discord.js", "discordjs/voice", "@discordjs/rest", "@discordjs/builders")),
    TextSig("discordpy", "dev.discordbot", 6.0, "discord.py dependency",
            ("discord.py", "nextcord", "disnake", "py-cord", "discord.ext.commands",
             "from discord import", "interactions.py")),
    TextSig("discordlogin", "dev.discordbot", 5.4, "bot login call",
            ("client.login(", "bot.login(", "client.run(", "bot.run(", "discord.Client(",
             "commands.Bot(", "client.start(")),
    TextSig("discordintents", "dev.discordbot", 4.4, "gateway intents usage",
            ("gateway_intents", "intents.message_content", "intents.guilds", "intents.members",
             "GatewayIntentBits", "discord.Intents.")),
    TextSig("discordcmds", "dev.discordbot", 4.0, "slash command builders",
            ("slashcommandbuilder", "applicationcommand", "@app_commands.command",
             "rest.put(commands", "routes.applicationguildcommands", "setcommands(")),
    TextSig("discordtoken", "dev.discordbot", 5.0, "discord token variable",
            ("discord_token", "discordtoken", "bot_token", "token = os.getenv(\"token\"",
             "process.env.token", "process.env.discord_token")),
    TextSig("telegrampy", "dev.telegrambot", 6.0, "telegram bot library (python)",
            ("python-telegram-bot", "aiogram", "telebot", "pytelegrambotapi", "telegram.ext",
             "updater(messagehandler", "telegram.bot import bot")),
    TextSig("telegramjs", "dev.telegrambot", 6.0, "telegram bot library (node)",
            ("node-telegram-bot-api", "telegraf", "grammy", "botfather")),
    TextSig("mineflayer", "dev.gamebot", 6.0, "mineflayer library",
            ("mineflayer", "createbot(", "minecraft-protocol", "mc.createbot")),
    TextSig("aternos", "dev.gamebot", 5.0, "Aternos automation",
            ("aternos", "keep-alive", "keepalive", "auto-reconnect", "autoconnect")),
    # --- Minecraft: plugins ----------------------------------------------
    TextSig("bukkitapi", "mc.plugin", 6.0, "Bukkit API usage",
            ("org.bukkit", "org/bukkit", "javacommand", "javaplugin", "bukkit.getserverscheduler",
             "onenable", "getcommand(\"")),
    TextSig("paperapi", "mc.plugin", 6.0, "Paper API usage",
            ("io.papermc", "com.destroystokyo.paper", "paper-api", "org.bukkit.plugin.java")),
    TextSig("bungeeapi", "mc.plugin", 6.2, "BungeeCord plugin API",
            ("net.md_5.bungee.api", "net/md_5/bungee", "pluginmessage", "bungeecord")),
    TextSig("velocityapi", "mc.plugin", 6.2, "Velocity plugin API",
            ("com.velocitypowered.api", "velocity-api", "com/velocitypowered")),
    TextSig("nukkitapi", "mc.plugin", 5.8, "Nukkit plugin API",
            ("cn.nukkit", "cn/nukkit", "nukkit")),
    TextSig("spongeapi", "mc.plugin", 5.8, "Sponge plugin API",
            ("org.spongepowered.api", "sponge_plugins.json", "spongeapi")),
    TextSig("pluginyml", "mc.plugin", 5.4, "plugin descriptor keys",
            ("main: ", "api-version", "author:", "folia-supported", "softdepend")),
    # --- Minecraft: mods --------------------------------------------------
    TextSig("fabricmod", "mc.mod", 6.4, "Fabric mod descriptor keys",
            ("fabric-loader", "fabric.mod.json", "\"entrypoints\"", "net.fabricmc", "fabric-api")),
    TextSig("forgemod", "mc.mod", 6.2, "Forge mod metadata",
            ("net.minecraftforge", "net/minecraftforge", "modloader", "mods.toml",
             "@mod(", "fmlcommonhandler", "forge_version")),
    TextSig("neoforge", "mc.mod", 6.4, "NeoForge mod metadata",
            ("net.neoforged", "neoforge.mods.toml", "neoforge_version", "neoForge")),
    TextSig("mixins", "mc.mod", 4.8, "Mixin usage",
            ("org.spongepowered.asm.mixin", "org/spongepowered/asm/mixin", "@mixin",
             "mixins.json", "mixin.env.remaprefmap")),
    # --- Minetweaker/plugin/mod breadth ----------------------------------
    TextSig("mcmodded", "mc.mod", 3.0, "mod loader internals",
            ("modcontainer", "modloadingcontext", "registermodbus", "modlist", "tickevent",
             "forgeeventbus", "modid")),
    # --- Shaderpacks ------------------------------------------------------
    TextSig("shaderprogram", "mc.shaderpack", 6.0, "GLSL program source",
            ("#version 120", "#version 150", "/* drawbuffers", "gbuffers_", "gl_fragdata",
             "composite.fsh", "shadow.fsh", "uniform sampler2d", "varying vec2")),
    TextSig("shaderpacksigned", "mc.shaderpack", 5.6, "shaderpack identifiers",
            ("shaderpack", "optifine", "iris", "dimension.properties", "program.enabled")),
    # --- Resource packs ---------------------------------------------------
    TextSig("packmcmeta", "mc.resourcepack", 4.6, "pack.mcmeta descriptor",
            ("\"pack_format\"", "\"pack\":", "\"description\":", "resourcepack")),
    TextSig("vanillapack", "mc.resourcepack", 5.0, "vanilla pack contents",
            ("minecraft:textures/", "textures/gui/container", "assets/minecraft",
             "blockstates", "model_parent", "parent\": \"minecraft:item/")),
    # --- Datapacks --------------------------------------------------------
    TextSig("mcfunction", "mc.datapack", 5.6, "mcfunction commands",
            ("execute as @", "execute if ", "say ", "# load", "schedule function",
             "scoreboard objectives", "data merge", "forceload")),
    TextSig("datapackfiles", "mc.datapack", 4.6, "datapack json assets",
            ("minecraft:function", "loot_table", "advancement", "predicate", "worldgen",
             "dimension_type", "structure_set", "datapacks")),
    # --- Software ---------------------------------------------------------
    TextSig("electron", "sw.portable", 5.6, "Electron app",
            ("electron-builder", "app.asar", "electron.js", "\"electron\":")),
    TextSig("unity", "sw.game", 5.8, "Unity project/player",
            ("unityplayer", "assembly-csharp.dll", "unityengine", "il2cpp", "mono/2.0")),
    TextSig("unityproject", "sw.game", 4.4, "Unity project layout",
            ("projectsettings/projectversion.txt", "assets/", "packages/manifest.json")),
    TextSig("unrealproject", "sw.game", 5.0, "Unreal project",
            ("unrealengine", "unreal project", "engineversion", "*.uproject")),
    TextSig("godotproject", "sw.game", 5.4, "Godot project",
            ("godot_project_name", "config_version=5", "[gdscript]", "[rendering]")),
    TextSig("dotnetapp", "sw.portable", 4.0, ".NET application",
            ("runtimeconfig.json", "netcoreapp", "net8.0", "net6.0", "system.windows.forms",
             "microsoft.netcore.app")),
    TextSig("pythonapp", "sw.portable", 4.0, "packaged Python app",
            ("pyinstaller", "_meipass", "sys._meipass", "cx_freeze")),
    TextSig("wineprefix", "sw.portable", 3.0, "Windows app shipped with runtime",
            ("winhttp.dll", "vcruntime140.dll", "msvcp140.dll")),
    # --- Dev ecosystems ---------------------------------------------------
    TextSig("nodepkg", "dev.node", 4.4, "npm package metadata",
            ("\"dependencies\"", "\"devdependencies\"", "\"scripts\":", "node_modules/")),
    TextSig("pythonpkg", "dev.python", 4.4, "Python project files",
            ("from setuptools", "if __name__ == \"__main__\"", "def main(", "import os",
             "requirements.txt", "[project]")),
    TextSig("maven", "dev.java", 4.6, "Maven build",
            ("<project", "<groupid>", "<artifactid>", "maven-compiler-plugin", "mvnw")),
    TextSig("gradle", "dev.java", 4.6, "Gradle build",
            ("plugins {", "dependencies {", "repositories {", "gradlewrapper", "sourcecompatibility")),
    TextSig("cargo", "dev.rust", 5.4, "Cargo manifest",
            ("[package]", "[dependencies]", "cargo.toml", "edition = \"2021\"")),
    TextSig("gomod", "dev.go", 5.4, "Go module",
            ("go 1.2", "go 1.1", "module ", "go.mod", "golang.org/x/")),
    TextSig("csproj", "dev.dotnet", 5.2, ".NET project",
            ("<targetframework>", "<project sdk", "net8.0", "msbuild", "packagereference")),
    TextSig("vscodeengine", "dev.vscodeext", 6.2, "VS Code extension manifest",
            ("\"vscode\":", "vscode.modules", "@types/vscode", "\"activationevents\"",
             "\"contributes\"")),
    TextSig("vscodeapi", "dev.vscodeext", 5.2, "VS Code extension API usage",
            ("import * as vscode", "vscode.window.", "vscode.commands.register",
             "import vscode = require")),
    TextSig("obsidian", "dev.obsidianplugin", 6.2, "Obsidian plugin API",
            ("obsidian", "plugin.onload", "this.addcommand(", "this.registerevent(",
             "app.vault", "notice(")),
    TextSig("obsidianmanifest", "dev.obsidianplugin", 5.6, "Obsidian manifest keys",
            ("\"minappversion\"", "\"isdesktoponly\"", "minAppVersion")),
    TextSig("webext", "dev.browserext", 5.8, "Web extension manifest",
            ("\"manifest_version\"", "browser_action", "content_scripts", "\"background\":",
             "service_worker", "chrome.runtime", "browser.runtime")),
    TextSig("wordpress", "dev.wordpressplugin", 6.2, "WordPress plugin header",
            ("plugin name:", "add_action(", "wp_enqueue_script", "register_activation_hook",
             "function_exists(", "wp-content/plugins")),
    TextSig("webapp", "dev.web", 3.6, "web app markup",
            ("<!doctype html", "<html", "styles.css", "addEventListener", "fetch(",
             "react", "vue", "svelte")),
    TextSig("shellscript", "dev.shell", 3.2, "shell/batch script",
            ("@echo off", "#!/bin/sh", "#!/bin/bash", "set -e", "pause", "goto :eof",
             "param(", ">nul")),
    TextSig("dockerfile", "dev.other", 3.0, "container build",
            ("from node", "from python", "docker-compose", "entrypoint", "workdir /app")),
    TextSig("protocol", "mc.mod", 2.4, "Minecraft packet protocol usage",
            ("packetencoder", "netty", "varint", "readvarint", "craftbukkit")),
]

TEXT_SIG_BY_ID: Dict[str, TextSig] = {s.sid: s for s in TEXT_SIGS}
TEXT_SIG_NEEDLES: Dict[str, Tuple[str, ...]] = {s.sid: s.needles for s in TEXT_SIGS}


# ---------------------------------------------------------------------------
# Bytecode markers (Java constant pool strings)
# ---------------------------------------------------------------------------

BYTECODE_MARKERS: Dict[str, List[Tuple[str, float, str]]] = {
    "mc.plugin": [
        ("org/bukkit", 6.0, "Bukkit API"),
        ("org/bukkit/plugin", 6.2, "Bukkit plugin API"),
        ("org/bukkit/event", 5.6, "Bukkit event API"),
        ("org/bukkit/command", 5.4, "Bukkit command API"),
        ("org/bukkit/scheduler", 5.4, "Bukkit scheduler"),
        ("io/papermc", 6.0, "Paper API"),
        ("com/destroystokyo/paper", 5.8, "Paper API (legacy package)"),
        ("net/md_5/bungee", 6.4, "BungeeCord API"),
        ("com/velocitypowered", 6.4, "Velocity API"),
        ("cn/nukkit", 6.0, "Nukkit API"),
        ("org/spongepowered/api", 5.8, "Sponge API"),
        ("org/bstats", 5.6, "bStats metrics (plugin-side)"),
        ("org/bukkit/craftbukkit", 4.6, "CraftBukkit internals"),
        ("net/minecraft/server", 2.6, "NMS mapping (plugin or mod)"),
        ("dev/jorel", 5.0, "CommandAPI for plugins"),
        ("com/sk89q/worldedit", 4.4, "WorldEdit API"),
        ("com/sk89q/worldguard", 4.4, "WorldGuard API"),
        ("me/clip", 4.4, "PlaceholderAPI"),
        ("com/gmail/nossr50", 4.2, "mcMMO API"),
        ("com/comphenix/protocol", 4.6, "ProtocolLib"),
    ],
    "mc.mod": [
        ("net/minecraftforge", 6.2, "Forge API"),
        ("net/neoforged", 6.4, "NeoForge API"),
        ("net/fabricmc", 6.2, "Fabric loader API"),
        ("org/quiltmc", 5.8, "Quilt loader API"),
        ("cpw/mods", 5.6, "Forge mod API"),
        ("org/spongepowered/mixin", 5.2, "Mixin framework"),
        ("net/minecraft/client", 3.2, "client-side Minecraft code"),
        ("net/minecraft/world", 3.0, "Minecraft world classes"),
        ("com/mojang/blaze3d", 3.4, "Minecraft render pipeline"),
        ("com/mojang/brigadier", 3.0, "Minecraft command library"),
        ("org/lwjgl", 2.6, "LWJGL (client-side)"),
        ("net/minecraftforge/fml", 6.2, "Forge mod loader"),
        ("mezz/jei", 4.4, "JEI integration"),
        ("net/createmod", 4.0, "Create mod integration"),
        ("com/simibubi/create", 4.0, "Create mod integration"),
        ("dev/architectury", 4.6, "Architectury API"),
        ("net/optifine", 3.6, "OptiFine compatibility"),
        ("net/irisshaders", 3.6, "Iris compatibility"),
        ("net/minecraftforge/event", 5.6, "Forge event bus"),
        ("net/neoforged/neoforge", 6.2, "NeoForge internals"),
    ],
    "mc.shaderpack": [
        ("composite.fsh", 4.4, "shader stage file reference"),
        ("gbuffers_", 4.4, "OptiFine shader program name"),
        ("shaders.properties", 4.2, "shaderpack descriptor"),
        ("dimension.properties", 3.6, "Iris dimension config"),
    ],
    "mc.resourcepack": [
        ("minecraft:textures", 4.4, "vanilla texture namespace"),
        ("assets/minecraft", 4.0, "vanilla asset path"),
        ("blockstates", 2.8, "blockstate references"),
    ],
    "dev.other": [
        ("kotlin", 2.4, "Kotlin runtime"),
        ("scala", 2.2, "Scala runtime"),
        ("groovy", 1.6, "Groovy runtime"),
        ("com/google/gson", 1.0, "Gson library"),
        ("org/apache/commons", 0.8, "Apache Commons"),
        ("slf4j", 0.8, "SLF4J logging"),
    ],
    "sw.library": [
        ("java/lang/Object", 0.6, "plain JVM classes"),
    ],
}

BYTECODE_MARKER_INDEX: List[Tuple[str, str, float, str]] = [
    (label, marker, weight, note)
    for label, rows in BYTECODE_MARKERS.items()
    for (marker, weight, note) in rows
]

KNOWN_JAVA_FRAMEWORKS: Dict[str, Tuple[str, float, str]] = {
    "org/bukkit": ("mc.plugin", 6.0, "Bukkit"),
    "io/papermc": ("mc.plugin", 6.0, "Paper"),
    "net/md_5/bungee": ("mc.plugin", 6.4, "BungeeCord"),
    "com/velocitypowered": ("mc.plugin", 6.4, "Velocity"),
    "net/minecraftforge": ("mc.mod", 6.2, "Forge"),
    "net/neoforged": ("mc.mod", 6.4, "NeoForge"),
    "net/fabricmc": ("mc.mod", 6.2, "Fabric"),
    "org/quiltmc": ("mc.mod", 5.8, "Quilt"),
}

# ---------------------------------------------------------------------------
# Name hints (matched against the file's own name, never decisive alone)
# ---------------------------------------------------------------------------

NAME_HINTS: Dict[str, List[Tuple[str, float, str]]] = {
    "mc.shaderpack": [
        ("shader", 2.6, "'shader' in name"),
        ("shaders", 2.8, "'shaders' in name"),
        ("bsl", 1.8, "known shaderpack acronym"),
        ("complementary", 2.0, "known shaderpack name"),
        ("photon", 1.6, "known shaderpack name"),
        ("chocapic", 1.6, "known shaderpack name"),
        ("sildur", 1.6, "known shaderpack name"),
        ("kapa", 1.4, "known shaderpack name"),
        ("seus", 1.6, "known shaderpack name"),
        ("makeup", 1.4, "known shaderpack name"),
        ("vanillaplus", 1.2, "shader variant"),
        ("nostalgia", 1.2, "shader variant"),
        ("rethinking", 1.4, "known shaderpack name"),
        ("insanity", 1.2, "known shaderpack name"),
    ],
    "mc.resourcepack": [
        ("resourcepack", 3.0, "'resourcepack' in name"),
        ("resource_pack", 3.0, "'resource_pack' in name"),
        ("resource-pack", 3.0, "'resource-pack' in name"),
        ("texturepack", 2.8, "'texturepack' in name"),
        ("texture-pack", 2.8, "'texture-pack' in name"),
        ("textures", 1.6, "textures in name"),
        ("faithful", 1.6, "known resource pack"),
        ("xray", 2.0, "known resource pack type"),
        ("x-ray", 2.0, "known resource pack type"),
        ("connected", 1.0, "possible CTM pack"),
        ("pbr", 1.4, "PBR textures"),
        ("hud", 1.0, "HUD pack"),
        ("gui", 0.8, "GUI pack"),
        ("overlay", 0.8, "overlay pack"),
    ],
    "mc.mod": [
        ("mod", 0.8, "'mod' in name (very weak)"),
        ("forge", 1.4, "forge in name"),
        ("fabric", 1.4, "fabric in name"),
        ("neoforge", 1.6, "neoforge in name"),
        ("quilt", 1.2, "quilt in name"),
        ("minecraft", 0.4, "minecraft in name (very weak)"),
    ],
    "mc.modpack": [
        ("modpack", 3.0, "'modpack' in name"),
        ("mod-packs", 2.6, "modpack collection"),
        ("atm", 1.4, "All The Mods style pack"),
        ("ftb", 2.4, "Feed The Beast pack"),
        ("rlcraft", 2.0, "known modpack"),
        ("better-mc", 1.6, "known modpack"),
        ("create", 0.8, "possible Create-based pack"),
    ],
    "mc.plugin": [
        ("plugin", 2.2, "'plugin' in name"),
        ("spigot", 1.6, "spigot in name"),
        ("bukkit", 1.6, "bukkit in name"),
        ("paper", 1.2, "paper in name"),
        ("bungee", 2.0, "bungee in name"),
        ("velocity", 1.6, "velocity in name"),
        ("skript", 1.6, "Skript addon"),
        ("viaversion", 2.0, "known plugin"),
        ("essentials", 2.0, "known plugin"),
        ("luckperms", 2.0, "known plugin"),
        ("worldedit", 1.8, "known plugin"),
        ("worldguard", 1.8, "known plugin"),
        ("placeholderapi", 2.0, "known plugin"),
        ("citizens", 1.6, "known plugin"),
        ("vault", 1.4, "known plugin"),
        ("ciphergate", 2.4, "auth plugin"),
        ("nethrion", 1.6, "server plugin series"),
        ("mystery", 1.0, "possible plugin name"),
    ],
    "dev.discordbot": [
        ("discord", 2.4, "'discord' in name"),
        ("bot", 1.4, "'bot' in name (very weak)"),
        ("dj", 0.8, "'dj' in name (weak)"),
        ("music", 0.8, "music bot hint"),
        ("ticket", 1.0, "ticket bot hint"),
        ("moderation", 1.0, "moderation bot hint"),
        ("loid", 1.4, "personal assistant bot"),
        ("selfbot", 2.0, "self-bot"),
    ],
    "dev.telegrambot": [
        ("telegram", 3.0, "'telegram' in name"),
        ("tg", 1.2, "telegram abbreviation"),
    ],
    "dev.gamebot": [
        ("afk", 2.6, "AFK bot"),
        ("aternos", 2.8, "'aternos' in name"),
        ("minez", 1.2, "minez-style bot"),
        ("mineflayer", 2.8, "mineflayer in name"),
        ("uptime", 2.0, "uptime keeper"),
    ],
    "sw.installer": [
        ("setup", 3.2, "'setup' in name"),
        ("installer", 3.4, "'installer' in name"),
        ("install", 2.4, "'install' in name"),
        ("win64", 1.2, "windows 64-bit build"),
        ("x64", 0.8, "64-bit build"),
        ("portable", -1.2, "portable builds are not installers"),
        ("uninstall", 1.0, "uninstaller bundle"),
        ("patch", 1.4, "patch installer"),
        ("update", 1.0, "update package"),
    ],
    "sw.portable": [
        ("portable", 2.6, "'portable' in name"),
        ("win64", 1.0, "windows build"),
        ("win32", 1.0, "windows build"),
        ("app", 0.6, "'app' in name (weak)"),
        ("standalone", 2.2, "standalone build"),
        ("noinstall", 2.4, "no-install build"),
    ],
    "sw.android": [
        ("android", 2.6, "'android' in name"),
        ("apk", 2.0, "apk in name"),
        ("mod_menu", 1.4, "modded APK convention"),
    ],
    "sw.game": [
        ("game", 1.2, "'game' in name (weak)"),
        ("repack", 1.6, "release repack"),
        ("fitgirl", 2.4, "release group"),
        ("dodi", 2.0, "release group"),
        ("empress", 1.8, "release group"),
        ("codex", 1.8, "release group"),
        ("skidrow", 1.8, "release group"),
        ("steam", 1.4, "steam build"),
        ("gog", 1.6, "GOG build"),
        ("rg mechanics", 1.8, "release group"),
        ("portable edition", 1.2, "game portable edition"),
    ],
    "dev.vscodeext": [
        ("vscode", 3.0, "vscode in name"),
        ("vsce", 2.2, "vsce packaging"),
        ("extension", 1.2, "'extension' in name (weak)"),
    ],
    "dev.browserext": [
        ("chrome", 1.6, "chrome in name"),
        ("firefox", 1.6, "firefox in name"),
        ("extension", 1.2, "'extension' in name (weak)"),
        ("tampermonkey", 1.8, "userscript"),
        ("userscript", 1.8, "userscript"),
    ],
    "dev.python": [("py", 0.8, "'py' in name (weak)")],
    "dev.rust": [("rust", 2.0, "rust in name"), ("cargo", 2.0, "cargo in name")],
    "dev.go": [("golang", 2.0, "golang in name"), ("go-", 1.0, "go prefix")],
    "dev.java": [("java", 1.8, "java in name"), ("maven", 1.6, "maven in name")],
    "dev.dotnet": [("dotnet", 2.0, "dotnet in name"), ("csharp", 1.6, "csharp in name")],
    "dev.node": [("node", 1.8, "node in name"), ("npm", 1.6, "npm in name")],
    "media.video": [("1080p", 1.6, "resolution tag"), ("2160p", 1.6, "resolution tag"),
                    ("x264", 1.4, "codec tag"), ("x265", 1.4, "codec tag"),
                    ("hevc", 1.4, "codec tag"), ("web-dl", 1.4, "release tag")],
    "media.audio": [("album", 1.0, "album in name"), ("ost", 1.2, "soundtrack"),
                    ("flac", 1.6, "flac in name"), ("320kbps", 1.6, "bitrate tag")],
    "doc.pdf": [("pdf", 1.6, "pdf in name")],
    "doc.office": [("docx", 1.2, "docx in name"), ("xlsx", 1.2, "xlsx in name"),
                   ("pptx", 1.2, "pptx in name")],
}

# ---------------------------------------------------------------------------
# Extension maps — cheap first-stage evidence
# ---------------------------------------------------------------------------

EXT_LABELS: Dict[str, Tuple[str, float]] = {
    # media
    ".mp4": ("media.video", 7.0), ".mkv": ("media.video", 7.0), ".avi": ("media.video", 7.0),
    ".mov": ("media.video", 7.0), ".webm": ("media.video", 7.0), ".flv": ("media.video", 7.0),
    ".m4v": ("media.video", 7.0), ".wmv": ("media.video", 7.0), ".mpg": ("media.video", 7.0),
    ".mpeg": ("media.video", 7.0), ".ts": ("media.video", 3.0), ".3gp": ("media.video", 7.0),
    ".mp3": ("media.audio", 7.0), ".wav": ("media.audio", 7.0), ".flac": ("media.audio", 7.0),
    ".m4a": ("media.audio", 7.0), ".aac": ("media.audio", 7.0), ".ogg": ("media.audio", 5.0),
    ".opus": ("media.audio", 7.0), ".wma": ("media.audio", 7.0), ".aiff": ("media.audio", 7.0),
    ".m3u": ("media.audio", 3.0), ".m3u8": ("media.audio", 3.0),
    ".jpg": ("media.image", 6.0), ".jpeg": ("media.image", 6.0), ".png": ("media.image", 6.0),
    ".gif": ("media.image", 6.0), ".bmp": ("media.image", 6.0), ".webp": ("media.image", 6.0),
    ".tif": ("media.image", 6.0), ".tiff": ("media.image", 6.0), ".svg": ("media.image", 5.0),
    ".psd": ("media.image", 5.5), ".ai": ("media.image", 4.0), ".xcf": ("media.image", 5.5),
    ".ttf": ("media.font", 7.0), ".otf": ("media.font", 7.0), ".woff": ("media.font", 7.0),
    ".woff2": ("media.font", 7.0), ".fnt": ("media.font", 4.0),
    ".epub": ("media.ebook", 7.0), ".mobi": ("media.ebook", 7.0), ".azw3": ("media.ebook", 7.0),
    ".cbz": ("media.ebook", 4.0), ".cbr": ("media.ebook", 3.0),
    # documents
    ".pdf": ("doc.pdf", 7.0),
    ".doc": ("doc.office", 6.5), ".docx": ("doc.office", 7.0), ".xls": ("doc.office", 6.5),
    ".xlsx": ("doc.office", 7.0), ".ppt": ("doc.office", 6.5), ".pptx": ("doc.office", 7.0),
    ".odt": ("doc.office", 6.5), ".ods": ("doc.office", 6.5), ".odp": ("doc.office", 6.5),
    ".rtf": ("doc.office", 5.0), ".csv": ("doc.data", 5.0), ".tsv": ("doc.data", 5.0),
    ".txt": ("doc.text", 4.0), ".md": ("doc.text", 4.0), ".log": ("doc.text", 3.0),
    ".srt": ("doc.text", 4.0), ".vtt": ("doc.text", 4.0), ".json": ("doc.data", 2.0),
    ".xml": ("doc.data", 2.0), ".yml": ("doc.data", 2.0), ".yaml": ("doc.data", 2.0),
    ".toml": ("doc.data", 2.0), ".ini": ("doc.data", 2.0), ".cfg": ("doc.data", 2.0),
    ".db": ("doc.data", 5.0), ".sqlite": ("doc.data", 6.0), ".sql": ("doc.data", 4.0),
    ".parquet": ("doc.data", 6.0), ".h5": ("doc.data", 4.0), ".pkl": ("doc.data", 4.0),
    ".npy": ("doc.data", 5.0), ".npz": ("doc.data", 5.0), ".mat": ("doc.data", 4.0),
    # code (also evidence for dev projects)
    ".py": ("doc.code", 2.5), ".js": ("doc.code", 2.0), ".ts": ("doc.code", 2.0),
    ".java": ("doc.code", 3.0), ".c": ("doc.code", 2.5), ".h": ("doc.code", 2.0),
    ".cpp": ("doc.code", 2.5), ".hpp": ("doc.code", 2.5), ".cs": ("doc.code", 2.5),
    ".rs": ("doc.code", 3.0), ".go": ("doc.code", 3.0), ".php": ("doc.code", 2.5),
    ".rb": ("doc.code", 2.5), ".kt": ("doc.code", 3.0), ".swift": ("doc.code", 3.0),
    ".sh": ("doc.code", 2.0), ".bat": ("doc.code", 2.0), ".ps1": ("doc.code", 2.5),
    ".sql2": ("doc.code", 0.0), ".lua": ("doc.code", 2.0), ".dart": ("doc.code", 2.5),
    # binaries / containers
    ".exe": ("sw.portable", 5.0), ".msi": ("sw.installer", 6.5), ".dll": ("sw.library", 5.0),
    ".so": ("sw.library", 4.0), ".dylib": ("sw.library", 4.0), ".appimage": ("sw.portable", 6.0),
    ".apk": ("sw.android", 7.5), ".aab": ("sw.android", 7.5), ".xapk": ("sw.android", 7.0),
    ".deb": ("sw.portable", 6.0), ".rpm": ("sw.portable", 6.0), ".dmg": ("sw.installer", 6.0),
    ".iso": ("sw.portable", 6.0), ".img": ("sw.portable", 5.0),
    ".class": ("doc.code", 3.0),
    # archives (routed by content, not by extension)
    ".zip": ("misc.other", 0.0), ".jar": ("misc.other", 0.0), ".rar": ("misc.other", 0.0),
    ".7z": ("misc.other", 0.0), ".gz": ("misc.other", 0.0), ".tar": ("misc.other", 0.0),
    ".tgz": ("misc.other", 0.0), ".xz": ("misc.other", 0.0), ".bz2": ("misc.other", 0.0),
}

ARCHIVE_EXTS = {
    ".zip", ".jar", ".rar", ".7z", ".gz", ".tar", ".tgz", ".xz", ".bz2",
    ".mrpack", ".mcpack", ".mcaddon", ".mcworld", ".litemod", ".whl", ".crx", ".xpi",
    ".vsix", ".nupkg", ".apkg", ".jar.disabled", ".aar",
}

# Minecraft-ish names, used only as a *tie-breaker* inside ambiguous Minecraft cases
MC_TOKEN_STRONG = ("minecraft", "mc", "bukkit", "spigot", "paper", "forge", "fabric",
                   "neoforge", "iris", "optifine", "curseforge", "modrinth", "modpack")

# Jar-with-no-descriptor heuristics: these folder names inside a jar strongly
# suggest code that was compiled against a Minecraft server/client API.
JAR_SERVER_HINTS = ("plugin.yml", "bukkit.yml", "paper-plugin.yml", "config.yml", "lang/",
                    "messages.yml", "permissions.yml", "commands.yml")
JAR_CLIENT_HINTS = ("assets/", "data/", "META-INF/mods.toml", "fabric.mod.json", "mixins.json")

PACK_FORMAT_LABELS: Dict[int, str] = {
    # pack_format -> what changed (helps sanity-check resourcepack vs datapack)
    1: "1.6.1", 2: "1.9", 3: "1.11", 4: "1.13", 5: "1.15", 6: "1.16.1", 7: "1.17",
    8: "1.18", 9: "1.19", 12: "1.19.4", 13: "1.20.1", 15: "1.20.1+", 18: "1.20.2",
    22: "1.20.5", 32: "1.21", 34: "1.21.2", 42: "1.21.4", 46: "1.21.5",
}

RE_PACK_FORMAT = re.compile(r'"pack_format"\s*:\s*(\d+)')
