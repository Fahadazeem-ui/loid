"""Builds a labelled, synthetic test corpus that mirrors real-world layouts.

Every fixture reproduces a *structure* that broke the old sorter:

* the user's own ``FileSorter.zip`` (wrapper folder + nested engine package),
* ``FileSorter-exe.zip`` (a zip that contains exactly one .exe),
* shaderpacks vs resource packs that contain ``assets/minecraft/shaders/core``,
* jars with and without descriptors, mods inside a modpack,
* Discord / Telegram / Aternos bots, VS Code / Chrome / Obsidian extensions,
* installers, Unity games, APKs, wallpaper collections, mixed drive dumps.

None of these are real files — they are built here so accuracy can be *measured*
(see ``benchmark.py``) instead of estimated by feel. Drop your own archives in
``corpus/<label>/`` and the same benchmark runs against them.
"""
from __future__ import annotations

import io
import json
import os
import struct
import zlib
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

MINI_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00"
    b"\x00\x00IEND\xaeB`\x82"
)


def png(width: int = 16, height: int = 16, seed: int = 0) -> bytes:
    """A tiny but valid PNG with the requested dimensions."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([(seed + i) % 256] * 4) for i in range(height))
    idat = zlib.compress(raw)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def fake_class(markers: List[str], size_pad: int = 400) -> bytes:
    """Java .class-ish bytes: right magic + version + marker strings."""
    body = b"".join(m.encode() + b"\x00\x01" for m in markers)
    padding = b"\x00" * max(0, size_pad - len(body))
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + body + padding


def fake_pe(markers: List[str], product: str = "", company: str = "", dll: bool = False) -> bytes:
    """A minimal *parseable* PE file (header + section names + marker strings)."""
    e_lfanew = 0x80
    opt_size = 0xF0
    n_sections = 3
    header = bytearray(b"\x00" * e_lfanew)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = struct.pack("<I", e_lfanew)
    machine = 0x8664
    characteristics = 0x2000 if dll else 0x0022
    pe = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, n_sections, 0, 0, 0, opt_size, characteristics)
    opt = bytearray(b"\x00" * opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+
    struct.pack_into("<H", opt, 0x5C, 2)           # subsystem GUI
    struct.pack_into("<II", opt, 0x70 + 14 * 8, 0x2000, 0x48)  # CLR directory (fake .NET)
    sections = b"".join(name.ljust(8, b"\x00") + b"\x00" * 32 for name in (b".text", b".rdata", b".rsrc"))
    strings = "".join(m + "\x00" for m in markers)
    if product:
        strings += "ProductName\x00" + product + "\x00FileDescription\x00" + product + "\x00"
    if company:
        strings += "CompanyName\x00" + company + "\x00"
    return bytes(header) + pe + bytes(opt) + sections + strings.encode("utf-8", "replace") + b"\x00" * 512


# Test credentials are assembled from fragments on purpose: the built fixtures
# contain a token-shaped value (so the credential scanner is exercised for real),
# but this source file never contains a complete secret-shaped string.
def fake_discord_token() -> str:
    return ".".join(["MTIzNDU2Nzg5MDEyMzQ1Njc4", "GaBcDe", "fGhIjKlMnOpQrStUvWxYz0123456789ab"])


def fake_telegram_token() -> str:
    return "".join(["123456789", ":AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"])


def _zip(path: Path, files: Dict[str, bytes], comment: bytes = b"") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        if comment:
            zf.comment = comment


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, indent=1).encode()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def build_all(root: Path) -> List[Dict[str, str]]:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    expectations: List[Dict[str, str]] = []

    def record(path: Path, label: str, note: str = "") -> None:
        expectations.append({"file": str(path.relative_to(root)), "label": label, "note": note})

    # 1. Bukkit/Paper plugin ------------------------------------------------
    p = root / "ExamplePlugin-1.0.jar"
    _zip(p, {
        "plugin.yml": b"name: ExamplePlugin\nmain: com.example.plugin.ExamplePlugin\n"
                      b"version: 1.0.0\napi-version: '1.20'\nauthor: Tester\n"
                      b"commands:\n  example:\n    description: demo\n",
        "config.yml": b"enabled: true\n",
        "messages.yml": b"prefix: '&a[Example]'\n",
        "com/example/plugin/ExamplePlugin.class": fake_class(
            ["org/bukkit/plugin/java/JavaPlugin", "org/bukkit/event/Listener", "org/bukkit/command/CommandExecutor"]),
        "com/example/plugin/EventListener.class": fake_class(["org/bukkit/event/EventHandler", "org/bukkit/event/player/PlayerJoinEvent"]),
        "com/example/plugin/api/ExampleApi.class": fake_class(["org/bukkit/Bukkit", "org/bukkit/plugin/Plugin"]),
        "lang/en_us.yml": b"welcome: Welcome!\n",
        "org/bstats/bukkit/Metrics.class": fake_class(["org/bstats/Metrics"]),
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nBuilt-By: Maven\n",
        "META-INF/maven/com.example/example/pom.properties": b"version=1.0.0\n",
    })
    record(p, "mc.plugin", "Bukkit plugin with descriptor + bytecode")

    # 2. Fabric mod ---------------------------------------------------------
    p = root / "ExampleMod-1.20.1.jar"
    _zip(p, {
        "fabric.mod.json": _json_bytes({
            "id": "examplemod", "version": "1.2.0", "environment": "*",
            "entrypoints": {"main": ["com.example.mod.ExampleMod"]},
            "depends": {"minecraft": "~1.20.1", "fabricloader": ">=0.14"},
            "mixins": ["examplemod.mixins.json"],
        }),
        "examplemod.mixins.json": _json_bytes({"required": True, "package": "com.example.mod.mixin"}),
        "com/example/mod/ExampleMod.class": fake_class(
            ["net/fabricmc/api/ModInitializer", "net/fabricmc/loader/api/FabricLoader"]),
        "com/example/mod/mixin/PlayerMixin.class": fake_class(
            ["org/spongepowered/asm/mixin/Mixin", "net/minecraft/client/MinecraftClient"]),
        "assets/examplemod/lang/en_us.json": b'{"item.examplemod.thing": "Thing"}',
        "assets/examplemod/textures/item/thing.png": png(16, 16, 2),
    })
    record(p, "mc.mod", "Fabric mod descriptor + loader bytecode")

    # 3. Forge mod ----------------------------------------------------------
    p = root / "ForgeMod-1.20.1.jar"
    _zip(p, {
        "META-INF/mods.toml": b'modLoader="javafml"\nloaderVersion="[47,)"\n[[mods]]\nmodId="forgemod"\n'
                              b'version="1.0"\ndisplayName="Forge Mod"\n',
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nFMLModType: MOD\n",
        "com/example/forge/ForgeMod.class": fake_class(
            ["net/minecraftforge/fml/common/Mod", "net/minecraftforge/eventbus/api/IEventBus"]),
        "assets/forgemod/lang/en_us.json": b'{"block.forgemod.ore": "Ore"}',
    })
    record(p, "mc.mod", "Forge mod with mods.toml")

    # 4. OptiFine/Iris shaderpack -------------------------------------------
    p = root / "BSL_v8.2.0.zip"
    _zip(p, {
        "shaders/shaders.properties": b"# BSL shaders\nshadowMapResolution=2048\n",
        "shaders/composite.fsh": b"#version 120\n/* DRAWBUFFERS:0 */\nuniform sampler2D colortex0;\nvoid main() { gl_FragData[0] = texture2D(colortex0, gl_TexCoord[0].st); }",
        "shaders/composite.vsh": b"#version 120\nvarying vec2 texcoord;\nvoid main() { texcoord = gl_MultiTexCoord0.st; gl_Position = ftransform(); }",
        "shaders/gbuffers_terrain.fsh": b"#version 120\nvarying vec4 lmcoord;\nvoid main() { gl_FragData[0] = vec4(lmcoord.xy, 0.0, 1.0); }",
        "shaders/gbuffers_terrain.vsh": b"#version 120\nvoid main() { gl_Position = ftransform(); }",
        "shaders/gbuffers_water.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(0.0, 0.2, 0.4, 1.0); }",
        "shaders/shadow.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(1.0); }",
        "shaders/lib/util.glsl": b"float luma(vec3 c) { return dot(c, vec3(0.299, 0.587, 0.114)); }",
        "shaders/lang/en_US.lang": b"option.SHADOW_QUALITY=Shadow Quality\n",
        "shaders/world0/composite.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(1.0); }",
        "shaders/dimension.properties": b"# iris\n",
    })
    record(p, "mc.shaderpack", "OptiFine-style shaderpack: shaders/*.fsh + shaders.properties")

    # 5. Resource pack ------------------------------------------------------
    p = root / "Faithful32x-1.20.zip"
    files = {
        "pack.mcmeta": _json_bytes({"pack": {"pack_format": 15, "description": "Faithful 32x"}}),
        "pack.png": png(64, 64, 3),
        "assets/minecraft/lang/en_us.json": b'{"block.minecraft.stone": "Stone"}',
        "assets/minecraft/models/block/stone.json": b'{"parent": "minecraft:block/cube_all"}',
        "assets/minecraft/blockstates/stone.json": b'{"variants": {}}',
        "assets/minecraft/sounds.json": b'{"block.stone.break": {}}',
        "assets/minecraft/textures/gui/container/inventory.png": png(256, 256, 4),
        "assets/minecraft/textures/block/stone.png": png(32, 32, 5),
        "assets/minecraft/textures/item/diamond.png": png(32, 32, 6),
        "assets/minecraft/font/default.json": b'{"providers": []}',
    }
    for i in range(24):
        files[f"assets/minecraft/textures/block/texture_{i}.png"] = png(32, 32, i)
    _zip(p, files)
    record(p, "mc.resourcepack", "classic 32x resource pack")

    # 6. Resource pack that ships *core shaders* (the old engine's trap) -----
    p = root / "ShaderTweaks-ResourcePack.zip"
    _zip(p, {
        "pack.mcmeta": _json_bytes({"pack": {"pack_format": 15, "description": "Shader tweaks pack"}}),
        "assets/minecraft/shaders/core/rendertype_solid.fsh": b"#version 150\nout vec4 fragColor;\nvoid main() { fragColor = vec4(1.0); }",
        "assets/minecraft/shaders/core/rendertype_solid.vsh": b"#version 150\nin vec3 Position;\nvoid main() { gl_Position = vec4(Position, 1.0); }",
        "assets/minecraft/shaders/include/light.glsl": b"vec4 minecraft_mix_light(vec3 a, vec3 b, vec3 c) { return vec4(1.0); }",
        "assets/minecraft/shaders/post/entity_outline.fsh": b"#version 150\nout vec4 fragColor;\nvoid main() { fragColor = vec4(0.0); }",
        "assets/minecraft/textures/gui/title/background/panorama_0.png": png(64, 64, 7),
        "assets/minecraft/textures/block/glass.png": png(16, 16, 8),
    })
    record(p, "mc.resourcepack", "resource pack with core shaders (must NOT be a shaderpack)")

    # 7. Data pack ----------------------------------------------------------
    p = root / "VanillaTweaks-DataPack.zip"
    _zip(p, {
        "pack.mcmeta": _json_bytes({"pack": {"pack_format": 15, "description": "Tweaks"}}),
        "data/minecraft/tags/functions/tick.json": b'{"values": ["tweaks:tick"]}',
        "data/tweaks/functions/tick.mcfunction": b"say tick\nexecute as @a run function tweaks:player_tick\n",
        "data/tweaks/functions/player_tick.mcfunction": b"execute if score @s kills matches 10.. run say ten kills\n",
        "data/tweaks/advancements/root.json": b'{"display": {"title": "Tweaks"}}',
        "data/tweaks/loot_tables/blocks/stone.json": b'{"pools": []}',
        "data/tweaks/recipes/diamond.json": b'{"type": "minecraft:crafting_shaped"}',
    })
    record(p, "mc.datapack", "datapack with functions + tags")

    # 8. Server bundle ------------------------------------------------------
    p = root / "MyServer-1.20.zip"
    _zip(p, {
        "server.properties": b"motd=My Server\nmax-players=20\n",
        "eula.txt": b"eula=true\n",
        "bukkit.yml": b"settings:\n  allow-end: true\n",
        "spigot.yml": b"world-settings:\n  default:\n    mob-spawn-range: 6\n",
        "paper-global.yml": b"_version: 28\n",
        "ops.json": b"[]",
        "whitelist.json": b"[]",
        "usercache.json": b"[]",
        "world/level.dat": b"\x0a\x00\x04Data" + b"\x00" * 200,
        "world/region/r.0.0.mca": b"\x00" * 8192,
        "world/session.lock": b"\x00" * 16,
        "plugins/EssentialsX.jar": fake_class(["org/bukkit/plugin/java/JavaPlugin"]),
        "start.bat": b"@echo off\r\njava -Xmx4G -jar server.jar nogui\r\npause\r\n",
        "logs/latest.log": b"[INFO] Done\n",
    })
    record(p, "mc.server", "server deployment bundle")

    # 9. Modpack ------------------------------------------------------------
    p = root / "AllTheMods10-1.0.zip"
    _zip(p, {
        "manifest.json": _json_bytes({
            "minecraft": {"version": "1.20.1", "modLoaders": [{"id": "forge-47.2.0", "primary": True}]},
            "name": "All The Mods 10", "version": "1.0.0", "author": "ATM",
            "files": [{"projectID": 1, "fileID": 2, "required": True}],
        }),
        "overrides/config/settings.cfg": b"enabled=true\n",
        "overrides/config/fancymenu.txt": b"hello\n",
        "mods/jei-1.20.1.jar": fake_class(["mezz/jei/api/IModPlugin", "net/minecraftforge/fml/common/Mod"]),
        "mods/create-1.20.1.jar": fake_class(["com/simibubi/create/Create", "net/minecraftforge/eventbus/api/IEventBus"]),
        "mods/ferritecore.jar": fake_class(["malte0811/ferritecore/FerriteCore"]),
        "mods/moremekanism.jar": fake_class(["mekanism/api/IMekanismModule"]),
        "instance.cfg": b"InstanceType=OneSix\nname=ATM10\n",
        "mmc-pack.json": _json_bytes({"components": [{"uid": "net.minecraftforge", "version": "47.2.0"}]}),
    })
    record(p, "mc.modpack", "CurseForge manifest + overrides + mods folder")

    # 10. Discord bot (the user's case: wrapper folder, nested package) -----
    p = root / "MyCoolBot.zip"
    _zip(p, {
        "MyCoolBot/package.json": _json_bytes({
            "name": "my-cool-bot", "version": "1.0.0", "type": "module",
            "dependencies": {"discord.js": "^14.14.1", "dotenv": "^16.3.1"},
            "scripts": {"start": "node src/index.js"},
        }),
        "MyCoolBot/src/index.js": b"import { Client, GatewayIntentBits } from 'discord.js';\n"
                                  b"import { token } from './config.js';\n"
                                  b"const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages] });\n"
                                  b"client.on('ready', () => console.log(`Logged in as ${client.user.tag}`));\n"
                                  b"client.login(token);\n",
        "MyCoolBot/src/config.js": b"import 'dotenv/config';\nexport const token = process.env.DISCORD_TOKEN;\n",
        "MyCoolBot/src/commands/ping.js": b"export const command = { name: 'ping', execute: async (i) => i.reply('pong') };\n",
        "MyCoolBot/src/events/ready.js": b"export default (client) => client.once('ready', () => {});\n",
        "MyCoolBot/.env": ("DISCORD_TOKEN=" + fake_discord_token() + "\n").encode(),
        "MyCoolBot/README.md": b"# My Cool Bot\nA discord bot.\n",
        "MyCoolBot/deploy-commands.js": b"import { REST, Routes } from 'discord.js';\nrest.put(Routes.applicationCommands(id), { body: [] });\n",
    })
    record(p, "dev.discordbot", "discord.js bot in a wrapper folder + token in .env")

    # 11. Telegram bot ------------------------------------------------------
    p = root / "telegram-bot.zip"
    _zip(p, {
        "requirements.txt": b"python-telegram-bot==20.7\nrequests\npython-dotenv\n",
        "bot.py": b"from telegram.ext import ApplicationBuilder, CommandHandler\n"
                  b"async def start(update, context):\n    await update.message.reply_text('hi')\n"
                  b"app = ApplicationBuilder().token(TOKEN).build()\napp.run_polling()\n",
        "handlers/commands.py": b"from telegram import Update\n",
        "config.py": ("TOKEN = '" + fake_telegram_token() + "'\n").encode(),
    })
    record(p, "dev.telegrambot", "python-telegram-bot project + token")

    # 12. Aternos AFK bot ---------------------------------------------------
    p = root / "minecraft-afk-bot.zip"
    _zip(p, {
        "package.json": _json_bytes({"name": "afk-bot", "dependencies": {"mineflayer": "^4.20.0"}}),
        "bot.js": b"const mineflayer = require('mineflayer');\n"
                  b"const bot = mineflayer.createBot({ host, port, username });\n"
                  b"bot.on('end', () => setTimeout(connect, 60000));\n",
        "config.json": _json_bytes({"server": "myserver.aternos.me", "port": 25565, "username": "AFK_Bot"}),
        "aternos.js": b"// aternos keep-alive helper\nmodule.exports = () => {};\n",
    })
    record(p, "dev.gamebot", "mineflayer AFK/uptime bot")

    # 13. VS Code extension -------------------------------------------------
    p = root / "my-vscode-ext.zip"
    _zip(p, {
        "extension/package.json": _json_bytes({
            "name": "my-ext", "displayName": "My Ext", "engines": {"vscode": "^1.80.0"},
            "activationEvents": ["onCommand:myext.hello"],
            "contributes": {"commands": [{"command": "myext.hello", "title": "Hello"}]},
        }),
        "extension/out/extension.js": b"const vscode = require('vscode');\n"
                                      b"function activate(context) { vscode.commands.registerCommand('myext.hello', () => {}); }\n",
        "extension.vsixmanifest": b'<?xml version="1.0"?><PackageManifest></PackageManifest>',
        "extension/README.md": b"# My Ext\n",
    })
    record(p, "dev.vscodeext", "VS Code extension with vsixmanifest")

    # 14. Chrome extension --------------------------------------------------
    p = root / "chrome-extension.zip"
    _zip(p, {
        "manifest.json": _json_bytes({
            "manifest_version": 3, "name": "My Ext", "version": "1.0",
            "background": {"service_worker": "background.js"},
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
            "permissions": ["storage"],
        }),
        "background.js": b"chrome.runtime.onInstalled.addListener(() => {});\n",
        "content.js": b"document.body.style.filter = 'invert(1)';\n",
        "popup.html": b"<html><body><button id='go'>Go</button></body></html>",
        "_locales/en/messages.json": b'{"appName": {"message": "My Ext"}}',
        "icons/icon128.png": png(128, 128, 9),
    })
    record(p, "dev.browserext", "MV3 web extension")

    # 15. Obsidian plugin ---------------------------------------------------
    p = root / "obsidian-plugin.zip"
    _zip(p, {
        "manifest.json": _json_bytes({"id": "my-obsidian-plugin", "name": "My Plugin",
                                      "version": "1.0.0", "minAppVersion": "1.4.0", "isDesktopOnly": False}),
        "main.js": b"const { Plugin } = require('obsidian');\n"
                   b"module.exports = class extends Plugin { async onload() { this.addCommand({id: 'x'}); } };\n",
        "styles.css": b".my-plugin { color: red; }\n",
        "versions.json": b'{"1.0.0": "1.4.0"}',
    })
    record(p, "dev.obsidianplugin", "Obsidian plugin bundle")

    # 16. Installer (single exe) -------------------------------------------
    p = root / "Setup-1.2.3.zip"
    _zip(p, {"Setup-1.2.3.exe": fake_pe(["Nullsoft", "$PLUGINSDIR"], product="My Installer", company="Acme")})
    record(p, "sw.installer", "zip wrapping a single NSIS installer")

    # 17. Unity game repack -------------------------------------------------
    p = root / "CoolGame-Repack.zip"
    _zip(p, {
        "CoolGame/CoolGame.exe": fake_pe(["UnityPlayer"], product="Cool Game", company="Indie"),
        "CoolGame/UnityPlayer.dll": fake_pe(["UnityPlayer", "il2cpp"], dll=True),
        "CoolGame/CoolGame_Data/globalgamemanagers": b"\x00" * 1024,
        "CoolGame/CoolGame_Data/Managed/Assembly-CSharp.dll": fake_pe([], dll=True),
        "CoolGame/CoolGame_Data/il2cpp_data/Metadata/global-metadata.dat": b"\xaf\x1b\xb1\xfa" + b"\x00" * 512,
        "CoolGame/CoolGame_Data/resources.assets": b"UnityFS" + b"\x00" * 512,
        "CoolGame/steam_api64.dll": fake_pe(["Steamworks"], dll=True),
        "CoolGame/_CommonRedist/DirectX/Jun2010/dxsetup.exe": fake_pe(["InstallShield"]),
        "CoolGame/readme.txt": b"Cool Game repack\n",
    })
    record(p, "sw.game", "Unity game repack with redists")

    # 18. Portable app ------------------------------------------------------
    p = root / "myapp-portable-win64.zip"
    _zip(p, {
        "myapp.exe": fake_pe(["Electron"], product="My App", company="My Co"),
        "resources/app.asar": b"asar" + b"\x00" * 256,
        "resources/app/package.json": _json_bytes({"name": "myapp", "dependencies": {"electron": "^28.0.0"}}),
        "locales/en-US.pak": b"\x00" * 128,
        "ffmpeg.dll": fake_pe([], dll=True),
        "libEGL.dll": fake_pe([], dll=True),
        "vcruntime140.dll": fake_pe([], dll=True),
        "LICENSE.txt": b"MIT\n",
    })
    record(p, "sw.portable", "Electron portable app")

    # 19. Android app -------------------------------------------------------
    p = root / "myapp-1.4.2.zip"
    _zip(p, {
        "AndroidManifest.xml": b"\x03\x00\x08\x00" + b"com.example.app" + b"\x00" * 64,
        "classes.dex": b"dex\n035\x00" + b"\x00" * 512,
        "resources.arsc": b"\x02\x00\x0c\x00" + b"\x00" * 256,
        "res/layout/main.xml": b"\x03\x00\x08\x00" + b"\x00" * 64,
        "res/drawable/icon.png": png(192, 192, 10),
        "lib/arm64-v8a/libnative.so": b"\x7fELF" + b"\x00" * 256,
        "META-INF/CERT.RSA": b"\x30\x82" + b"\x00" * 128,
        "META-INF/CERT.SF": b"Signature-Version: 1.0\n",
    })
    record(p, "sw.android", "APK-like archive")

    # 20. Wallpaper collection ---------------------------------------------
    p = root / "wallpapers.zip"
    _zip(p, {f"wallpapers/wall_{i}.png": png(1920, 1080, i) for i in range(8)})
    record(p, "media.image", "zip full of images (not Archives)")

    # 21. The user's FileSorter.zip (python project, wrapper folder) --------
    p = root / "FileSorter.zip"
    _zip(p, {
        "FileSorter/README.md": b"# FileSorter\nA python file sorter.\n",
        "FileSorter/run.bat": b"@echo off\r\npython file_sorter.py %*\r\n",
        "FileSorter/file_sorter.py": b"import argparse\nif __name__ == '__main__':\n    pass\n",
        "FileSorter/sorter_core.py": b"from fsengine.classify import classify\n",
        "FileSorter/fixtures_builder.py": b"import zipfile\n",
        "FileSorter/test_sorter.py": b"import unittest\n",
        "FileSorter/fsengine/__init__.py": b'__version__ = "1.0.0"\n',
        "FileSorter/fsengine/classify.py": b"def classify(path):\n    return None\n",
        "FileSorter/fsengine/documents.py": b"# doc parsers\n",
        "FileSorter/fsengine/listing.py": b"# listing\n",
        "FileSorter/fsengine/magic.py": b"# magic\n",
        "FileSorter/fsengine/media.py": b"# media\n",
        "FileSorter/fsengine/model.py": b"# model\n",
        "FileSorter/fsengine/rules.py": b"# rules\n",
        "FileSorter/fsengine/ecosystems/__init__.py": b"",
        "FileSorter/fsengine/ecosystems/minecraft.py": b"# minecraft\n",
        "FileSorter/fsengine/ecosystems/java.py": b"# java\n",
        "FileSorter/fsengine/ecosystems/devprojects.py": b"# dev\n",
        "FileSorter/.github/workflows/build.yml": b"name: build\non: [push]\n",
    })
    record(p, "dev.python", "the user's real-world python project layout")

    # 22. FileSorter-exe.zip (single exe inside a zip) ----------------------
    p = root / "FileSorter-exe.zip"
    _zip(p, {"FileSorter.exe": fake_pe(["pyi-", "PyInstaller"], product="FileSorter", company="fahad")})
    record(p, "sw.portable", "zip wrapping exactly one exe (was 'Archives' before)")

    # 23. Plain Node library ------------------------------------------------
    p = root / "lodashish.zip"
    _zip(p, {
        "package.json": _json_bytes({"name": "lodashish", "version": "4.17.21", "main": "index.js",
                                     "dependencies": {"commander": "^11.0.0"}}),
        "index.js": b"module.exports = require('./lib/core');\n",
        "lib/core.js": b"function chunk(a, n) { return a; }\nmodule.exports = { chunk };\n",
        "lib/utils.js": b"const noop = () => {};\nmodule.exports = { noop };\n",
    })
    record(p, "dev.node", "ordinary npm package")

    # 24. Data-pack + resource pack hybrid ---------------------------------
    p = root / "combined-pack.zip"
    _zip(p, {
        "pack.mcmeta": _json_bytes({"pack": {"pack_format": 15, "description": "Combined"}}),
        "assets/minecraft/lang/en_us.json": b'{"item.example.thing": "Thing"}',
        "assets/minecraft/textures/item/thing.png": png(16, 16, 11),
        "data/tweaks/functions/hello.mcfunction": b"say hello\n",
        "data/tweaks/tags/functions/load.json": b'{"values": ["tweaks:hello"]}',
    })
    record(p, "mc.resourcepack", "hybrid pack (assets + data) — expect the resource pack side")

    # 25. Mixed drive dump --------------------------------------------------
    p = root / "mixed-dump.zip"
    _zip(p, {
        "report.pdf": b"%PDF-1.7\n" + b"\x00" * 256,
        "photo.jpg": b"\xff\xd8\xff\xe0" + b"\x00" * 256,
        "Setup.exe": fake_pe(["Nullsoft"]),
        "notes.txt": b"random notes\n",
        "song.mp3": b"ID3\x03\x00" + b"\x00" * 128,
        "readme.md": b"# mixed\n",
    })
    record(p, "misc.collection", "unrelated files in one archive")

    # 26. Unknown binary ----------------------------------------------------
    p = root / "mystery.dat"
    p.write_bytes(os.urandom(4096))
    record(p, "misc.review", "random binary — must not be filed confidently")

    # 27. Unreadable container (RAR) ---------------------------------------
    p = root / "rlcraft-shaders.rar"
    p.write_bytes(b"Rar!\x1a\x07\x01\x00" + os.urandom(512))
    record(p, "mc.review", "RAR cannot be opened: best-effort from the name, flagged for review")

    # 28. Misnamed file (txt renamed to .png) ------------------------------
    p = root / "totally_an_image.png"
    p.write_bytes(b"This is obviously plain text with words in it.\n" * 20)
    record(p, "misc.review", "extension lie: .png that is text")

    # 29. Python scripts collection ----------------------------------------
    p = root / "scripts-collection.zip"
    _zip(p, {
        "cleanup.py": b"import os, shutil\n\ndef main():\n    print('cleanup')\n",
        "backup.py": b"import shutil, datetime\n\ndef main():\n    pass\n",
        "requirements.txt": b"requests\nclick\n",
        "utils/__init__.py": b"",
        "utils/helper.py": b"def helper():\n    return True\n",
        "main.py": b"from utils.helper import helper\nif __name__ == '__main__':\n    helper()\n",
    })
    record(p, "dev.python", "small python script collection")

    # 30. Java library jar (no plugin/mod descriptors) ---------------------
    p = root / "jsoup-1.17.2.jar"
    _zip(p, {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Title: jsoup\nMain-Class: org.jsoup.Jsoup\n",
        "META-INF/maven/org.jsoup/jsoup/pom.properties": b"groupId=org.jsoup\nartifactId=jsoup\nversion=1.17.2\n",
        "org/jsoup/Jsoup.class": fake_class(["org/jsoup/Jsoup", "java/lang/Object"]),
        "org/jsoup/nodes/Document.class": fake_class(["org/jsoup/nodes/Document"]),
        "org/jsoup/parser/Parser.class": fake_class(["org/jsoup/parser/Parser"]),
        "org/jsoup/nodes/Element.class": fake_class(["org/jsoup/nodes/Element"]),
        "org/jsoup/select/Selector.class": fake_class(["org/jsoup/select/Selector"]),
    })
    record(p, "sw.library", "ordinary Java library jar (not a plugin!)")

    # 31. Mindustry-style / unknown Java app (no descriptors, no markers) ---
    p = root / "weird-java-app.jar"
    _zip(p, {
        "com/example/app/Main.class": fake_class(["com/example/app/Main"]),
        "com/example/app/Model.class": fake_class(["com/example/app/Model"]),
        "com/example/app/View.class": fake_class(["com/example/app/View"]),
        "javafx/base/Platform.class": fake_class(["javafx/application/Application"]),
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nMain-Class: com.example.app.Main\n",
    })
    record(p, "dev.java", "JavaFX desktop app jar without plugin/mod markers")

    with (root / "expectations.json").open("w", encoding="utf-8") as fh:
        json.dump(expectations, fh, indent=1)
    return expectations


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures")
    rows = build_all(target)
    print(f"built {len(rows)} fixtures in {target}")
    for row in rows:
        print(f"  {row['file']:<40} -> {row['label']:<18} {row['note']}")
