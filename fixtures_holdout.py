"""Holdout corpus — cases deliberately *different* from the tuning set.

Everything here was written after the engine was tuned, so it can catch
overfitting. It exercises variations the main fixtures do not:

* wrappers around shaderpacks and packs with unusual folder names
* Velocit / Sponge / Quilt descriptors instead of the usual three
* Forge mods that carry only MANIFEST attributes (no mods.toml)
* plugin *source repositories* (Gradle + src/main/resources/plugin.yml)
* resource/datapack layouts with no pack.mcmeta at all
* .mrpack and Bedrock add-ons
* C/C++ source archives, FNF mod zips, theme packs, panel exports

Run it with:  python benchmark.py --holdout  (or merge it into the corpus).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

from fixtures_builder import _zip, fake_class, fake_pe, png


def build_holdout(root: Path) -> List[Dict[str, str]]:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, str]] = []

    def record(path: Path, label: str, note: str = "") -> None:
        rows.append({"file": str(path.relative_to(root)), "label": label, "note": note})

    # 1. Shaderpack inside a wrapper folder, different naming -------------
    p = root / "Sildurs Vibrant Shaders v1.29.zip"
    _zip(p, {
        "Sildurs Vibrant Shaders v1.29/shaders/shaders.properties": b"# sindurs\nshadowMapResolution=2048\n",
        "Sildurs Vibrant Shaders v1.29/shaders/gbuffers_textured.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(1.0); }\n",
        "Sildurs Vibrant Shaders v1.29/shaders/gbuffers_textured.vsh": b"#version 120\nvoid main() { gl_Position = ftransform(); }\n",
        "Sildurs Vibrant Shaders v1.29/shaders/composite.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(0.5); }\n",
        "Sildurs Vibrant Shaders v1.29/shaders/composite1.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(0.5); }\n",
        "Sildurs Vibrant Shaders v1.29/shaders/final.fsh": b"#version 120\nvoid main() { gl_FragData[0] = vec4(0.5); }\n",
        "Sildurs Vibrant Shaders v1.29/shaders/lang/en_US.lang": b"profile.LOW=Low\n",
    })
    record(p, "mc.shaderpack", "wrapper folder + Iris-style file names")

    # 2. Resource pack with no pack.mcmeta, nested assets ------------------
    p = root / "PixelPack-v2.zip"
    files = {
        "assets/minecraft/textures/block/dirt.png": png(16, 16, 1),
        "assets/minecraft/textures/block/grass_block_top.png": png(16, 16, 2),
        "assets/minecraft/textures/item/stick.png": png(16, 16, 3),
        "assets/minecraft/models/item/stick.json": b'{"parent": "minecraft:item/handheld"}',
        "assets/minecraft/blockstates/dirt.json": b'{"variants": {}}',
        "assets/minecraft/lang/en_us.json": b'{"block.minecraft.dirt": "Dirt"}',
    }
    for i in range(12):
        files[f"assets/minecraft/textures/block/extra_{i}.png"] = png(16, 16, i + 10)
    _zip(p, files)
    record(p, "mc.resourcepack", "pack without pack.mcmeta")

    # 3. Datapack with only data/ -----------------------------------------
    p = root / "OneBlockDatapack.zip"
    _zip(p, {
        "data/oneblock/functions/start.mcfunction": b"say starting\nsetblock 0 -60 0 minecraft:stone\n",
        "data/oneblock/functions/tick.mcfunction": b"execute at @a run function oneblock:progress\n",
        "data/minecraft/tags/functions/load.json": b'{"values": ["oneblock:start"]}',
        "data/minecraft/tags/functions/tick.json": b'{"values": ["oneblock:tick"]}',
        "data/oneblock/advancements/oneblock.json": b'{"display": {"title": "OneBlock"}}',
    })
    record(p, "mc.datapack", "datapack without pack.mcmeta")

    # 4. Velocity proxy plugin (META-INF descriptor) ----------------------
    p = root / "VelocityExample-2.1.jar"
    _zip(p, {
        "META-INF/velocity-plugin.json": json.dumps({
            "id": "velocityexample", "name": "VelocityExample", "version": "2.1",
            "main": "com.example.velocity.ExamplePlugin",
        }).encode(),
        "com/example/velocity/ExamplePlugin.class": fake_class(
            ["com/velocitypowered/api/proxy/ProxyServer", "com/velocitypowered/api/event/Subscribe"]),
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
    })
    record(p, "mc.plugin", "Velocity plugin")

    # 5. Sponge plugin -----------------------------------------------------
    p = root / "SpongeExample-8.0.jar"
    _zip(p, {
        "META-INF/sponge_plugins.json": b'{"loader": {"name": "java_plain"}}',
        "org/spongepowered/plugin/Plugin.class": fake_class(["org/spongepowered/api/Sponge", "org/spongepowered/plugin/plugin/Plugin"]),
    })
    record(p, "mc.plugin", "Sponge plugin")

    # 6. Quilt mod ---------------------------------------------------------
    p = root / "QuiltExample-1.0.jar"
    _zip(p, {
        "quilt.mod.json": json.dumps({"quilt_loader": {"id": "quiltexample", "version": "1.0"}}).encode(),
        "com/example/quilt/QuiltMod.class": fake_class(["org/quiltmc/loader/api/metadata/ModMetadata"]),
    })
    record(p, "mc.mod", "Quilt mod")

    # 7. Forge mod with only MANIFEST attributes ---------------------------
    p = root / "legacy-forge-1.12.2.jar"
    _zip(p, {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nFMLModType: MOD\nTweakClass: net.minecraftforge.fml.common.launcher.FMLTweaker\n",
        "com/legacy/mod/LegacyMod.class": fake_class(["net/minecraftforge/fml/common/Mod", "cpw/mods/fml/common/Mod"]),
        "assets/legacy/lang/en_US.lang": b"item.legacy.name=Legacy\n",
    })
    record(p, "mc.mod", "legacy Forge mod detected from MANIFEST")

    # 8. Plugin *source repository* (Gradle + resources) -------------------
    p = root / "MyCoolPlugin-src.zip"
    _zip(p, {
        "MyCoolPlugin-src/build.gradle": b"plugins { id 'java' }\nrepositories { maven { url = 'https://repo.papermc.io' } }\n"
                                          b"dependencies { compileOnly 'io.papermc.paper:paper-api:1.20.4-R0.1-SNAPSHOT' }\n",
        "MyCoolPlugin-src/settings.gradle": b"rootProject.name = 'MyCoolPlugin'\n",
        "MyCoolPlugin-src/gradlew": b"#!/bin/sh\n",
        "MyCoolPlugin-src/src/main/resources/plugin.yml": b"name: MyCoolPlugin\nmain: com.cool.MyCoolPlugin\napi-version: '1.20'\n",
        "MyCoolPlugin-src/src/main/java/com/cool/MyCoolPlugin.java": b"package com.cool;\nimport org.bukkit.plugin.java.JavaPlugin;\npublic class MyCoolPlugin extends JavaPlugin { }\n",
        "MyCoolPlugin-src/src/main/java/com/cool/listeners/JoinListener.java": b"package com.cool.listeners;\nimport org.bukkit.event.Listener;\n",
        "MyCoolPlugin-src/README.md": b"# MyCoolPlugin\n",
    })
    record(p, "mc.plugin", "plugin source repository")

    # 9. Modrinth modpack (.mrpack) ---------------------------------------
    p = root / "FabulouslyOptimized-5.0.mrpack"
    _zip(p, {
        "modrinth.index.json": json.dumps({
            "formatVersion": 1,
            "name": "Fabulously Optimized", "versionId": "5.0",
            "dependencies": {"minecraft": "1.20.4", "fabric-loader": "0.15.0"},
            "files": [{"path": "mods/sodium.jar", "downloads": ["https://cdn.modrinth.com/..."], "hashes": {}}],
        }).encode(),
        "overrides/config/sodium-options.json": b'{"quality": {}}',
        "overrides/config/iris.properties": b"shaderPack=\n",
        "mods/placeholder.txt": b"mods are downloaded on install\n",
    })
    record(p, "mc.modpack", "Modrinth .mrpack")

    # 10. Bedrock behaviour + resource pack --------------------------------
    p = root / "BedrockAddon.zip"
    _zip(p, {
        "manifest.json": json.dumps({
            "format_version": 2,
            "header": {"name": "Bedrock Addon", "uuid": "x", "version": [1, 0, 0]},
            "modules": [{"type": "data", "uuid": "y", "version": [1, 0, 0]}],
        }).encode(),
        "functions/init.mcfunction": b"say bedrock\n",
        "entities/custom.json": b'{"format_version": "1.16.0"}',
    })
    record(p, "mc.datapack", "Bedrock behaviour pack")

    # 11. C/C++ source archive --------------------------------------------
    p = root / "engine-src.zip"
    src = {f"engine/src/core/module_{i}.cpp": b"#include <vector>\nint f() { return 0; }\n" for i in range(6)}
    src.update({f"engine/include/module_{i}.h": b"#pragma once\n" for i in range(6)})
    src["engine/CMakeLists.txt"] = b"project(engine)\nadd_executable(engine main.cpp)\n"
    src["engine/src/main.cpp"] = b"int main() { return 0; }\n"
    src["engine/README.md"] = b"# engine\n"
    _zip(p, src)
    record(p, "dev.other", "C++ project (no dedicated taxonomy folder)")

    # 12. FNF-style mod zip (game data + json) -----------------------------
    p = root / "MyFnfMod-1.0.zip"
    _zip(p, {
        "mods/MyFnfMod/data/song/song.json": b'{"song": {"notes": [], "bpm": 150}}',
        "mods/MyFnfMod/data/song/song-chart.json": b'{"song": {"notes": []}}',
        "mods/MyFnfMod/data/song/Inst.ogg": b"OggS" + b"\x00" * 256,
        "mods/MyFnfMod/pack.json": b'{"name": "MyFnfMod", "version": "1.0"}',
        "mods/MyFnfMod/readme.txt": b"FNF mod\n",
    })
    record(p, "sw.game", "Friday Night Funkin' style mod package")

    # 13. Pterodactyl-style server export ---------------------------------
    p = root / "pterodactyl-export.zip"
    _zip(p, {
        "server.properties": b"motd=Ptero\nonline-mode=true\n",
        "paper-global.yml": b"_version: 28\n",
        "eula.txt": b"eula=true\n",
        "plugins/Vault.jar": fake_class(["org/bukkit/plugin/java/JavaPlugin"]),
        "plugins/LuckPerms.jar": fake_class(["net/luckperms/api/LuckPermsApi"]),
        "world/level.dat": b"\x00" * 128,
        "server.jar": fake_class(["net/minecraft/server/MinecraftServer"]),
        "run.sh": b"#!/bin/sh\njava -Xms2G -Xmx2G -jar server.jar nogui\n",
    })
    record(p, "mc.server", "hosting panel export")

    # 14. Installer with uninstaller + payload ----------------------------
    p = root / "AppInstaller-4.1.zip"
    _zip(p, {
        "setup.exe": fake_pe(["Inno Setup", "nsis"], product="App", company="Vendor"),
        "unins000.exe": fake_pe(["Inno Setup"]),
        "payload/files/app.dll": fake_pe([], dll=True),
        "payload/files/app.exe": fake_pe(["Electron"]),
        "readme.txt": b"Run setup.exe\n",
    })
    record(p, "sw.installer", "installer bundle with uninstaller")

    # 15. Discord bot repo without requirements.txt -----------------------
    p = root / "AternosKeeper.zip"
    _zip(p, {
        "afk_bot/bot.js": b"const mineflayer = require('mineflayer');\n"
                          b"const bot = mineflayer.createBot({ host: SERVER, username: 'AFK' });\n"
                          b"bot.on('end', () => setTimeout(connect, 30000));\n",
        "afk_bot/config.json": json.dumps({"server": "x.aternos.me", "port": 25565}).encode(),
        "afk_bot/package.json": b'{"name": "aternos-keeper", "dependencies": {"mineflayer": "^4.20.0"}}',
        "afk_bot/README.md": b"# AternosKeeper\nKeeps your Aternos server online with mineflayer.\n",
        "afk_bot/start.sh": b"#!/bin/bash\nnode bot.js\n",
    })
    record(p, "dev.gamebot", "AFK keeper with a discord hint mixed in")

    # 16. Misleading: .zip named like a shader that is really a resourcepack
    p = root / "Enhanced-Shaders-TexturePack.zip"
    _zip(p, {
        "pack.mcmeta": b'{"pack": {"pack_format": 15, "description": "shader-like textures"}}',
        "assets/minecraft/textures/block/glowstone.png": png(16, 16, 4),
        "assets/minecraft/textures/item/blaze_rod.png": png(16, 16, 5),
        "assets/minecraft/textures/effect/dither.png": png(16, 16, 6),
        "assets/minecraft/textures/environment/rain.png": png(16, 16, 7),
    })
    record(p, "mc.resourcepack", "name says 'shaders', content is a resource pack")

    # 17. Mixed Minecraft + bot - a genuine multi-project bundle ----------
    p = root / "mc-stuff-and-bots.zip"
    _zip(p, {
        "mods/sodium.jar": fake_class(["net/fabricmc/api/ModInitializer"]),
        "mods/lithium.jar": fake_class(["net/fabricmc/api/ModInitializer"]),
        "bots/DiscordBot/package.json": b'{"dependencies": {"discord.js": "^14"}}',
        "bots/DiscordBot/index.js": b"client.login(TOKEN);\n",
        "docs/notes.pdf": b"%PDF-1.7\n" + b"\x00" * 256,
    })
    record(p, "misc.collection", "several unrelated projects bundled together")

    # 18. Old Bukkit plugin jar with no api-version, odd casing ----------
    p = root / "OldTool_1.4.jar"
    _zip(p, {
        "Plugin.YML": b"Name: OldTool\nmain: com.old.Tool\nversion: 1.4\n",
        "com/old/Tool.class": fake_class(["org/bukkit/plugin/java/JavaPlugin", "org/bukkit/event/Listener"]),
    })
    record(p, "mc.plugin", "legacy plugin with odd descriptor casing")

    with (root / "expectations.json").open("w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    return rows


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures_holdout")
    built = build_holdout(target)
    print(f"built {len(built)} holdout fixtures in {target}")
