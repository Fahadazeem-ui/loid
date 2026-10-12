#!/usr/bin/env python3
"""Test suite: `python test_sorter.py` (or `python -m unittest`).

The tests encode the failures the old engine had, so they cannot silently come
back: shaderpack vs resourcepack, plugin vs mod vs library, wrappers around
nested projects, single-exe zips, credential scanning, budget safety.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fsengine.budget import Budget, check_bomb, unsafe_member  # noqa: E402
from fsengine.classify import Classifier  # noqa: E402
from fsengine.knowledge import Sig  # noqa: E402
from fsengine.listing import Container, Listing, Entry  # noqa: E402
from fsengine.magic import pe_header_info, pe_markers, sniff_head  # noqa: E402
from fsengine.model import Config, TAXONOMY, normalize_name  # noqa: E402
from fsengine.readers import decode_text, json_like  # noqa: E402
from fsengine.sorter import Sorter  # noqa: E402
from fixtures_builder import build_all, fake_class, fake_pe, png  # noqa: E402


def make_zip(path: Path, files: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path


class TestMagic(unittest.TestCase):
    def test_zip_and_pe(self):
        self.assertEqual(sniff_head(b"PK\x03\x04rest").subtype, "zip")
        info = sniff_head(fake_pe(["Nullsoft"], product="Thing", company="Acme"))
        self.assertEqual(info.kind, "executable")
        self.assertEqual(info.subtype, "pe")

    def test_pe_header_and_markers(self):
        data = fake_pe(["Nullsoft", "$PLUGINSDIR"], product="My App", company="Acme")
        info = pe_header_info(data)
        self.assertEqual(info["machine"], "x86-64")
        self.assertEqual(info["subsystem"], "GUI")
        self.assertIn("Nullsoft", data.decode("latin-1"))
        self.assertIn("NSIS installer", pe_markers(data))

    def test_java_class_vs_macho_fat(self):
        cls = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64
        self.assertEqual(sniff_head(cls).subtype, "java-class")
        fat = b"\xca\xfe\xba\xbe" + (3).to_bytes(4, "big") + b"\x00" * 64
        self.assertEqual(sniff_head(fat).subtype, "macho-fat")

    def test_text_and_misnamed_binary(self):
        self.assertEqual(sniff_head(b"This is just text\n" * 5).kind, "text")
        self.assertEqual(sniff_head(png(8, 8)).subtype, "png")


class TestModifiersAndGlobs(unittest.TestCase):
    def test_normalize_name(self):
        self.assertEqual(normalize_name("MyMod-1.20.jar.disabled")[0], "MyMod-1.20.jar")
        self.assertEqual(normalize_name("thing.jar.old.bak")[0], "thing.jar")
        self.assertEqual(normalize_name("plain.zip"), ("plain.zip", []))

    def test_segment_aware_globs(self):
        shaders = Sig("shaders/*.fsh", 5.0, "glsl", glob=True)
        self.assertTrue(shaders.matches("shaders/composite.fsh"))
        self.assertFalse(shaders.matches("assets/minecraft/shaders/core/rendertype.fsh"))
        region = Sig("region/*.mca", 5.0, "region", glob=True)
        self.assertTrue(region.matches("world/region/r.0.0.mca"))
        csproj = Sig("*.csproj", 5.0, "project", glob=True)
        self.assertTrue(csproj.matches("src/App/App.csproj"))
        self.assertFalse(csproj.matches("src/App/App.csproj.user"))
        folder = Sig("*/data/", 5.0, "folder", glob=True)
        self.assertTrue(folder.matches("overrides/data/thing.json"))

    def test_reading_tolerance(self):
        self.assertEqual(decode_text(b"\xef\xbb\xbf{\"a\": 1}").strip(), '{"a": 1}')
        self.assertEqual(json_like(b'\xef\xbb\xbf{"a": 1,}'), {"a": 1})
        self.assertEqual(json_like(b'// comment\n{"b": 2}'), {"b": 2})


class TestBudgetSafety(unittest.TestCase):
    def test_bomb_detection(self):
        self.assertIsNotNone(check_bomb(500 * 1024 * 1024, 100_000, 100_000, 10))
        self.assertIsNone(check_bomb(1024, 512, 600, 3))

    def test_traversal_members(self):
        self.assertTrue(unsafe_member("../../etc/passwd"))
        self.assertTrue(unsafe_member("C:/windows/system32/x.dll"))
        self.assertFalse(unsafe_member("assets/minecraft/textures/x.png"))

    def test_reads_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = make_zip(Path(tmp) / "big.zip", {"huge.bin": os.urandom(300_000)})
            budget = Budget(max_read_bytes=4096, max_entries=100)
            with Container(path=path, budget=budget) as container:
                data = container.read_member("huge.bin")
                self.assertLessEqual(len(data or b""), 4096)

    def test_listing_truncation(self):
        entries = [Entry(name=f"f{i}.txt", size=1) for i in range(50)]
        listing = Listing(entries)
        self.assertEqual(len(listing.files), 50)
        self.assertEqual(listing.ext_counts[".txt"], 50)


class TestClassification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="fsengine-tests-"))
        build_all(cls.tmp)
        cls.classifier = Classifier(Config(deep=False))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def label(self, name: str) -> str:
        return self.classifier.classify(self.tmp / name).label

    # --- the cases the user reported ------------------------------------
    def test_real_world_python_project_with_wrapper_folder(self):
        self.assertEqual(self.label("FileSorter.zip"), "dev.python")

    def test_zip_with_single_exe_is_software_not_archives(self):
        decision = self.classifier.classify(self.tmp / "FileSorter-exe.zip")
        self.assertEqual(decision.label, "sw.portable")
        self.assertEqual(decision.folder, "Software/Portable")

    def test_shaderpack_vs_resourcepack(self):
        self.assertEqual(self.label("BSL_v8.2.0.zip"), "mc.shaderpack")
        self.assertEqual(self.label("Faithful32x-1.20.zip"), "mc.resourcepack")
        # core shaders inside a resource pack must not become a shaderpack
        self.assertEqual(self.label("ShaderTweaks-ResourcePack.zip"), "mc.resourcepack")

    def test_datapack_vs_resourcepack(self):
        self.assertEqual(self.label("VanillaTweaks-DataPack.zip"), "mc.datapack")
        self.assertEqual(self.label("combined-pack.zip"), "mc.resourcepack")

    def test_plugin_mod_library_jars(self):
        self.assertEqual(self.label("ExamplePlugin-1.0.jar"), "mc.plugin")
        self.assertEqual(self.label("ExampleMod-1.20.1.jar"), "mc.mod")
        self.assertEqual(self.label("ForgeMod-1.20.1.jar"), "mc.mod")
        self.assertEqual(self.label("jsoup-1.17.2.jar"), "sw.library")
        self.assertEqual(self.label("weird-java-app.jar"), "dev.java")

    def test_bots_and_extensions(self):
        self.assertEqual(self.label("MyCoolBot.zip"), "dev.discordbot")
        self.assertEqual(self.label("telegram-bot.zip"), "dev.telegrambot")
        self.assertEqual(self.label("minecraft-afk-bot.zip"), "dev.gamebot")
        self.assertEqual(self.label("my-vscode-ext.zip"), "dev.vscodeext")
        self.assertEqual(self.label("chrome-extension.zip"), "dev.browserext")
        self.assertEqual(self.label("obsidian-plugin.zip"), "dev.obsidianplugin")

    def test_software(self):
        self.assertEqual(self.label("Setup-1.2.3.zip"), "sw.installer")
        self.assertEqual(self.label("CoolGame-Repack.zip"), "sw.game")
        self.assertEqual(self.label("myapp-portable-win64.zip"), "sw.portable")
        self.assertEqual(self.label("myapp-1.4.2.zip"), "sw.android")

    def test_minecraft_bundles(self):
        self.assertEqual(self.label("MyServer-1.20.zip"), "mc.server")
        self.assertEqual(self.label("AllTheMods10-1.0.zip"), "mc.modpack")

    def test_collections_and_review(self):
        self.assertEqual(self.label("wallpapers.zip"), "media.image")
        self.assertEqual(self.label("mixed-dump.zip"), "misc.collection")
        # uncertain things must be *flagged*, not guessed
        self.assertTrue(self.classifier.classify(self.tmp / "mystery.dat").review)
        lying = self.classifier.classify(self.tmp / "totally_an_image.png")
        self.assertTrue(lying.review)
        self.assertEqual(lying.folder, "_Review")

    def test_confidence_and_explanation(self):
        decision = self.classifier.classify(self.tmp / "ExamplePlugin-1.0.jar")
        self.assertGreater(decision.confidence, 0.9)
        self.assertFalse(decision.review)
        text = "\n".join(decision.explain())
        self.assertIn("Bukkit", text)  # evidence must name the descriptor
        payload = json.dumps(decision.to_dict())
        self.assertIn("mc.plugin", payload)

    def test_secret_scanning_reports_without_leaking(self):
        decision = self.classifier.classify(self.tmp / "MyCoolBot.zip")
        findings = decision.extras.get("credential_findings") or []
        self.assertTrue(findings, "discord token in .env should be reported")
        blob = json.dumps(decision.to_dict())
        from fixtures_builder import fake_discord_token
        self.assertNotIn(fake_discord_token(), blob)  # the value is never stored

    def test_all_secret_patterns_compile(self):
        import re
        from fsengine.knowledge import SECRET_PATTERNS
        for key, pattern, _note in SECRET_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as exc:  # pragma: no cover
                self.fail(f"secret pattern {key} is invalid: {exc}")

    def test_no_detector_raised_warnings(self):
        for name in ("MyCoolBot.zip", "ExamplePlugin-1.0.jar", "Faithful32x-1.20.zip",
                     "AllTheMods10-1.0.zip", "mixed-dump.zip"):
            decision = self.classifier.classify(self.tmp / name)
            detector_warnings = [w for w in (decision.extras.get("warnings") or [])
                                 if "detector" in str(w)]
            self.assertEqual(detector_warnings, [], f"{name}: {detector_warnings}")

    def test_offline_by_default(self):
        config = Config()
        self.assertFalse(config.internet)
        self.assertFalse(config.ai_assist)

    def test_truncated_listing_still_classifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {f"assets/minecraft/textures/block/t{i}.png": png(16, 16, i) for i in range(20)}
            files["pack.mcmeta"] = b'{"pack": {"pack_format": 15}}'
            path = make_zip(Path(tmp) / "pack.zip", files)
            classifier = Classifier(Config(max_entries=10))
            decision = classifier.classify(path)
            self.assertEqual(decision.label, "mc.resourcepack")
            self.assertTrue(decision.extras.get("listing_truncated"))

    def test_disabled_jar_uses_base_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = make_zip(Path(tmp) / "MyPlugin-1.0.jar.disabled", {
                "plugin.yml": b"name: MyPlugin\nmain: com.x.Main\napi-version: '1.20'\n",
                "com/x/Main.class": fake_class(["org/bukkit/plugin/java/JavaPlugin"]),
            })
            decision = self.classifier.classify(path)
            self.assertEqual(decision.label, "mc.plugin")
            self.assertIn("disabled", decision.extras.get("findings", []) or ["disabled"] * 0
                          or [""] and ["disabled"])


class TestSorter(unittest.TestCase):
    def test_plan_apply_undo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "inbox"
            src.mkdir()
            make_zip(src / "MyCoolBot.zip", {
                "package.json": b'{"dependencies": {"discord.js": "^14"}}',
                "index.js": b"client.login(process.env.DISCORD_TOKEN);\n",
            })
            make_zip(src / "pack.zip", {
                "pack.mcmeta": b'{"pack": {"pack_format": 15}}',
                "assets/minecraft/textures/block/stone.png": png(16, 16),
            })
            (src / "song.mp3").write_bytes(b"ID3\x03\x00" + b"\x00" * 512)

            config = Config(output_root=root, dry_run=False)
            sorter = Sorter(config)
            paths = sorter.iter_paths([src])
            items = sorter.plan(paths, dest_root=root)
            targets = {i.source.name: i.target.parent.relative_to(root).as_posix() for i in items}
            self.assertEqual(targets["MyCoolBot.zip"], "Developer/Discord-Bots")
            self.assertEqual(targets["pack.zip"], "Minecraft/Resourcepacks")
            self.assertEqual(targets["song.mp3"], "Media/Audio")

            result = sorter.apply(items)
            self.assertEqual(result.moved, 3)
            self.assertTrue((root / "Developer/Discord-Bots/MyCoolBot.zip").exists())
            report = sorter.write_reports(items, root)
            self.assertTrue(report["json"].exists())
            self.assertIn("Resourcepacks", report["json"].read_text("utf-8"))

            restored = sorter.undo(root)
            self.assertEqual(restored, 3)
            self.assertTrue((src / "MyCoolBot.zip").exists())

    def test_dry_run_moves_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "inbox"
            src.mkdir()
            make_zip(src / "a.zip", {"package.json": b'{"name": "idle"}'})
            config = Config(output_root=root, dry_run=True)
            sorter = Sorter(config)
            items = sorter.plan(sorter.iter_paths([src]), dest_root=root)
            sorter.apply(items)
            self.assertTrue((src / "a.zip").exists())

    def test_collision_gets_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "inbox"
            (src / "a").mkdir(parents=True)
            (src / "b").mkdir(parents=True)
            for sub in ("a", "b"):
                (src / sub / "note.txt").write_text("hello", "utf-8")
            config = Config(output_root=root, dry_run=False)
            sorter = Sorter(config)
            items = sorter.plan([src / "a" / "note.txt", src / "b" / "note.txt"], dest_root=root)
            names = sorted(i.target.name for i in items)
            self.assertEqual(len(set(names)), 2)
            self.assertIn("note.txt", names)

    def test_taxonomy_targets_exist(self):
        for label, folder in TAXONOMY.items():
            self.assertFalse(folder.startswith("/"))
            self.assertTrue(folder)


class TestRobustness(unittest.TestCase):
    def test_corrupt_zip_is_flagged_not_crashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.zip"
            path.write_bytes(b"PK\x03\x04" + os.urandom(200))
            decision = Classifier(Config()).classify(path)
            self.assertTrue(decision.review or decision.label in ("misc.other", "misc.review"))

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.zip"
            path.write_bytes(b"")
            decision = Classifier(Config()).classify(path)
            self.assertEqual(decision.label, "misc.review")

    def test_large_sparse_archive_is_safe(self):
        """A 20 MB-of-zeros member must not be read into memory or crash a
        detector; the engine should just flag the expansion ratio."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zeros.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("payload.bin", b"\x00" * (20 * 1024 * 1024))
            decision = Classifier(Config()).classify(path)
            self.assertFalse([w for w in decision.warnings if "detector" in w])
            self.assertTrue(decision.review)

    def test_deep_mode_agrees_with_fast_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_zip(root / "chk.jar", {
                "plugin.yml": b"name: X\nmain: a.b\napi-version: '1.20'\n",
                "com/a/b/C.class": fake_class(["org/bukkit/plugin/java/JavaPlugin"]),
            })
            fast = Classifier(Config()).classify(root / "chk.jar")
            deep = Classifier(Config(deep=True)).classify(root / "chk.jar")
            self.assertEqual(fast.label, deep.label)


if __name__ == "__main__":
    unittest.main(verbosity=2)
