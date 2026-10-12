"""Optional internet knowledge layer (OFF by default).

What it can do when enabled:

1. **Hash lookups** — the exact identity of published files. Modrinth knows
   whether a file is a *mod, resourcepack, shader, datapack or modpack* — which
   is precisely the shader-vs-resourcepack question. Maven Central knows the
   exact ``groupId:artifactId:version`` of a library jar.
2. **Rule packs** — the classifier can download extra signature rows, so new
   loaders/formats can be supported without shipping a new build.

Privacy contract:
* Only the **SHA-1 hash** is ever sent. File names, paths and contents are not.
* Results are cached on disk; lookups happen once per hash.
* Everything degrades to "no data" when offline; the local engine result is
  never overridden by a failed lookup.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = "FileSorter/2.0 (+local file classifier; hash-only lookups)"
CACHE_TTL_S = 60 * 60 * 24 * 30

# Modrinth project_type -> our label
MODRINTH_LABELS = {
    "mod": "mc.mod",
    "plugin": "mc.plugin",
    "resourcepack": "mc.resourcepack",
    "shader": "mc.shaderpack",
    "datapack": "mc.datapack",
    "modpack": "mc.modpack",
    "project": "mc.other",
}


def sha1_of(path: Path, limit_bytes: Optional[int] = None) -> Optional[str]:
    """Hash a file (or just its first N bytes for a cheap fingerprint)."""
    h = hashlib.sha1()
    try:
        with open(path, "rb") as fh:
            remaining = limit_bytes
            while True:
                chunk = fh.read(1024 * 128 if remaining is None else min(1024 * 128, remaining))
                if not chunk:
                    break
                h.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
    except OSError:
        return None
    return h.hexdigest()


class NetKnowledge:
    def __init__(self, config) -> None:
        self.config = config
        self.cache_file = Path(config.cache_path()) / "netkb.json"
        self._cache: Dict[str, Any] = {}
        self._loaded = False
        self.requests = 0

    # -- cache ------------------------------------------------------------
    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            if self.cache_file.is_file():
                self._cache = json.loads(self.cache_file.read_text("utf-8"))
        except Exception:
            self._cache = {}

    def _save(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache, indent=1), "utf-8")
            tmp.replace(self.cache_file)
        except Exception:
            pass

    def _cached(self, key: str) -> Optional[Any]:
        self._load()
        row = self._cache.get(key)
        if not row:
            return None
        if time.time() - row.get("at", 0) > CACHE_TTL_S:
            return None
        return row.get("value")

    def _store(self, key: str, value: Any) -> None:
        self._load()
        self._cache[key] = {"at": time.time(), "value": value}
        self._save()

    # -- http -------------------------------------------------------------
    def _get_json(self, url: str, timeout: float = 8.0) -> Optional[Any]:
        if not self.config.internet:
            return None
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                self.requests += 1
                return json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
            return None

    # -- lookups ----------------------------------------------------------
    def lookup_sha1(self, sha1: str) -> Optional[Dict[str, Any]]:
        """Ask Modrinth (then Maven Central) what this exact file is."""
        if not self.config.internet or not sha1:
            return None
        key = f"sha1:{sha1}"
        cached = self._cached(key)
        if cached is not None:
            return cached or None

        result: Dict[str, Any] = {}
        version = self._get_json(
            f"https://api.modrinth.com/v2/version_file/{sha1}?algorithm=sha1"
        )
        if isinstance(version, dict) and version.get("project_id"):
            project = self._get_json(f"https://api.modrinth.com/v2/project/{version['project_id']}")
            if isinstance(project, dict):
                ptype = str(project.get("project_type", ""))
                result = {
                    "source": "modrinth",
                    "project": project.get("title") or project.get("slug"),
                    "project_type": ptype,
                    "label": MODRINTH_LABELS.get(ptype.lower()),
                    "loader": project.get("loaders") or version.get("loaders"),
                    "game_versions": version.get("game_versions"),
                    "version": version.get("version_number"),
                    "downloads": project.get("downloads"),
                }
        if not result:
            maven = self._get_json(
                "https://search.maven.org/solrsearch/select?q="
                + urllib.parse.quote(f'1:"{sha1}"')
                + "&rows=3&wt=json"
            )
            docs = ((maven or {}).get("response") or {}).get("docs") or []
            if docs:
                d = docs[0]
                result = {
                    "source": "maven-central",
                    "group": d.get("g"),
                    "artifact": d.get("a"),
                    "version": d.get("v"),
                    "label": "sw.library",
                }
        self._store(key, result or {})
        return result or None

    def identify(self, path: Path) -> Optional[Dict[str, Any]]:
        """Hash the file and look it up (hash only — never the file itself)."""
        if not self.config.internet:
            return None
        sha1 = sha1_of(path)
        if not sha1:
            return None
        info = self.lookup_sha1(sha1)
        if info:
            info = dict(info)
            info["sha1"] = sha1
        return info

    # -- rule packs -------------------------------------------------------
    def fetch_rule_pack(self, url: str) -> Optional[Dict[str, Any]]:
        """Download a signature update pack (JSON). Opt-in, like everything here."""
        if url.startswith("file://"):
            try:
                return json.loads(Path(url[7:]).read_text("utf-8"))
            except Exception:
                return None
        return self._get_json(url, timeout=10.0)


def merge_rule_pack(pack: Dict[str, Any]) -> Dict[str, int]:
    """Merge a downloaded rule pack into the in-memory knowledge tables."""
    from . import knowledge

    counts = {"path_sigs": 0, "name_hints": 0, "text_sigs": 0}
    for row in pack.get("path_sigs", []):
        try:
            label = str(row["label"])
            sig = knowledge.Sig(
                needle=str(row["needle"]),
                weight=float(row["weight"]),
                note=str(row.get("note", "downloaded rule")),
                glob=bool(row.get("glob", False)),
                contains=bool(row.get("contains", False)),
            )
            knowledge.PATH_SIGS.setdefault(label, []).append(sig)
            counts["path_sigs"] += 1
        except Exception:
            continue
    for row in pack.get("name_hints", []):
        try:
            knowledge.NAME_HINTS.setdefault(str(row["label"]), []).append(
                (str(row["needle"]), float(row["weight"]), str(row.get("note", "downloaded hint")))
            )
            counts["name_hints"] += 1
        except Exception:
            continue
    for row in pack.get("text_sigs", []):
        try:
            sig = knowledge.TextSig(
                sid=str(row["sid"]),
                label=str(row["label"]),
                weight=float(row["weight"]),
                note=str(row.get("note", "downloaded text signature")),
                needles=tuple(str(n) for n in row["needles"]),
            )
            knowledge.TEXT_SIGS.append(sig)
            knowledge.TEXT_SIG_BY_ID[sig.sid] = sig
            knowledge.TEXT_SIG_NEEDLES[sig.sid] = sig.needles
            counts["text_sigs"] += 1
        except Exception:
            continue
    return counts
