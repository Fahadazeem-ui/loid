"""Local corrections ("teach once").

When you tell the sorter that a file was filed wrongly, the correction is stored
as a name pattern -> label rule. It applies with very high weight, only ever
lives on your machine, and never leaves it. This is how accuracy grows for *your*
files even when the general rules cannot know them.

Storage:
    <script folder>/filesorter_corrections.json   (if it already exists)
    <cache dir>/corrections.json                  (default: ~/.filesorter)

Format:
    {"corrections": [{"pattern": "netherion-*.jar", "label": "mc.plugin",
                      "note": "my own plugin builds", "added": 1712345678}]}
"""
from __future__ import annotations

import fnmatch
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

from .model import Config, TAXONOMY


def _candidates(config: Config) -> List[Path]:
    here = Path(__file__).resolve().parent.parent / "filesorter_corrections.json"
    return [here, Path(config.cache_path()) / "corrections.json"]


def load(config: Config) -> List[Dict[str, str]]:
    for path in _candidates(config):
        if path.is_file():
            try:
                data = json.loads(path.read_text("utf-8"))
            except Exception:
                continue
            rows = data.get("corrections") if isinstance(data, dict) else data
            if isinstance(rows, list):
                return [r for r in rows if isinstance(r, dict) and r.get("pattern") and r.get("label")]
    return []


def save(config: Config, pattern: str, label: str, note: str = "") -> Path:
    target = next((p for p in _candidates(config) if p.is_file()), _candidates(config)[1])
    existing: List[Dict[str, str]] = []
    if target.is_file():
        try:
            data = json.loads(target.read_text("utf-8"))
            existing = data.get("corrections", data if isinstance(data, list) else [])
        except Exception:
            existing = []
    existing = [r for r in existing if r.get("pattern") != pattern]
    existing.append({"pattern": pattern, "label": label, "note": note, "added": int(time.time())})
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"corrections": existing}, indent=1), "utf-8")
    return target


def match(name: str, config: Config) -> Optional[Dict[str, str]]:
    """Return the first correction whose pattern matches this file name."""
    low = name.lower()
    for row in load(config):
        pattern = str(row["pattern"]).lower()
        if fnmatch.fnmatch(low, pattern) or fnmatch.fnmatch(low, pattern + "*") or pattern in low:
            if row["label"] in TAXONOMY:
                return row
    return None
