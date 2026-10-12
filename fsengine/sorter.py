"""Planning and applying the sort: safe by default, undoable, explainable."""
from __future__ import annotations

import csv
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .classify import Classifier
from .model import Config, Decision, TAXONOMY, LABEL_TITLES
from .netkb import NetKnowledge

UNDO_FILENAME = "_filesorter_undo.json"
REPORT_FILENAME = "_filesorter_report.json"


@dataclass
class PlanItem:
    source: Path
    decision: Decision
    target: Path
    action: str = "move"          # move | copy | skip
    note: str = ""

    @property
    def label(self) -> str:
        return self.decision.label

    @property
    def title(self) -> str:
        return self.decision.title


@dataclass
class SortResult:
    planned: List[PlanItem] = field(default_factory=list)
    moved: int = 0
    copied: int = 0
    skipped: int = 0
    failed: List[Tuple[Path, str]] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    elapsed: float = 0.0


class Sorter:
    """Classify a set of paths and organise them into the taxonomy tree."""

    def __init__(self, config: Optional[Config] = None, progress: Optional[Callable[[str], None]] = None):
        self.config = config or Config()
        self.classifier = Classifier(self.config)
        self.progress = progress or (lambda _msg: None)
        self.net = NetKnowledge(self.config) if self.config.internet else None
        self.dest_root: Optional[Path] = None

    # -- scanning ---------------------------------------------------------
    def iter_paths(self, roots: Sequence[Path], recursive: bool = False,
                   include: Optional[Sequence[str]] = None,
                   exclude: Optional[Sequence[str]] = None) -> List[Path]:
        import fnmatch

        out: List[Path] = []
        for root in roots:
            root = Path(root)
            if root.is_file():
                out.append(root)
                continue
            if not root.is_dir():
                continue
            if recursive:
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                    for name in filenames:
                        if name.startswith("."):
                            continue
                        out.append(Path(dirpath) / name)
            else:
                for child in sorted(root.iterdir()):
                    if child.name.startswith("."):
                        continue
                    out.append(child)
        if include:
            out = [p for p in out if any(fnmatch.fnmatch(p.name.lower(), pat.lower()) for pat in include)]
        if exclude:
            out = [p for p in out if not any(fnmatch.fnmatch(p.name.lower(), pat.lower()) for pat in exclude)]
        return out

    # -- planning ---------------------------------------------------------
    def plan(self, paths: Sequence[Path], dest_root: Optional[Path] = None) -> List[PlanItem]:
        dest_root = Path(dest_root or self.config.output_root or Path.cwd())
        self.dest_root = dest_root
        items: List[PlanItem] = []
        used: Dict[str, set] = {}
        for path in paths:
            decision = self.classifier.classify(path, budget=None)
            self._apply_net_knowledge(path, decision)
            label = decision.label
            # Decision.folder already routes uncertain files to _Review.
            folder = decision.folder
            target_dir = dest_root / folder
            target = self._unique_target(target_dir, path, used)
            action = "skip" if decision.review and not self.config.move else "move"
            items.append(PlanItem(source=path, decision=decision, target=target, action=action))
            self.progress(f"{path.name} -> {decision.title} ({decision.confidence:.0%})")
        return items

    def _apply_net_knowledge(self, path: Path, decision: Decision) -> None:
        """Optional hash lookup. Adds identity, never overrides local evidence."""
        if not self.net or not path.is_file():
            return
        try:
            info = self.net.identify(path)
        except Exception:
            return
        if not info:
            return
        decision.extras["online_identity"] = info
        remote_label = info.get("label")
        if remote_label:
            decision.extras["online_label"] = remote_label
            decision.reason += (f" | online: {info.get('source')} says {info.get('project') or remote_label}")
            if info.get("source") == "modrinth" and remote_label in LABEL_TITLES:
                # Hash is exact identity: it may override local scoring.
                decision.label = remote_label
                if info.get("project"):
                    decision.confidence = max(decision.confidence, 0.97)

    def _unique_target(self, target_dir: Path, source: Path, used: Dict[str, set]) -> Path:
        key = str(target_dir).lower()
        used.setdefault(key, set())
        candidate = target_dir / source.name
        stem, suffix = candidate.stem, candidate.suffix
        n = 2
        while str(candidate).lower() in used[key] or (candidate.exists() and candidate != source):
            candidate = target_dir / f"{stem} ({n}){suffix}"
            n += 1
        used[key].add(str(candidate).lower())
        return candidate

    # -- applying ---------------------------------------------------------
    def apply(self, items: Sequence[PlanItem], copy: bool = False,
              dry_run: Optional[bool] = None) -> SortResult:
        dry_run = self.config.dry_run if dry_run is None else dry_run
        result = SortResult()
        result.planned = list(items)
        undo: List[Dict[str, str]] = []
        for item in items:
            if item.action == "skip":
                result.skipped += 1
                continue
            if dry_run:
                continue
            try:
                item.target.parent.mkdir(parents=True, exist_ok=True)
                if copy:
                    if item.source.is_dir():
                        shutil.copytree(item.source, item.target)
                    else:
                        shutil.copy2(item.source, item.target)
                    result.copied += 1
                    undo.append({"action": "copy", "target": str(item.target)})
                else:
                    shutil.move(str(item.source), str(item.target))
                    result.moved += 1
                    undo.append({"from": str(item.source), "to": str(item.target), "label": item.label})
            except Exception as exc:
                result.failed.append((item.source, str(exc)))
        result.elapsed = time.time() - result.started
        if not dry_run and undo:
            self._write_undo(self._undo_root(items), undo)
        return result

    def _undo_root(self, items: Sequence[PlanItem]) -> Optional[Path]:
        if self.dest_root is not None:
            return self.dest_root
        return item_target_root(items)

    def _write_undo(self, root: Optional[Path], entries: List[Dict[str, str]]) -> None:
        if root is None:
            return
        try:
            path = root / UNDO_FILENAME
            payload = {"created": time.time(), "entries": entries}
            path.write_text(json.dumps(payload, indent=1), "utf-8")
        except Exception:
            pass

    def undo(self, root: Path) -> int:
        path = Path(root) / UNDO_FILENAME
        if not path.is_file():
            return 0
        try:
            data = json.loads(path.read_text("utf-8"))
        except Exception:
            return 0
        count = 0
        for entry in reversed(data.get("entries", [])):
            if "from" not in entry:
                continue
            src, dst = Path(entry["to"]), Path(entry["from"])
            try:
                if src.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dst))
                    count += 1
            except Exception:
                continue
        if count:
            path.unlink(missing_ok=True)
        return count

    # -- reporting --------------------------------------------------------
    def write_reports(self, items: Sequence[PlanItem], dest_root: Path,
                      report_stem: str = "filesorter-report") -> Dict[str, Path]:
        dest_root = Path(dest_root)
        dest_root.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "engine_version": "2.0.0",
            "count": len(items),
            "items": [i.decision.to_dict() | {"target": str(i.target), "action": i.action} for i in items],
        }
        json_path = dest_root / f"{report_stem}.json"
        json_path.write_text(json.dumps(payload, indent=1, ensure_ascii=False), "utf-8")

        csv_path = dest_root / f"{report_stem}.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["file", "label", "title", "confidence", "review", "target", "reason"])
            for item in items:
                d = item.decision
                writer.writerow([item.source.name, d.label, d.title, f"{d.confidence:.2f}",
                                 "yes" if d.review else "no", str(item.target), d.reason])

        md_path = dest_root / f"{report_stem}.md"
        counts: Dict[str, int] = {}
        for item in items:
            counts[item.decision.title] = counts.get(item.decision.title, 0) + 1
        lines = ["# FileSorter report", "", f"Generated {payload['generated']} — {len(items)} items", "",
                 "| category | count |", "| --- | --- |"]
        for title, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {title} | {count} |")
        review = [i for i in items if i.decision.review]
        if review:
            lines += ["", f"## Needs review ({len(review)})", ""]
            for item in review[:200]:
                lines.append(f"- `{item.source.name}` — {item.decision.reason}")
        md_path.write_text("\n".join(lines), "utf-8")
        return {"json": json_path, "csv": csv_path, "md": md_path}


def item_target_root(items: Sequence[PlanItem]) -> Optional[Path]:
    """Fallback: the nearest existing ancestor of the first planned target."""
    if not items:
        return None
    parent = items[0].target.parent
    while parent != parent.parent:
        if parent.exists():
            return parent
        parent = parent.parent
    return None
