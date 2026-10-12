#!/usr/bin/env python3
"""Benchmark: measure accuracy instead of estimating it.

Two corpora are supported, and they can be combined:

1. **Synthetic** (default) — built by ``fixtures_builder.py``. Fast, reproducible,
   covers the exact layouts that used to fail.
2. **Real** — your own files. Drop archives into::

       corpus/<label>/<any-file>

   e.g. ``corpus/mc.shaderpack/BSL_v8.2.zip``. Folder names *are* the ground
   truth (any label from ``fsengine.model.TAXONOMY``, or ``misc.review`` /
   ``mc.review`` to mean "must be flagged").

Output: overall accuracy, per-label precision/recall/F1, a confusion matrix, and
the list of misclassified files with their reasoning — so every rule change can
be judged by numbers.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fsengine.classify import Classifier  # noqa: E402
from fsengine.model import Config, TAXONOMY  # noqa: E402
from fixtures_builder import build_all  # noqa: E402


def expected_matches(want: str, got_label: str, review: bool) -> bool:
    if want.endswith(".review"):
        return review
    return want == got_label


def collect_corpus(root: Path, build_if_missing: bool = True) -> List[Tuple[Path, str]]:
    rows: List[Tuple[Path, str]] = []
    if build_if_missing and not (root / "expectations.json").exists():
        build_all(root)
    exp_file = root / "expectations.json"
    if exp_file.exists():
        for row in json.loads(exp_file.read_text("utf-8")):
            rows.append((root / row["file"], row["label"]))
    for label_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        label = label_dir.name
        if label not in TAXONOMY and not label.endswith(".review"):
            continue
        for path in sorted(label_dir.rglob("*")):
            if path.is_file() and not path.name.startswith("."):
                rows.append((path, label))
    return rows


def run_benchmark(rows: List[Tuple[Path, str]], config: Config, verbose: bool = True) -> Dict:
    classifier = Classifier(config)
    results: List[Dict] = []
    per_label = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    confusion = Counter()
    t0 = time.time()
    for path, want in rows:
        decision = classifier.classify(path)
        ok = expected_matches(want, decision.label, decision.review)
        confusion[(want, decision.label)] += 1
        bucket = per_label[want]
        if ok:
            bucket["tp"] += 1
        else:
            bucket["fn"] += 1
            per_label[decision.label]["fp"] += 1
        results.append({
            "file": str(path.relative_to(path.parents[len(path.parts) - 2]) if False else path),
            "name": path.name,
            "want": want,
            "got": decision.label,
            "confidence": round(decision.confidence, 3),
            "review": decision.review,
            "ok": ok,
            "reason": decision.reason,
            "scores": [(c.label, round(c.score, 2)) for c in decision.candidates[:3]],
        })
    elapsed = time.time() - t0
    correct = sum(1 for r in results if r["ok"])
    total = len(results) or 1
    report = {
        "total": len(results),
        "correct": correct,
        "accuracy": correct / total,
        "elapsed_s": round(elapsed, 2),
        "per_label": {},
        "confusion": [{"want": w, "got": g, "count": c} for (w, g), c in confusion.most_common()],
        "failures": [r for r in results if not r["ok"]],
        "results": results,
    }
    for label, b in sorted(per_label.items()):
        tp, fp, fn = b["tp"], b["fp"], b["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        report["per_label"][label] = {
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "support": tp + fn,
        }
    if verbose:
        print(f"analysed {report['total']} files in {report['elapsed_s']}s")
        print(f"accuracy: {correct}/{report['total']} = {report['accuracy']:.1%}")
        print()
        print(f"{'label':<20} {'prec':>6} {'recall':>6} {'f1':>6} {'n':>4}")
        for label, m in sorted(report["per_label"].items(), key=lambda kv: -kv[1]["support"]):
            if m["support"] == 0 and m["precision"] == 1.0:
                continue
            print(f"{label:<20} {m['precision']:>6.2f} {m['recall']:>6.2f} {m['f1']:>6.2f} {m['support']:>4}")
        if report["failures"]:
            print()
            print(f"--- {len(report['failures'])} failure(s) ---")
            for row in report["failures"]:
                print(f"  {row['name']}: want {row['want']}, got {row['got']} "
                      f"({row['confidence']:.0%}, review={row['review']})")
                print(f"      scores: {row['scores']}")
                print(f"      reason: {row['reason'][:160]}")
        else:
            print("\nno failures")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="FileSorter accuracy benchmark")
    parser.add_argument("--fixtures", default="fixtures", help="synthetic corpus dir")
    parser.add_argument("--holdout", default="fixtures_holdout",
                        help="independent holdout dir (cases written after tuning)")
    parser.add_argument("--real", default="corpus", help="your labelled corpus dir")
    parser.add_argument("--synthetic", action="store_true", help="synthetic corpus only")
    parser.add_argument("--deep", action="store_true", help="run every stage (no early stop)")
    parser.add_argument("--json", metavar="PATH", help="write the full report as JSON")
    parser.add_argument("--time-budget", type=float, default=4.0)
    args = parser.parse_args(argv)

    config = Config(deep=args.deep, time_budget_s=args.time_budget)
    rows: List[Tuple[Path, str]] = []

    # Synthetic corpus (built on demand — it is fast and deterministic).
    fixtures = Path(args.fixtures)
    if not (fixtures / "expectations.json").exists():
        build_all(fixtures)
    rows += collect_corpus(fixtures, build_if_missing=False)

    # Independent holdout corpus (cases written after tuning).
    holdout = Path(args.holdout)
    if not (holdout / "expectations.json").exists():
        from fixtures_holdout import build_holdout
        build_holdout(holdout)
    holdout_rows = collect_corpus(holdout, build_if_missing=False)
    if holdout_rows:
        print(f"including {len(holdout_rows)} holdout file(s) from {holdout}")
        rows += holdout_rows

    # Your own files: corpus/<label>/...
    real = Path(args.real)
    if not args.synthetic and real.exists():
        real_rows = collect_corpus(real, build_if_missing=False)
        if real_rows:
            print(f"including {len(real_rows)} file(s) from {real}")
            rows += real_rows
    print()

    if not rows:
        print("nothing to benchmark", file=sys.stderr)
        return 1
    report = run_benchmark(rows, config)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1), "utf-8")
        print(f"\nreport written to {args.json}")
    return 0 if report["accuracy"] >= 0.9 else 2


if __name__ == "__main__":
    raise SystemExit(main())
