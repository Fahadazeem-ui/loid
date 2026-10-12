#!/usr/bin/env python3
"""FileSorter 2.0 — evidence-based, deep-reading file & archive organiser.

Examples
--------
    python file_sorter.py                      # analyse the current folder (dry run)
    python file_sorter.py D:\\Downloads --apply  # actually organise
    python file_sorter.py D:\\Downloads --deep   # ignore the early-stop, read everything
    python file_sorter.py some.zip --explain     # show the full evidence chain
    python file_sorter.py D:\\Downloads --online --ai   # both optional helpers on
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from fsengine.classify import Classifier
from fsengine.model import Config, TAXONOMY
from fsengine.netkb import NetKnowledge, merge_rule_pack
from fsengine.sorter import Sorter

VERSION = "2.0.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="file_sorter.py",
        description=f"FileSorter {VERSION} — scores evidence instead of guessing, reads archives "
                    f"as deeply as needed, and only says 'Archives' when the content really is unknown.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files/folders to organise")
    p.add_argument("--dest", "-d", help="destination root (default: the source folder)")
    p.add_argument("--apply", action="store_true", help="really move files (default is a dry run)")
    p.add_argument("--copy", action="store_true", help="copy instead of move")
    p.add_argument("--recursive", "-r", action="store_true", help="descend into subfolders")
    p.add_argument("--include", action="append", help="only these globs (repeatable)")
    p.add_argument("--exclude", action="append", help="skip these globs (repeatable)")
    p.add_argument("--deep", action="store_true", help="no early stop: run every stage")
    p.add_argument("--max-stage", type=int, default=6, help="cap the analysis ladder (0-6)")
    p.add_argument("--time-budget", type=float, default=4.0, help="seconds per file (default 4)")
    p.add_argument("--explain", action="store_true", help="print the evidence chain per file")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--report", metavar="DIR", help="write JSON/CSV/Markdown reports to DIR")
    p.add_argument("--no-review", action="store_true",
                   help="leave uncertain files where they are instead of moving them into _Review/")
    p.add_argument("--files-only", action="store_true", help="ignore folders, sort only files")
    p.add_argument("--ai", action="store_true", help="ask Claude for a second opinion on ambiguous files "
                                                    "(needs ANTHROPIC_API_KEY; names/structure only)")
    p.add_argument("--ai-model", default="claude-sonnet-4-5", help="model for --ai")
    p.add_argument("--online", action="store_true", help="enable hash-only lookups (Modrinth/Maven Central)")
    p.add_argument("--rules", action="append", help="extra signature pack (local JSON path or URL)")
    p.add_argument("--undo", metavar="DIR", help="undo the last run in DIR")
    p.add_argument("--teach", metavar="LABEL",
                   help="remember the given paths as LABEL (e.g. --teach mc.plugin MyPlugin.jar)")
    p.add_argument("--forget", metavar="PATTERN", help="remove a remembered correction")
    p.add_argument("--corrections", action="store_true", help="list remembered corrections")
    p.add_argument("--max-files", type=int, default=0, help="stop after N files (0 = no limit)")
    p.add_argument("--quiet", "-q", action="store_true", help="only print the summary")
    p.add_argument("--version", action="version", version=f"FileSorter {VERSION}")
    return p


def make_config(args) -> Config:
    return Config(
        output_root=Path(args.dest) if args.dest else None,
        max_stage=max(0, min(6, args.max_stage)),
        deep=args.deep,
        time_budget_s=args.time_budget,
        move=(not args.no_review),
        dry_run=(not args.apply),
        internet=args.online,
        ai_assist=args.ai,
        ai_model=args.ai_model,
        verbose=not args.quiet,
    )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    config = make_config(args)

    if args.undo:
        sorter = Sorter(config)
        count = sorter.undo(Path(args.undo))
        print(f"restored {count} file(s)")
        return 0

    if args.corrections or args.forget:
        from fsengine import corrections
        if args.forget:
            from fsengine.corrections import load, save
            remaining = [r for r in load(config) if r["pattern"].lower() != args.forget.lower()]
            path = corrections.save(config, "__tmp__", "misc.other")
            path.write_text(json.dumps({"corrections": remaining}, indent=1), "utf-8")
            print(f"forgot {args.forget} ({len(remaining)} correction(s) left)")
            return 0
        rows = corrections.load(config)
        if not rows:
            print("no corrections remembered yet")
        for row in rows:
            print(f"  {row['pattern']:<40} -> {row['label']}  {row.get('note', '')}")
        return 0

    if args.teach:
        from fsengine.corrections import save
        if args.teach not in TAXONOMY:
            print(f"! '{args.teach}' is not a known label. Pick one of:\n  "
                  + "\n  ".join(sorted(TAXONOMY)), file=sys.stderr)
            return 1
        if not args.paths:
            print("! give me a file (or folder) to remember", file=sys.stderr)
            return 1
        for raw in args.paths:
            pattern = Path(raw).name
            where = save(config, pattern, args.teach, note="taught by hand")
            print(f"remembered: {pattern} -> {args.teach}  ({where})")
        return 0

    if args.rules:
        net = NetKnowledge(config)
        for source in args.rules:
            pack = net.fetch_rule_pack(source if "://" in source else Path(source).as_uri())
            if not pack:
                print(f"! could not load rule pack: {source}", file=sys.stderr)
                continue
            counts = merge_rule_pack(pack)
            print(f"loaded rule pack {source}: {counts}")

    roots = [Path(p) for p in args.paths] or [Path(".")]
    dest_root = Path(args.dest) if args.dest else (roots[0] if roots[0].is_dir() else roots[0].parent)
    dest_root = dest_root.resolve()

    if not args.quiet:
        mode = "LIVE" if args.apply else "dry run"
        print(f"FileSorter {VERSION} — {mode}"
              + ("  [online hashes]" if config.internet else "")
              + ("  [claude assist]" if config.ai_assist else ""))
        print(f"source: {', '.join(str(r) for r in roots)}")
        print(f"dest  : {dest_root}")
        print("-" * 78)

    sorter = Sorter(config)
    paths = sorter.iter_paths(roots, recursive=args.recursive,
                              include=args.include, exclude=args.exclude)
    if args.files_only:
        paths = [p for p in paths if p.is_file()]
    if args.max_files:
        paths = paths[: args.max_files]
    if not paths:
        print("nothing to do")
        return 0

    items = sorter.plan(paths, dest_root=dest_root)

    if args.json:
        import json as _json
        print(_json.dumps([i.decision.to_dict() | {"target": str(i.target), "action": i.action}
                           for i in items], indent=1, ensure_ascii=False))
    elif not args.quiet:
        for item in items:
            d = item.decision
            flag = "rev" if d.review else " ok"
            conf = "--" if d.review and d.confidence < 0.2 else f"{d.confidence * 100:.0f}%"
            name = shorten(item.source.name, 46)
            print(f"  {flag} {name:<46} {d.title:<34} {conf:>4}  {TAXONOMY.get(d.label, '?')}")
            if args.explain:
                for line in d.explain(max_evidence=8)[1:]:
                    print(f"      {line.strip()}")

    result = sorter.apply(items, copy=args.copy)

    if args.report:
        report_dir = Path(args.report)
        written = sorter.write_reports(items, report_dir)
        if not args.quiet:
            print(f"reports: {', '.join(str(p) for p in written.values())}")

    counts = {}
    for item in items:
        counts[item.title] = counts.get(item.title, 0) + 1
    print("-" * 78)
    print(f"analysed {len(items)} item(s) in {time.time() - result.started:.1f}s"
          + (f", moved {result.moved}" if result.moved else "")
          + (f", copied {result.copied}" if result.copied else "")
          + (f", left for review {result.skipped}" if result.skipped else ""))
    for title, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"   {title:<36} {count}")
    if result.failed:
        print(f"! {len(result.failed)} file(s) failed:")
        for src, err in result.failed[:10]:
            print(f"   {src.name}: {err}")
    if not args.apply:
        print("dry run — nothing was moved. Re-run with --apply to organise.")
    return 0


def shorten(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def explain_path(path: str) -> None:
    classifier = Classifier(Config(deep=True))
    for line in classifier.explain(Path(path)):
        print(line)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--explain-file":
        explain_path(sys.argv[2])
        raise SystemExit(0)
    raise SystemExit(main())
