"""Facts: the (privacy-safe) summary of what the engine actually observed."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .context import AnalysisContext
from .listing import Listing
from .model import Decision


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


@dataclass
class Facts:
    path: Path
    name: str
    base_name: str
    size: int
    kind: str
    magic: str
    modifiers: List[str] = field(default_factory=list)
    file_count: int = 0
    dir_count: int = 0
    extensions: Dict[str, int] = field(default_factory=dict)
    top_level: List[str] = field(default_factory=list)
    wrapper: str = ""
    truncated: bool = False
    extras: Dict[str, Any] = field(default_factory=dict)
    stages_run: List[int] = field(default_factory=list)
    evidence_count: int = 0
    warnings: List[str] = field(default_factory=list)
    nested: List[Dict[str, Any]] = field(default_factory=list)
    elapsed_s: float = 0.0

    # -- reporting --------------------------------------------------------
    def summary_lines(self) -> List[str]:
        lines = [
            f"file        : {self.name}",
            f"path        : {self.path}",
            f"size        : {self.size / 1024:.1f} KiB",
            f"container   : {self.kind} ({self.magic})",
        ]
        if self.modifiers:
            lines.append(f"name mods   : {', '.join(self.modifiers)}")
        if self.file_count:
            lines.append(f"contents    : {self.file_count} files, {self.dir_count} dirs"
                         + (f", wrapper {self.wrapper}/" if self.wrapper else "")
                         + (" [listing truncated]" if self.truncated else ""))
            top_ext = ", ".join(f"{k or 'none'}={v}" for k, v in list(self.extensions.items())[:8])
            lines.append(f"extensions  : {top_ext}")
            roots = ", ".join(self.top_level[:8])
            if roots:
                lines.append(f"top-level   : {roots}")
        for key in ("product_name", "company", "pe_markers", "plugin_name", "mod_id",
                    "package_json_name", "python_dependencies", "bytecode_markers",
                    "text_signatures", "pack_format", "nested_identities", "credential_findings"):
            if key in self.extras:
                lines.append(f"{key:<12}: {self.extras[key]}")
        if self.nested:
            for n in self.nested:
                lines.append(f"nested      : {n.get('name')} -> {n.get('label')} ({n.get('confidence')})")
        if self.warnings:
            lines.append(f"warnings    : {'; '.join(self.warnings)}")
        return lines

    def ai_payload(self, decision: Optional[Decision] = None) -> Dict[str, Any]:
        """Everything an optional AI helper would see. No file contents leak,
        only names/структура and detector output."""
        payload: Dict[str, Any] = {
            "name": self.name,
            "container": self.kind,
            "magic": self.magic,
            "size": self.size,
            "file_count": self.file_count,
            "extensions": dict(list(self.extensions.items())[:15]),
            "top_level": self.top_level[:15],
            "wrapper": self.wrapper,
            "facts": {k: _jsonable(v) for k, v in self.extras.items()
                      if k not in ("findings",) and not k.startswith("raw")},
            "warnings": self.warnings[:5],
        }
        if decision is not None:
            payload["engine_candidates"] = [
                {"label": c.label, "score": round(c.score, 2)} for c in decision.candidates[:4]
            ]
        return payload


def build_facts(ctx: AnalysisContext, decision: Decision, stages: List[int], elapsed: float) -> Facts:
    listing: Optional[Listing] = ctx.listing
    facts = Facts(
        path=ctx.path,
        name=ctx.name,
        base_name=ctx.base_name,
        size=ctx.size,
        kind=ctx.kind,
        magic=ctx.magic.describe(),
        modifiers=ctx.modifiers,
        file_count=len(listing.files) if listing else 0,
        dir_count=len(listing.dirs) if listing else 0,
        extensions=dict((listing.ext_counts.most_common(10) if listing else {})),
        top_level=(listing.top_roots()[:15] if listing else []),
        wrapper=(listing.wrapper if listing else ""),
        truncated=bool(listing.truncated) if listing else False,
        extras=ctx.extras,
        stages_run=stages,
        evidence_count=sum(len(c.evidence) for c in decision.candidates),
        warnings=list(ctx.warnings),
        nested=[
            {"name": n.path.name, "label": n.label, "confidence": round(n.confidence, 2)}
            for n in ctx.nested_results
        ],
        elapsed_s=round(elapsed, 3),
    )
    return facts
