"""The classifier: iterative deepening over the detector ladder.

Stage ladder (each stage only runs if the previous one did not settle it):

    0  name / extension          - free
    1  magic bytes, PE metadata  - one small read
    2  archive listing structure - the central directory (cheap, huge value)
    3  descriptor files          - a handful of small reads
    4  content grep, secrets     - bounded member scan
    5  bytecode / binary strings - bounded deep scan
    6  nested archives           - recursion, bounded

This is where "read as deep as necessary, but no deeper" lives.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .budget import Budget
from .context import AnalysisContext, make_context
from .facts import Facts, build_facts
from .fusion import build_candidates, fuse
from .model import Config, Decision, Evidence


class Classifier:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    # -- public API -------------------------------------------------------
    def classify(self, path: Path, budget: Optional[Budget] = None) -> Decision:
        path = Path(path)
        budget = budget or Budget(
            time_budget_s=self.config.time_budget_s,
            max_entries=self.config.max_entries,
            max_read_bytes=self.config.max_read_bytes,
            max_total_read_bytes=self.config.max_total_read_bytes,
            max_scan_members=self.config.max_scan_members,
            max_nested_depth=self.config.max_nested_depth,
            max_nested_bytes=self.config.max_nested_bytes,
        )
        ctx = make_context(path, self.config, budget, nested_depth=0)
        ctx.child_analyzer = self._child_analyzer
        return self._run(ctx, discount=1.0)

    def classify_bytes(self, data: bytes, name: str, budget: Budget, depth: int, discount: float = 0.55) -> Decision:
        """Classify an in-memory archive (used for nested members)."""
        from .listing import Container

        path = Path(name)
        ctx = AnalysisContext(path=path, config=self.config, budget=budget, nested_depth=depth)
        container = Container(data=data, budget=budget, display_name=name)
        ctx.container = container
        ctx.magic = container.magic
        if container.kind in ("zip", "tar"):
            ctx.listing = container.listing
        ctx.parent = None
        ctx.child_analyzer = self._child_analyzer
        return self._run(ctx, discount=discount)

    def explain(self, path: Path) -> List[str]:
        decision = self.classify(path)
        lines = decision.explain()
        if decision.facts:
            lines.append("  -- facts --")
            lines.extend("  " + line for line in decision.facts.summary_lines())
        return lines

    # -- internals --------------------------------------------------------
    def _child_analyzer(self, data: bytes, name: str, discount: float) -> Optional[Decision]:
        parent = getattr(self, "_current_ctx", None)
        depth = (parent.nested_depth + 1) if parent is not None else 1
        budget = parent.budget if parent is not None else self._budget()
        if depth > self.config.max_nested_depth:
            return None
        return self.classify_bytes(data, name, budget, depth=depth, discount=discount)

    def _budget(self) -> Budget:
        return Budget(
            time_budget_s=self.config.time_budget_s,
            max_entries=self.config.max_entries,
            max_read_bytes=self.config.max_read_bytes,
            max_total_read_bytes=self.config.max_total_read_bytes,
            max_scan_members=self.config.max_scan_members,
            max_nested_depth=self.config.max_nested_depth,
            max_nested_bytes=self.config.max_nested_bytes,
        )

    def _run(self, ctx: AnalysisContext, discount: float = 1.0) -> Decision:
        from .detectors import DETECTORS

        started = time.monotonic()
        self._current_ctx = ctx
        evidence: List[Evidence] = []
        stages_run: List[int] = []

        # Nothing to analyse: not even a container
        if ctx.kind not in ("zip", "tar", "dir", "zip-unreadable") and ctx.size == 0:
            ctx.warn(f"{ctx.name}: empty or unreadable file")
            decision = fuse(evidence, ctx, self.config)
            decision.facts = build_facts(ctx, decision, stages_run, time.monotonic() - started)
            self._close(ctx)
            return decision

        max_stage = self.config.max_stage
        ran: set = set()
        for stage in range(0, max_stage + 1):
            if ctx.budget.exhausted():
                ctx.note("stages_skipped_budget", True)
                break
            stage_detectors = [d for d in DETECTORS if d.stage == stage]
            if not stage_detectors:
                continue
            produced = []
            for detector in stage_detectors:
                ran.add(detector.id)
                produced.extend(detector(ctx))
            if discount != 1.0:
                produced = [
                    Evidence(e.rule, e.label, round(e.weight * discount, 3), e.note, e.stage)
                    for e in produced
                ]
            evidence.extend(produced)
            stages_run.append(stage)
            if self.config.deep or stage >= max_stage:
                continue
            if self._settled(evidence, ctx):
                ctx.note("stopped_early_at_stage", stage)
                break

        # Safety detectors (credential scan, ...) run even when the identity was
        # already clear: a settled classification must never hide a leaked token.
        for detector in DETECTORS:
            if detector.always and detector.id not in ran and detector.stage <= max_stage:
                evidence.extend(detector(ctx))
                ran.add(detector.id)

        decision = fuse(evidence, ctx, self.config)
        decision.facts = build_facts(ctx, decision, stages_run, time.monotonic() - started)

        if decision.review and self.config.ai_assist and decision.facts is not None:
            self._maybe_ai_second_opinion(decision)

        self._close(ctx)
        return decision

    def _settled(self, evidence: Sequence[Evidence], ctx: AnalysisContext) -> bool:
        """Stop deepening when the identity is already unambiguous.

        Important: a name or extension alone never settles anything. The old
        engine's core failure was trusting the cheapest signal first, so a
        ``.png`` that is actually text got filed as an image. We require at
        least one *substantive* observation (magic bytes or deeper) before the
        ladder is allowed to stop.
        """
        candidates = build_candidates(evidence)
        if not candidates:
            return False
        top = candidates[0]
        second = candidates[1] if len(candidates) > 1 else None
        if any(e.rule.startswith("user:correction") for e in top.evidence):
            return True  # the user already told us what this is
        margin = top.score - (second.score if second else 0.0)
        # "Substantive" means: one really strong observation, or medium-strength
        # observations from two different stages. Counting .py files and finding
        # a requirements.txt are both medium-strength — a project that *looks*
        # like a generic Python repo at stage 2 may still turn out to be a
        # telegram bot at stage 3, so those must not stop the ladder.
        # Evidence from stage 0 (name/extension) never counts as substantive:
        # it is exactly what the extension-lie problem exploits.
        strong_hit = any(e.stage >= 1 and e.weight >= 4.5 for e in top.evidence)
        medium_stages = {e.stage for e in top.evidence if e.stage >= 1 and e.weight >= 3.0}
        if not strong_hit and len(medium_stages) < 2:
            return False
        if top.score >= self.config.strong_score and margin >= self.config.min_margin:
            # Descriptor-level evidence is decisive; don't burn the budget.
            return True
        if top.score >= self.config.strong_score * 1.6 and margin >= 2.0:
            return True
        return False

    def _maybe_ai_second_opinion(self, decision: Decision) -> None:
        """Optional: ask a model for a second opinion on *ambiguous* files only.

        Off by default. Only names, structure and detector output are sent —
        never file contents — and only when the local engine is unsure.
        """
        try:
            from .ai_assist import request_second_opinion

            suggestion = request_second_opinion(decision, self.config)
        except Exception as exc:  # pragma: no cover - optional path
            decision.extras.setdefault("ai_error", str(exc))
            return
        if not suggestion:
            return
        decision.extras["ai_suggestion"] = suggestion
        label = suggestion.get("label")
        if label:
            decision.extras["ai_label"] = label

    @staticmethod
    def _close(ctx: AnalysisContext) -> None:
        if ctx.container is not None:
            ctx.container.close()
