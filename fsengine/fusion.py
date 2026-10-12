"""Evidence fusion: many weak signals -> one ranked, explainable decision.

Rules are *scored*, never first-match-wins. Conflicts get explicit resolution
policies (shaderpack vs resource pack, plugin vs mod, pack vs modpack), and when
the evidence genuinely does not separate two hypotheses, the file goes to
``_Review`` with both candidates listed instead of being filed wrongly.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from .context import AnalysisContext
from .model import Candidate, Config, Decision, Evidence, family_of, LABEL_TITLES

# Mutually exclusive pairs with a resolution policy.
EXCLUSIVE_PAIRS: List[Tuple[str, str, str]] = [
    ("mc.shaderpack", "mc.resourcepack", "shader-vs-resourcepack"),
    ("mc.plugin", "mc.mod", "plugin-vs-mod"),
    ("mc.datapack", "mc.resourcepack", "datapack-vs-resourcepack"),
    ("mc.modpack", "mc.mod", "pack-vs-single-mod"),
    ("dev.discordbot", "dev.node", "bot-vs-generic-node"),
    ("dev.vscodeext", "dev.node", "vscode-vs-generic-node"),
    ("dev.obsidianplugin", "dev.node", "obsidian-vs-generic-node"),
    ("dev.telegrambot", "dev.python", "telegram-vs-generic-python"),
    ("dev.discordbot", "dev.python", "discord-vs-generic-python"),
]


def build_candidates(evidence: Sequence[Evidence]) -> List[Candidate]:
    scores: Dict[str, float] = defaultdict(float)
    bucket: Dict[str, List[Evidence]] = defaultdict(list)
    for ev in evidence:
        if ev.label in ("misc.other",) and ev.weight == 0:
            continue  # informational evidence only
        scores[ev.label] += ev.weight
        bucket[ev.label].append(ev)
    candidates = [
        Candidate(label=label, score=round(score, 3), evidence=bucket[label])
        for label, score in scores.items()
        if score > 0.01
    ]
    candidates.sort(key=lambda c: (-c.score, c.label))
    return candidates


def _distinct_stages(candidate: Candidate) -> int:
    return len({e.stage for e in candidate.evidence})


def _has_rule(candidate: Optional[Candidate], prefix: str) -> bool:
    if candidate is None:
        return False
    return any(e.rule.startswith(prefix) for e in candidate.evidence)


IDENTITY_RULES = (
    "text:", "pkg:", "py:", "descriptor:", "manifest:", "bytecode:", "maven:", "gradle:",
    "cargo", "go.mod", "csproj", "wp:header", "bedrock:manifest", "guard:", "nested:file",
)


def _identity_evidence(candidate: Optional[Candidate]) -> float:
    """Strongest evidence that *names* what the thing is (not just its shape)."""
    if candidate is None:
        return 0.0
    return max([e.weight for e in candidate.evidence if e.rule.startswith(IDENTITY_RULES)], default=0.0)


def _rule_weight(candidate: Optional[Candidate], prefix: str) -> float:
    if candidate is None:
        return 0.0
    return sum(e.weight for e in candidate.evidence if e.rule.startswith(prefix))


def resolve_conflicts(
    candidates: List[Candidate], ctx: AnalysisContext
) -> Tuple[Optional[Candidate], List[str]]:
    """Apply exclusive-pair policies; returns (winner-or-None, notes)."""
    notes: List[str] = []
    by_label = {c.label: c for c in candidates}
    top = candidates[0] if candidates else None

    def prefer(winner: str, loser: str, note: str) -> Optional[Candidate]:
        w, l = by_label.get(winner), by_label.get(loser)
        if w is not None and l is not None:
            if l in candidates:
                candidates.remove(l)
            by_label.pop(loser, None)
            notes.append(note)
            return w
        return w

    # --- shaderpack vs resource pack -------------------------------------
    shader, pack = by_label.get("mc.shaderpack"), by_label.get("mc.resourcepack")
    if shader and pack:
        shader_proof = _rule_weight(shader, "path:shaders/shaders.properties") + _rule_weight(shader, "stats:glsl")
        core_shaders = _rule_weight(pack, "guard:core-shaders")
        pack_paths = _distinct_stages(pack)
        if _has_rule(pack, "descriptor:pack.mcmeta") and _has_rule(shader, "stats:glsl") and not _has_rule(shader, "path:shaders/shaders.properties"):
            # hybrid: a resource pack that also ships GLSL (core shaders)
            notes.append("hybrid: resource pack containing core shaders")
        if _rule_weight(shader, "path:shaders/shaders.properties") > 0 or _rule_weight(shader, "path:shaders/*.fsh") > 0:
            prefer("mc.shaderpack", "mc.resourcepack", "shaders/ tree with OptiFine/Iris descriptors -> shaderpack")
        elif core_shaders > 0 or _rule_weight(pack, "path:assets/minecraft/textures") > 0:
            prefer("mc.resourcepack", "mc.shaderpack", "vanilla asset tree (core shaders) -> resource pack")
        elif shader.score > pack.score:
            prefer("mc.shaderpack", "mc.resourcepack", "shader evidence stronger than pack evidence")
        else:
            prefer("mc.resourcepack", "mc.shaderpack", "asset evidence stronger than shader evidence")

    # --- datapack vs resource pack ---------------------------------------
    dp, rp = by_label.get("mc.datapack"), by_label.get("mc.resourcepack")
    if dp and rp:
        has_assets = any(_rule_weight(rp, p) > 0 for p in ("path:assets/minecraft/textures", "path:assets/*/textures"))
        has_data = any(_rule_weight(dp, p) > 0 for p in ("path:data/minecraft/tags", "path:data/*/function/",
                                                          "path:data/*/functions/", "stats:mcfunction"))
        if has_assets and has_data:
            notes.append("hybrid: resource pack + data pack in one file")
            if rp.score >= dp.score:
                prefer("mc.resourcepack", "mc.datapack", "both trees present; resource pack stronger")
            else:
                prefer("mc.datapack", "mc.resourcepack", "both trees present; data pack stronger")
        elif has_data:
            prefer("mc.datapack", "mc.resourcepack", "data/ tree -> data pack")
        else:
            prefer("mc.resourcepack", "mc.datapack", "assets/ tree -> resource pack")

    # --- plugin vs mod ----------------------------------------------------
    plugin, mod = by_label.get("mc.plugin"), by_label.get("mc.mod")
    if plugin and mod:
        plugin_desc = sum(_rule_weight(plugin, p) for p in
                          ("descriptor:plugin.yml", "descriptor:velocity-plugin.json", "gradle:paper",
                           "gradle:spigot", "maven:spigot", "maven:paper", "gradle:velocity"))
        mod_desc = sum(_rule_weight(mod, p) for p in
                       ("descriptor:fabric.mod.json", "descriptor:mods.toml", "descriptor:mcmod.info",
                        "gradle:fabric", "gradle:forge", "gradle:neoforge", "maven:forge", "maven:neoforge"))
        if plugin_desc and not mod_desc:
            prefer("mc.plugin", "mc.mod", "server plugin descriptor/build; no mod loader evidence")
        elif mod_desc and not plugin_desc:
            prefer("mc.mod", "mc.plugin", "mod loader descriptor/build; no server plugin evidence")
        elif plugin_desc and mod_desc:
            notes.append("conflict: both plugin and mod descriptors present")
        elif plugin.score >= mod.score * 1.15:
            prefer("mc.plugin", "mc.mod", "server-side API evidence dominates")
        elif mod.score >= plugin.score * 1.15:
            prefer("mc.mod", "mc.plugin", "mod loader evidence dominates")
        else:
            notes.append("conflict: plugin and mod evidence are near-equal")

    # --- server bundle vs bare world --------------------------------------
    server, world = by_label.get("mc.server"), by_label.get("mc.world")
    if server and world:
        server_config = (_rule_weight(server, "path:server.properties") + _rule_weight(server, "path:eula.txt")
                         + _rule_weight(server, "path:spigot.yml") + _rule_weight(server, "path:bukkit.yml")
                         + _rule_weight(server, "path:paper-global.yml") + _rule_weight(server, "descriptor"))
        if server_config > 0 and _rule_weight(server, "path:server.properties") > 0:
            prefer("mc.server", "mc.world",
                   "server config files present alongside a world — deployable server bundle")
        elif world.score > server.score:
            prefer("mc.world", "mc.server", "world data with no server configuration")

    # --- modpack vs single mod -------------------------------------------
    packm, single = by_label.get("mc.modpack"), by_label.get("mc.mod")
    if packm and single:
        if _has_rule(packm, "descriptor") or _has_rule(packm, "nested:mods-folder") or _rule_weight(packm, "path:overrides/") > 0:
            prefer("mc.modpack", "mc.mod", "modpack container (manifest/overrides/mods folder)")
        elif packm.score >= single.score * 1.3:
            prefer("mc.modpack", "mc.mod", "multi-mod bundle")

    # --- specific identities beat generic language/framework labels --------
    # A *framework* signature names what the thing IS ("discord.py dependency",
    # "vscode engine"). A *language* signal only says what it is written IN
    # ("14 python files"). The first must win even when the second scores higher.
    specific = {
        "dev.discordbot": ("dev.node", "dev.python", "dev.other"),
        "dev.telegrambot": ("dev.python", "dev.node", "dev.other"),
        "dev.vscodeext": ("dev.node", "dev.other"),
        "dev.obsidianplugin": ("dev.node", "dev.other"),
        "dev.gamebot": ("dev.node", "dev.python", "dev.other"),
        "dev.browserext": ("dev.web", "dev.node", "dev.other"),
        "dev.wordpressplugin": ("dev.web", "dev.other"),
        "mc.plugin": ("dev.java", "dev.other", "sw.library"),
        "mc.mod": ("dev.java", "dev.other", "sw.library"),
        "mc.modpack": ("dev.java", "dev.other", "sw.library", "misc.collection"),
    }
    framework_rules = ("text:", "pkg:", "py:", "descriptor:", "manifest:", "bytecode:", "maven:",
                       "gradle:", "cargo", "go.mod", "csproj", "wp:header", "bedrock:manifest")
    language_rules = ("ext:", "stats:", "lang:", "path:*.py", "path:*.js", "path:*.cs", "path:*.sh",
                      "path:*.bat", "path:*.cmd", "path:*.ps1", "path:src/main/java/", "scripts:")
    for winner, losers in specific.items():
        if winner not in by_label:
            continue
        w = by_label[winner]
        has_framework_name = any(
            e.rule.startswith(framework_rules) and e.weight >= 3.5 for e in w.evidence
        )
        for loser in losers:
            if loser not in by_label:
                continue
            l = by_label[loser]
            generic_only = all(
                e.rule.startswith(language_rules) or e.weight <= 2.0 for e in l.evidence
            )
            if has_framework_name and generic_only:
                prefer(winner, loser,
                       f"{winner} is a named framework identity ({w.score:.1f}) while {loser} "
                       f"only reflects the language/extension mix")
            elif _identity_evidence(w) >= 3.5 and _identity_evidence(l) < 3.5:
                # The winner's evidence *names* the thing; the loser's evidence
                # only describes its shape. Identity wins over shape.
                prefer(winner, loser,
                       f"{winner} carries identity evidence ({_identity_evidence(w):.1f}) while "
                       f"{loser} only describes the project shape")
            elif w.score >= l.score * 0.9:
                prefer(winner, loser, f"{winner} is the specific identity of this project")

    return by_label.get(candidates[0].label) if candidates else None, notes


def detect_collection(candidates: List[Candidate], config: Config) -> Optional[Candidate]:
    """A bundle of unrelated things (a mixed drive dump) -> Collections."""
    strong = [c for c in candidates if c.score >= 5.0 and c.label != "misc.collection"]
    if len(strong) < 2:
        return None
    families = {family_of(c.label) for c in strong}
    if len(families) < 2:
        return None
    top = strong[0]
    second = strong[1]
    if second.score >= top.score * 0.6:
        return Candidate("misc.collection", top.score, [])
    return None


def fuse(
    evidence: Sequence[Evidence],
    ctx: AnalysisContext,
    config: Config,
) -> Decision:
    candidates = build_candidates(evidence)
    notes: List[str] = []

    # A homogeneous archive (all images / all video) is a *collection of one
    # kind*: it should live in that kind's folder, not in Archives.
    if candidates:
        collection_override = detect_collection(candidates, config)
        if collection_override:
            candidates.append(collection_override)
            candidates.sort(key=lambda c: (-c.score, c.label))
            notes.append("mixed unrelated content -> Collections")

    winner, conflict_notes = resolve_conflicts(candidates, ctx)
    notes.extend(conflict_notes)
    if not candidates:
        return Decision(
            path=ctx.path,
            label="misc.review",
            confidence=0.0,
            margin=0.0,
            candidates=[],
            facts=None,
            review=True,
            reason="no evidence produced any hypothesis",
            extras=dict(ctx.extras),
        )

    top = candidates[0]
    second = candidates[1] if len(candidates) > 1 else None
    margin = top.score - (second.score if second else 0.0)

    coverage = min(1.0, top.score / max(0.001, config.strong_score))
    decisiveness = min(1.0, margin / max(1.0, 0.5 * top.score))
    confidence = 0.30 + 0.50 * coverage + 0.18 * decisiveness
    confidence = max(0.05, min(0.98, confidence))

    review = False
    reasons: List[str] = []
    if top.score < config.min_score:
        review = True
        reasons.append(f"best score {top.score:.1f} below the minimum ({config.min_score})")
    elif margin < config.min_margin * 0.5:
        review = True
        reasons.append(f"two hypotheses are nearly tied ({top.label} {top.score:.1f} vs "
                       f"{second.label if second else '?'} {second.score if second else 0:.1f})")
    elif top.score < config.strong_score and margin < config.min_margin:
        review = True
        reasons.append("strong evidence missing and no clear margin")
    if ctx.extras.get("unreadable_container") and top.score < config.strong_score:
        review = True
        reasons.append(f"container ({ctx.extras['unreadable_container']}) cannot be inspected")
    if ctx.extras.get("credential_findings"):
        notes.append("contains possible credentials — handle with care")

    label = top.label if not review else (top.label if top.score >= config.min_score else "misc.review")
    if review and top.score >= config.min_score:
        label = top.label  # keep the best guess but flag it

    # The winner being "needs review" is itself a verdict: never file it silently.
    if label == "misc.review":
        review = True
        if not reasons:
            reasons.append("engine selected the review bucket")
    # A *structural* mix of unrelated content is certain, not uncertain.
    if label == "misc.collection" and _has_rule(top, "mix:unrelated"):
        review = False
        reasons = [r for r in reasons if "nearly tied" not in r and "no clear margin" not in r]

    reason = "; ".join(reasons) if reasons else f"score {top.score:.1f}, margin {margin:.1f}"
    if notes:
        reason += " | " + "; ".join(notes)

    return Decision(
        path=ctx.path,
        label=label,
        confidence=confidence,
        margin=margin,
        candidates=candidates,
        review=review,
        reason=reason,
        extras=dict(ctx.extras),
    )


def review_decision(ctx: AnalysisContext, reason: str) -> Decision:
    return Decision(
        path=ctx.path,
        label="misc.review",
        confidence=0.0,
        margin=0.0,
        candidates=[],
        review=True,
        reason=reason,
        extras=dict(ctx.extras),
    )
