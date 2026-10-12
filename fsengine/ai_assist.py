"""Optional second opinion from Claude — for *ambiguous* files only.

Rules that make this safe to ship:

* **Off by default.** ``Config.ai_assist`` must be enabled explicitly.
* **Never uploads file contents.** Only the file name, container shape, the
  member-name sample and detector output leave the machine.
* **Only called when the local engine is unsure** (decision.review is True) and
  at most ``Config.ai_max_calls`` times per run.
* **Constrained output**: the model must answer with one of the engine's own
  labels, otherwise the answer is discarded.

The request uses the plain HTTP API through ``urllib`` so the engine keeps zero
third-party dependencies. Requires ``ANTHROPIC_API_KEY`` in the environment.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .model import Config, Decision, LABEL_TITLES

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-5"

_calls = {"n": 0}


def _allowed_labels() -> List[str]:
    return sorted(LABEL_TITLES.keys())


def build_prompt(decision: Decision) -> str:
    facts = decision.facts
    payload: Dict[str, Any] = {}
    if facts is not None:
        payload = facts.ai_payload(decision)
    labels = ", ".join(_allowed_labels())
    return (
        "You are a file-classification consultant. A local, offline engine has "
        "already analysed a file and is unsure about its identity. Decide which "
        "single label fits best.\n\n"
        f"Allowed labels (answer with exactly one): {labels}\n\n"
        "Rules:\n"
        "- Judge only from the structural facts provided; never guess wildly.\n"
        "- If the facts are genuinely insufficient, answer \"misc.review\".\n"
        "- A zip full of .java + build.gradle + src/main/resources/plugin.yml is "
        "mc.plugin, not dev.java.\n"
        "- A zip with shaders/*.fsh + shaders.properties is mc.shaderpack; "
        "assets/minecraft/textures means mc.resourcepack.\n"
        "- Respond with JSON only: {\"label\": \"...\", \"confidence\": 0-1, "
        "\"why\": \"one short sentence\"}\n\n"
        "FACTS:\n" + json.dumps(payload, indent=2, ensure_ascii=False)[:6000]
    )


def request_second_opinion(decision: Decision, config: Config) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    if _calls["n"] >= config.ai_max_calls:
        return None
    prompt = build_prompt(decision)
    body = json.dumps(
        {
            "model": config.ai_model or DEFAULT_MODEL,
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        _calls["n"] += 1
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None
    text = ""
    for block in data.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            text += block.get("text", "")
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[-1] if "\n" in text else text
    try:
        parsed = json.loads(text[text.find("{") : text.rfind("}") + 1])
    except Exception:
        return None
    label = str(parsed.get("label", "")).strip()
    if label not in LABEL_TITLES:
        return None
    return {
        "label": label,
        "confidence": float(parsed.get("confidence", 0.5) or 0.5),
        "why": str(parsed.get("why", ""))[:200],
        "model": config.ai_model,
    }
