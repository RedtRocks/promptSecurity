"""Tolerant parsing of JSON returned by LLMs.

Models routinely wrap JSON in markdown fences (```json ... ```) or surround it
with prose. A bare ``json.loads`` rejects all of these, and every stage used to
fall back to a silent default when it did — which is how a whole run could be
scored entirely by the heuristic grader without anyone noticing. Every stage
parses LLM output through here, and reports the outcome via ``note_parse`` so
fallbacks show up in ``run_manifest.json`` instead of in the headline numbers.
"""

from __future__ import annotations

import json
from typing import Any


def parse_llm_json(raw: str) -> Any | None:
    """Return the first JSON object or array in ``raw``, or None if there is none.

    Accepts plain JSON, fenced JSON, and JSON surrounded by prose or trailing
    garbage. Scalars are rejected: every caller expects an object or a list.
    """
    text = (raw or "").strip()
    if not text:
        return None

    if text.startswith("```"):
        text = "\n".join(
            ln for ln in text.splitlines() if not ln.strip().startswith("```")
        ).strip()

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, (dict, list)) else None
    except json.JSONDecodeError:
        pass

    # Earliest balanced object/array wins, so trailing prose or a repeated
    # second object does not break decoding.
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    for start in sorted(starts):
        snippet = _balanced_span(text, start)
        if snippet is None:
            continue
        try:
            obj = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, (dict, list)):
            return obj
    return None


def parse_llm_json_object(raw: str) -> dict[str, Any] | None:
    """Like ``parse_llm_json`` but only accepts an object."""
    obj = parse_llm_json(raw)
    return obj if isinstance(obj, dict) else None


def note_parse(llm: Any, site: str, ok: bool) -> None:
    """Record a parse outcome on the provider, if it tracks them (fakes may not)."""
    record = getattr(llm, "record_parse", None)
    if callable(record):
        record(site, ok)


def _balanced_span(text: str, start: int) -> str | None:
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None
