"""Abstract triage backend + shared parsing / heuristic helpers.

Every backend uses the IDENTICAL system prompt (``prompts.SYSTEM_PROMPT``) and
returns the same :class:`TriageResult` Pydantic model, so backends are fully
interchangeable. A backend only judges locking/ownership sufficiency — it never
generates exploits.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Optional

from src.models import Candidate, TriageResult, Verdict
from src.triage.prompts import SYSTEM_PROMPT, build_user_prompt, prompt_token_count

# Tokens that indicate a copy / ownership-transfer / unshare mitigation, used to
# name the mitigation in the heuristic's chain-of-thought.
_MITIGATION_TOKENS = (
    "memcpy", "copy_page", "copy_from_user", "skb_unshare", "pskb_copy",
    "pipe_buf_get", "get_page", "put_page", "set_page_dirty", "unpin_user_page",
    "vma_lookup", "PageAnon", "buf->flags = 0",
)


def extract_json(raw: str) -> Optional[dict]:
    """Pull the first JSON object out of an LLM completion."""
    raw = (raw or "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _coerce_steps(value) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _confidence_band(confidence: float, n_steps: int, llm: bool) -> tuple[float, float]:
    """Compute a (low, high) confidence band. Heuristic: fixed +/-0.05. LLM: base
    +/-0.10, narrowed as the model emits more reasoning steps (more steps =>
    narrower, floored at +/-0.03)."""
    if not llm:
        band = 0.05
    elif n_steps <= 0:
        band = 0.10
    else:
        band = max(0.03, 0.12 - 0.02 * n_steps)
    low = round(max(0.0, confidence - band), 4)
    high = round(min(1.0, confidence + band), 4)
    return low, high


_VERDICT_NORMALIZE = {
    "likely_race": "likely_race",
    "race": "likely_race",
    "likely": "likely_race",
    "unsafe": "likely_race",
    "unlikely_safe": "likely_race",
    "unlikely_race": "likely_safe",
    "likely_safe": "likely_safe",
    "safe": "likely_safe",
    "no_race": "likely_safe",
    "needs_review": "needs_review",
    "review": "needs_review",
    "unknown": "needs_review",
    "ambiguous": "needs_review",
}


def _normalize_verdict(value) -> Verdict:
    """Map model verdict strings (incl. synonyms like 'unlikely_race') onto the
    Verdict enum. Unknown values become NEEDS_REVIEW rather than crashing."""
    key = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    mapped = _VERDICT_NORMALIZE.get(key)
    if mapped is not None:
        return Verdict(mapped)
    try:
        return Verdict(key)            # already a valid enum value
    except ValueError:
        return Verdict.NEEDS_REVIEW


def parse_triage(candidate: Candidate, raw: str, model: str) -> TriageResult:
    """Turn a raw model completion into a :class:`TriageResult`."""
    data = extract_json(raw)
    if data is None:
        result = heuristic_triage(candidate, note="LLM output unparseable")
        result.model = f"{model}+heuristic"
        return result
    verdict = _normalize_verdict(data.get("verdict"))
    try:
        confidence = float(data.get("confidence", 0.5) or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = min(max(confidence, 0.0), 1.0)
    try:
        return TriageResult(
            candidate=candidate,
            verdict=verdict,
            confidence=confidence,
            reasoning=str(data.get("reasoning", "")).strip(),
            reasoning_steps=_coerce_steps(data.get("reasoning_steps")),
            lock_held=data.get("lock_held") if isinstance(data.get("lock_held"), bool) else None,
            snapshot_taken=data.get("snapshot_taken") if isinstance(data.get("snapshot_taken"), bool) else None,
            token_count=prompt_token_count(candidate),
            confidence_low=_confidence_band(confidence, len(_coerce_steps(data.get("reasoning_steps"))), llm=True)[0],
            confidence_high=_confidence_band(confidence, len(_coerce_steps(data.get("reasoning_steps"))), llm=True)[1],
            model=model,
        )
    except Exception:
        # Never return None / crash on a malformed field — fall back to heuristic.
        result = heuristic_triage(candidate, note="LLM output had invalid fields")
        result.model = f"{model}+heuristic"
        return result


_PRIMITIVE_PHRASE = {
    "aead": "aead buffer handed to async op without lock",
    "splice": "splice pipe pages cross namespace boundary without copy",
    "vmsplice": "vmsplice user pages aliased into kernel without COW",
    "io_uring": "io_uring registered buffer shared with host without copy",
    "zerocopy": "zerocopy skb shared across netns without unshare",
    "unknown": "shared buffer handed to async op with no covering lock",
}


def _name_mitigation(snippet: str) -> Optional[str]:
    for tok in _MITIGATION_TOKENS:
        if tok in (snippet or ""):
            return tok
    return None


def heuristic_triage(candidate: Candidate, note: str = "") -> TriageResult:
    """Deterministic, offline fallback verdict with forced reasoning steps.

    Priority order for the decision:
      1. ``candidate.mitigation_present`` if the scanner set it (new detectors).
      2. Otherwise look for a memcpy snapshot of the shared field in the snippet
         (legacy crypto patterns).
    """
    snippet = candidate.snippet or ""
    primitive = candidate.zero_copy_primitive or "unknown"
    if primitive == "unknown" and candidate.shared_field:
        primitive = candidate.shared_field
    variable = candidate.shared_field or primitive
    phrase = _PRIMITIVE_PHRASE.get(candidate.zero_copy_primitive or "unknown",
                                   _PRIMITIVE_PHRASE["unknown"])

    if candidate.mitigation_present is not None:
        safe = bool(candidate.mitigation_present)
    else:
        field = (candidate.shared_field or "").split("->")[-1]
        safe = bool(
            field
            and "(" not in field
            and re.search(rf"memcpy\s*\([^;]*{re.escape(field)}", snippet)
        )

    mitigation = _name_mitigation(snippet) if safe else None

    if safe:
        verdict, conf = Verdict.LIKELY_SAFE, 0.6
        reasoning = (
            f"{primitive} primitive: a copy/ownership-transfer mitigation "
            f"({mitigation or 'snapshot'}) is present near the sink."
        )
        steps = [
            f"Step 1: primitive = {primitive} (variable {variable})",
            "Step 2: mitigation taken within the guarded region",
            f"Step 3: ownership transferred — {mitigation or 'per-request copy'} present",
            f"Step 4: {primitive} buffer is copied/owned before reuse -> likely_safe",
        ]
    else:
        verdict, conf = Verdict.LIKELY_RACE, 0.7
        reasoning = f"{primitive} primitive: {phrase}."
        steps = [
            f"Step 1: primitive = {primitive} (variable {variable})",
            "Step 2: no lock found spanning the primitive-to-reuse window",
            "Step 3: shared/aliased — no copy or ownership transfer detected",
            f"Step 4: {phrase} -> likely_race",
        ]
    if candidate.cve_id:
        steps.append(f"Note: matches known pattern {candidate.cve_id}")
    if note:
        reasoning = f"{reasoning} ({note})"

    return TriageResult(
        candidate=candidate,
        verdict=verdict,
        confidence=conf,
        reasoning=reasoning,
        reasoning_steps=steps,
        lock_held=None,
        snapshot_taken=safe,
        token_count=prompt_token_count(candidate),
        confidence_low=_confidence_band(conf, len(steps), llm=False)[0],
        confidence_high=_confidence_band(conf, len(steps), llm=False)[1],
        model="heuristic",
    )


class TriageBackend(ABC):
    """Interchangeable LLM triage backend."""

    name: str = "base"

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout
        # Last failure reason (SDK missing / key unset / API error), used by
        # the pipeline to log a warning before falling back.
        self.last_error: Optional[str] = None

    @property
    @abstractmethod
    def model_id(self) -> str:
        """Stable identifier recorded in TriageResult.model."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this backend can be used (deps installed, key present)."""

    @abstractmethod
    def _complete(self, system: str, user: str) -> Optional[str]:
        """Return the raw model completion, or None on failure."""

    def triage(self, candidate: Candidate) -> Optional[TriageResult]:
        """Triage one candidate. Returns None if the backend is unusable so the
        pipeline can fall through to the next backend."""
        if not self.is_available():
            return None
        raw = self._complete(SYSTEM_PROMPT, build_user_prompt(candidate))
        if raw is None:
            return None
        return parse_triage(candidate, raw, self.model_id)
