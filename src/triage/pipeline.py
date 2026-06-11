"""TriagePipeline: selects an LLM backend (Ollama / Anthropic / OpenAI / Gemini),
falls through to the next backend if one is unavailable, and always ends at the
deterministic heuristic so a ranked result is produced even fully offline.

The LLM is a triage filter for false-positive reduction only — never an exploit
generator.
"""

from __future__ import annotations

from typing import Optional

from src.models import Candidate, TriageResult
from src.triage.backends import (
    AUTO_CHAIN,
    BACKEND_CLASSES,
    TriageBackend,
    heuristic_triage,
)


class TriagePipeline:
    def __init__(
        self,
        backend: str = "ollama",
        ollama_model: str = "llama3.2",
        ollama_host: str = "http://localhost:11434",
        anthropic_model: str = "claude-sonnet-4-6",
        openai_model: str = "gpt-4o-mini",
        gemini_model: str = "gemini-2.0-flash",
        timeout: int = 120,
        cache_enabled: bool = False,
        demo_mode: bool = False,
        cache_path=None,
    ) -> None:
        self.backend_name = backend
        self.timeout = timeout
        self._model_cfg = {
            "ollama": {"model": ollama_model, "host": ollama_host},
            "anthropic": {"model": anthropic_model},
            "openai": {"model": openai_model},
            "gemini": {"model": gemini_model},
            "heuristic": {},
        }
        self._instances: dict[str, TriageBackend] = {}
        self.active_backend: str = "heuristic"
        # Fallback diagnostics surfaced to the CLI/UI.
        self.warnings: list[str] = []
        self._seen_warnings: set[str] = set()
        # Part 6: SQLite response cache / demo mode.
        self.demo_mode = demo_mode
        self.cache_enabled = cache_enabled or demo_mode
        self._cache = None
        if self.cache_enabled:
            from src.triage.cache import TriageCache
            self._cache = TriageCache(cache_path)

    # -- backend construction ----------------------------------------------

    def _get(self, name: str) -> TriageBackend:
        if name not in self._instances:
            cls = BACKEND_CLASSES[name]
            self._instances[name] = cls(timeout=self.timeout, **self._model_cfg[name])
        return self._instances[name]

    def _chain(self) -> list[str]:
        """Ordered list of backend names to attempt for each candidate."""
        if self.backend_name == "auto":
            return list(AUTO_CHAIN)
        if self.backend_name == "heuristic":
            return ["heuristic"]
        if self.backend_name not in BACKEND_CLASSES:
            return ["heuristic"]
        return [self.backend_name, "heuristic"]

    # -- public API ---------------------------------------------------------

    def triage(self, candidates: list[Candidate]) -> list[TriageResult]:
        return [self.triage_one(c) for c in candidates]

    def triage_one(self, candidate: Candidate) -> TriageResult:
        if self.cache_enabled and self._cache is not None:
            key = self._cache.key(candidate)
            hit = self._cache.get(key)
            if hit is not None:
                return self._cache.to_result(candidate, hit)
            if self.demo_mode:
                # Demo mode never calls an LLM API; use the offline heuristic.
                return heuristic_triage(candidate)
            result = self._triage_uncached(candidate)
            self._cache.put(key, result)
            return result
        return self._triage_uncached(candidate)

    def _triage_uncached(self, candidate: Candidate) -> TriageResult:
        requested = self.backend_name
        fell_back_from: Optional[str] = None
        for name in self._chain():
            backend = self._get(name)
            result: Optional[TriageResult] = backend.triage(candidate)
            if result is not None:
                # Make the fallback explicit, e.g. "gemini (fallback: heuristic)".
                if (fell_back_from and name == "heuristic"
                        and requested not in ("auto", "heuristic")):
                    result.model = f"{requested} (fallback: heuristic)"
                self.active_backend = result.model
                return result
            if name != "heuristic":
                fell_back_from = name
                err = getattr(backend, "last_error", None)
                msg = (f"{name} backend unavailable, falling back to heuristic"
                       + (f": {err}" if err else "."))
                if msg not in self._seen_warnings:
                    self._seen_warnings.add(msg)
                    self.warnings.append(msg)
        return heuristic_triage(candidate)
