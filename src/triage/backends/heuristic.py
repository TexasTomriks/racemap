"""Heuristic backend: deterministic, fully offline. Always available — used as
the final fallback and as the demo/test default."""

from __future__ import annotations

from typing import Optional

from src.models import Candidate, TriageResult
from src.triage.backends.base import TriageBackend, heuristic_triage


class HeuristicBackend(TriageBackend):
    name = "heuristic"

    @property
    def model_id(self) -> str:
        return "heuristic"

    def is_available(self) -> bool:
        return True

    def _complete(self, system: str, user: str) -> Optional[str]:
        return None  # never calls a model

    def triage(self, candidate: Candidate) -> Optional[TriageResult]:
        return heuristic_triage(candidate)
