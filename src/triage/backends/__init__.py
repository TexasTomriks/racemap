"""Triage backend registry.

All backends share the same system prompt and return the same TriageResult
model, so they are interchangeable via the ``--llm`` CLI flag.
"""

from __future__ import annotations

from src.triage.backends.anthropic import AnthropicBackend
from src.triage.backends.base import (
    TriageBackend,
    extract_json,
    heuristic_triage,
    parse_triage,
)
from src.triage.backends.gemini import GeminiBackend
from src.triage.backends.heuristic import HeuristicBackend
from src.triage.backends.ollama import OllamaBackend
from src.triage.backends.openai import OpenAIBackend

# Name -> backend class.
BACKEND_CLASSES: dict[str, type[TriageBackend]] = {
    OllamaBackend.name: OllamaBackend,
    AnthropicBackend.name: AnthropicBackend,
    OpenAIBackend.name: OpenAIBackend,
    GeminiBackend.name: GeminiBackend,
    HeuristicBackend.name: HeuristicBackend,
}

# Order tried in --llm auto mode (local/private first, heuristic last).
AUTO_CHAIN: list[str] = ["ollama", "anthropic", "openai", "gemini", "heuristic"]

# Valid --llm choices (registry names + the auto selector).
LLM_CHOICES: list[str] = ["auto"] + list(BACKEND_CLASSES.keys())

__all__ = [
    "TriageBackend",
    "AnthropicBackend",
    "GeminiBackend",
    "HeuristicBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "BACKEND_CLASSES",
    "AUTO_CHAIN",
    "LLM_CHOICES",
    "extract_json",
    "heuristic_triage",
    "parse_triage",
]
