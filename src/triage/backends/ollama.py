"""Ollama backend: local, private LLM via the Ollama HTTP API. Default backend."""

from __future__ import annotations

import os
from typing import Optional

from src.triage.backends.base import TriageBackend

try:  # optional dependency
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


class OllamaBackend(TriageBackend):
    name = "ollama"

    def __init__(
        self,
        model: str = "llama3.2",
        host: str = "http://localhost:11434",
        timeout: int = 120,
    ) -> None:
        super().__init__(timeout)
        self.model = model
        self.host = host.rstrip("/")

    @property
    def model_id(self) -> str:
        return f"ollama:{self.model}"

    def is_available(self) -> bool:
        return requests is not None

    def _complete(self, system: str, user: str) -> Optional[str]:
        if requests is None:
            return None
        try:
            resp = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.0},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            content = payload.get("message", {}).get("content")
            # Debug: surface the raw model response before JSON parsing.
            if os.environ.get("RACEMAP_DEBUG"):
                print(f"[ollama] raw response: {content!r}")
            if content is None:
                self.last_error = f"ollama response had no message.content: {payload!r}"
            return content
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None
