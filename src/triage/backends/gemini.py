"""Gemini backend: Google Gemini via the new ``google-genai`` SDK.

Requires GEMINI_API_KEY (GOOGLE_API_KEY is accepted as a fallback). If the SDK
is missing, the key is unset, or the API call fails, the backend records the
actual error in ``self.last_error`` and returns None so the pipeline falls back
to the deterministic heuristic.
"""

from __future__ import annotations

import os
from typing import Optional

from src.triage.backends.base import TriageBackend


def _api_key() -> Optional[str]:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


class GeminiBackend(TriageBackend):
    name = "gemini"

    def __init__(self, model: str = "gemini-2.0-flash", timeout: int = 120) -> None:
        super().__init__(timeout)
        self.model = model

    @property
    def model_id(self) -> str:
        return f"gemini:{self.model}"

    def is_available(self) -> bool:
        if not _api_key():
            self.last_error = "GEMINI_API_KEY not set"
            return False
        try:
            from google import genai  # noqa: F401  (new google-genai SDK)
        except Exception as exc:
            self.last_error = f"google-genai SDK not installed ({exc})"
            return False
        return True

    def _complete(self, system: str, user: str) -> Optional[str]:
        try:
            from google import genai
            from google.genai import types
        except Exception as exc:
            self.last_error = f"google-genai SDK not installed ({exc})"
            return None
        client = genai.Client(api_key=_api_key())
        config = types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.0,
            response_mime_type="application/json",
        )
        # Try the selected model, then fall back to the lite variant.
        models = [self.model]
        if "gemini-2.0-flash-lite" not in models:
            models.append("gemini-2.0-flash-lite")
        last_exc: Optional[Exception] = None
        for model_name in models:
            try:
                resp = client.models.generate_content(
                    model=model_name, contents=user, config=config,
                )
                return resp.text
            except Exception as exc:
                last_exc = exc
        # Surface the real error so the pipeline can log it before falling back.
        if last_exc is not None:
            self.last_error = f"{type(last_exc).__name__}: {last_exc}"
        return None
