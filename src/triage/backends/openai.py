"""OpenAI backend: chat completions via the OpenAI API. Requires OPENAI_API_KEY."""

from __future__ import annotations

import os
from typing import Optional

from src.triage.backends.base import TriageBackend


class OpenAIBackend(TriageBackend):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", timeout: int = 120) -> None:
        super().__init__(timeout)
        self.model = model

    @property
    def model_id(self) -> str:
        return f"openai:{self.model}"

    def is_available(self) -> bool:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401
        except Exception:
            return False
        return True

    def _complete(self, system: str, user: str) -> Optional[str]:
        try:
            from openai import OpenAI
        except Exception:
            return None
        try:
            client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=self.timeout)
            resp = client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return resp.choices[0].message.content
        except Exception:
            return None
