"""Anthropic backend: Claude via the Anthropic API. Requires ANTHROPIC_API_KEY."""

from __future__ import annotations

import os
from typing import Optional

from src.triage.backends.base import TriageBackend


class AnthropicBackend(TriageBackend):
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-6", timeout: int = 120) -> None:
        super().__init__(timeout)
        self.model = model

    @property
    def model_id(self) -> str:
        return f"anthropic:{self.model}"

    def is_available(self) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except Exception:
            return False
        return True

    def _complete(self, system: str, user: str) -> Optional[str]:
        try:
            import anthropic
        except Exception:
            return None
        try:
            client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
            msg = client.messages.create(
                model=self.model,
                max_tokens=512,
                temperature=0.0,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(
                block.text
                for block in msg.content
                if getattr(block, "type", "") == "text"
            )
        except Exception:
            return None
