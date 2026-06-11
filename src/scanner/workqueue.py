"""Workqueue / deferred-execution pattern detection (Part 5).

INIT_WORK / INIT_DELAYED_WORK / queue_work / schedule_work near a shared-buffer
access indicates a deferred execution path — a second, asynchronous context that
can race the main path. Escalate (+0.1) when no lock covers it.
"""

from __future__ import annotations

import re

_WQ_RE = re.compile(
    r"\b(INIT_WORK|INIT_DELAYED_WORK|queue_work|queue_delayed_work|"
    r"schedule_work|schedule_delayed_work|mod_delayed_work|tasklet_schedule)\s*\("
)


def detect(window_text: str) -> bool:
    text = "\n".join(
        ln for ln in (window_text or "").splitlines()
        if not ln.lstrip().startswith(("*", "//", "/*"))
    )
    return bool(_WQ_RE.search(text))
