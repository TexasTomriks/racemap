"""Interrupt / atomic context detection (Part 4).

If the candidate function or its callers run in interrupt/atomic context, the
race window is harder to serialise; escalate the score (+0.1) and note it.
"""

from __future__ import annotations

import re
from typing import Optional

_IRQ_RE = re.compile(
    r"\b(in_interrupt|in_atomic|irqs_disabled|irq_disabled|local_irq_save|"
    r"spin_lock_irq|spin_lock_irqsave|tasklet_|__do_softirq|napi_)\w*\s*\(?"
)


def detect(text: str) -> Optional[str]:
    clean = "\n".join(
        ln for ln in (text or "").splitlines()
        if not ln.lstrip().startswith(("*", "//", "/*"))
    )
    m = _IRQ_RE.search(clean)
    if m:
        return f"runs in interrupt/atomic context ({m.group(1)})"
    return None
