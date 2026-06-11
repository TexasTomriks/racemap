"""Memory-barrier awareness (Part 3).

A memory barrier between the shared access and the async call means the code is
ordering-aware; treat it as a (weak) false-positive signal (-0.15).
"""

from __future__ import annotations

import re

_BARRIER_RE = re.compile(
    r"\b(READ_ONCE|WRITE_ONCE|smp_mb|smp_rmb|smp_wmb|smp_load_acquire|"
    r"smp_store_release|barrier|rcu_dereference)\s*\("
)


def detect(window_text: str) -> bool:
    """Whether a memory barrier appears in the candidate window."""
    text = "\n".join(
        ln for ln in (window_text or "").splitlines()
        if not ln.lstrip().startswith(("*", "//", "/*"))
    )
    return bool(_BARRIER_RE.search(text))
