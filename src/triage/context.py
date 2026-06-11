"""AST-lite context builder for the triage LLM.

Instead of dumping raw file content, racemap sends the model a small structured
JSON context: the function, the classified zero-copy primitive, the shared
variable, the lock primitives found, the lock→unlock window size, a token-budgeted
code snippet, and the taint callee. This keeps prompts tight and focuses the
model on the differential-locking question.
"""

from __future__ import annotations

import re

# Classify the flagged primitive into a coarse family for the prompt.
_PRIMITIVE_CLASS = [
    ("req->imu", "io_uring"),
    ("pipe->bufs", "splice"),
    ("buf->flags", "splice"),
    ("gup pages", "vmsplice"),
    ("skb_shared_info", "zerocopy"),
    ("skb(shared_frag)", "zerocopy"),
    ("copy_user under mmap_read_lock", "mmap-copy"),
    ("ctx->", "shared-iv"),
]

_LOCK_TOKENS = (
    "mutex_lock", "spin_lock", "spin_lock_bh", "spin_lock_irqsave", "lock_sock",
    "read_lock", "write_lock", "down_read", "down_write", "rcu_read_lock",
    "raw_spin_lock", "mmap_read_lock", "mmap_write_lock", "local_irq_save",
    "preempt_disable",
)
_LOCK_RE = re.compile(r"\b(" + "|".join(_LOCK_TOKENS) + r")\b")
_UNLOCK_RE = re.compile(
    r"\b(mutex_unlock|spin_unlock\w*|release_sock|read_unlock|write_unlock|"
    r"up_read|up_write|rcu_read_unlock|raw_spin_unlock|mmap_read_unlock|"
    r"mmap_write_unlock|local_irq_restore|preempt_enable)\b"
)


def classify_primitive(shared_field: str | None) -> str:
    f = shared_field or ""
    for needle, label in _PRIMITIVE_CLASS:
        if needle in f:
            return label
    return "other"


def shared_variable(shared_field: str | None) -> str:
    f = shared_field or ""
    special = {"gup pages": "pages", "skb_shared_info": "skb",
               "pipe->bufs[].page": "page", "skb(shared_frag)": "skb"}
    if f in special:
        return special[f]
    if "->" in f:
        tail = f.split("->")[-1]
        if "]." in tail:                 # e.g. bufs[].page -> page
            tail = tail.split("].")[-1]
        return tail.split("[")[0].split()[0]
    m = re.search(r"[A-Za-z_][A-Za-z0-9_]*", f)
    return m.group(0) if m else "buffer"


def locks_found(snippet: str) -> list[str]:
    return sorted(set(_LOCK_RE.findall(snippet or "")))


def lock_window_lines(snippet: str) -> int:
    lines = (snippet or "").splitlines()
    lock_i = unlock_i = None
    for i, ln in enumerate(lines):
        if lock_i is None and _LOCK_RE.search(ln):
            lock_i = i
        if _UNLOCK_RE.search(ln):
            unlock_i = i
    if lock_i is not None and unlock_i is not None and unlock_i >= lock_i:
        return unlock_i - lock_i
    return 0


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token)."""
    return max(1, len(text or "") // 4)


def _budgeted_snippet(snippet: str) -> str:
    """Max 30 lines if the snippet is already token-heavy (>800), else 50 lines,
    centred on the candidate."""
    lines = (snippet or "").splitlines()
    limit = 30 if estimate_tokens(snippet) > 800 else 50
    if len(lines) <= limit:
        return snippet or ""
    keep = lines[:limit]
    return "\n".join(keep)


def build_context(candidate) -> dict:
    """Return the structured JSON context dict for a candidate."""
    snippet = candidate.snippet or ""
    prim = getattr(candidate, "zero_copy_primitive", "") or ""
    if not prim or prim == "unknown":
        prim = classify_primitive(candidate.shared_field)
    return {
        "function_name": candidate.function or "unknown",
        "zero_copy_primitive": prim,
        "shared_variable": shared_variable(candidate.shared_field),
        "lock_primitives_found": locks_found(snippet),
        "lock_to_unlock_window_lines": lock_window_lines(snippet),
        "code_snippet": _budgeted_snippet(snippet),
        "taint_callee": candidate.taint_callee,
        "cve_id": candidate.cve_id,
        "subsystem": candidate.subsystem,
        "location": candidate.location,
    }
