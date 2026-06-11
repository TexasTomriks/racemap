"""Taint tracking lite — 1-hop call-graph propagation.

For each candidate, check whether the flagged shared variable is passed to a
callee within ~10 lines. Follow a single hop into that callee (if its definition
is in the same file) and check whether the callee holds a covering lock. If the
variable propagates into a callee that has *no* lock, the candidate's risk is
escalated (see ``TriageResult.score``).

This is a deliberately shallow, regex-based pass — no full AST, no inter-file
resolution — matching racemap's "keep scope tight" philosophy.
"""

from __future__ import annotations

import re
from typing import Optional

from src.models import Candidate

# Locking primitives that count as "the callee takes a lock".
_LOCK_RE = re.compile(
    r"\b(mutex_lock|spin_lock(_bh|_irqsave)?|lock_sock|read_lock|write_lock|"
    r"down_read|down_write|rcu_read_lock|raw_spin_lock|mmap_read_lock|"
    r"mmap_write_lock|local_irq_save|preempt_disable|refcount_inc)\b"
)

# A call site: an identifier immediately followed by "(".
_CALL_RE = re.compile(r"\b([a-z_][a-z0-9_]+)\s*\(")

# A function definition header (no trailing semicolon): used to restrict 1-hop
# taint to helpers actually defined in the same file (not kernel APIs).
_DEF_RE = re.compile(r"^\s*(?:static\s+)?[\w\*][\w\s\*]+\b(\w+)\s*\([^;]*$")


def _local_defs(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for ln in lines:
        if ln.lstrip().startswith(("*", "//", "/*")):
            continue
        m = _DEF_RE.match(ln)
        if m:
            names.add(m.group(1))
    return names

# Calls that are not local helpers (kernel APIs / control flow) — ignore as hops.
_NON_HELPERS = {
    "if", "for", "while", "switch", "return", "sizeof", "memcpy", "memset",
    "container_of", "le32_to_cpu", "cpu_to_le32", "min", "max", "likely",
    "unlikely", "BUG_ON", "WARN_ON", "kfree", "kmalloc", "kzalloc",
}

# Map a flagged primitive to the variable name we track into callees.
_PRIMITIVE_VAR = {
    "gup pages": "pages",
    "skb_shared_info": "skb",
    "pipe->bufs[].page": "page",
    "buf->flags CAN_MERGE": "buf",
    "copy_user under mmap_read_lock": None,
}


def _track_var(candidate: Candidate) -> Optional[str]:
    field = candidate.shared_field or ""
    if field in _PRIMITIVE_VAR:
        return _PRIMITIVE_VAR[field]
    if "->" in field:
        field = field.split("->")[-1]
    m = re.search(r"[a-z_][a-z0-9_]*", field)
    return m.group(0) if m else None


def _callee_has_lock(lines: list[str], callee: str) -> Optional[bool]:
    """Return True if the callee's in-file definition holds a lock, False if it
    does not, or None if no definition is found."""
    def_re = re.compile(rf"^\s*[\w\*][\w\s\*]*\b{re.escape(callee)}\s*\([^;]*$")
    for i, line in enumerate(lines):
        if not def_re.match(line):
            continue
        # Walk forward to the opening brace, then brace-match the body.
        depth = 0
        started = False
        body: list[str] = []
        for ln in lines[i:i + 200]:
            body.append(ln)
            depth += ln.count("{") - ln.count("}")
            if "{" in ln:
                started = True
            if started and depth <= 0:
                break
        text = "\n".join(body)
        return bool(_LOCK_RE.search(text))
    return None


def analyze(candidate: Candidate, lines: list[str]) -> Candidate:
    """Set ``taint_propagated`` / ``taint_callee`` on a candidate in place."""
    var = _track_var(candidate)
    if not var:
        return candidate

    idx = candidate.line - 1
    window = lines[max(0, idx): idx + 10]
    var_re = re.compile(rf"\b{re.escape(var)}\b")
    local = _local_defs(lines)

    callee: Optional[str] = None
    for ln in window:
        if ln.lstrip().startswith(("*", "//", "/*")):
            continue
        for m in _CALL_RE.finditer(ln):
            name = m.group(1)
            if name in _NON_HELPERS or name not in local:
                continue  # only hop into helpers defined in this file
            args = ln[m.end():]
            if var_re.search(args):
                callee = name
                break
        if callee:
            break

    if not callee:
        return candidate

    candidate.taint_callee = callee
    # Escalate only when the variable flows into a callee with no covering lock.
    has_lock = _callee_has_lock(lines, callee)
    candidate.taint_propagated = has_lock is False
    return candidate
