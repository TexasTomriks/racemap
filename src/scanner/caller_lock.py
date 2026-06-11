"""Caller lock traversal — false-positive filter.

Traverses UP the (in-file) call graph from a candidate's enclosing function, up
to 3 hops, and checks whether every caller holds a covering lock before the call
site. If ALL callers are lock-protected, the candidate is very likely a false
positive (the race is serialised by the caller) — ``caller_lock_held`` is set and
the score is demoted (-0.3). If ANY caller has no lock, the candidate stays a
likely race.

Regex-based and intra-file only — a deliberately shallow, graceful analysis.
"""

from __future__ import annotations

import re
from typing import Optional

from src.models import Candidate

_LOCK_RE = re.compile(
    r"\b(mutex_lock(_\w+)?|spin_lock(_\w+)?|lock_sock|read_lock(_\w+)?|"
    r"write_lock(_\w+)?|down_read|down_write|rcu_read_lock|raw_spin_lock(_\w+)?|"
    r"mmap_read_lock|mmap_write_lock|local_irq_save|preempt_disable)\s*\(([^)]*)\)"
)
_DEF_RE_TMPL = r"^\s*(?:static\s+)?[\w\*][\w\s\*]+\b{name}\s*\([^;]*$"
_CALL_RE_TMPL = r"\b{name}\s*\("


def _function_def_index(lines: list[str], name: str) -> Optional[int]:
    rx = re.compile(_DEF_RE_TMPL.format(name=re.escape(name)))
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith(("*", "//", "/*")):
            continue
        if rx.match(ln):
            return i
    return None


def _function_bounds(lines: list[str], def_idx: int) -> tuple[int, int]:
    """Return (start, end) line indices of a function body via brace matching."""
    depth = 0
    started = False
    for j in range(def_idx, min(len(lines), def_idx + 400)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth <= 0:
            return def_idx, j
    return def_idx, min(len(lines), def_idx + 400)


def _enclosing_function(lines: list[str], idx: int) -> Optional[str]:
    func_re = re.compile(r"^\s*(?:static\s+)?[\w\*][\w\s\*]+\b(\w+)\s*\([^;]*$")
    for j in range(idx, max(-1, idx - 120), -1):
        if lines[j].lstrip().startswith(("*", "//", "/*")):
            continue
        m = func_re.match(lines[j])
        if m:
            return m.group(1)
    return None


def _callers_of(lines: list[str], name: str) -> list[tuple[str, int]]:
    """Find (caller_function, call_line_idx) for each call site of ``name`` that
    is not the function's own definition."""
    call_rx = re.compile(_CALL_RE_TMPL.format(name=re.escape(name)))
    def_rx = re.compile(_DEF_RE_TMPL.format(name=re.escape(name)))
    out: list[tuple[str, int]] = []
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith(("*", "//", "/*")):
            continue
        if def_rx.match(ln):
            continue  # this is the definition, not a call
        if call_rx.search(ln):
            caller = _enclosing_function(lines, i)
            if caller and caller != name:
                out.append((caller, i))
    return out


def _holds_lock(lines: list[str], caller: str, call_idx: int, depth: int) -> tuple[bool, Optional[str]]:
    """Whether ``caller`` holds a lock before the call at ``call_idx`` — directly,
    or (within ``depth`` hops) because all of *its* callers hold a lock."""
    def_idx = _function_def_index(lines, caller)
    if def_idx is None:
        return False, None
    # Direct: a lock taken between the caller's def and the call site.
    for j in range(def_idx, call_idx):
        m = _LOCK_RE.search(lines[j])
        if m:
            return True, m.group(1)
    if depth <= 1:
        return False, None
    # Indirect: every caller of `caller` must hold a lock.
    parents = _callers_of(lines, caller)
    if not parents:
        return False, None
    name = None
    for pname, pidx in parents:
        held, lname = _holds_lock(lines, pname, pidx, depth - 1)
        if not held:
            return False, None
        name = name or lname
    return True, name


def analyze(candidate: Candidate, lines: list[str], depth: int = 3) -> Candidate:
    """Set ``caller_lock_held`` / ``caller_lock_name`` on the candidate."""
    fname = candidate.function
    if not fname:
        return candidate
    callers = _callers_of(lines, fname)
    if not callers:
        return candidate  # cannot conclude without a caller
    all_locked = True
    lock_name: Optional[str] = None
    for caller, idx in callers:
        held, lname = _holds_lock(lines, caller, idx, depth)
        if held:
            lock_name = lock_name or lname
        else:
            all_locked = False
    if all_locked:
        candidate.caller_lock_held = True
        candidate.caller_lock_name = lock_name
    return candidate
