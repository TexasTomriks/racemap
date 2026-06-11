"""Sparse annotation parsing — false-positive filter.

Looks for Sparse lock annotations near a candidate's function:
  __must_hold(lock)  -> the function requires the lock held on entry
  __acquires(lock)   -> the function acquires the lock
  __releases(lock)   -> the function releases the lock
  __context(lock,n,m)-> explicit lock-context count

If the candidate's function is annotated __must_hold (or __acquires before the
call site of the candidate function in a caller), the access is lock-protected
and the score is demoted (-0.2).
"""

from __future__ import annotations

import re
from typing import Optional

from src.models import Candidate

_ANNOT_RE = re.compile(r"__(must_hold|acquires|releases|context)\s*\([^;\n]*?\)")
_DEF_RE_TMPL = r"^\s*(?:static\s+)?[\w\*][\w\s\*]+\b{name}\s*\("


def _function_header(lines: list[str], idx: int) -> Optional[int]:
    """Index of the function-definition line enclosing ``idx``."""
    func_re = re.compile(r"^\s*(?:static\s+)?[\w\*][\w\s\*]+\b\w+\s*\([^;]*$")
    for j in range(idx, max(-1, idx - 120), -1):
        ln = lines[j]
        if ln.lstrip().startswith(("*", "//", "/*")):
            continue
        if func_re.match(ln):
            return j
    return None


def _annotation_near_header(lines: list[str], header_idx: int) -> Optional[str]:
    # Annotations can be on the signature line, the next line, or just above.
    window = "\n".join(lines[max(0, header_idx - 1): header_idx + 3])
    m = _ANNOT_RE.search(window)
    return m.group(0) if m else None


def analyze(candidate: Candidate, lines: list[str]) -> Candidate:
    if not lines:
        return candidate
    idx = candidate.line - 1

    # 1. The candidate's own function annotated __must_hold / __acquires.
    header = _function_header(lines, idx)
    if header is not None:
        ann = _annotation_near_header(lines, header)
        if ann and ("must_hold" in ann or "acquires" in ann):
            candidate.annotation_protected = True
            candidate.annotation_detail = ann
            return candidate

    # 2. A caller acquires the lock before calling the candidate function.
    fname = candidate.function
    if fname:
        call_rx = re.compile(rf"\b{re.escape(fname)}\s*\(")
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith(("*", "//", "/*")):
                continue
            if not call_rx.search(ln):
                continue
            chdr = _function_header(lines, i)
            if chdr is None:
                continue
            body = "\n".join(lines[chdr: i + 1])
            m = re.search(r"__acquires\s*\([^;\n]*?\)", body)
            if m:
                candidate.annotation_protected = True
                candidate.annotation_detail = m.group(0)
                return candidate
    return candidate
