"""Diff mode — compare racemap findings between two kernel source trees.

Scans an *old* and a *new* tree, then classifies each live finding (a candidate
that is not exonerated) by whether it appears in only the new tree (NEW), only
the old tree (RESOLVED), or both (PERSISTENT). Findings are keyed by
(file, pattern) so they survive line-number shifts between versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.models import Candidate
from src.scanner.scanner import Scanner
from src.triage import TriagePipeline

NEW = "NEW"
RESOLVED = "RESOLVED"
PERSISTENT = "PERSISTENT"


@dataclass
class DiffEntry:
    file: str
    line: int
    pattern: str
    status: str
    score: float
    cve_id: Optional[str] = None


def _findings(scanner: Scanner, root: Path) -> dict[tuple, Candidate]:
    """Live findings (not exonerated) keyed by (file, shared_field)."""
    out: dict[tuple, Candidate] = {}
    for c in scanner.scan(root):
        if c.mitigation_present is True:
            continue  # exonerated / fixed variant is not a live finding
        out[(c.file, c.shared_field)] = c
    return out


def compare(old: Path, new: Path, rules_dir: Path,
            subsystems: Optional[list[str]] = None,
            backend: str = "heuristic") -> list[DiffEntry]:
    """Return the classified diff between two kernel trees."""
    triage = TriagePipeline(backend=backend)
    old_f = _findings(Scanner(rules_dir=rules_dir, subsystems=subsystems), Path(old))
    new_f = _findings(Scanner(rules_dir=rules_dir, subsystems=subsystems), Path(new))

    entries: list[DiffEntry] = []

    def _entry(cand: Candidate, status: str) -> DiffEntry:
        score = triage.triage_one(cand).score
        pattern = cand.pattern_name or cand.zero_copy_primitive or (cand.shared_field or "")
        return DiffEntry(cand.file, cand.line, pattern,
                         status, score, cand.cve_id)

    for key, cand in new_f.items():
        entries.append(_entry(cand, PERSISTENT if key in old_f else NEW))
    for key, cand in old_f.items():
        if key not in new_f:
            entries.append(_entry(cand, RESOLVED))

    order = {NEW: 0, PERSISTENT: 1, RESOLVED: 2}
    entries.sort(key=lambda e: (order[e.status], -e.score))
    return entries


def summary(entries: list[DiffEntry]) -> dict[str, int]:
    out = {NEW: 0, RESOLVED: 0, PERSISTENT: 0}
    for e in entries:
        out[e.status] += 1
    return out
