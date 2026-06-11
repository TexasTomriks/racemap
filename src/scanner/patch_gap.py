"""Patch-gap analysis.

Each known issue has a unique code signature that is present once the upstream
patch is applied. If that signature is ABSENT from a candidate's file, the patch
is missing and the candidate's risk is boosted (see ``TriageResult.score``,
which adds +0.15 when ``patch_missing`` is set).
"""

from __future__ import annotations

import re
from pathlib import Path

from src.models import Candidate
from src.scanner.db_updater import BUILTIN_SIGNATURES, get_db

# Backwards-compatible alias; the live DB is resolved per call via get_db().
PATCH_SIGNATURES = BUILTIN_SIGNATURES


def signature_for(candidate: Candidate) -> str | None:
    db = get_db()
    if candidate.cve_id and candidate.cve_id in db:
        return db[candidate.cve_id]
    if candidate.shared_field and candidate.shared_field in db:
        return db[candidate.shared_field]
    return None


def _strip_comments(text: str) -> str:
    return "\n".join(
        ln for ln in text.splitlines()
        if not ln.lstrip().startswith(("*", "//", "/*"))
    )


def check_text(candidate: Candidate, file_text: str) -> bool:
    """Return True if the patch signature is ABSENT (patch missing)."""
    sig = signature_for(candidate)
    if not sig:
        return False
    return re.search(sig, _strip_comments(file_text)) is None


def apply_all(candidates: list[Candidate], base: Path) -> list[Candidate]:
    """Set ``patch_missing`` on each candidate by inspecting its file."""
    cache: dict[str, str] = {}
    base = Path(base)
    root = base if base.is_dir() else base.parent
    for c in candidates:
        path = root / c.file
        key = str(path)
        if key not in cache:
            try:
                cache[key] = path.read_text(errors="ignore")
            except OSError:
                cache[key] = ""
        if check_text(c, cache[key]):
            c.patch_missing = True
    return candidates


def missing_patches(candidates: list[Candidate]) -> list[dict]:
    """Summarise which known patches are missing among the candidates."""
    out: dict[str, dict] = {}
    for c in candidates:
        if not c.patch_missing:
            continue
        key = c.cve_id or (c.shared_field or "unknown")
        entry = out.setdefault(key, {"signature_for": key, "count": 0,
                                     "subsystems": set()})
        entry["count"] += 1
        if c.subsystem:
            entry["subsystems"].add(c.subsystem)
    for e in out.values():
        e["subsystems"] = sorted(e["subsystems"])
    return list(out.values())
