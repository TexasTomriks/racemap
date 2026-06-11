"""Git log cross-reference (Part 8).

For each candidate file, query ``git log`` in the kernel source directory to find
the last commit date/author and how many commits landed in the last 90 days. A
recently-modified file may have a patch in progress. Degrades gracefully when git
is unavailable or the path is not a repository.
"""

from __future__ import annotations

import datetime
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from src.models import Candidate

_HAS_GIT = shutil.which("git") is not None


def _run_git(repo: Path, args: list[str]) -> Optional[str]:
    if not _HAS_GIT:
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.SubprocessError, OSError):
        return None


def _humanize(days: int) -> str:
    if days < 1:
        return "today"
    if days < 14:
        return f"{days} day{'s' if days != 1 else ''} ago"
    if days < 60:
        return f"{days // 7} weeks ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


def file_history(repo: Path, file_rel: str) -> Optional[dict]:
    """Return git metadata for ``file_rel`` within ``repo``, or None."""
    out = _run_git(repo, ["log", "--follow", "-n", "10",
                          "--date=short", "--format=%h|%ad|%ae|%s", "--", file_rel])
    if not out or not out.strip():
        return None
    lines = [ln for ln in out.splitlines() if ln.strip()]
    first = lines[0].split("|")
    if len(first) < 3:
        return None
    last_date, last_email = first[1], first[2]
    today = datetime.date.today()
    days_ago = 9999
    count_90d = 0
    try:
        d = datetime.date.fromisoformat(last_date)
        days_ago = (today - d).days
    except ValueError:
        pass
    for ln in lines:
        parts = ln.split("|")
        if len(parts) >= 2:
            try:
                cd = datetime.date.fromisoformat(parts[1])
                if (today - cd).days <= 90:
                    count_90d += 1
            except ValueError:
                continue
    return {
        "last_commit_date": last_date,
        "last_author_email": last_email,
        "commit_count_90d": count_90d,
        "recently_modified": days_ago <= 90,
        "age_note": f"{_humanize(days_ago)} by {last_email}",
    }


def annotate(candidate: Candidate, repo: Path, cache: Optional[dict] = None) -> Candidate:
    """Annotate a candidate with git metadata, using an optional per-repo cache."""
    if not _HAS_GIT:
        return candidate
    repo = Path(repo)
    key = candidate.file
    if cache is not None and key in cache:
        info = cache[key]
    else:
        info = file_history(repo, candidate.file)
        if cache is not None:
            cache[key] = info
    if not info:
        return candidate
    candidate.last_commit_date = info["last_commit_date"]
    candidate.last_author_email = info["last_author_email"]
    candidate.commit_count_90d = info["commit_count_90d"]
    candidate.recently_modified = info["recently_modified"]
    candidate.git_age_note = info["age_note"]
    return candidate
