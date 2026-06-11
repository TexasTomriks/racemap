"""Part 8 — git log cross-reference (graceful with/without git)."""

import shutil
import subprocess
from pathlib import Path

import pytest

from src.models import Candidate, Engine
from src.scanner import git_log

HAS_GIT = shutil.which("git") is not None


def _cand(file="foo.c", line=1):
    return Candidate(rule_id="r", engine=Engine.COCCINELLE, file=file, line=line,
                     shared_field="ctx->iv")


def test_no_repo_is_graceful(tmp_path):
    # tmp_path is not a git repo -> annotate must leave defaults, not crash.
    c = _cand()
    git_log.annotate(c, tmp_path)
    assert c.recently_modified is False
    assert c.last_commit_date is None


@pytest.mark.skipif(not HAS_GIT, reason="git not available")
def test_recent_commit_flagged(tmp_path):
    repo = tmp_path
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "dev@kernel.org"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Dev"], check=True)
    f = repo / "foo.c"
    f.write_text("int x;\n")
    subprocess.run(["git", "-C", str(repo), "add", "foo.c"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "add foo"], check=True)

    info = git_log.file_history(repo, "foo.c")
    assert info is not None
    assert info["last_author_email"] == "dev@kernel.org"
    assert info["recently_modified"] is True
    assert info["commit_count_90d"] >= 1

    c = _cand()
    git_log.annotate(c, repo)
    assert c.recently_modified is True
    assert "dev@kernel.org" in (c.git_age_note or "")


def test_humanize_ranges():
    assert git_log._humanize(0) == "today"
    assert git_log._humanize(3) == "3 days ago"
    assert "weeks ago" in git_log._humanize(20)
    assert "months ago" in git_log._humanize(90)
