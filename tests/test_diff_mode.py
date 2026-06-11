"""Diff-mode tests: comparing an old (unfixed) tree to a new (fixed) tree."""

from pathlib import Path

import pytest

from src.scanner import diff_mode
from src.scanner.diff_mode import NEW, RESOLVED, PERSISTENT

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
OLD = TESTS_DIR / "sample_kernel_old"
NEW_TREE = TESTS_DIR / "sample_kernel_new"


@pytest.fixture(scope="module")
def entries():
    return diff_mode.compare(OLD, NEW_TREE, RULES_DIR)


def test_summary_counts(entries):
    s = diff_mode.summary(entries)
    assert s[NEW] == 1
    assert s[RESOLVED] == 1
    assert s[PERSISTENT] == 1


def test_new_finding_is_added_file(entries):
    new = [e for e in entries if e.status == NEW]
    assert len(new) == 1
    assert "added.c" in new[0].file


def test_resolved_finding_is_resolved_file(entries):
    resolved = [e for e in entries if e.status == RESOLVED]
    assert len(resolved) == 1
    assert "resolved.c" in resolved[0].file


def test_persistent_finding_is_common_file(entries):
    persistent = [e for e in entries if e.status == PERSISTENT]
    assert len(persistent) == 1
    assert "common.c" in persistent[0].file
