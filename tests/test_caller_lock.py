"""Part 1 — caller lock traversal (false-positive filter)."""

from pathlib import Path

import pytest

from src.scanner import Scanner
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
FIX = TESTS_DIR / "analysis_fixtures"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def test_parent_holds_lock_sets_caller_lock_held(scanner):
    c = scanner.scan(FIX / "caller_lock_esp.c")[0]
    assert c.caller_lock_held is True
    assert c.caller_lock_name == "spin_lock"


def test_no_lock_caller_not_flagged(scanner):
    c = scanner.scan(FIX / "caller_nolock.c")[0]
    assert c.caller_lock_held is False


def test_caller_lock_demotes_score(scanner):
    triage = TriagePipeline(backend="heuristic")
    locked = scanner.scan(FIX / "caller_lock_esp.c")[0]
    unlocked = scanner.scan(FIX / "caller_nolock.c")[0]
    locked_score = triage.triage_one(locked).score
    unlocked_score = triage.triage_one(unlocked).score
    # Same base pattern; the lock-protected one must score ~0.3 lower.
    assert locked_score < unlocked_score
    assert unlocked_score - locked_score == pytest.approx(0.3, abs=0.01)
