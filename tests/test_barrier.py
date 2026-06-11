"""Part 3 — memory barrier awareness."""

from pathlib import Path

import pytest

from src.scanner import Scanner
from src.scanner.barrier import detect
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
FIX = TESTS_DIR / "analysis_fixtures"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def test_detect_barrier_tokens():
    assert detect("x = READ_ONCE(p);") is True
    assert detect("smp_rmb();") is True
    assert detect("rcu_dereference(p);") is True
    assert detect("int x = 1;") is False


def test_barrier_protected_set_and_demotes(scanner):
    triage = TriagePipeline(backend="heuristic")
    c = scanner.scan(FIX / "barrier.c")[0]
    assert c.barrier_protected is True
    plain = scanner.scan(FIX / "caller_nolock.c")[0]
    assert triage.triage_one(c).score < triage.triage_one(plain).score
