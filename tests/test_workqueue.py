"""Part 5 — workqueue / deferred-execution pattern detection."""

from pathlib import Path

import pytest

from src.scanner import Scanner
from src.scanner.workqueue import detect
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
FIX = TESTS_DIR / "analysis_fixtures"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def test_detect_workqueue_tokens():
    assert detect("INIT_WORK(&w, fn);") is True
    assert detect("queue_work(wq, &w);") is True
    assert detect("schedule_work(&w);") is True
    assert detect("int x;") is False


def test_workqueue_async_set_and_escalates(scanner):
    triage = TriagePipeline(backend="heuristic")
    c = scanner.scan(FIX / "workqueue.c")[0]
    assert c.workqueue_async is True
    # +0.1 escalation when no caller lock.
    assert triage.triage_one(c).score == pytest.approx(0.95, abs=0.01)


def test_interrupt_context_detected_and_escalates(scanner):
    triage = TriagePipeline(backend="heuristic")
    c = scanner.scan(FIX / "interrupt.c")[0]
    assert c.interrupt_context_note is not None
    assert "interrupt" in c.interrupt_context_note
    assert triage.triage_one(c).score == pytest.approx(0.95, abs=0.01)
