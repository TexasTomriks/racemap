"""Part 2 — sparse annotation parsing (__must_hold / __acquires)."""

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


def test_must_hold_sets_annotation_protected(scanner):
    c = scanner.scan(FIX / "must_hold.c")[0]
    assert c.annotation_protected is True
    assert c.annotation_detail == "__must_hold(&ctx->lock)"


def test_annotation_demotes_score(scanner):
    triage = TriagePipeline(backend="heuristic")
    annotated = scanner.scan(FIX / "must_hold.c")[0]
    plain = scanner.scan(FIX / "caller_nolock.c")[0]
    # annotated: -0.2; plain: caller has no lock so no demotion.
    assert triage.triage_one(annotated).score < triage.triage_one(plain).score
