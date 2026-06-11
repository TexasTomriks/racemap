"""Patch-gap analysis tests."""

from pathlib import Path

import pytest

from src.scanner import Scanner, patch_gap

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
FIX = TESTS_DIR / "patchgap_fixtures"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def test_unpatched_fixture_flagged_missing(scanner):
    f = FIX / "unpatched.c"
    cands = patch_gap.apply_all(scanner.scan(f), f)
    assert cands
    dirty = next(c for c in cands if c.cve_id == "CVE-2022-0847")
    assert dirty.patch_missing is True


def test_patched_fixture_not_flagged(scanner):
    f = FIX / "patched.c"
    cands = patch_gap.apply_all(scanner.scan(f), f)
    dirty = next(c for c in cands if c.cve_id == "CVE-2022-0847")
    assert dirty.patch_missing is False


def test_patch_missing_boosts_score(scanner):
    from src.triage import TriagePipeline
    f = FIX / "unpatched.c"
    cands = patch_gap.apply_all(scanner.scan(f), f)
    triage = TriagePipeline(backend="heuristic")
    dirty = next(c for c in cands if c.cve_id == "CVE-2022-0847")
    r = triage.triage_one(dirty)
    # likely_race base 0.85 + patch-missing 0.15 = 1.0
    assert r.score == pytest.approx(1.0)


def test_missing_patches_summary(scanner):
    f = FIX / "unpatched.c"
    cands = patch_gap.apply_all(scanner.scan(f), f)
    summary = patch_gap.missing_patches(cands)
    assert any(e["signature_for"] == "CVE-2022-0847" for e in summary)
