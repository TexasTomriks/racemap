"""Part 10 — io_uring advanced registered-buffer detection."""

from pathlib import Path

import pytest

from src.models import Verdict
from src.scanner import Scanner
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
FIXTURE = TESTS_DIR / "sample_kernel" / "io_uring" / "io_uring_advanced.c"


@pytest.fixture(scope="module")
def candidates():
    return Scanner(rules_dir=RULES_DIR, subsystems=[]).scan(FIXTURE)


def test_new_io_mapped_ubuf_detector_fires(candidates):
    ubuf = [c for c in candidates if c.shared_field == "io_mapped_ubuf"]
    assert ubuf, "io_mapped_ubuf net-send detector did not fire"
    # A vulnerable and a fixed variant.
    assert any(c.mitigation_present is False for c in ubuf)
    assert any(c.mitigation_present is True for c in ubuf)


def test_all_io_uring_primitive_and_versioned(candidates):
    assert candidates
    assert all(c.zero_copy_primitive == "io_uring" for c in candidates)
    assert all(c.affected_versions and c.affected_versions[0] == "5.1"
               for c in candidates)


def test_vulnerable_variants_triaged_race_fixed_exonerated(candidates):
    triage = TriagePipeline(backend="heuristic")
    verdicts = {c.shared_field: [] for c in candidates}
    for c in candidates:
        verdicts[c.shared_field].append(triage.triage_one(c).verdict)
    # At least one race and one safe overall.
    flat = [v for vs in verdicts.values() for v in vs]
    assert Verdict.LIKELY_RACE in flat
    assert Verdict.LIKELY_SAFE in flat
