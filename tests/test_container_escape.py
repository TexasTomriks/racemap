"""Container-escape flag tests.

algif_skcipher (our finding) and the splice fixture must be flagged as
container-escape primitives; the clean random.c snapshot fixtures must not.
"""

from pathlib import Path

import pytest

from src.scanner import Scanner
from src.scanner.container_escape import assess
from src.models import Candidate, Engine

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def _flagged(cands):
    return {c.line: c.container_escape_potential for c in cands}


def test_algif_vulnerable_is_escape_primitive(scanner):
    cands = scanner.scan(TESTS_DIR / "ground_truth" / "algif_skcipher_vulnerable.c")
    assert cands
    assert all(c.container_escape_potential for c in cands)
    assert any("escape" in c.container_escape_reason.lower() for c in cands)


def test_splice_vulnerable_is_escape_primitive(scanner):
    cands = scanner.scan(TESTS_DIR / "sample_kernel" / "fs" / "splice_race.c")
    flags = _flagged(cands)
    # The vulnerable branch (no pipe_buf_get) is an escape primitive...
    vuln = [c for c in cands if c.mitigation_present is False]
    assert vuln and all(c.container_escape_potential for c in vuln)
    # ...and its reason mentions the namespace boundary.
    assert any("namespace" in c.container_escape_reason for c in vuln)


def test_splice_fixed_is_not_escape(scanner):
    cands = scanner.scan(TESTS_DIR / "sample_kernel" / "fs" / "splice_race.c")
    fixed = [c for c in cands if c.mitigation_present is True]
    assert fixed and not any(c.container_escape_potential for c in fixed)


def test_random_clean_is_not_escape(scanner):
    cands = scanner.scan(TESTS_DIR / "sample_kernel" / "drivers" / "char" / "random.c")
    assert cands
    assert not any(c.container_escape_potential for c in cands)


def test_mitigated_candidate_is_never_escape():
    c = Candidate(
        rule_id="r", engine=Engine.COCCINELLE, file="net/x.c", line=1,
        shared_field="ctx->iv", subsystem="net", mitigation_present=True,
    )
    potential, reason = assess(c)
    assert potential is False
    assert "mitigated" in reason
