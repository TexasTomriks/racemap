"""Regression tests for the Docker-testing bug-fix pass (bugs 1-6)."""

from pathlib import Path

import pytest

from src.models import Verdict
from src.scanner import Scanner, patch_gap
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
SK = TESTS_DIR / "sample_kernel"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def _live(cands):
    return [c for c in cands if c.mitigation_present is not True]


# Bug 1 + 6 — primitive + pattern_name classification per fixture.
@pytest.mark.parametrize("rel,prim,pat", [
    ("net/tls/tls_sw.c", "aead", "aead_inplace_write"),
    ("io_uring/io_uring_crypto.c", "io_uring", "io_uring_shared_buffer"),
    ("fs/splice_race.c", "splice", "splice_pipe_race"),
    ("fs/vmsplice_race.c", "vmsplice", "vmsplice_gup_race"),
    ("net/zerocopy_race.c", "zerocopy", "zerocopy_skb_race"),
    ("net/tipc/crypto.c", "aead", "aead_inplace_write"),
    ("mystery/mystery_driver.c", "aead", "aead_inplace_write"),
])
def test_primitive_and_pattern(scanner, rel, prim, pat):
    live = _live(scanner.scan(SK / rel))
    assert live, f"{rel} produced no live candidate"
    assert live[0].zero_copy_primitive == prim
    assert live[0].pattern_name == pat
    assert live[0].zero_copy_primitive != "unknown"


# Bug 2 — container-escape True for the key fixtures.
@pytest.mark.parametrize("rel", [
    "net/tls/tls_sw.c", "io_uring/io_uring_crypto.c", "net/tipc/crypto.c",
    "../ground_truth/algif_skcipher_vulnerable.c",
])
def test_container_escape_flagged(scanner, rel):
    live = _live(scanner.scan(SK / rel))
    assert any(c.container_escape_potential for c in live)


# Bug 3 — taint escalates mystery_driver to 1.0; scores differ across fixtures.
def test_score_escalation(scanner):
    triage = TriagePipeline(backend="heuristic")
    myst = _live(scanner.scan(SK / "mystery/mystery_driver.c"))[0]
    assert triage.triage_one(myst).score == pytest.approx(1.0)
    iou = _live(scanner.scan(SK / "io_uring/io_uring_crypto.c"))[0]
    # io_uring fixture has no taint and (no patch gap applied) stays at base.
    assert triage.triage_one(iou).score == pytest.approx(0.85)


# Bug 4 — reasoning differs across primitives.
def test_reasoning_is_differentiated(scanner):
    triage = TriagePipeline(backend="heuristic")
    aead = triage.triage_one(_live(scanner.scan(SK / "net/tls/tls_sw.c"))[0])
    splice = triage.triage_one(_live(scanner.scan(SK / "fs/splice_race.c"))[0])
    assert aead.reasoning != splice.reasoning
    assert "aead" in aead.reasoning
    assert "splice" in splice.reasoning
    assert aead.reasoning_steps[0] != splice.reasoning_steps[0]
