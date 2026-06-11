"""Taint tracking lite tests.

The mystery_driver fixture passes the shared IV into a lockless helper
(myx_stage_iv); taint must mark it propagated and the score must escalate.
"""

from pathlib import Path

import pytest

from src.models import Verdict
from src.scanner import Scanner
from src.scanner import taint
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
MYSTERY = TESTS_DIR / "sample_kernel" / "mystery" / "mystery_driver.c"


@pytest.fixture(scope="module")
def scanner():
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


def test_mystery_driver_taint_propagates(scanner):
    cands = scanner.scan(MYSTERY)
    assert cands, "mystery_driver must produce a candidate"
    c = cands[0]
    assert c.taint_propagated is True
    assert c.taint_callee == "myx_stage_iv"


def test_taint_escalates_risk_score(scanner):
    cands = scanner.scan(MYSTERY)
    triage = TriagePipeline(backend="heuristic")
    result = triage.triage_one(cands[0])
    assert result.verdict == Verdict.LIKELY_RACE
    # Base race score is 0.85; taint propagation adds +0.2 (clamped to 1.0).
    assert result.score > 0.85
    assert result.score == pytest.approx(1.0)


def test_callee_with_lock_is_not_escalated():
    lines = [
        "static void helper(struct ctx *ctx, u8 *iv)",
        "{",
        "    mutex_lock(&ctx->lock);",
        "    ctx->stage = iv[0];",
        "    mutex_unlock(&ctx->lock);",
        "}",
        "static int caller(struct ctx *ctx, u8 *iv)",
        "{",
        "    helper(ctx, iv);",
        "    return 0;",
        "}",
    ]
    from src.models import Candidate, Engine
    c = Candidate(rule_id="r", engine=Engine.COCCINELLE, file="f.c", line=9,
                  shared_field="ctx->iv")
    taint.analyze(c, lines)
    assert c.taint_callee == "helper"
    assert c.taint_propagated is False  # callee holds a lock -> no escalation


def test_no_helper_means_no_taint():
    lines = [
        "static int caller(struct ctx *ctx, u8 *iv)",
        "{",
        "    skcipher_request_set_crypt(req, sg, sg, len, iv);",
        "    return crypto_skcipher_encrypt(req);",
        "}",
    ]
    from src.models import Candidate, Engine
    c = Candidate(rule_id="r", engine=Engine.COCCINELLE, file="f.c", line=3,
                  shared_field="ctx->iv")
    taint.analyze(c, lines)
    # Only kernel APIs (no in-file helper) -> no taint hop.
    assert c.taint_propagated is False
