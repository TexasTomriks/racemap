"""Tests for the AST-lite structured context builder and token accounting."""

from pathlib import Path

import json
import pytest

from src.models import Candidate, Engine
from src.scanner import Scanner
from src.triage import TriagePipeline
from src.triage.context import (
    build_context, classify_primitive, locks_found, shared_variable,
)
from src.triage.prompts import build_user_prompt, prompt_token_count

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"


def _cand(**kw):
    base = dict(rule_id="r", engine=Engine.COCCINELLE, file="net/x.c", line=2)
    base.update(kw)
    return Candidate(**base)


def test_classify_primitive():
    assert classify_primitive("ctx->iv") == "shared-iv"
    assert classify_primitive("req->imu") == "io_uring"
    assert classify_primitive("pipe->bufs[].page") == "splice"
    assert classify_primitive("gup pages") == "vmsplice"
    assert classify_primitive("skb_shared_info") == "zerocopy"
    assert classify_primitive("copy_user under mmap_read_lock") == "mmap-copy"


def test_shared_variable_extraction():
    assert shared_variable("ctx->iv") == "iv"
    assert shared_variable("gup pages") == "pages"
    assert shared_variable("pipe->bufs[].page") == "page"


def test_locks_found_in_snippet():
    snip = "mutex_lock(&x);\n do_thing();\n mutex_unlock(&x);"
    assert "mutex_lock" in locks_found(snip)


def test_build_context_structure():
    c = _cand(shared_field="ctx->iv", function="foo", subsystem="net",
              taint_callee="helper",
              snippet="skcipher_request_set_crypt(req, sg, sg, len, ctx->iv);")
    ctx = build_context(c)
    expected_keys = {
        "function_name", "zero_copy_primitive", "shared_variable",
        "lock_primitives_found", "lock_to_unlock_window_lines",
        "code_snippet", "taint_callee", "cve_id", "subsystem", "location",
    }
    assert expected_keys <= set(ctx.keys())
    assert ctx["zero_copy_primitive"] == "shared-iv"
    assert ctx["shared_variable"] == "iv"
    assert ctx["taint_callee"] == "helper"


def test_user_prompt_contains_json_and_question():
    c = _cand(shared_field="ctx->iv",
              snippet="skcipher_request_set_crypt(req, sg, sg, len, ctx->iv);")
    prompt = build_user_prompt(c)
    assert "Structured context (JSON):" in prompt
    assert "Differential Locking Analysis" in prompt
    # The embedded context must be valid JSON.
    start = prompt.index("{")
    end = prompt.index("}\n", start) + 1
    json.loads(prompt[start:end])


def test_token_count_is_set_on_result():
    s = Scanner(rules_dir=RULES_DIR, subsystems=[])
    c = s.scan(TESTS_DIR / "ground_truth" / "algif_skcipher_vulnerable.c")[0]
    r = TriagePipeline(backend="heuristic").triage_one(c)
    assert r.token_count > 0
    assert r.token_count == prompt_token_count(c)
