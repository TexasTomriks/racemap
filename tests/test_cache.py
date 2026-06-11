"""Part 6 — SQLite triage cache + demo mode."""

from pathlib import Path

import pytest

from src.models import Candidate, Engine, Verdict
from src.triage.cache import TriageCache
from src.triage import TriagePipeline


def _cand(line=2):
    return Candidate(rule_id="r", engine=Engine.COCCINELLE, file="net/x.c", line=line,
                     shared_field="ctx->iv", zero_copy_primitive="aead",
                     snippet="skcipher_request_set_crypt(req, sg, sg, len, ctx->iv);")


def test_cache_roundtrip(tmp_path):
    cache = TriageCache(tmp_path / "c.db")
    cand = _cand()
    key = cache.key(cand)
    assert cache.get(key) is None

    pipe = TriagePipeline(backend="heuristic")
    result = pipe.triage_one(cand)
    cache.put(key, result)

    rec = cache.get(key)
    assert rec is not None
    restored = cache.to_result(cand, rec)
    assert restored.verdict == result.verdict
    assert "[CACHED]" in restored.model


def test_demo_mode_serves_from_cache(tmp_path):
    db = tmp_path / "c.db"
    cand = _cand()
    # First populate via a normal cached pipeline.
    warm = TriagePipeline(backend="heuristic", cache_enabled=True, cache_path=db)
    first = warm.triage_one(cand)
    assert "[CACHED]" not in first.model

    # Demo mode must serve the stored entry, marked [CACHED].
    demo = TriagePipeline(backend="heuristic", demo_mode=True, cache_path=db)
    served = demo.triage_one(cand)
    assert served.verdict == first.verdict
    assert "[CACHED]" in served.model


def test_demo_mode_miss_uses_heuristic_offline(tmp_path):
    db = tmp_path / "c.db"
    demo = TriagePipeline(backend="gemini", demo_mode=True, cache_path=db)
    # No cache entry and no LLM call allowed -> heuristic result, not None.
    result = demo.triage_one(_cand(line=9))
    assert result is not None
    assert result.verdict in (Verdict.LIKELY_RACE, Verdict.LIKELY_SAFE,
                              Verdict.NEEDS_REVIEW)


def test_clear_cache(tmp_path):
    cache = TriageCache(tmp_path / "c.db")
    pipe = TriagePipeline(backend="heuristic")
    cache.put(cache.key(_cand()), pipe.triage_one(_cand()))
    assert cache.clear() == 1
    assert cache.get(cache.key(_cand())) is None
