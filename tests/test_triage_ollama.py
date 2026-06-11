"""Mocked-Ollama tests: verify the triage pipeline parses structured LLM output
and ranks candidates correctly, without a running Ollama server."""

from unittest.mock import MagicMock, patch

import pytest

from src.models import Candidate, Engine, ScanReport, Verdict
from src.triage import TriagePipeline


def _candidate(line: int, field: str = "ctx->iv", snippet: str = "") -> Candidate:
    return Candidate(
        rule_id="racemap.shared-state-no-snapshot",
        engine=Engine.COCCINELLE,
        file="crypto/algif_skcipher.c",
        line=line,
        function="_skcipher_recvmsg",
        subsystem="crypto",
        snippet=snippet or "skcipher_request_set_crypt(req, src, dst, len, ctx->iv);",
        message="shared state, no snapshot",
        shared_field=field,
    )


def _fake_ollama_response(content: str) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"message": {"content": content}}
    return resp


RACE_JSON = (
    '{"verdict": "likely_race", "confidence": 0.92, "lock_held": false, '
    '"snapshot_taken": false, "reasoning": "ctx->iv used after lock release '
    'with no snapshot."}'
)
SAFE_JSON = (
    '{"verdict": "likely_safe", "confidence": 0.88, "lock_held": true, '
    '"snapshot_taken": true, "reasoning": "snapshot taken under lock."}'
)


@patch("src.triage.backends.ollama.requests")
def test_parses_structured_race_verdict(mock_requests):
    mock_requests.post.return_value = _fake_ollama_response(RACE_JSON)
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(32))

    assert result.verdict == Verdict.LIKELY_RACE
    assert result.confidence == pytest.approx(0.92)
    assert result.snapshot_taken is False
    assert result.lock_held is False
    assert result.model == "ollama:llama3.2"
    assert mock_requests.post.called


@patch("src.triage.backends.ollama.requests")
def test_parses_structured_safe_verdict(mock_requests):
    mock_requests.post.return_value = _fake_ollama_response(SAFE_JSON)
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(20))

    assert result.verdict == Verdict.LIKELY_SAFE
    assert result.snapshot_taken is True


@patch("src.triage.backends.ollama.requests")
def test_ranking_orders_race_above_safe(mock_requests):
    mock_requests.post.side_effect = [
        _fake_ollama_response(RACE_JSON),
        _fake_ollama_response(SAFE_JSON),
    ]
    pipe = TriagePipeline(backend="ollama")
    results = pipe.triage([_candidate(32), _candidate(20)])

    report = ScanReport(target="t", candidates_found=2, results=results)
    ranked = report.ranked()
    assert ranked[0].verdict == Verdict.LIKELY_RACE
    assert ranked[1].verdict == Verdict.LIKELY_SAFE
    assert ranked[0].score > ranked[1].score


@patch("src.triage.backends.ollama.requests")
def test_malformed_json_falls_back_to_heuristic(mock_requests):
    mock_requests.post.return_value = _fake_ollama_response("not json at all")
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(32))

    assert result.verdict == Verdict.LIKELY_RACE
    assert "heuristic" in result.model


@patch("src.triage.backends.ollama.requests")
def test_server_error_falls_through_to_heuristic(mock_requests):
    mock_requests.post.side_effect = Exception("connection refused")
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(32))

    # Fallback is now explicit so the user knows what happened.
    assert result.model == "ollama (fallback: heuristic)"
    assert "heuristic" in result.model
    assert result.verdict == Verdict.LIKELY_RACE
    assert pipe.warnings  # a warning was recorded for the failed backend


@patch("src.triage.backends.ollama.requests")
def test_unlikely_race_normalizes_to_safe(mock_requests):
    """Ollama returning 'unlikely_race' must normalise to LIKELY_SAFE, not None."""
    js = ('{"verdict": "unlikely_race", "confidence": 0.8, "lock_held": true, '
          '"snapshot_taken": true, "reasoning": "lock covers the access.", '
          '"reasoning_steps": []}')
    mock_requests.post.return_value = _fake_ollama_response(js)
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(20))

    assert result is not None
    assert result.verdict == Verdict.LIKELY_SAFE
    assert result.reasoning_steps == []     # empty list must not break parsing
    assert result.model == "ollama:llama3.2"


@patch("src.triage.backends.ollama.requests")
def test_likely_race_stays_race(mock_requests):
    js = ('{"verdict": "likely_race", "confidence": 0.9, '
          '"reasoning": "no snapshot", "reasoning_steps": ["Step 1"]}')
    mock_requests.post.return_value = _fake_ollama_response(js)
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(32))

    assert result is not None
    assert result.verdict == Verdict.LIKELY_RACE


@patch("src.triage.backends.ollama.requests")
def test_unknown_verdict_becomes_needs_review(mock_requests):
    js = '{"verdict": "totally_bogus_value", "confidence": 0.5, "reasoning": "x"}'
    mock_requests.post.return_value = _fake_ollama_response(js)
    pipe = TriagePipeline(backend="ollama")
    result = pipe.triage_one(_candidate(32))

    assert result is not None
    assert result.verdict == Verdict.NEEDS_REVIEW
