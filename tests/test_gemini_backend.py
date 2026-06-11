"""Gemini backend tests — new google-genai SDK + explicit heuristic fallback."""

import sys
import types as pymod
from unittest import mock

import pytest

from src.models import Candidate, Engine, Verdict
from src.triage import TriagePipeline
from src.triage.backends.gemini import GeminiBackend

RACE_JSON = ('{"verdict":"likely_race","confidence":0.9,"lock_held":false,'
             '"snapshot_taken":false,"reasoning":"shared iv, no snapshot",'
             '"reasoning_steps":["Step 1: aead"]}')


def _cand():
    return Candidate(rule_id="r", engine=Engine.COCCINELLE, file="net/x.c", line=2,
                     shared_field="ctx->iv", zero_copy_primitive="aead")


def _fake_genai(capture: dict, raise_exc: bool = False) -> dict:
    """Build fake google.genai / google.genai.types modules for sys.modules."""
    genai = pymod.ModuleType("google.genai")
    types_mod = pymod.ModuleType("google.genai.types")

    class GenerateContentConfig:
        def __init__(self, **kw):
            capture["config"] = kw

    types_mod.GenerateContentConfig = GenerateContentConfig

    class _Resp:
        text = RACE_JSON

    class _Models:
        def generate_content(self, model, contents, config):
            capture["model"] = model
            capture["contents"] = contents
            if raise_exc:
                raise RuntimeError("boom-403 PERMISSION_DENIED")
            return _Resp()

    class _Client:
        def __init__(self, api_key=None):
            capture["api_key"] = api_key
            self.models = _Models()

    genai.Client = _Client
    genai.types = types_mod
    google = pymod.ModuleType("google")
    google.genai = genai
    return {"google": google, "google.genai": genai, "google.genai.types": types_mod}


def test_gemini_uses_new_genai_sdk(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    cap: dict = {}
    with mock.patch.dict(sys.modules, _fake_genai(cap)):
        backend = GeminiBackend()
        assert backend.is_available() is True
        result = backend.triage(_cand())

    assert result is not None
    assert result.verdict == Verdict.LIKELY_RACE
    assert result.model == "gemini:gemini-2.0-flash"
    assert cap["api_key"] == "test-key"
    assert cap["model"] == "gemini-2.0-flash"
    assert cap["config"]["response_mime_type"] == "application/json"
    assert cap["config"]["system_instruction"]


def test_gemini_api_error_falls_back_with_warning(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    cap: dict = {}
    with mock.patch.dict(sys.modules, _fake_genai(cap, raise_exc=True)):
        pipe = TriagePipeline(backend="gemini")
        result = pipe.triage_one(_cand())

    assert result.verdict == Verdict.LIKELY_RACE
    # Verbose output must show the fallback explicitly.
    assert result.model == "gemini (fallback: heuristic)"
    # The actual error is logged as a warning.
    assert any("boom-403" in w for w in pipe.warnings)


def test_gemini_missing_key_falls_back_with_warning(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    pipe = TriagePipeline(backend="gemini")
    result = pipe.triage_one(_cand())

    assert result.model == "gemini (fallback: heuristic)"
    assert any("GEMINI_API_KEY not set" in w for w in pipe.warnings)
