"""Ground-truth validation.

racemap must:
  * retroactively surface the algif_skcipher race and exonerate its fix,
  * flag each zero-copy attack-surface pattern (A-D) vulnerable variant and
    exonerate the fixed variant,
  * surface the known CVEs — Dirty Pipe and the mmap_lock race carry a cve_id;
    Dirty Frag (CVE-2026-43284) is measured as a vulnerable/fixed pair only,
    since the in-place-decrypt detector does not tag candidates with a cve_id.

All run with the regex-fallback scanner + heuristic triage, so they pass with
no kernel toolchain, no Ollama and no API key.
"""

import json
from pathlib import Path

import pytest

from src.models import Verdict
from src.scanner import Scanner
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
GT_DIR = TESTS_DIR / "ground_truth"
RULES_DIR = TESTS_DIR.parent / "rules"
EXPECTED = json.loads((GT_DIR / "expected.json").read_text())


@pytest.fixture(scope="module")
def scanner():
    # subsystems=[] disables scope filtering so single-file fixtures are scanned.
    return Scanner(rules_dir=RULES_DIR, subsystems=[])


@pytest.fixture(scope="module")
def triage():
    return TriagePipeline(backend="heuristic")


# -- algif_skcipher ---------------------------------------------------------

def test_vulnerable_is_flagged(scanner):
    candidates = scanner.scan(GT_DIR / "algif_skcipher_vulnerable.c")
    assert candidates, "vulnerable algif_skcipher fixture must produce a candidate"
    c = candidates[0]
    assert c.shared_field == "ctx->iv"
    assert "skcipher_request_set_crypt" in c.snippet


def test_vulnerable_triaged_as_race(scanner, triage):
    results = triage.triage(scanner.scan(GT_DIR / "algif_skcipher_vulnerable.c"))
    assert results
    top = max(results, key=lambda r: r.score)
    assert top.verdict == Verdict.LIKELY_RACE
    assert top.snapshot_taken is False
    assert top.reasoning_steps, "heuristic must emit chain-of-thought steps"


def test_fixed_is_not_a_race(scanner, triage):
    results = triage.triage(scanner.scan(GT_DIR / "algif_skcipher_fixed.c"))
    if results:
        top = max(results, key=lambda r: r.score)
        assert top.verdict == Verdict.LIKELY_SAFE
        assert top.snapshot_taken is True


def test_ranking_puts_race_above_safe(scanner, triage):
    vuln = triage.triage(scanner.scan(GT_DIR / "algif_skcipher_vulnerable.c"))
    fixed = triage.triage(scanner.scan(GT_DIR / "algif_skcipher_fixed.c"))
    assert max(r.score for r in vuln) > max((r.score for r in fixed), default=0.0)


# -- zero-copy patterns A-D + CVEs (one fixture file per case) --------------

@pytest.mark.parametrize("case", EXPECTED["cases"], ids=[c["id"] for c in EXPECTED["cases"]])
def test_pattern_vulnerable_flagged_and_fixed_exonerated(scanner, triage, case):
    results = triage.triage(scanner.scan(TESTS_DIR / case["path"]))
    assert results, f"{case['id']} must produce candidates"

    verdicts = {r.verdict for r in results}
    fields = {r.candidate.shared_field for r in results}
    assert case["shared_field"] in fields

    if case.get("expect_race"):
        assert Verdict.LIKELY_RACE in verdicts, f"{case['id']} vulnerable not flagged"
    if case.get("expect_safe"):
        assert Verdict.LIKELY_SAFE in verdicts, f"{case['id']} fixed not exonerated"


@pytest.mark.parametrize(
    "case",
    [c for c in EXPECTED["cases"] if c.get("cve_id")],
    ids=[c["id"] for c in EXPECTED["cases"] if c.get("cve_id")],
)
def test_cve_id_is_surfaced(scanner, triage, case):
    results = triage.triage(scanner.scan(TESTS_DIR / case["path"]))
    cve_ids = {r.candidate.cve_id for r in results if r.candidate.cve_id}
    assert case["cve_id"] in cve_ids, f"{case['cve_id']} not surfaced"

    # The vulnerable variant carrying the CVE must be triaged as a race.
    cve_race = [
        r for r in results
        if r.candidate.cve_id == case["cve_id"] and r.verdict == Verdict.LIKELY_RACE
    ]
    assert cve_race, f"{case['cve_id']} vulnerable variant not flagged likely_race"
