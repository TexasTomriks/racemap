"""Semgrep rule exporter tests."""

from pathlib import Path

import pytest

from src.reporter.semgrep_exporter import export_yaml, filename_for
from src.scanner import Scanner

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"


@pytest.fixture(scope="module")
def algif_candidate():
    s = Scanner(rules_dir=RULES_DIR, subsystems=[])
    cands = s.scan(TESTS_DIR / "ground_truth" / "algif_skcipher_vulnerable.c")
    assert cands
    return cands[0]


@pytest.fixture(scope="module")
def cve_candidate():
    s = Scanner(rules_dir=RULES_DIR, subsystems=[])
    cands = s.scan(TESTS_DIR / "ground_truth" / "cve_2022_0847" / "dirtypipe.c")
    return next(c for c in cands if c.cve_id == "CVE-2022-0847")


def test_export_is_valid_yaml(algif_candidate):
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(export_yaml(algif_candidate))
    assert "rules" in doc
    assert len(doc["rules"]) == 1


def test_pattern_field_present_and_correct(algif_candidate):
    yaml = pytest.importorskip("yaml")
    rule = yaml.safe_load(export_yaml(algif_candidate))["rules"][0]
    assert rule["languages"] == ["c"]
    assert rule["severity"] == "WARNING"
    pat = rule["patterns"][0]["pattern"]
    assert "skcipher_request_set_crypt" in pat
    assert rule["metadata"]["racemap_version"]
    assert "export_timestamp" in rule["metadata"]


def test_cve_export_is_error_severity_with_cve_meta(cve_candidate):
    yaml = pytest.importorskip("yaml")
    rule = yaml.safe_load(export_yaml(cve_candidate))["rules"][0]
    assert rule["severity"] == "ERROR"
    assert rule["metadata"]["cve_id"] == "CVE-2022-0847"


def test_filename_is_slugged(algif_candidate):
    fn = filename_for(algif_candidate)
    assert fn.startswith("racemap-export-")
    assert fn.endswith(".yaml")
