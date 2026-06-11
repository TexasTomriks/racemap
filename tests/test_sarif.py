"""SARIF 2.1.0 export tests."""

from pathlib import Path

import pytest

from src.models import ScanReport
from src.reporter.sarif import to_sarif, write_sarif
from src.scanner import Scanner
from src.triage import TriagePipeline

TESTS_DIR = Path(__file__).parent
RULES_DIR = TESTS_DIR.parent / "rules"
SAMPLE = TESTS_DIR / "sample_kernel"


@pytest.fixture(scope="module")
def report():
    scanner = Scanner(rules_dir=RULES_DIR, subsystems=None)
    triage = TriagePipeline(backend="heuristic")
    cands = scanner.scan(SAMPLE)
    return ScanReport(
        target=str(SAMPLE), kernel_version="6.8",
        candidates_found=len(cands), results=triage.triage(cands),
    )


def test_sarif_top_level_structure(report):
    doc = to_sarif(report)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_sarif_tool_metadata(report):
    driver = to_sarif(report)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "racemap"
    assert driver["version"]
    assert len(driver["rules"]) >= 1
    assert all("id" in rule for rule in driver["rules"])


def test_sarif_result_count_matches(report):
    doc = to_sarif(report)
    assert len(doc["runs"][0]["results"]) == len(report.results)


def test_sarif_result_shape(report):
    res = to_sarif(report)["runs"][0]["results"][0]
    assert res["ruleId"]
    assert res["level"] in {"error", "warning", "note"}
    loc = res["locations"][0]["physicalLocation"]
    assert "uri" in loc["artifactLocation"]
    assert loc["region"]["startLine"] >= 1
    assert "tags" in res["properties"]


def test_sarif_levels_map_verdicts(report):
    results = to_sarif(report)["runs"][0]["results"]
    # At least one error (likely_race) and one note (likely_safe) on sample_kernel.
    levels = {r["level"] for r in results}
    assert "error" in levels
    assert "note" in levels


def test_write_sarif_roundtrip(report, tmp_path):
    import json
    out = write_sarif(report, tmp_path / "scan.sarif")
    data = json.loads(Path(out).read_text())
    assert data["version"] == "2.1.0"
