"""SARIF 2.1.0 export for racemap.

Produces a Static Analysis Results Interchange Format document that GitHub Code
Scanning (and other SARIF consumers) can ingest. Each triaged candidate becomes
a SARIF result with a ruleId, level, location, message and racemap-specific
properties (cve_id, container_escape, taint, affected_versions).
"""

from __future__ import annotations

import json
from pathlib import Path

from src import __version__
from src.models import ScanReport, TriageResult, Verdict

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Triage verdict -> SARIF result level.
_LEVEL = {
    Verdict.LIKELY_RACE: "error",
    Verdict.NEEDS_REVIEW: "warning",
    Verdict.TRIAGE_ERROR: "warning",
    Verdict.LIKELY_SAFE: "note",
}


def _rules(report: ScanReport) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in report.results:
        rid = r.candidate.rule_id
        if rid in seen:
            continue
        seen[rid] = {
            "id": rid,
            "name": rid.replace(".", "_"),
            "shortDescription": {"text": r.candidate.message or rid},
            "defaultConfiguration": {"level": _LEVEL[r.verdict]},
            "properties": {"tags": ["security", "race-condition", "kernel"]},
        }
    return list(seen.values())


def _result(r: TriageResult) -> dict:
    c = r.candidate
    tags = ["race-condition"]
    if c.cve_id:
        tags.append(c.cve_id)
    if c.container_escape_potential:
        tags.append("container-escape")
    if c.taint_propagated:
        tags.append("taint-propagated")
    if c.patch_missing:
        tags.append("patch-missing")
    return {
        "ruleId": c.rule_id,
        "level": _LEVEL[r.verdict],
        "message": {"text": f"{r.reasoning} (verdict: {r.verdict.value}, "
                            f"score {r.score:.2f})"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": c.file},
                "region": {"startLine": c.line},
            }
        }],
        "properties": {
            "verdict": r.verdict.value,
            "risk_score": r.score,
            "shared_field": c.shared_field,
            "cve_id": c.cve_id,
            # `ruleId` must resolve to exactly one entry in tool.driver.rules,
            # so a line matched by more than one rule is reported under the
            # primary id with the others recorded here. Without this a
            # code-scanning view grouping by rule id never learns the row was a
            # merge — which is the audience Scanner._dedupe() exists for.
            "also_matched_by": c.also_matched_by,
            "also_cve_ids": c.also_cve_ids,
            "container_escape": c.container_escape_potential,
            "container_escape_reason": c.container_escape_reason,
            "taint_propagated": c.taint_propagated,
            "taint_callee": c.taint_callee,
            "patch_missing": c.patch_missing,
            "affected_versions": c.affected_versions,
            "fixed_in": c.fixed_in,
            "tags": tags,
        },
    }


def to_sarif(report: ScanReport) -> dict:
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "racemap",
                    "version": __version__,
                    "informationUri": "https://github.com/racemap/racemap",
                    "shortDescription": {
                        "text": "Linux kernel shared page-cache / zero-copy race "
                                "scanner with LLM triage."
                    },
                    "rules": _rules(report),
                }
            },
            "properties": {
                "kernel_version": report.kernel_version,
                "subsystems": report.subsystems,
                "candidates_found": report.candidates_found,
            },
            "results": [_result(r) for r in report.ranked()],
        }],
    }


def write_sarif(report: ScanReport, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_sarif(report), indent=2))
    return path
