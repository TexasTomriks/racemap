#!/usr/bin/env python3
"""racemap benchmark harness (taint + patch-gap enabled).

Runs the full scan + heuristic-triage pipeline over tests/sample_kernel/ N times
and reports candidate counts, taint propagation hits, missing-patch flags, triage
timing, and false-positive / false-negative rates.

Ground truth for FP/FN is the scanner's mitigation_present flag: mitigation_present
True ⇒ a fixed (clean) variant that should be triaged likely_safe; False ⇒ a
vulnerable variant that should be triaged likely_race.

Writes results/benchmark.json and results/benchmark_final.json.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import __version__
from src.models import Verdict
from src.scanner import Scanner, patch_gap
from src.triage import TriagePipeline

TARGET = ROOT / "tests" / "sample_kernel"
RULES_DIR = ROOT / "rules"


def _files_scanned() -> int:
    scanner = Scanner(rules_dir=RULES_DIR, subsystems=None, external_tools=False)
    return sum(1 for _ in scanner._iter_sources(TARGET))


def run(n: int = 100) -> dict:
    triage = TriagePipeline(backend="heuristic")
    raw, after, scan_t, triage_t = [], [], [], []
    taint_hits, missing_hits = [], []
    fp = fn = clean_total = vuln_total = 0

    for _ in range(n):
        scanner = Scanner(rules_dir=RULES_DIR, subsystems=None, external_tools=False)
        t0 = time.perf_counter()
        candidates = scanner.scan(TARGET)
        patch_gap.apply_all(candidates, TARGET)
        t1 = time.perf_counter()
        results = triage.triage(candidates)
        t2 = time.perf_counter()

        scan_t.append(t1 - t0)
        triage_t.append(t2 - t1)
        raw.append(len(candidates))
        after.append(sum(1 for r in results if r.verdict == Verdict.LIKELY_RACE))
        taint_hits.append(sum(1 for c in candidates if c.taint_propagated))
        missing_hits.append(sum(1 for c in candidates if c.patch_missing))

        for r in results:
            mp = r.candidate.mitigation_present
            is_race = r.verdict == Verdict.LIKELY_RACE
            if mp is True:
                clean_total += 1
                fp += int(is_race)
            elif mp is False:
                vuln_total += 1
                fn += int(not is_race)

    return {
        "tool": "racemap",
        "version": __version__,
        "runs": n,
        "target": str(TARGET.relative_to(ROOT)),
        "backend": "heuristic",
        "files_scanned": _files_scanned(),
        "mean_raw_candidates": round(statistics.mean(raw), 2),
        "candidates_before_triage": round(statistics.mean(raw), 2),
        "mean_after_triage": round(statistics.mean(after), 2),
        "candidates_after_triage": round(statistics.mean(after), 2),
        "taint_propagation_hits": round(statistics.mean(taint_hits), 2),
        "missing_patch_flags": round(statistics.mean(missing_hits), 2),
        "mean_scan_seconds": round(statistics.mean(scan_t), 6),
        "mean_triage_seconds": round(statistics.mean(triage_t), 6),
        "mean_triage_ms": round(statistics.mean(triage_t) * 1000, 3),
        "clean_candidates_total": clean_total,
        "vulnerable_candidates_total": vuln_total,
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate": round((fp / clean_total) if clean_total else 0.0, 4),
        "false_negative_rate": round((fn / vuln_total) if vuln_total else 0.0, 4),
    }


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    print(f"Benchmarking racemap over {TARGET.name}/ x{n} "
          f"(heuristic, taint + patch-gap enabled) ...")
    data = run(n)
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "benchmark.json").write_text(json.dumps(data, indent=2))
    (ROOT / "results" / "benchmark_final.json").write_text(json.dumps(data, indent=2))
    print(f"  files scanned          : {data['files_scanned']}")
    print(f"  candidates before triage: {data['candidates_before_triage']}")
    print(f"  candidates after triage : {data['candidates_after_triage']}  (likely_race)")
    print(f"  taint propagation hits  : {data['taint_propagation_hits']}")
    print(f"  missing patch flags     : {data['missing_patch_flags']}")
    print(f"  mean triage time        : {data['mean_triage_ms']} ms")
    print(f"  false positive rate     : {data['false_positive_rate'] * 100:.1f}%")
    print(f"  false negative rate     : {data['false_negative_rate'] * 100:.1f}%")
    print("Wrote results/benchmark.json and results/benchmark_final.json")


if __name__ == "__main__":
    main()
