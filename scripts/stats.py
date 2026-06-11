#!/usr/bin/env python3
"""Print the headline triage-reduction metric from results/benchmark.json.

Produces the "raw -> after triage" line used in the Arsenal submission abstract.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "results" / "benchmark.json"


def main() -> None:
    if not DATA.exists():
        sys.exit("results/benchmark.json not found — run scripts/benchmark.py first.")
    d = json.loads(DATA.read_text())
    raw = d["mean_raw_candidates"]
    after = d["mean_after_triage"]
    fp_rate = d["false_positive_rate"] * 100
    fn_rate = d["false_negative_rate"] * 100

    print(
        f"Raw candidates: {raw} → After triage: {after} → "
        f"False positive rate: {fp_rate:.1f}%"
    )
    extra = ""
    if "taint_propagation_hits" in d:
        extra = (f"; taint hits: {d['taint_propagation_hits']}; "
                 f"missing patches: {d.get('missing_patch_flags', 0)}")
    print(
        f"(over {d['runs']} runs of {d['target']}; "
        f"false negative rate: {fn_rate:.1f}%; "
        f"mean triage {d['mean_triage_seconds'] * 1000:.3f} ms{extra})"
    )


if __name__ == "__main__":
    main()
