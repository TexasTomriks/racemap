"""Live-scan handler for the Streamlit "Live Scan" tab.

Takes raw C source (uploaded or a preset), runs the full racemap pipeline with
the fast offline heuristic backend, and returns a ScanReport. Designed to finish
well within a few seconds for a single driver file.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from src.models import ScanReport
from src.scanner import Scanner, patch_gap as _patch_gap
from src.triage import TriagePipeline

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"

# Demo presets (relative to the repo root).
PRESETS = {
    "Vulnerable driver (tls_sw.c)": "tests/sample_kernel/net/tls/tls_sw.c",
    "Clean driver (random.c)": "tests/sample_kernel/drivers/char/random.c",
    "Mystery driver": "tests/sample_kernel/mystery/mystery_driver.c",
}


def preset_source(name: str) -> str:
    path = ROOT / PRESETS[name]
    return path.read_text(errors="ignore")


def scan_source(source: str, filename: str = "upload.c",
                patch_gap: bool = False) -> tuple[ScanReport, float]:
    """Scan raw C source and return (report, elapsed_seconds)."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / Path(filename).name
        path.write_text(source)
        scanner = Scanner(rules_dir=RULES_DIR, subsystems=[])
        candidates = scanner.scan(path)
        if patch_gap:
            _patch_gap.apply_all(candidates, path)
        results = TriagePipeline(backend="heuristic").triage(candidates)
    elapsed = time.perf_counter() - t0
    report = ScanReport(
        target=filename, candidates_found=len(candidates), results=results,
    )
    return report, elapsed
