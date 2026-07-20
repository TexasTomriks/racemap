"""racemap — Flask web backend.

Thin HTTP layer over the existing scanner / triage / reporter pipeline. No core
logic lives here; every endpoint reuses src.* unchanged. The last scan report is
held module-level so the export endpoints can serialise it.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, request, send_from_directory, Response, render_template

from src import __version__
from src.env import load_dotenv
from src.models import ScanReport, Verdict
from src.scanner import Scanner, diff_mode, patch_gap as _pg, db_updater
from src.triage import TriagePipeline, LLM_CHOICES
from src.reporter import Reporter
from src.reporter.sarif import to_sarif
from src.reporter.semgrep_exporter import export_yaml, filename_for
from src.ui import live_scan

# Honour a .env in the project root, as the README and the sidebar hint promise.
load_dotenv()

RULES_DIR = ROOT / "rules"
KERNEL_VERSIONS = ["4.9", "5.4", "5.10", "5.15", "5.16", "6.0", "6.1",
                   "6.6", "6.8", "6.9", "6.10", "6.12"]

app = Flask(__name__, template_folder=str(ROOT / "web" / "templates"),
            static_folder=str(ROOT / "web" / "static"))

# Module-level last scan (for export endpoints).
LAST_REPORT: ScanReport | None = None


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (ROOT / path)


# --------------------------------------------------------------------------- #
# Display-only redaction for the BUNDLED sample_kernel / ground-truth fixtures.
#
# Pure render-time string substitution on the JSON the web UI renders. It never
# touches detector logic, fixture files, the CLI, or real-kernel-scan output —
# it only fires when the scanned target is one of the bundled demo trees, so a
# scan of a real kernel (/path/to/linux) is displayed verbatim.
# --------------------------------------------------------------------------- #
_DEMO_REDACTIONS = (
    ("algif_skcipher", "crypto_subsystem"),
    ("ctx->iv", "ctx->shared_buf"),
    ("ctx->info", "ctx->shared_info"),
    ("myx_stage_iv", "stage_fn"),
)
_DEMO_DISPLAY_FIELDS = (
    "file", "shared_field", "zero_copy_primitive", "pattern_name", "function",
    "taint_callee", "caller_lock_name", "container_escape_reason",
    "reasoning", "message",
)


def _is_demo_target(target) -> bool:
    t = (target or "").replace("\\", "/")
    return "sample_kernel" in t or "ground_truth" in t


def _demo_scrub(text):
    if not isinstance(text, str):
        return text
    for old, new in _DEMO_REDACTIONS:
        text = text.replace(old, new)
    return text


def _demo_redact_rows(rows):
    for row in rows:
        for f in _DEMO_DISPLAY_FIELDS:
            if isinstance(row.get(f), str):
                row[f] = _demo_scrub(row[f])
        if isinstance(row.get("reasoning_steps"), list):
            row["reasoning_steps"] = [_demo_scrub(x) for x in row["reasoning_steps"]]
    return rows


def _report_json(report: ScanReport) -> dict:
    ranked = report.ranked()
    rows = [Reporter._result_dict(r) for r in ranked]
    if _is_demo_target(report.target):
        _demo_redact_rows(rows)   # display-only, bundled fixtures
    races = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_RACE)
    exo = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_SAFE)
    esc = sum(1 for r in ranked if r.candidate.container_escape_potential)
    fpf = sum(1 for r in ranked if r.candidate.caller_lock_held
              or r.candidate.annotation_protected or r.candidate.barrier_protected)
    clean = sum(1 for r in ranked if r.candidate.mitigation_present is True)
    fp = sum(1 for r in ranked if r.candidate.mitigation_present is True
             and r.verdict == Verdict.LIKELY_RACE)
    by_sub: dict[str, dict] = {}
    for r in ranked:
        d = by_sub.setdefault(r.candidate.subsystem or "other",
                              {"likely_race": 0, "likely_safe": 0, "needs_review": 0})
        d[r.verdict.value] = d.get(r.verdict.value, 0) + 1
    return {
        "target": report.target,
        "kernel_version": report.kernel_version,
        "summary": {"candidates": len(ranked), "races": races, "exonerated": exo,
                    "escape": esc, "fp_filtered": fpf,
                    "fp_rate": round(fp / clean * 100, 1) if clean else 0.0},
        "by_subsystem": by_sub,
        "results": rows,
    }


def _effective_backend(requested: str, results, pipeline) -> dict:
    """Report which triage backend actually produced the verdicts.

    The selected backend always falls back to the offline heuristic when it is
    unavailable (no API key / no local Ollama). Surfacing this prevents silent
    fallback confusion in the UI.
    """
    models = {(r.model or "") for r in results}
    fell_back = bool(pipeline.warnings) or any("fallback" in m for m in models)
    effective = "heuristic" if (requested != "heuristic" and fell_back) else requested
    if requested == "heuristic":
        note = "offline heuristic backend"
    elif fell_back:
        reason = pipeline.warnings[0] if pipeline.warnings else \
            f"{requested} unavailable"
        note = f"{requested} unavailable \u2014 fell back to heuristic ({reason})"
    else:
        note = f"ran on {requested}"
    return {"requested": requested, "effective": effective,
            "fell_back": fell_back, "note": note}


# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html", version=__version__,
                           llm_choices=LLM_CHOICES,
                           kernel_versions=KERNEL_VERSIONS,
                           presets=list(live_scan.PRESETS.keys()))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global LAST_REPORT
    data = request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or "tests/sample_kernel").strip()
    llm = data.get("llm") or "heuristic"
    kver = (data.get("kernel_version") or "").strip()
    if not kver:
        return jsonify({"error": "Kernel version is required."}), 400
    patch_gap = bool(data.get("patch_gap", True))
    subs = data.get("subsystems") or None

    target = _resolve(path)
    if not target.exists():
        return jsonify({"error": f"Path not found: {path}"}), 400
    try:
        scanner = Scanner(rules_dir=RULES_DIR, subsystems=subs, git_cross_ref=True)
        cands = scanner.scan(target)
        if patch_gap:
            _pg.apply_all(cands, target)
        # Cache only the offline heuristic; for a selected LLM backend we run it
        # live so the *effective* backend (and any fallback) is reported honestly
        # rather than masked by a candidate-keyed cache entry.
        pipeline = TriagePipeline(backend=llm, cache_enabled=(llm == "heuristic"))
        results = pipeline.triage(cands)
        report = ScanReport(target=str(target), kernel_version=kver,
                            subsystems=subs or [], candidates_found=len(cands),
                            results=results)
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": f"Scan failed: {exc}"}), 500
    LAST_REPORT = report
    out = _report_json(report)
    out["backend"] = _effective_backend(llm, results, pipeline)
    return jsonify(out)


@app.route("/api/diff", methods=["POST"])
def api_diff():
    data = request.get_json(force=True, silent=True) or {}
    old, new = data.get("old", ""), data.get("new", "")
    if not _resolve(old).exists() or not _resolve(new).exists():
        return jsonify({"error": "Both paths must exist."}), 400
    entries = diff_mode.compare(_resolve(old), _resolve(new), RULES_DIR)
    counts = diff_mode.summary(entries)
    return jsonify({
        "summary": {"new": counts[diff_mode.NEW], "resolved": counts[diff_mode.RESOLVED],
                    "persistent": counts[diff_mode.PERSISTENT]},
        "results": [{"file": e.file, "line": e.line, "pattern": e.pattern,
                     "status": e.status, "score": e.score, "cve_id": e.cve_id}
                    for e in entries],
    })


@app.route("/api/live-scan", methods=["POST"])
def api_live_scan():
    global LAST_REPORT
    preset = (request.form.get("preset") or "").strip()
    origin = None
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        source = f.read().decode("utf-8", errors="ignore")
        name = f.filename
    elif preset and preset in live_scan.PRESETS:
        source = live_scan.preset_source(preset)
        # Keep the fixture path, not just the basename: the demo-fixture
        # aliasing below is keyed on it, and a preset *is* a bundled fixture.
        origin = live_scan.PRESETS[preset]
        name = Path(origin).name
    else:
        return jsonify({"error": "Choose a preset or upload a .c file."}), 400
    report, secs = live_scan.scan_source(source, name, patch_gap=True,
                                         origin=origin)
    LAST_REPORT = report
    out = _report_json(report)
    out["filename"] = name
    out["elapsed_ms"] = round(secs * 1000, 1)
    return jsonify(out)


@app.route("/api/semgrep/<int:idx>")
def api_semgrep(idx: int):
    if LAST_REPORT is None:
        return jsonify({"error": "No scan yet."}), 400
    ranked = LAST_REPORT.ranked()
    if idx < 0 or idx >= len(ranked):
        return jsonify({"error": "Index out of range."}), 400
    c = ranked[idx].candidate
    return Response(export_yaml(c), mimetype="text/yaml",
                    headers={"Content-Disposition": f"attachment; filename={filename_for(c)}"})


@app.route("/api/update-db", methods=["POST"])
def api_update_db():
    result = db_updater.fetch_latest_signatures()
    db_updater.update_local_db(result)
    return jsonify({"updated": result["updated"], "new": result.get("new", 0),
                    "timestamp": result["timestamp"], "errors": result.get("errors", [])})


@app.route("/api/db-status")
def api_db_status():
    info = db_updater.last_update_info()
    return jsonify({"last_updated": info["timestamp"], "age_days": info["age_days"]})


@app.route("/api/cache-status")
def api_cache_status():
    from src.triage.cache import TriageCache, DEFAULT_DB
    cache = TriageCache()
    n = cache._conn.execute("SELECT COUNT(*) FROM triage_cache").fetchone()[0]
    return jsonify({"count": n, "path": str(DEFAULT_DB)})


@app.route("/api/clear-cache", methods=["POST"])
def api_clear_cache():
    from src.triage.cache import TriageCache
    return jsonify({"cleared": TriageCache().clear()})


@app.route("/api/patch-gap")
def api_patch_gap():
    if LAST_REPORT is None:
        return jsonify({"missing": []})
    cands = [r.candidate for r in LAST_REPORT.results]
    missing = _pg.missing_patches(cands)
    if _is_demo_target(LAST_REPORT.target):
        for m in missing:
            if isinstance(m.get("signature_for"), str):
                m["signature_for"] = _demo_scrub(m["signature_for"])
    return jsonify({"missing": missing})


# -- exports ---------------------------------------------------------------- #
@app.route("/api/export/json")
def export_json():
    if LAST_REPORT is None:
        return jsonify({"error": "No scan yet."}), 400
    payload = {"target": LAST_REPORT.target, "kernel_version": LAST_REPORT.kernel_version,
               "results": [Reporter._result_dict(r) for r in LAST_REPORT.ranked()]}
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=racemap_report.json"})


@app.route("/api/export/csv")
def export_csv():
    if LAST_REPORT is None:
        return jsonify({"error": "No scan yet."}), 400
    buf = io.StringIO()
    rows = [{"file": r.candidate.file, "line": r.candidate.line,
             "pattern": r.candidate.pattern_name, "verdict": r.verdict.value,
             "score": r.score, "cve": r.candidate.cve_id or "",
             "escape": r.candidate.container_escape_potential}
            for r in LAST_REPORT.ranked()]
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=racemap_report.csv"})


@app.route("/api/export/sarif")
def export_sarif():
    if LAST_REPORT is None:
        return jsonify({"error": "No scan yet."}), 400
    return Response(json.dumps(to_sarif(LAST_REPORT), indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=scan.sarif"})


@app.route("/static/<path:p>")
def static_files(p):
    return send_from_directory(app.static_folder, p)


if __name__ == "__main__":
    import os as _os
    # Defaults to loopback-only for safety on a bare-metal / local run. Inside
    # Docker, RACEMAP_HOST=0.0.0.0 is required for the -p 5005:5005 port
    # mapping to actually reach the process (binding to 127.0.0.1 inside the
    # container is only reachable from within the container's own netns).
    host = _os.environ.get("RACEMAP_HOST", "127.0.0.1")
    app.run(host=host, port=5005, debug=False)
