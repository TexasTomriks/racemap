# racemap web UI (Flask + vanilla JS)

A single-page front-end over the existing racemap pipeline. The core scanner,
triage, and reporter packages are unchanged — this is purely a UI layer.

## Run

```bash
pip install flask
python web/server.py          # http://127.0.0.1:5005
```

The CLI (`python main.py scan ...`) continues to work exactly as before; the old
Streamlit app (`src/ui/app.py`) is kept but the Flask UI is primary.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET  | `/`                | SPA |
| POST | `/api/scan`        | `{path, llm, kernel_version, patch_gap}` -> ranked candidates |
| POST | `/api/diff`        | `{old, new}` -> NEW/RESOLVED/PERSISTENT |
| POST | `/api/live-scan`   | multipart `.c` upload or `preset` |
| GET  | `/api/semgrep/<i>` | export candidate *i* as a Semgrep rule |
| POST | `/api/update-db`   | refresh patch-gap signature DB |
| GET  | `/api/db-status`   | last DB update |
| GET  | `/api/cache-status`, POST `/api/clear-cache` | triage cache |
| GET  | `/api/patch-gap`   | missing upstream patches from last scan |
| GET  | `/api/export/{json,csv,sarif}` | download last report |

## Notes

* Theme (light/dark) is held in a JS variable — no `localStorage`.
* The call graph uses D3 v7.9.0, vendored at `static/d3.min.js` (unmodified
  upstream bundle, not loaded from a CDN) so the graph — and the "runs
  fully offline" claim — don't depend on network access. If it's ever
  removed or fails to load for some other reason, the graph falls back to
  a deterministic static SVG, so it always renders.

## Self-verification

`python web/verify.py` drives the UI with Playwright and screenshots
light/dark/scan/export/call-graph/diff into `web/screenshots/`, asserting the
fixed-header, non-stretching-sidebar, and button-alignment invariants. It must
be run where a Chromium browser is available.
