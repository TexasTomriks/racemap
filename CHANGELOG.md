# Changelog

## v1 — Arsenal Europe 2026 submission (as demoed in the video)

State as submitted for review. The algif_skcipher disclosure was still generic
in the README ("a Linux kernel crypto subsystem"), since the patch was not yet
public at submission time. The bundled web-UI demo (`web/server.py`) displays
the `algif_skcipher` / `ctx->iv` fixture under generic aliases
(`crypto_subsystem` / `ctx->shared_buf`) for the on-screen demo — this
redaction is unchanged in v2 and still matches the submitted video exactly.

## v2 — post-acceptance reconciliation (2026-07-19)

The patch series was accepted by the stable maintainers on 2026-07-17 and the
technical analysis is now public. This pass reconciles the repo with that:

- **Disclosure**: README now names `crypto/algif_skcipher.c` and `ctx->iv`
  explicitly, with the report/acceptance dates, the seven queued stable
  trees, and the public lore.kernel.org patch link. `tests/ground_truth/expected.json`
  no longer says "under embargo — CVE pending".
- **Validation**: added a README section documenting the ground-truth set
  (Dirty Pipe CVE-2022-0847, CVE-2022-2590 — both with vulnerable/fixed
  fixture pairs and used for the `validate` pass/fail check) versus the
  Dirty Frag / CVE-2026-43284 rule, which is demonstrated live against a
  real `net/tipc/crypto.c` fixture (flagged correctly in every scan) but has
  no fixed-variant counterpart, so it "informs" the rule set rather than
  being part of the formal recall/false-positive measurement.
- **Terminal output bug**: `python main.py validate` / `scan --kernel-version`
  was printing `"(no fix yet)"` next to the algif finding — misleading now
  that a fix is accepted and queued. Changed to `"(no fixed_in on record —
  check upstream)"`.
- **`--llm` default**: `scan` now defaults to `heuristic` (was `ollama`),
  matching the README's "runs fully offline by default" claim.
- **Missing dependency**: `requirements.txt` never declared `flask`, so the
  web UI shown in the demo video could not run from a clean
  `pip install -r requirements.txt`. Added.
- **Web UI docs**: README now documents how to launch the Flask web UI
  (`python web/server.py`, port 5005) and the unused alternate Streamlit
  dashboard (`src/ui/app.py`), plus a note on the demo-fixture redaction
  above so it isn't mistaken for an inconsistency.
- **Docker**: added a `web` service to `docker-compose.yml` and a
  `docker run --entrypoint python racemap web/server.py` example, since
  neither existed before.
- Misc: `demo.sh` / `demo.ps1` presenter notes updated to the verified
  "12 likely races / 23 candidates" figure; stale comments in
  `src/scanner/version_tracker.py` and its test corrected.

No detector logic, rule, or test assertion changed in this pass — only
disclosure text, one terminal string, one CLI default, one missing
dependency, and documentation.
