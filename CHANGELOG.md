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

## v2.2 — Dirty Frag promoted to a measured ground-truth pair (2026-07-20)

The demo video's closing card reads "Validated against public CVEs — Dirty
Pipe (CVE-2022-0847) · Dirty Frag (CVE-2026-43284)". Until this pass that was
only true of Dirty Pipe: the Dirty Frag pattern shipped as a single vulnerable
fixture (`tests/sample_kernel/net/tipc/crypto.c`), flagged correctly in every
scan but with no fixed-variant counterpart, so it was not part of the measured
recall/false-positive set. Rather than qualify the claim, this pass makes it
true.

- **New ground-truth pair**: `tests/ground_truth/cve_2026_43284/tipc_inplace.c`
  carries the vulnerable and guarded variants via `#ifndef FIXED` / `#else`,
  matching the layout of the Dirty Pipe and CVE-2022-2590 fixtures, and is
  registered in `tests/ground_truth/expected.json` as a measured case
  (`expect_race` + `expect_safe`). Test count 104 → 105.
- **Detector consistency fix** (`src/scanner/scanner.py`): the
  `racemap.inplace-decrypt-no-cow` detector used to `continue` — emitting
  nothing at all — when an `skb_has_shared_frag()` guard was present. Every
  other detector emits the candidate and sets `mitigation_present`, letting the
  triage layer exonerate it. Silently dropping the guarded site meant the
  *fixed* variant of this pattern was invisible, which is why no pair could
  exist. It now sets `mitigation_present` like the rest, and uses the
  preprocessor-aware `_clip_window()` so a `#ifndef FIXED` branch cannot read
  the guard out of its paired `#else`.
- **Deliberately unchanged**: the detector still does not set `cve_id` on
  in-place-decrypt candidates. Adding it would tag
  `net/tipc/crypto.c` rows in the `--kernel-version` "affected by" listing,
  which the demo video shows; the validation is the measured vulnerable/fixed
  pair, not the metadata tag.
- **Verified**: `scan tests/sample_kernel` still reports 12 likely races across
  23 candidates and `validate` output is byte-identical, so every figure shown
  in the demo video still holds. The new fixture lives under
  `tests/ground_truth/`, which the sample-tree scan does not walk.
- Docs, same pass: the README now states that JSON/CSV/SARIF exports are always
  verbatim (the aliasing is view-only), and `docs/screenshots/scan.png` is
  captioned as a v1.0 capture predating the aliasing — it shows the real
  identifiers, which previously read as a contradiction of the Web UI note.
  `tests/test_ground_truth.py`'s module docstring was updated from "two known
  CVEs" to reflect the third.

## v2.1 — follow-up fixes from an independent review (2026-07-19)

An independent LLM review of v2 caught two real remaining issues:

- **v2's README claim about CLI redaction was inaccurate.** The README said the
  demo-fixture redaction "never touches ... the CLI," but `src/reporter/reporter.py`
  had its own, separate redaction layer (different aliases than the web UI's —
  `ctx->(redacted)` vs. `ctx->shared_buf` — and a hardcoded fake report target
  `ground_truth/crypto_subsystem`). Now that the disclosure is public and the
  demo video never shows terminal output, this CLI-side redaction served no
  purpose and only risked an auditor finding `python main.py validate` printing
  something the README explicitly said it wouldn't. Removed the CLI redaction
  entirely (`reporter.py` now renders every identifier verbatim, always) and
  fixed `main.py`'s `validate` command to report a real target name
  (`ground_truth/algif_skcipher`). The web UI's redaction (`web/server.py`) is
  unchanged — it must still match the locked demo video.
- **The documented Docker web UI command was silently broken.** `web/server.py`
  bound to `127.0.0.1` unconditionally; inside a container that's unreachable
  from the host even with `-p 5005:5005` mapped. Added a `RACEMAP_HOST` env var
  (defaults to `127.0.0.1` for safe local/bare-metal use), set to `0.0.0.0` in
  `docker-compose.yml`'s `web` service and in the README's `docker run` example.

(A reviewer also flagged that GitFront appeared to still show v1 content —
that was a CDN caching artifact on the reviewer's side, not an actual sync
problem; re-fetching with a cache-busting query param confirmed GitFront was
already serving v2 correctly.)
