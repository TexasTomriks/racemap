# Changelog

Entries below track revisions to this repository **after** the Arsenal Europe
2026 submission, newest first. They are independent of the tool's own version
string (`racemap --version`, currently 0.1.0), which has not changed: nothing
here alters the scanner's published behaviour or figures.

## v2.6 — third review round: the fixes' own bugs (2026-07-20)

The reviewer re-checked v2.5 and found a bug inside each of the two code fixes
it had asked for, plus one genuine scoping miss in the web UI. All three are
real and fixed here. It also withdrew one of its earlier findings, having traced
it to its own working notes rather than to anything in this repository.

- **The `iouring` mitigation bucket collapsed two different detectors.**
  v2.5 keyed the mitigation check on a letters-only substring of the rule id, and
  both io_uring rules normalise to contain `iouring`: Pattern A
  (`io-uring-fixed-buffer-no-copy`, about unpinning a registered buffer) and
  Pattern A2 (`io-uring-net-send-no-copy`, about copying before a network send).
  Their mitigations are not interchangeable, so the merged bucket both missed a
  legitimate `skb_copy` fix on A2 and would exonerate an A candidate sitting
  next to an unrelated `sk_msg_memcopy`. That is the same pattern-agnostic
  failure v2.5 set out to remove, narrowed from seven rule families to two.
  Split into `fixedbuffer` and `netsend` fragments, checked before any generic
  match; `io_uring_race.cocci` covers both patterns and is therefore genuinely
  ambiguous, so it now falls through to no verdict rather than a guess.
- **The dedupe merge was prose-only.** v2.5 recorded a collapsed row by
  appending `also matched by <rule_id>` to the message, which a human reading
  the terminal sees and a machine does not. SARIF, CSV and code-scanning views
  group by rule id and CVE, so a second rule firing on the same line was still
  invisible to exactly the CI consumers the dedupe change was written for — and
  a second, *different* CVE was dropped outright. `Candidate` now carries
  `also_matched_by: list[str]` and `also_cve_ids: list[str]` as real fields,
  populated on collapse and emitted in the JSON report.
- **Live Scan never applied the demo-fixture aliasing.** `live_scan.scan_source()`
  set the report target to the bare filename, while `_is_demo_target()` gates the
  web UI's aliasing on `sample_kernel` / `ground_truth` appearing in that target.
  So picking the bundled "Vulnerable driver (tls_sw.c)" preset — which reads
  `tests/sample_kernel/net/tls/tls_sw.c`, containing both `ctx->iv` and
  `ctx->info` — displayed those verbatim, while the Scan view aliased the very
  same file. The README's description of the aliasing scope was accurate about
  intent and wrong about this path. `scan_source()` now takes an `origin` and the
  preset branch passes the fixture path through; an uploaded file has no origin
  and is correctly left unaliased. Candidate counts are unchanged (2 for that
  preset), so the demo video's Live Scan frame still matches.
- **Withdrawn by the reviewer:** the earlier `DEFAULT_SUBSYSTEMS` finding. It
  traced the "three subsystem" scope statement it was comparing against to its
  own private task notes, not to this repository or the submission.
- **Downgraded:** the lore.kernel.org link. Independent corroboration for the
  environment-limitation explanation: fetching the `linux-crypto` list index
  from that environment returns a newest entry dated 2024-05-15, i.e. a stale
  view of the domain rather than a missing page.

Closing the two open notes from the review of these fixes:

- The reviewer could verify the rule-id routing for the built-in detectors and
  the Coccinelle file stems, but had to *infer* it for Semgrep. Measured
  instead: all nine `check_id`s in `rules/semgrep/*.yaml` route correctly, and
  the two that matter here separate as intended —
  `racemap-io-uring-net-send-no-copy` gets the `skb_copy` set,
  `racemap-io-uring-fixed-buffer-no-copy` gets the unpin set.
- `also_matched_by` / `also_cve_ids` are now also emitted in the SARIF result
  property bag, not only in the JSON report. SARIF's `ruleId` must resolve to a
  single entry in `tool.driver.rules`, so the primary id stays as-is and the
  merged ids live alongside it — otherwise a code-scanning view grouping by rule
  id never learns the row was a merge, which is the audience the dedupe change
  was written for. CSV is left alone: it does not carry `rule_id` either, so
  this is not a regression there.

No detector, rule, fixture, or test assertion on the default path changed.
`scan tests/sample_kernel` still reports 12 likely races across 23 candidates,
`validate` still passes, and the suite is still 105 tests.

## v2.5 — second-opinion review: pattern-aware mitigation, lossless dedupe (2026-07-20)

A second reviewer went over the repository independently. Three of its findings
held up and are fixed here; two are recorded below as rejected or reworded.

- **The v2.3 mitigation annotation was pattern-agnostic.** `_GENERIC_MITIGATION_RE`
  was a flat union of every detector's tokens, applied to any engine-reported
  candidate. It would exonerate a shared-IV hit that merely sat near an
  unrelated `put_page()`. That is the same failure that made v2.3's first draft
  exonerate `net/tipc/crypto.c`, and removing one token (`skb_cow_data`) treated
  the symptom. Replaced with `_MITIGATION_BY_RULE`: the check is now chosen from
  the candidate's own `rule_id`, mirroring the matching built-in detector's
  `mitigation` regex, and a rule family that isn't recognised gets **no verdict
  at all** rather than a guess — the triage layer then falls back to its own
  lock/annotation/barrier signals. (Writing the lookup surfaced a third bug of
  the same shape: `"splice"` is a substring of `"vmsplice"`, so the vmsplice
  rule was picking up the splice mitigation set. Ordered accordingly, as
  `_PRIMITIVE_KEYWORDS` already does for the same reason.)
- **`_dedupe()` could silently drop a distinct finding.** Keying on
  `(file, line)` merges the duplicate engine hits it was meant to merge, but on
  a real kernel tree two different rules can legitimately land on one line, and
  the lower-ranked row simply vanished. It now carries the dropped row's
  `cve_id` across and appends an `also matched by <rule_id>` note to the
  message, so a collapse is visible instead of lossy.
- **README conflated two different measurements.** "12 likely races across 23
  candidates at a 0% measured false-positive rate against the ground truth,
  reproducible offline via `scan tests/sample_kernel`" read as one claim from
  one command. It is two: the ground-truth suite lives in `tests/ground_truth/`
  and runs under `pytest tests/test_ground_truth.py` (13 cases), while the
  sample-tree scan is a separate fixture set whose 0% is measured against those
  fixtures' own mitigation annotations. The Validation section now separates
  them and names the command for each.
- **"Per-candidate confidence intervals" overstated what `_confidence_band()`
  does** — it returns a fixed width per verdict path (±0.05 heuristic, ±0.10
  narrowing to ±0.03 for LLM backends by reasoning-step count), not a calibrated
  interval. Reworded to "confidence bands" with the mechanism spelled out.
- **Rejected:** a claim that `DEFAULT_SUBSYSTEMS` (`net, crypto, drivers/char,
  io_uring, fs, mystery`) contradicts a documented three-subsystem scope. No such
  scope statement exists in this repository or the submission; `demo.sh`,
  `demo.ps1` and `main.py`'s docstring each list all six correctly.
- **Rejected after checking:** the reviewer reported that the lore.kernel.org
  patch URL cited under Disclosure does not resolve, and rated it critical. It
  resolves. Verified from a browser on a clean network: the cover letter, the
  `/T/#u` thread view (3 replies, 4 messages), the `/all/` mirror of the same
  message-id, and a full-text search for the author's address — the last
  returning all eleven messages of the v1, v2 and v3 series. Two independent
  automated reviewers failed to fetch it while browsers succeed, which points at
  lore rate-limiting datacenter traffic, not at the link.

No detector, rule, fixture, or test assertion on the default path changed.
`scan tests/sample_kernel` still reports 12 likely races across 23 candidates,
`validate` still passes, and the suite is still 105 tests.

## v2.4 — make the documented `.env` support real (2026-07-20)

Both the README ("or put it in a `.env` file in the project root") and the web
UI sidebar ("Keys read from environment / .env") told users an API key could
live in a `.env` file. Nothing ever read one: every backend goes straight to
`os.environ`, and `python-dotenv` is not a dependency. A key placed in `.env`
was silently ignored and the run quietly fell back to the offline heuristic —
which, because the fallback is deliberately silent, looked like the tool working
rather than the key being dropped.

- New `src/env.py`: a ~20-line loader, no new dependency. Called once at startup
  from `main.py` and `web/server.py`. Comments and malformed lines are skipped,
  surrounding quotes and an `export ` prefix are stripped, and a variable that
  is already exported always beats the file. A missing `.env` returns 0 and is
  the normal case.
- No behaviour change for any published figure: there is no `.env` in the
  repository (it is gitignored), so `scan`, `validate` and the test suite are
  unaffected — still 12 likely races across 23 candidates, ground truth passing,
  105 tests.

## v2.3 — make the Coccinelle/Semgrep path actually work (2026-07-20)

Until this release the README described stage 1 as "Coccinelle and Semgrep rules
(with a regex fallback when those tools are unavailable)". That was wrong, and
testing inside the project's own Docker image — which installs both `spatch` and
`semgrep` — showed exactly how wrong:

- `Scanner.__init__` takes `external_tools`, defaulting to `False`, and **no
  caller anywhere in the tree passes `True`** — not `main.py`, the web UI,
  `diff_mode`, `live_scan`, the Streamlit dashboard, or `scripts/benchmark.py`.
  There was no CLI flag either, so the external engines were unreachable, and
  the built-in matcher was never a fallback: it has always been the only engine.
- Forcing `external_tools=True` with both binaries present produces output
  byte-identical to the default run, because both engines return nothing and
  `if not candidates` silently falls through to the built-in matcher:
  - `spatch 1.3` **cannot parse the shipped `.cocci` files**
    (`shared_iv_no_snapshot.cocci:38`, `memcpy(iv, ctx->iv, ...)` — SmPL syntax
    error), so the Coccinelle rules have never executed;
  - `semgrep 1.170` loads the ten rules fine but scans **0 targets** against the
    bundled fixtures, since its default ignore patterns exclude `tests/`.

Five bugs stood between the shipped rules and a working run. All are fixed, and
`--external-tools` now exists as a real, verified option:

- `rules/coccinelle/shared_iv_no_snapshot.cocci`: the `@safe@` rule declared an
  `expression iv` metavariable while also matching the literal field `ctx->iv`.
  Coccinelle read the field name as the metavariable and rejected the whole
  file. Renamed to `snap`.
- `Scanner._run_coccinelle` now passes `-D report`. The `.cocci` files declare
  `virtual report` and gate their `@script:python` blocks on it, so without that
  flag spatch printed nothing no matter what matched.
- `Scanner._parse_cocci_output` unpacked `RACEMAP:<file>:<line>:<field>` into
  four names when it only ever yields three, so every emitted line raised
  `ValueError` and was silently discarded. Fixed, and paths are relativised
  against the scan target like every other engine's.
- `Scanner._run_coccinelle` now checks spatch's exit status, so a rule file that
  fails to load is reported instead of being indistinguishable from "matched
  nothing" — that is how a broken rule stayed invisible in the first place.
- `Scanner._run_semgrep` relativises `hit["path"]` the same way, and a new
  `.semgrepignore` overrides Semgrep's built-in ignore list, which excludes
  `tests/` and silently reduced any run against the bundled fixtures to zero
  targets.

Two changes were needed to make the merged output usable, both of which leave
the default path byte-identical:

- **`_dedupe()` keys on `(file, line)` and keeps the richest record.** Semgrep
  matches several of its rules on one line and Coccinelle reports sites the
  built-in matcher also finds; the old `(file, line, shared_field)` key let those
  through as separate rows, so an external run listed the same site two or three
  times.
- **Engine-reported candidates are annotated with a mitigation verdict.**
  Coccinelle and Semgrep report a match without saying whether the site is
  already guarded, so every external finding came back "likely race" and the
  exonerated variants disappeared. `_enrich_all()` now fills in
  `mitigation_present` when an engine left it unset, using the same windowed
  check the built-in detectors use. Built-in candidates always arrive with a
  bool and are untouched.

  `skb_cow_data()` is deliberately excluded from that check. A first draft
  included it, which exonerated `net/tipc/crypto.c:26` — precisely the site the
  Dirty Frag fixture exists to catch, since copying the data does not make the
  fragments unshared. Only `skb_has_shared_frag()` qualifies.

Verified in the project's own Docker image, which carries spatch 1.3 and
semgrep 1.170:

| | candidates | likely race |
|---|---|---|
| default (built-in matcher) | 23 | 12 |
| `--external-tools` | 8 | 8 |

The external path finds fewer sites by design: the rule files encode only the
vulnerable shapes, while the built-in matcher also surfaces the guarded variants
so the triage layer has something to exonerate. All nine `.cocci` rules load
cleanly (`exit=0`) and together emit nine matches; Semgrep contributes ten.
Note that `spatch --parse-cocci` reports failures for several rules that run
correctly under `--sp-file ... -D report`, so that check over-reports when the
virtual rule is undefined — use a real invocation to judge a rule.

No detector, rule, fixture, or test assertion on the default path changed.
`scan tests/sample_kernel` still reports 12 likely races across 23 candidates,
`validate` still passes, and the 105-test suite is unchanged.

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

## v1 — Arsenal Europe 2026 submission (as demoed in the video)

State as submitted for review. The algif_skcipher disclosure was still generic
in the README ("a Linux kernel crypto subsystem"), since the patch was not yet
public at submission time. The bundled web-UI demo (`web/server.py`) displays
the `algif_skcipher` / `ctx->iv` fixture under generic aliases
(`crypto_subsystem` / `ctx->shared_buf`) for the on-screen demo — this
redaction is unchanged in v2 and still matches the submitted video exactly.

