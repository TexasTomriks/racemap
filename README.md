# racemap

**A Linux kernel race-condition scanner with deterministic LLM triage.**

racemap scans Linux kernel source for shared page-cache and zero-copy
asynchronous patterns that can race. Static analysis does the finding: it
surfaces candidate sites where shared state is handed to a deferred operation
without a copy or ownership transfer. A deterministic LLM layer then acts
strictly as a **triage filter** — it does not find bugs, it only reduces false
positives by judging whether each candidate is already adequately protected.

![Scan results](docs/screenshots/scan.png)

*Recorded on v1.0, before the disclosure went public — this screenshot predates
the demo-fixture aliasing described under [Web UI](#web-ui) and so shows the
real identifiers.*

## How it works

racemap is two layers:

**1. Static candidate detection.** Coccinelle and Semgrep rules (with a regex
fallback when those tools are unavailable) match shared page-cache and zero-copy
async patterns across the target subsystems. This layer is responsible for
recall — it casts a wide net and produces candidates.

**2. Deterministic triage.** Each candidate is triaged by a pluggable backend
(Ollama, Anthropic, OpenAI, or Gemini, with an offline heuristic fallback that
makes runs fully reproducible). The triage layer reduces false positives by
reasoning over locking and ownership sufficiency: caller-lock traversal, Sparse
annotations, memory barriers, interrupt-context detection, and workqueue
detection. It classifies each candidate as *likely race*, *likely safe*, or
*needs review* — it never generates exploit code.

## Features

- Multi-backend triage: Ollama / Anthropic / OpenAI / Gemini, with a
  deterministic offline heuristic fallback
- Export to SARIF 2.1.0, JSON, and CSV
- Diff mode — compare findings between two kernel trees (new / resolved /
  persistent)
- Patch-gap analysis — flag candidates whose known upstream fix is absent
- Git-log cross-reference for recently-modified hot spots
- Per-candidate confidence intervals
- SQLite response cache for fast, repeatable runs
- Interactive call-graph visualization in the web UI
- Live "bring your own driver" scan — paste or upload a single `.c` file

![Live scan](docs/screenshots/live_scan.png)

## Install

**Docker:**

```bash
docker build -t racemap .
docker run --rm racemap scan <path>

# Web UI (overrides the CLI entrypoint, maps the Flask port; RACEMAP_HOST is
# required — binding to the default 127.0.0.1 inside the container would be
# unreachable from the host despite the port mapping)
docker run --rm -p 5005:5005 -e RACEMAP_HOST=0.0.0.0 --entrypoint python racemap web/server.py
# open http://127.0.0.1:5005
```

**pip:**

```bash
pip install -r requirements.txt
python main.py scan <path>
```

## Configuration

racemap runs fully offline with the default `heuristic` backend — no API key
required, and runs are deterministic.

To use an LLM triage backend, set the matching environment variable (or put it
in a `.env` file in the project root):

| Backend | Variable |
|---------|----------|
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY` |

Ollama needs no key — it talks to a local Ollama server.

If a selected backend's key is unset (or the backend is otherwise unavailable),
racemap automatically falls back to the offline `heuristic` backend and reports
the effective backend in its output, so a run never fails for a missing key.

`.env` is gitignored, so keys are never committed.

## Usage

```bash
# Scan a kernel tree or a single file (offline heuristic backend)
python main.py scan /path/to/linux --llm heuristic

# Scope to specific subsystems
python main.py scan /path/to/linux --subsystem net --subsystem crypto

# Compare two kernel trees
python main.py diff --old /path/to/linux-6.7 --new /path/to/linux-6.8

# Run the self-contained ground-truth validation
python main.py validate

# Export results as SARIF 2.1.0 (written to results/scan.sarif)
python main.py scan /path/to/linux --output sarif
```

Run `python main.py --help` (or `<command> --help`) for the full option list.

## Web UI

racemap ships a Flask web UI (the one shown in the demo video) alongside the
CLI — Scan, Diff, Live "bring your own driver" scan, Patch Gap, and Cache
views, plus an interactive per-candidate call-graph.

```bash
python web/server.py
# open http://127.0.0.1:5005
```

Note: when the scanned target is one of the bundled demo fixtures
(`tests/sample_kernel` or `tests/ground_truth`), the web UI displays a few
identifiers under generic aliases for the on-screen demo (e.g. `ctx->iv` shows
as `ctx->shared_buf`, `algif_skcipher` shows as `crypto_subsystem`). This is a
display-only substitution in `web/server.py`; it never touches the underlying
detector, the CLI, or a scan of a real kernel tree — those always show the
real identifiers, as named in the [Disclosure](#disclosure) section below.
The JSON / CSV / SARIF exports are likewise always verbatim: the aliasing is
view-only, so a downloaded report never matches the on-screen labels for these
two fixtures.

An alternate Streamlit dashboard (`src/ui/app.py`, not used in the demo video)
is also included: `streamlit run src/ui/app.py`.

## Validation

racemap ships a ground-truth set drawn from real kernel crypto code and three
public CVEs — Dirty Pipe (CVE-2022-0847), a `copy_from_user`-under-
`mmap_read_lock` VMA-stability bug (CVE-2022-2590), and the ESP
in-place-decryption bug Dirty Frag (CVE-2026-43284) — each fixture carrying a
vulnerable and a fixed variant; the scanner must flag the former and exonerate
the latter.

On the bundled sample tree, racemap surfaces 12 likely races across 23
candidates at a 0% measured false-positive rate against the ground truth,
reproducible offline:

```bash
python main.py clear-cache && python main.py scan tests/sample_kernel --llm heuristic
```

## Disclosure

racemap's ground-truth set includes a real async-request IV race in
`crypto/algif_skcipher.c`, discovered and reported to security@kernel.org
under coordinated disclosure (2026-06-07), with the fix authored by the same
researcher. The stable maintainers accepted the series on 2026-07-17, queuing
it for 7.1.y, 6.18.y, 6.12.y, 6.6.y, 6.1.y, 5.15.y, and 5.10.y. Technical
analysis and the patch series are public:
https://lore.kernel.org/linux-crypto/20260716025838.2672-1-muhammetkaankilinc@gmail.com/

A CVE is expected once the fix ships in a released stable kernel — the Linux
CNA assigns after release, not on acceptance. No proof-of-concept or exploit
code is included in this repository; the working PoC stays unpublished until
the fix reaches released stable kernels, per the commitment made in the patch
cover letter.

## License

MIT — see [LICENSE](LICENSE).
