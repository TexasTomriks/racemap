# racemap

**A Linux kernel race-condition scanner with deterministic LLM triage.**

racemap scans Linux kernel source for shared page-cache and zero-copy
asynchronous patterns that can race. Static analysis does the finding: it
surfaces candidate sites where shared state is handed to a deferred operation
without a copy or ownership transfer. A deterministic LLM layer then acts
strictly as a **triage filter** — it does not find bugs, it only reduces false
positives by judging whether each candidate is already adequately protected.

![Scan results](docs/screenshots/scan.png)

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

## Disclosure

racemap's ground-truth validation set includes a real async-request race
pattern in a Linux kernel crypto subsystem, reported under coordinated
disclosure. The tool retroactively flags this pattern with high confidence. No
proof-of-concept or exploit code is included in this repository.

## License

MIT — see [LICENSE](LICENSE).
