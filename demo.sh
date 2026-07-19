#!/usr/bin/env bash
#
# racemap presenter walkthrough (Linux/macOS).
# Black Hat Arsenal Europe 2026.
#
# Usage:  ./demo.sh            # interactive, pauses between steps
#         ./demo.sh --no-pause # run straight through (for recording)
set -euo pipefail

cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
PAUSE=1
[[ "${1:-}" == "--no-pause" ]] && PAUSE=0

c_reset=$'\e[0m'; c_bold=$'\e[1m'; c_cyan=$'\e[36m'; c_green=$'\e[32m'; c_dim=$'\e[2m'

hr()      { printf '%s\n' "${c_dim}────────────────────────────────────────────────────────────${c_reset}"; }
section() { echo; hr; printf '%s\n' "${c_bold}${c_cyan}▶ $1${c_reset}"; hr; }
note()    { printf '%s\n' "${c_dim}$1${c_reset}"; }
pause()   { [[ $PAUSE -eq 1 ]] && { echo; read -r -p "${c_green}[ Enter to continue ]${c_reset} " _ || true; } || true; }

clear || true
printf '%s\n' "${c_bold}racemap${c_reset} — Linux kernel shared page-cache race scanner with LLM triage"
note "Static analysis (Coccinelle + Semgrep) → LLM triage → ranked report."
note "The LLM judges locking sufficiency only. It never generates exploits."
pause

section "STEP 1 — Validate against ground truth (algif_skcipher)"
note "Must surface the reported shared-IV race and exonerate the snapshotted fix."
$PY main.py validate
pause

section "STEP 2 — Scan a sample kernel tree (offline heuristic triage)"
note "Default subsystems (net/, crypto/, drivers/char/, io_uring/, fs/, mystery/)"
note "— expect 12 likely races across 23 candidates, 0% measured false-positive rate."
$PY main.py scan tests/sample_kernel/ --llm heuristic --kernel-version 6.8.0-124 \
    --json racemap_report.json
note "Ranked JSON written to racemap_report.json"
pause

section "STEP 3 — Switch the triage backend with --llm"
note "Same pipeline, swappable LLM. heuristic (fully offline, deterministic) is"
note "the default; ollama is local/private; anthropic / openai / gemini are cloud"
note "options. Backends auto-fall back to the heuristic when a key/server is absent."
echo
note "\$ racemap scan tests/sample_kernel/ --llm ollama     # local, private"
$PY main.py scan tests/sample_kernel/ --llm ollama --quiet --json /tmp/racemap_ollama.json
note "  (no Ollama server here → transparently fell back to heuristic)"
echo
note "\$ racemap scan tests/sample_kernel/ --llm auto        # try ollama→anthropic→openai→gemini→heuristic"
$PY main.py scan tests/sample_kernel/ --llm auto --quiet
pause

section "DONE"
note "Ranked JSON: racemap_report.json   |   Run the test suite with: pytest -q"
