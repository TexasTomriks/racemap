#!/usr/bin/env bash
#
# racemap split-screen demo for Black Hat Arsenal.
# Left pane:  racemap scanning a vulnerable fixture.
# Right pane: each candidate line mapped to its exploit-primitive class.
#
# Uses tmux split panes when available; otherwise runs the two views
# sequentially. Language note: this maps candidates to *exploit primitive
# classes* for prioritisation — it does not generate exploits or payloads.
#
#   ./demo/split_screen_demo.sh [fixture.c]
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
FIXTURE="${1:-tests/sample_kernel/mystery/mystery_driver.c}"
MAPLOG="$(mktemp)"

# Produce the candidate -> exploit-primitive mapping log from a JSON scan.
build_map() {
    "$PY" main.py scan "$FIXTURE" --llm heuristic --quiet \
        --json "$MAPLOG.json" --patch-gap >/dev/null 2>&1 || true
    "$PY" - "$MAPLOG.json" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("=== CANDIDATE MAPS TO EXPLOIT PRIMITIVE ===\n")
for r in d["results"]:
    if r["verdict"] != "likely_race":
        continue
    prim = r.get("shared_field") or "?"
    esc = r.get("container_escape_reason") or "n/a"
    cve = f"  [{r['cve_id']}]" if r.get("cve_id") else ""
    taint = f"  -> taint:{r['taint_callee']}" if r.get("taint_propagated") else ""
    patch = "  [patch-missing]" if r.get("patch_missing") else ""
    print(f"{r['file']}:{r['line']}{cve}")
    print(f"    primitive class : {prim}")
    print(f"    exploit-primitive mapping : {esc}{taint}{patch}")
    print(f"    risk score : {r['rank_score']}\n")
PYEOF
}

LEFT_CMD="echo '=== RACEMAP SCANNING ==='; echo; $PY main.py scan '$FIXTURE' --llm heuristic --verbose --patch-gap; echo; echo '(left pane: scan complete)'"

if command -v tmux >/dev/null 2>&1 && [ -z "${NO_TMUX:-}" ]; then
    build_map > "$MAPLOG"
    SESSION="racemap_demo_$$"
    tmux new-session -d -s "$SESSION" -x 220 -y 50 "bash -lc \"$LEFT_CMD; read -p 'Enter to exit...'\""
    tmux split-window -h -t "$SESSION" "bash -lc 'cat \"$MAPLOG\"; echo; read -p \"Enter to exit...\"'"
    tmux select-layout -t "$SESSION" even-horizontal
    tmux attach -t "$SESSION"
    rm -f "$MAPLOG" "$MAPLOG.json"
else
    echo "(tmux not available — running sequentially)"
    echo
    echo "=== RACEMAP SCANNING ==="
    echo
    "$PY" main.py scan "$FIXTURE" --llm heuristic --verbose --patch-gap
    echo
    build_map
    rm -f "$MAPLOG" "$MAPLOG.json"
fi
