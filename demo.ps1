<#
  racemap presenter walkthrough (Windows PowerShell).
  Black Hat Arsenal Europe 2026.

  Usage:  .\demo.ps1            # interactive, pauses between steps
          .\demo.ps1 -NoPause   # run straight through (for recording)
#>
param([switch]$NoPause)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
$PY = if ($env:PYTHON) { $env:PYTHON } else { "python" }

function Section($t) {
    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor DarkGray
    Write-Host "> $t" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}
function Note($t) { Write-Host $t -ForegroundColor DarkGray }
function Pause-Demo {
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "[ Enter to continue ]" | Out-Null
    }
}

Clear-Host
Write-Host "racemap" -ForegroundColor White -NoNewline
Write-Host " - Linux kernel shared page-cache race scanner with LLM triage"
Note "Static analysis (Coccinelle + Semgrep) -> LLM triage -> ranked report."
Note "The LLM judges locking sufficiency only. It never generates exploits."
Pause-Demo

Section "STEP 1 - Validate against ground truth (algif_skcipher)"
Note "Must surface the reported shared-IV race and exonerate the snapshotted fix."
& $PY main.py validate
Pause-Demo

Section "STEP 2 - Scan a sample kernel tree (offline heuristic triage)"
Note "Default subsystems (net/, crypto/, drivers/char/, io_uring/, fs/, mystery/)"
Note "- expect 12 likely races across 23 candidates, 0% measured false-positive rate."
& $PY main.py scan tests/sample_kernel/ --llm heuristic --kernel-version 6.8.0-124 --json racemap_report.json
Note "Ranked JSON written to racemap_report.json"
Pause-Demo

Section "STEP 3 - Switch the triage backend with --llm"
Note "Same pipeline, swappable LLM. heuristic (fully offline, deterministic) is"
Note "the default; ollama is local/private; anthropic / openai / gemini are cloud"
Note "options. Backends auto-fall back to the heuristic when a key/server is absent."
Write-Host ""
Note '$ racemap scan tests/sample_kernel/ --llm ollama     # local, private'
& $PY main.py scan tests/sample_kernel/ --llm ollama --quiet --json racemap_ollama.json
Note "  (no Ollama server here -> transparently fell back to heuristic)"
Write-Host ""
Note '$ racemap scan tests/sample_kernel/ --llm auto        # ollama->anthropic->openai->gemini->heuristic'
& $PY main.py scan tests/sample_kernel/ --llm auto --quiet
Pause-Demo

Section "DONE"
Note "Ranked JSON: racemap_report.json   |   Run the test suite with: pytest -q"
