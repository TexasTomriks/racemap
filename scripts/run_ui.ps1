# Launch the racemap Streamlit dashboard (Windows PowerShell).
#   .\scripts\run_ui.ps1
$ErrorActionPreference = "Stop"
Set-Location -Path (Join-Path $PSScriptRoot "..")
streamlit run src/ui/app.py @args
