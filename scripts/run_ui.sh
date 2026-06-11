#!/usr/bin/env bash
# Launch the racemap Streamlit dashboard (Linux/macOS).
set -euo pipefail
cd "$(dirname "$0")/.."
exec streamlit run src/ui/app.py "$@"
