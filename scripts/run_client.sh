#!/usr/bin/env bash
# Start the dashboard with the project's virtual environment (http://localhost:8501).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || { echo "No .venv found; see README 'Getting started'." >&2; exit 1; }
exec .venv/bin/python -m streamlit run client_demo/streamlit_app.py "$@"
