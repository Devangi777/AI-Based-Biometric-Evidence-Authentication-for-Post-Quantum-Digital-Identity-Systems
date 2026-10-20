#!/usr/bin/env bash
# Start the backend with the project's own virtual environment, so it works
# whether or not `.venv` is activated. (Plain `uvicorn` outside the venv runs
# a different Python without the project's packages: "No module named ...".)
#
#   ./scripts/run_server.sh              # http://localhost:8000
#   PORT=8001 ./scripts/run_server.sh    # another port
#   RELOAD=1 ./scripts/run_server.sh     # auto-reload on code changes
set -euo pipefail
cd "$(dirname "$0")/.."

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "No .venv found. Create it once:" >&2
  echo "  python3.11 -m venv .venv && source .venv/bin/activate" >&2
  echo "  pip install -r requirements.txt -r requirements-client.txt" >&2
  exit 1
fi
if ! "$PY" -c "import oqs, fastapi, imagehash" 2>/dev/null; then
  echo ".venv is missing server packages. Run: .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi
if lsof -iTCP:"${PORT:-8000}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port ${PORT:-8000} is already in use (another server, or the Docker container)." >&2
  echo "Stop it ('docker compose down') or use another port: PORT=8001 $0" >&2
  exit 1
fi

args=(server.main:app --host 0.0.0.0 --port "${PORT:-8000}")
[ "${RELOAD:-0}" = "1" ] && args+=(--reload)
exec "$PY" -m uvicorn "${args[@]}"
