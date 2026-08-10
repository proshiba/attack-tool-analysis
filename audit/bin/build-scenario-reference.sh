#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: build-scenario-reference.sh <tool-or-technique-id> <outdir>" >&2
  exit 2
fi
exec /usr/bin/python3 /opt/audit/lib/scenario_reference.py "$1" "$2"
