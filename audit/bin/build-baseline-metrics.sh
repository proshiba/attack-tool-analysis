#!/usr/bin/env bash
# Measure the per-category event denominators every FP rate is scored against.
#
#   build-baseline-metrics.sh [dataset-dir] [output-json]
#
# Takes ~10 min on evtx-baseline (8.2 GiB / 2,239 files); per-file CSVs are cached
# under $AUDIT_HOME/scratch/eid-metrics so a re-run is nearly free. Long runs should
# be detached: setsid bash -c '... > log 2>&1' </dev/null &
set -euo pipefail

AUDIT_HOME="${AUDIT_HOME:-/opt/audit}"
DATASET="${1:-/data/datasets/evtx-baseline}"
OUT="${2:-${AUDIT_HOME}/catalog/baseline-category-metrics.json}"

exec /usr/bin/python3 "${AUDIT_HOME}/lib/baseline_metrics.py" \
  --dataset "${DATASET}" \
  --out "${OUT}" \
  --hayabusa "${AUDIT_HOME}/bin/hayabusa" \
  --thor "${AUDIT_THOR:-/data/datasets/sigma/tests/thor.yml}" \
  --cache-dir "${AUDIT_HOME}/scratch/eid-metrics" \
  --jobs "${JOBS:-6}"
