#!/usr/bin/env bash
# Grade Sigma rules: syntax, measured false positives, detection, precision convention.
#
#   audit-rule.sh <rule-file-or-dir> <outdir>
#
# Every knob below is a deterministic policy default; export to override.
# Rates are a share of the rule's OWN logsource category, not of all corpus events
# (see lib/baseline_metrics.py for why that distinction matters).
set -euo pipefail

FP_CATEGORY_HIGH_PERCENT="${FP_CATEGORY_HIGH_PERCENT:-0.1}"      # >= this share -> fp_likelihood floor "high"
FP_CATEGORY_MEDIUM_PERCENT="${FP_CATEGORY_MEDIUM_PERCENT:-0.001}" # >= this share -> floor "medium"
FP_CATEGORY_FAIL_PERCENT="${FP_CATEGORY_FAIL_PERCENT:-5.0}"      # > this share -> verdict "fail"
REQUIRE_PRECISION_FIELDS="${REQUIRE_PRECISION_FIELDS:-true}"     # fp_likelihood/precision_notes/recommended_role
MAX_SAMPLE_MATCHES="${MAX_SAMPLE_MATCHES:-20}"
CHECKER_TIMEOUT_SECONDS="${CHECKER_TIMEOUT_SECONDS:-1800}"

AUDIT_HOME="${AUDIT_HOME:-/opt/audit}"
AUDIT_CATEGORY_METRICS="${AUDIT_CATEGORY_METRICS:-${AUDIT_HOME}/catalog/baseline-category-metrics.json}"

if [[ $# -ne 2 ]]; then
  echo "Usage: audit-rule.sh <rule-file-or-dir> <outdir>" >&2
  exit 2
fi

if [[ ! -f "${AUDIT_CATEGORY_METRICS}" ]]; then
  echo "WARNING: ${AUDIT_CATEGORY_METRICS} not found - run bin/build-baseline-metrics.sh first," >&2
  echo "         otherwise every rule is scored against the whole corpus and process rules" >&2
  echo "         look ~300x quieter than they are." >&2
fi

export FP_CATEGORY_HIGH_PERCENT FP_CATEGORY_MEDIUM_PERCENT FP_CATEGORY_FAIL_PERCENT
export REQUIRE_PRECISION_FIELDS MAX_SAMPLE_MATCHES CHECKER_TIMEOUT_SECONDS AUDIT_CATEGORY_METRICS
exec /usr/bin/python3 "${AUDIT_HOME}/lib/audit_engine.py" "$1" "$2"
