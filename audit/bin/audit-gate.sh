#!/usr/bin/env bash
# One iteration of the audit gate for a single verification. Runs ON THE AUDIT VM (107).
#
#   audit-gate.sh <verification-id> [--ref <git-ref>] [--iteration N] [--outdir DIR]
#                                   [--skip-auditor] [--repo-url URL]
#
#   audit-gate.sh tools/sliver --ref feat/verify-sliver
#
# Measure (harness) -> ground (scenario reference) -> judge (independent auditor, a different
# model) -> decide (gate_decide.py, deterministic). Exit code IS the gate verdict:
#
#   0  PASS        - no blocking defect; record the measured precision in verification.json
#   1  BLOCKED     - route-to-author.md holds the routed work
#   2  GATE ERROR  - inconclusive (an input was never produced); re-run, never merge on a 2
#
# The gate reads the repo from GitHub at a ref, so the branch under audit must be PUSHED first.
# This host holds no token and never writes to the repo: the author applies every fix.
set -euo pipefail

AUDIT_HOME="${AUDIT_HOME:-/opt/audit}"
REPO_URL="${REPO_URL:-https://github.com/proshiba/attack-tool-analysis}"
GATE_REPO="${GATE_REPO:-${AUDIT_HOME}/scratch/gate-repo}"
AUDITOR_TIMEOUT_SECONDS="${AUDITOR_TIMEOUT_SECONDS:-5400}"
SCENARIO_COVERAGE_MIN="${SCENARIO_COVERAGE_MIN:-0.6}"

VERIFICATION=""
REF="main"
ITERATION=1
OUTDIR=""
SKIP_AUDITOR="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --iteration) ITERATION="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --skip-auditor) SKIP_AUDITOR="true"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) VERIFICATION="$1"; shift ;;
  esac
done

if [[ -z "${VERIFICATION}" ]]; then
  echo "Usage: audit-gate.sh <verification-id> [--ref <git-ref>] [--iteration N]" >&2
  echo "  <verification-id> is a repo path such as tools/sliver or lol/techniques/regsvr32-sct" >&2
  exit 2
fi

VERIFICATION="${VERIFICATION%/}"
SLUG="$(echo "${VERIFICATION}" | tr '/' '-')"
STAMP="$(date -u +%Y%m%d-%H%M)"
OUTDIR="${OUTDIR:-${AUDIT_HOME}/results/gate-${SLUG}-${STAMP}}"
mkdir -p "${OUTDIR}"/{harness,scenario-reference,safety,auditor,precision}

log() { echo "[gate $(date -u +%H:%M:%S)] $*" >&2; }

# --- 1. the repo at the ref under audit ---------------------------------------------
if [[ ! -d "${GATE_REPO}/.git" ]]; then
  log "cloning ${REPO_URL} -> ${GATE_REPO}"
  git clone --quiet "${REPO_URL}" "${GATE_REPO}"
fi
git -C "${GATE_REPO}" fetch --quiet --prune origin '+refs/heads/*:refs/remotes/origin/*'
# This clone is scratch, not a workspace. Anything left in it from an earlier run - a stale
# local branch, an edited file - would otherwise be audited in place of the ref that was asked
# for, and the gate would report a verdict for code nobody requested.
git -C "${GATE_REPO}" reset --quiet --hard
git -C "${GATE_REPO}" clean -qfd
TARGET="$(git -C "${GATE_REPO}" rev-parse --verify --quiet "origin/${REF}^{commit}" \
          || git -C "${GATE_REPO}" rev-parse --verify --quiet "${REF}^{commit}" \
          || true)"
if [[ -z "${TARGET}" ]]; then
  echo "FATAL: ref '${REF}' resolves to nothing on origin - has the branch been pushed?" >&2
  printf '{"decision":"gate-error","verification":"%s","errors":["ref %s does not exist on origin"]}\n' \
    "${VERIFICATION}" "${REF}" > "${OUTDIR}/gate-result.json"
  exit 2
fi
git -C "${GATE_REPO}" checkout --quiet --detach "${TARGET}"
COMMIT="$(git -C "${GATE_REPO}" rev-parse --short HEAD)"
log "auditing ${VERIFICATION} at ${REF} (${COMMIT})"

VERIFICATION_DIR="${GATE_REPO}/${VERIFICATION}/verification"
if [[ ! -d "${VERIFICATION_DIR}/sigma" ]]; then
  echo "FATAL: ${VERIFICATION}/verification/sigma does not exist at ${REF}" >&2
  echo '{"errors":["verification path not found at the audited ref"]}' > "${OUTDIR}/gate-result.json"
  exit 2
fi

# --- 2. safety, deterministically, before anything else -----------------------------
# The auditor re-runs this itself; a design-time scope violation must not depend on a model
# noticing it.
log "safety: check-scenario-scope.py"
set +e
python3 "${GATE_REPO}/safety/check-scenario-scope.py" "${VERIFICATION_DIR}" \
  > "${OUTDIR}/safety/scope-check.txt" 2>&1
SCOPE_RC=$?
set -e
python3 - "${OUTDIR}/safety/scope-check.json" "${VERIFICATION_DIR}" "${SCOPE_RC}" <<'PY'
import json, sys
path, target, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
json.dump({"target": target, "exit_code": rc, "output": "scope-check.txt"},
          open(path, "w"), ensure_ascii=False, indent=2)
PY
log "safety: exit ${SCOPE_RC}"

# --- 3. measure the rules ------------------------------------------------------------
log "harness: audit_suite --only ${VERIFICATION}"
set +e
python3 "${AUDIT_HOME}/lib/audit_suite.py" "${GATE_REPO}" "${OUTDIR}/harness" \
  --only "${VERIFICATION}" > "${OUTDIR}/harness/run.log" 2>&1
SUITE_RC=$?
set -e
log "harness: exit ${SUITE_RC}"
[[ -f "${OUTDIR}/harness/scorecard.md" ]] && cp "${OUTDIR}/harness/scorecard.md" "${OUTDIR}/scorecard.md"

# --- 4. ground the scenarios ---------------------------------------------------------
log "scenario reference: $(basename "${VERIFICATION}")"
set +e
python3 "${AUDIT_HOME}/lib/scenario_reference.py" "$(basename "${VERIFICATION}")" \
  "${OUTDIR}/scenario-reference" > "${OUTDIR}/scenario-reference/run.log" 2>&1
set -e

# --- 5. the independent judgement ----------------------------------------------------
PROMPT_TEMPLATE="${GATE_REPO}/audit/prompts/audit-gate-agent.md"
PROMPT="${OUTDIR}/auditor/prompt.md"
if [[ "${SKIP_AUDITOR}" == "true" ]]; then
  log "auditor: SKIPPED (--skip-auditor); the gate can only report a gate error"
else
  sed -e "s|__VERIFICATION__|${VERIFICATION}|g" \
      -e "s|__REPO__|${GATE_REPO}|g" \
      -e "s|__GATE_DIR__|${OUTDIR}|g" \
      -e "s|__ITERATION__|${ITERATION}|g" \
      -e "s|__COVERAGE_MIN__|${SCENARIO_COVERAGE_MIN}|g" \
      "${PROMPT_TEMPLATE}" > "${PROMPT}"
  log "auditor: claude -p (timeout ${AUDITOR_TIMEOUT_SECONDS}s)"
  set +e
  timeout "${AUDITOR_TIMEOUT_SECONDS}" \
    bash -c "cd '${OUTDIR}/auditor' && claude -p --dangerously-skip-permissions < '${PROMPT}'" \
    > "${OUTDIR}/auditor/run.log" 2>&1
  AUDITOR_RC=$?
  set -e
  log "auditor: exit ${AUDITOR_RC}"
fi

# --- 6. reconcile measurement with judgement -----------------------------------------
if [[ -f "${OUTDIR}/harness/suite-summary.json" && -f "${OUTDIR}/auditor/audit-report.json" ]]; then
  log "precision: joining measurement with judgement"
  set +e
  python3 "${AUDIT_HOME}/lib/precision_input.py" \
    "${OUTDIR}/harness/suite-summary.json" "${OUTDIR}/auditor/audit-report.json" \
    "${OUTDIR}/precision" > "${OUTDIR}/precision/run.log" 2>&1
  set -e
fi

# --- 7. decide -----------------------------------------------------------------------
set +e
SCENARIO_COVERAGE_MIN="${SCENARIO_COVERAGE_MIN}" AUDIT_HOME="${AUDIT_HOME}" \
python3 "${AUDIT_HOME}/lib/gate_decide.py" "${OUTDIR}" \
  --verification "${VERIFICATION}" --iteration "${ITERATION}" --commit "${COMMIT}"
GATE_RC=$?
set -e

log "decision: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["decision"])' "${OUTDIR}/gate-result.json" 2>/dev/null || echo unknown) (exit ${GATE_RC})"
log "results: ${OUTDIR}"
exit "${GATE_RC}"
