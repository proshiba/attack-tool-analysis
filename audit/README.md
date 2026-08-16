# `audit/` — the deterministic rule-audit harness

Scripts decide the numbers; a reviewer interprets them. Nothing in here asks a model what a
false-positive rate is — it is measured, and every measurement names the corpus it came from
(`datasets/SOURCES.md`). The harness runs on the audit host (VM 107, `sigma-audit`), which is
deliberately a different model and a different machine from the author that writes the rules.

## Layout

```
audit/
  bin/build-baseline-metrics.sh   measure per-category event denominators (run once per corpus)
  bin/audit-rule.sh               grade one rule or one verification's sigma/ directory
  bin/build-scenario-reference.sh ATT&CK + LOLBAS/GTFOBins + daily-news reference for a tool
  bin/audit-gate.sh               ONE gate iteration for one verification: measure, judge, decide
  lib/baseline_metrics.py         per-file event counting -> category denominators
  lib/audit_engine.py             syntax + FP + detection + precision-convention scoring
  lib/audit_suite.py              run the engine across a whole repo, merge into a scorecard
  lib/scenario_reference.py       scenario grounding data builder
  lib/precision_input.py          join measurement with judgement -> what the author applies
  lib/gate_decide.py              the merge decision, deterministic; imports BLOCKING_VERDICTS
  prompts/rule-audit-agent.md     the auditor's standing instructions (repo-wide audit)
  prompts/audit-gate-agent.md     the same, narrowed to one verification as a merge gate
  catalog/                        small derived catalogs (committed) — never raw corpora
  datasets/SOURCES.md             where every corpus comes from and what it can/cannot prove
```

Deployment on VM 107 is `/opt/audit`; the files here are the source of truth for it.

## Usage

```bash
# once per corpus (~10 min on evtx-baseline; per-file CSVs are cached, re-runs are cheap)
bin/build-baseline-metrics.sh

# one verification
bin/audit-rule.sh <repo>/tools/sliver/verification/sigma /opt/audit/results/sliver

# the whole repo -> suite-summary.json + scorecard.md
python3 lib/audit_suite.py <repo> /opt/audit/results/suite-$(date +%Y%m%d-%H%M)
```

Long runs must be detached — an ssh drop otherwise kills them:

```bash
setsid bash -c 'python3 lib/audit_suite.py … > run.log 2>&1' </dev/null &
pgrep -f '[a]udit_suite'   # bracket the first char, or pgrep matches its own command line
```

## The merge gate

`bin/audit-gate.sh <verification-id> --ref <branch>` runs **one** gate iteration for one
verification and returns the verdict as its exit code — `0` PASS, `1` BLOCKED, `2` gate error
(inconclusive; never merge on a 2). It reads the branch from GitHub, so the branch under audit
must be pushed first. The workflow that calls it is `playbooks/verify-tool.md` step 8.

```
harness (audit_suite.py)      what the rules MEASURE on a clean corpus  ─┐
scenario_reference.py         ATT&CK + LOLBAS + real cases, as grounding ├─> auditor (claude -p,
check-scenario-scope.py       design-time safety, re-run deterministically┘   a different model)
                                                                              ↓ audit-report.json
                              precision_input.py  →  gate_decide.py  →  gate-result.json
                              (max(floor, judgement))  (deterministic)     route-to-author.md
```

Separation of powers is the point: the harness decides the numbers, the auditor decides the
judgement calls, and `gate_decide.py` only combines them — it asks no model anything, so the same
two inputs always produce the same verdict. It imports `BLOCKING_VERDICTS` from `audit_engine.py`
instead of restating the set, so the gate can never drift from the engine that assigns verdicts.

Blocking: a safety verdict of `reject`/`needs-change`, a harness verdict in `BLOCKING_VERDICTS`,
an auditor `blocking_defect`, a scenario `redo`, or a scenario `expand` below
`SCENARIO_COVERAGE_MIN` (default `0.6`). Explicitly NOT blocking: `no-corpus-coverage` and
`not-testable-on-evtx` — they describe a limit of the corpus, and routing them to the author asks
for a fix that does not exist.

`route-to-author.md` splits blocked work into **light** (rule text edits), **heavy** (needs a new
lab run) and **safety** (fix the scenario, never the finding), because those are three different
tasks for the author. Iterations are capped at 3 by the playbook; the cap lives with the human
loop, not in this script.

| Variable | Default | Effect |
|---|---|---|
| `SCENARIO_COVERAGE_MIN` | `0.6` | coverage below this makes an `expand` scenario blocking |
| `AUDITOR_TIMEOUT_SECONDS` | `5400` | hard timeout on the auditor run |
| `GATE_REPO` | `/opt/audit/scratch/gate-repo` | read-only checkout of the ref under audit |
| `REPO_URL` | the public repo | where the audited branch is fetched from |

## What the engine measures, and the defects it was built to fix

**1. A syntax gate runs before anything is staged.** `sigma-cli` 3.1.0 accepts only `1 of`
and `all of`; a numeric quantifier such as `2 of selection_check_*` is rejected anywhere it
appears. The old engine staged a whole directory into one `evtx-sigma-checker` invocation, so
that single rule aborted the run and *every* rule in the directory was reported as
`fp_per_million: 0.0, detection_hit: false` — a result indistinguishable from a clean one.
Non-compiling rules are now excluded up front, their neighbours are measured normally, and
the excluded rule gets `verdict: fail`, `code: sigma-syntax-error`.

**2. Nothing unmeasured is ever reported as zero.** If the checker still aborts, the engine
bisects the staged set to isolate the offender, quarantines it, re-measures the survivors, and
reports `measured: false` with `null` counts and `verdict: void` for anything it could not
measure. `0` means measured-and-zero. `null` means not measured.

**3. FP rates are normalised to the rule's own logsource category.** `fp_per_million` computed
over all 6,611,183 baseline events understates process-rule noise by ~279x — only 23,695 of those
events are `process_creation` (Sysmon EID 1: 15,092 + Security 4688: 8,603). Each scorecard now carries
`share_of_category_percent` alongside the corpus-wide rate. The Sliver rule
`proc_creation_untrusted_parent_spawns_shell` reads 46 FP per million *events* but **1.2% of
every process start** in a clean corpus; only the second number is decision-grade.

**4. Rules that cannot be tested here say so.** Zeek and Suricata rules have no EVTX
representation at all. They are marked `not-testable-on-evtx` and excluded from the corpus
runs entirely, instead of being failed for "no detection hit". Likewise a detection miss is
its own **non-blocking** verdict `no-corpus-coverage` (code `no-positive-corpus-sample`),
because `EVTX-ATTACK-SAMPLES` contains no mimikatz command line — SigmaHQ's own mimikatz rule
misses it too. No rule edit can clear it; only adding a positive sample can. Confirm with a
control rule, then judge recall qualitatively against the verification's own `evidence/`.

**5. Blocking is separate from severity.** `BLOCKING_VERDICTS` (`needs-work`, `void`, `fail`)
is the authoritative set the merge gate consumes; every scorecard and summary carries a
`blocking` boolean and a `blocking_count`. `no-corpus-coverage` and `not-testable-on-evtx`
state a limit of the corpus, so they are reported but never route work back to the author.

**6. A category mapping owns the service.** The THOR logsource mapping selects generic rules by
`category` + `product`, adds the category's EventID condition, and rewrites `service` to the
concrete provider. Declaring `service` on one of those mapped categories can therefore compile and
produce an apparently clean zero while matching no events. The structural schema gate derives the
service-rewriting keys from the active THOR mapping and rejects a rule that declares all three with
`rule-schema-invalid`; remove `service` and let the category mapping select the event stream.

Run the focused self-test with:

```bash
python3 -m unittest audit/tests/test_schema_gate.py
```

It exercises a known-bad Windows `file_event` + `service: sysmon` rule, the corrected category-only
form, and a valid service-only Linux `auditd` logsource.

The mirror-image failure from an over-broad `filter_*` cannot use the same hard gate: Sigma search
identifier names carry no semantics, and a filename may be attacker-controlled in one rule but an
invariant system value in another. A blanket filename-filter ban would reject legitimate allowlists.
A cheap future check could emit a non-blocking review warning when a negated filter suppresses the
same filename field used by a positive selection, but it should not become blocking without an
explicit rule annotation that identifies attacker-controlled fields.

## Precision-convention enforcement

Every verification rule must carry `fp_likelihood`, `precision_notes` and `recommended_role`,
with `level` set consistently with precision (severity-if-true is not precision). The engine
enforces this mechanically:

| Code | Meaning |
|---|---|
| `precision-fields-missing` | one of the three fields is absent |
| `precision-mismatch` | declared `fp_likelihood` is lower than the measured floor |
| `role-mismatch` | measured-high-FP rule declared `recommended_role: alert` |
| `level-mismatch` | measured-high-FP rule declared `level: high`/`critical` |
| `fp-share-excessive` | matches more than `FP_CATEGORY_FAIL_PERCENT` of its category on a clean corpus |

The measured `fp_likelihood` is a **floor**, from a clean lab corpus. An auditor may raise it
on qualitative grounds — `Microsoft-CryptoAPI/` is the user agent Windows uses for *all*
CRL/OCSP traffic, so that rule is high-FP in production despite measuring 0 here — but may
never lower it below what was measured.

Thresholds (share of the rule's category, on a clean corpus):

| Variable | Default | Effect |
|---|---|---|
| `FP_CATEGORY_HIGH_PERCENT` | `0.1` | floor becomes `high` |
| `FP_CATEGORY_MEDIUM_PERCENT` | `0.001` | floor becomes `medium` |
| `FP_CATEGORY_FAIL_PERCENT` | `5.0` | verdict becomes `fail` |
| `REQUIRE_PRECISION_FIELDS` | `true` | missing fields are `needs-work` (blocking) |

## Verdicts

Ordered by severity, lowest first:

| Verdict | Blocking | Meaning |
|---|---|---|
| `pass` | no | every deterministic threshold satisfied |
| `no-corpus-coverage` | no | no hit in the positive corpus — the corpus does not carry this tool |
| `not-testable-on-evtx` | no | Zeek/Suricata rule; an EVTX corpus cannot exercise it at all |
| `needs-work` | **yes** | a precision claim contradicts the measurement, or required fields are missing |
| `void` | **yes** | could not be measured |
| `fail` | **yes** | does not compile, fails the schema gate, or has an absurd FP share |

A verdict carries every reason code that fired, not just the first, and the rule's verdict is
the worst of them.
