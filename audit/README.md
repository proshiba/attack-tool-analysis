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
  lib/baseline_metrics.py         per-file event counting -> category denominators
  lib/audit_engine.py             syntax + FP + detection + precision-convention scoring
  lib/audit_suite.py              run the engine across a whole repo, merge into a scorecard
  lib/scenario_reference.py       scenario grounding data builder
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

## What the engine measures, and the four defects it was built to fix

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
