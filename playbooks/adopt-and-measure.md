# Playbook: adopt-and-measure (LOLBINs and anything the public rulesets already cover)

For a LOLBIN, the useful question is **not** "what rule would we write?" — SigmaHQ has almost certainly
written one. It is "is the public rule any good, and can we prove it?" This playbook makes that the
deliverable: the lab **grades and enriches** the public rule, and authors its own only where a measured
gap justifies it.

Use it for LOLBINs (certutil, regsvr32, mshta, rundll32, wmic, …). Use [`verify-tool.md`](verify-tool.md)
in full for brought-in attacker tooling (mimikatz, Seatbelt, Sliver), where naming is unreliable, public
coverage is thin, and the network dimension carries the signal.

## Why — what a measurement of LOLBAS actually shows (2026-08-10)

**LOLBAS does not author Sigma rules.** Its `Detection:` block is a list of links to other people's
rules: 295 Sigma links across 243 entries (84% of entries have at least one), plus Elastic (87), Splunk
(48) and prose IOCs (271).

Those links are not a maintained ruleset, and a rule taken from them is not the rule upstream ships
today:

| Measured | Result |
|---|---|
| Sigma links pinned to a commit | **280 of 295** |
| Top 5 pinned commits (75% of all links) | all dated **June 2023** |
| Sampled pinned rules that changed upstream since | **6 of 6** |
| Sampled pinned rules that **fail to compile** on sigma-cli 3.1.0 | **2 of 6** (`sigma-syntax-error`: the 2023 `date: 2023/05/24` format, `type: obsoletes`) |
| Sampled **current master** rules graded by `audit/bin/audit-rule.sh` | 5 `pass`, 1 `no-corpus-coverage`, 0 FP on the clean corpus |

The gap is concrete, not theoretical: the pinned `proc_creation_win_certutil_download.yml` matches only
`urlcache `/`verifyctl `. **LOLBAS documents `-URL` as a download command on the same page, and the rule
it links to cannot see it.** Upstream added `'URL '` later (master, `modified: 2025-12-01`).

**So: the baseline is SigmaHQ `master`, never the LOLBAS pin.**

### Where the public rules are strong, and where they are not

Strong: correct logsource, behaviour-based, ATT&CK tags, `related` ids, `regression_tests_path`. And
they are not behind us — `proc_creation_win_regsvr32_susp_exec_path_1.yml` already matches regsvr32
executing from `\AppData\Local\Temp\`, `\Users\Public\`, `\ProgramData\`, which is the dominant
real-world regsvr32 form and the exact gap our own audit found **uncovered in this repo**.

Weak, uniformly: **no measured precision.** Four of the six sampled rules carry `falsepositives:
Unknown`; none carries `fp_likelihood`, `recommended_role` or `precision_notes`; and `level` encodes
severity-if-true, not noise (SigmaHQ ships certutil decode at `level: high`). Nobody publishes an FP
rate measured against a corpus, per logsource category. **That is the hole this lab fills.**

## The mode

1. **Baseline.** Fetch the rule(s) SigmaHQ ships **at `master` today** for the technique. Record path,
   commit and `modified` date. Note where the LOLBAS pin differs from master — that difference is a
   finding about LOLBAS, and belongs in the writeup.
2. **Enumerate the documented forms.** From the LOLBAS entry, list every `Command` with its MitreID and
   privileges. For each, decide from the rule text whether the upstream rule would match — and say why.
3. **Run the lab for evidence, not for authorship.** Execute the forms that the reading says are
   uncertain or uncovered, per the safety rules in [`lab-safety-rules.md`](lab-safety-rules.md). The
   purpose of the run is to **prove or disprove** the reading with telemetry, and to produce the
   positive samples the public corpora lack.
4. **Measure the upstream rule** with `audit/bin/audit-rule.sh`: FP count and share of its own logsource
   category, detection hit, verdict. Add what upstream cannot: `fp_likelihood` (measured floor, raised
   on production reasoning), `recommended_role`, `precision_notes`, precision-adjusted `level`.
5. **Author only against a proven gap** (see the bar below).
6. **Send real gaps upstream.** A form the public rule misses is worth a SigmaHQ PR, not just a local
   fix — the lab has the lab evidence to justify it. Record whether it was reported.

## The bar for authoring our own rule

Write one only when at least one of these is true, and say which in the PR:

- **Form coverage** — the upstream rule misses a documented form, **and the lab run proves the miss**
  (as with `certutil /decode`: the plain rule scored no-hit, the `|windash` rule hit).
- **Dead or mis-declared logsource** — the rule cannot fire on the shipping format (as with
  `service: sysmon` pinned under `category: file_event`, which silently takes the rule off the
  file_creation mapping).
- **An unmeasured precision claim** — the rule's `level`/`falsepositives` contradict the measurement.
  Prefer enriching the upstream rule's metadata over forking the logic.
- **A dimension upstream does not cover** — file, registry, or NSM-sourced network telemetry
  (JA3/JARM, HTTP profile, beacon periodicity). Public LOLBIN coverage is process-heavy; this is where
  a new rule is most often justified.

"We could write one" is not on the list. A parallel rule that restates upstream costs review time,
drifts, and adds nothing an analyst can act on.

## What to record

In `verification.json`, alongside the usual entries, an `upstream` block per technique:

- the SigmaHQ rules compared (path, commit, `modified` date) and their measured numbers;
- the LOLBAS pin, and how it differs from master;
- **per documented LOLBAS command**: covered by upstream / covered by ours / uncovered — with the lab
  evidence that decided it;
- for each rule we authored: which bar it clears;
- anything reported upstream, with a link.

In `scenarios.md`, state plainly which forms the public rule already handles. A verification that
quietly re-derives existing coverage reads as new work when it is not.
