# Measurement: what the public LOLBIN rules are actually worth (2026-08-10)

The evidence behind [`playbooks/adopt-and-measure.md`](../../playbooks/adopt-and-measure.md). Every
number here was measured, not asserted; the commands to reproduce it are at the bottom.

## LOLBAS, as a detection source

`LOLBAS-Project/LOLBAS` at 2026-08-10, 243 entries / 482 documented commands.

| | Count | Share of entries |
|---|---:|---:|
| entries with any `Detection` block | 227 | 93% |
| entries with at least one Sigma link | 203 | 84% |

Detection entries by type: Sigma 295, IOC 271 (prose), Elastic 87, Splunk 48, BlockRule 23, Analysis 4.

**LOLBAS authors none of these rules.** The Sigma entries are links to other repositories:

| Link form | Count |
|---|---:|
| `SigmaHQ/sigma` pinned to a commit sha | 280 |
| `SigmaHQ/sigma` at a branch/tag | 10 |
| other repos (`tsale`, `The-DFIR-Report`, `manasmbellani`) | 3 |
| not a GitHub blob URL | 2 |

The pins concentrate on 25 distinct commits. The top five carry 221 links (75% of all Sigma links):

| Commit | Links | Date |
|---|---:|---|
| `62d4fd26…` | 61 | 2023-06-20 |
| `683b63f8…` | 56 | 2023-06-21 |
| `c04bef2f…` | 56 | 2023-06-20 |
| `6312dd1d…` | 37 | 2023-06-16 |
| `b02e3b69…` | 11 | 2023-06-09 |

## The pinned rules, graded

Six rules linked from the Certutil and Regsvr32 entries, fetched at the LOLBAS-pinned commit and at
`master`, then graded with `audit/bin/audit-rule.sh` (`REQUIRE_PRECISION_FIELDS=false` — the precision
convention is a lab convention and upstream is not held to it here).

| | pinned (June 2023) | master (today) |
|---|---|---|
| `pass` | 4 | 5 |
| `no-corpus-coverage` | 0 | 1 |
| **`fail` (`sigma-syntax-error`)** | **2** | 0 |
| FP hits on the clean corpus | 0 across all measured | 0 across all measured |

All six differ between the pin and master. The two failures are
`proc_creation_win_regsvr32_network_pattern.yml` and `proc_creation_win_regsvr32_susp_exec_path_1.yml`:
the 2023 schema (`date: 2023/05/24`, `related.type: obsoletes`) is rejected by sigma-cli 3.1.0.

**A concrete miss, not a hypothetical one.** The pinned `proc_creation_win_certutil_download.yml`
matches only `urlcache ` and `verifyctl `. LOLBAS documents `certutil.exe -URL {REMOTEURL:.exe}` as a
download command **on the same page as the link**. Upstream added `'URL '` later — master carries it,
`modified: 2025-12-01`.

## Where upstream is strong, and where it is not

`proc_creation_win_regsvr32_susp_exec_path_1.yml` (master) matches regsvr32 with a command line
containing `:\ProgramData\`, `:\Temp\`, `:\Users\Public\`, `:\Windows\Temp\`, `\AppData\Local\Temp\` or
`\AppData\Roaming\` — the local-DLL-from-a-user-writable-path form that this repo's own scenario audit
flagged as the dominant real-world regsvr32 shape **and as uncovered here**. On that form, upstream is
ahead of us.

What upstream does not have, in any of the six: a measured false-positive rate, `fp_likelihood`,
`recommended_role` or `precision_notes`. Four of six carry `falsepositives: Unknown`, and `level`
encodes severity-if-true rather than noise (certutil decode ships at `level: high`).

That asymmetry is the whole argument for adopt-and-measure: **take their logic, add our measurement.**

## Reproduce

```bash
# on the audit VM (107)
git clone --depth 1 https://github.com/LOLBAS-Project/LOLBAS.git /opt/audit/scratch/lolbas
# link census: parse yml/**/*.yml, count Detection entries by type, classify each Sigma URL

curl -sfL https://raw.githubusercontent.com/SigmaHQ/sigma/<pinned-sha>/<rule-path> -o pinned/<rule>
curl -sfL https://raw.githubusercontent.com/SigmaHQ/sigma/master/<rule-path>      -o master/<rule>

REQUIRE_PRECISION_FIELDS=false /opt/audit/audit-rule.sh master /opt/audit/results/upstream-master
REQUIRE_PRECISION_FIELDS=false /opt/audit/audit-rule.sh pinned /opt/audit/results/upstream-pinned
```

Re-run this before leaning on the numbers: upstream moves, and the point of the exercise is that a
three-year-old snapshot of a ruleset is not the ruleset.
