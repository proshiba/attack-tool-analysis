# Audit datasets — sources, not copies

**No corpus is committed to this repository.** The evaluation corpora are 8+ GiB of raw
Windows event logs; committing them would be both impractical and a sanitisation risk.
This file is the authoritative record of *which* data produced every number in the audit
results, and how to reconstitute it. Only small derived catalogs (event counts per
channel/EventID, per-category denominators) live in `audit/catalog/`.

All paths below are the layout on the audit host (VM 107, `sigma-audit`).

## Corpora

### `evtx-baseline` — the false-positive corpus (clean)

| | |
|---|---|
| Source | Nextron Systems `evtx-baseline`, release **v0.8.4** — <https://github.com/NextronSystems/evtx-baseline> |
| Local path | `/data/datasets/evtx-baseline` |
| Size | 8.2 GiB, 2,239 `.evtx` files |
| Measured events | **6,611,183** (see "Corrected event count" below) |
| Contents | `Logs_Client`, `Logs_Win11`, `Logs_Win11_2023`, `Win2022-AD`, `win2022-0-20348-azure`, `win2022-evtx`, `win7-x86` |
| Role | Every FP measurement. This corpus is *clean* — a rule that matches here matches benign activity. |

Caveat that must accompany every number derived from it: it is a **lab baseline**, not a
production estate. A rule measuring 0 FP here can still be noisy in production. Measured
values are therefore treated as a *floor* for `fp_likelihood`, never a ceiling.

#### Corrected event count

`catalog/dataset-metrics.json` originally recorded **6,923,967** events, derived as
"Hayabusa log-metrics CSV sum plus Chainsaw --skip-errors correction": 6,611,183 from
Hayabusa plus 312,784 records that Hayabusa was believed to have lost when it stopped at
malformed record 2783 of `Logs_Win11_2023/Security.evtx`.

Re-measuring per file (`audit/lib/baseline_metrics.py`) shows those 312,783 records are
**already included** in the 6,611,183 total — the per-file scan of that one file yields
312,783 records and 2,592 EventID 4688, and the corpus-wide 4688 total is 8,603 both with
and without the file scanned separately. The correction was therefore a double count, and
6,923,967 overstates the corpus by 4.7%. The measured value 6,611,183 is authoritative.

### `EVTX-ATTACK-SAMPLES` — positive corpus

| | |
|---|---|
| Source | <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES> @ `4ceed2f4706daf601c212a8f91c113dd85349a2c` (2023-01-24) |
| Local path | `/data/datasets/EVTX-ATTACK-SAMPLES` |
| Size | 50 MiB, 278 `.evtx` files, 7,840 events (880 of them `process_creation`) |
| Role | Detection (recall) checks. |

Known limit, measured not assumed: it contains **no mimikatz command line**. SigmaHQ's own
mimikatz rule scores `no-hit` against it. A detection miss here is reported as
`needs-work` with the code `no-positive-corpus-sample`, never as a rule failure.

### `regression_data` — SigmaHQ regression corpus

| | |
|---|---|
| Source | `tests/regression_data` inside <https://github.com/SigmaHQ/sigma> |
| Local path | `/data/datasets/regression_data` (copied from `/data/datasets/sigma`) |
| Size | 12 MiB, 202 `.evtx` files, 238 events |
| Role | Second positive corpus. |

### `SigmaHQ/sigma` — rule corpus and log-source mapping

| | |
|---|---|
| Source | <https://github.com/SigmaHQ/sigma> @ `8eaafff1f2845a696050e05e72ba1140ee190698` (2026-08-05) |
| Local path | `/data/datasets/sigma` |
| Role | `tests/thor.yml` is the category → (channel, EventID) mapping passed to `evtx-sigma-checker` and parsed by `baseline_metrics.py`. Upstream rules are also used as **control rules**: running SigmaHQ's equivalent rule against the same corpora separates "our rule is weak" from "the corpus lacks the technique". |

### `proshiba/tech-memo` — daily security news corpus

| | |
|---|---|
| Source | <https://github.com/proshiba/tech-memo> @ `a26e0feb958002424dfd09a674ba18cea2ccbbc7` (2026-08-10) |
| Local path | `/data/tech-memo` |
| Size | 51 MiB, 954 article files at time of the 2026-08-10 audit |
| Role | Grounds scenario realism. Every scenario judgement cites a `source_url` from this corpus. |

## Tooling

| Tool | Version | Role |
|---|---|---|
| `sigma-cli` | 3.1.0 | Syntax gate. Note: only `1 of` and `all of` parse — every numeric quantifier > 1 (`2 of selection_*`) is rejected in any position. |
| `evtx-sigma-checker` | Nextron (bundled binary) | FP and detection matching against EVTX. |
| `hayabusa` | 4.0.0 | Event counting (`eid-metrics`). Must be invoked **per file**: directory mode truncates `Logs_Win11_2023/Security.evtx`. |
| `chainsaw` | 2.16.3 | Cross-check for malformed EVTX. |

## What is committed here

- `audit/lib/`, `audit/bin/` — the harness itself.
- `audit/catalog/baseline-category-metrics.json` — derived per-category denominators
  (~100 KB): channel/EventID counts and the category mapping used to score rules.
- `audit/catalog/dataset-metrics.json` — corpus totals and their provenance.

Not committed: any `.evtx`, any raw checker output, any pcap, and any third-party dump
(LOLBAS/GTFOBins JSON) that a fetch script can reproduce.
