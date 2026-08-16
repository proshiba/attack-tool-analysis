# WMIC XSL script-processing verification

Seven original isolated-lab flows and a 14-row format-filter falsification
matrix completed, including the optional HTTPS flow. The original blind spot
remains: a medium-integrity standard user can apply scripted XSL from a local
user-writable directory without HTTP, SMB, TLS, URL, or Internet-cache signals.
The new result is an upstream logic defect: renaming that stylesheet
`list.xsl`, `csv.xsl`, `table.xsl`, or `value.xsl` caused the adopted broad
local rule to suppress a successful execution.

This remains an adopt-and-measure verification, not a claim that WMIC XSL is
prevalent. The 954-file daily-news corpus contains zero `xsl`/`XSL` files and
the audit scenario reference returned zero daily-news cases. It does ground
`wmic process call create` and `/node:`; `mshta` appears in 33 files and
`rundll32` in 12. Remote WMIC XSL should therefore rank below those currently
grounded forms.

## Flow results

| Flow | Result | Network | Files | Registry | Process | Parent/child |
|---|---|---|---|---|---|---|
| HTTP JScript | exit 0, marker | HTTP GET | cache + marker | JScript start | remote `/format:` | WMIC→cmd |
| Local JScript, standard user | task 0, marker, medium integrity | **none** | local XSL + marker; no cache | per-user JScript start | local Temp `/format:` | WMIC→cmd |
| SMB JScript | exit 0, marker | SMB/NTLM/share/file open | marker; no cache | JScript start | UNC `/format:` | WMIC→cmd |
| `process call create` | return 0, marker | **none attributable** | marker | **none relevant** | process-create command | WmiPrvSE→cmd |
| self `/node:` | exit 0, caption | **no DCOM; none attributable** | **none** | benign VBScript start | `/node:192.168.1.52` | **none** |
| HTTP VBScript | exit 0, marker | HTTP GET | cache + marker | VBScript start | remote `/format:` | WMIC→cmd |
| HTTPS JScript | exit 0, marker | TLS/SNI/x509/JA3; no plaintext HTTP | cache + marker | JScript start | HTTPS `/format:` | WMIC→cmd |

The `/node:` result is explicitly negative: Windows optimized the target's own
address locally, so the lab did not exercise a DCOM TCP path. Its command line
is observable, but it cannot be treated as proof of lateral execution.

## Format-filter falsification result

Bare relative paths resolve from the current working directory for both a
standard user and an administrator. With no CWD copy, WMIC falls back to
`%SystemRoot%\System32\wbem`. The evasion therefore needs only a user-writable
CWD; elevation is needed only to plant the fallback directory.

| Row | Executed | Original rule | Fixed rule | Measured cause |
|---|---:|---:|---:|---|
| relative `benign.xsl`, standard/admin | yes | fired | fired | selectors; no filter |
| WBEM-only relative `benign.xsl`, admin | yes | fired | fired | selectors; no filter |
| quoted absolute `benign.xsl` | yes | fired | fired | selectors; no filter |
| quoted absolute `list.xsl` | yes | fired | fired | path breaks the loose substring |
| relative `list/csv/table/value.xsl` | yes | **silent** | fired | known-format substring filter |
| dash `-format:list.xsl` | yes | **silent** | fired | known-format substring filter |
| extensionless `/format:list` with planted `list.xsl` | no; built-in output | silent | silent | exact built-in token correctly suppressed |
| unquoted absolute `benign.xsl` | no, exit 44005 | fired | fired | WMIC refused; not an evasion |
| quoted absolute `.txt` / `.jpg` | no, exit 44210 | fired | fired | WMIC refused extension; not an evasion |

The selector-only diagnostic matched 14/14 captured WMIC events. The
known-format filter diagnostic matched the five successful silent rows plus
the benign extensionless built-in row, and the remote-operation filter matched
0/14. The hypothesis is
therefore confirmed. Our copy changes the built-in filter from `contains` to
`endswith`; its trade-off is a possible alert when a benign built-in token is
not the final command-line text. The filter is retained rather than removed.
The fixed rule restored all five findings.

## Detection disposition

SigmaHQ `master` commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993` was the comparison point. The
former local remote-XSL process rule was retired in favor of upstream ID
`8d63dadf-b91b-4187-87b6-34a1114577ea`, whose logic already handles URL and
UNC sources, executable identity hashes, and `/format:` through `|windash`.
The three corpus-grounded adjacent rules were likewise adopted from master.

Only one new rule was authored in the original expansion: a high-confidence user-Temp narrowing of
SigmaHQ's broad local-XSL rule, against its unmeasured precision gap. The broad
local rule remains hunt/low, but its adopted logic is now locally repaired for
the measured built-in-filename evasion. Other local paths remain covered.
Existing process-child, cache, registry, Zeek, and Suricata rules were retained
as independently measured sensor dimensions. The dead
`service: sysmon` qualifiers were removed from file/registry rules, slash
arguments use `|windash`, and no condition uses a numeric quantifier above
`1 of`. Network rules are hunt/low because their precision cannot be measured
on EVTX. Broad process-create and `/node:` rules are also hunt/low.

| Rule | Origin | Measurement | FP/category | Role/level |
|---|---|---|---:|---|
| SquiblyTwo remote `/format:` (8d63…) | adopted | pass, positive hit | 0/23,695 (0%) | alert/high, medium FP |
| Broad local XSL (05c3…) | adopted | no positive corpus sample | 0/23,695 (0%) | hunt/low, medium FP |
| Local user Temp XSL (5b4b…) | precision-gap narrowing | no positive corpus sample | 0/23,695 (0%) | alert/high |
| WMIC XSL spawns shell (ac2c…) | existing local | pass, positive hit | 0/23,695 (0%) | alert/high |
| WMIC cache XSL (e329…) | existing local, repaired logsource | pass, positive hit | 0/542,441 (0%) | alert/high |
| WMIC JScript telemetry (59a1…) | existing local, repaired logsource | no positive corpus sample | 0/1,151,508 (0%) | alert/high |
| Generic process call create (526b…) | adopted | pass, positive hit | 0/23,695 (0%) | hunt/low, medium FP |
| Suspicious process call create (3c89…) | adopted | pass, positive hit | 0/23,695 (0%) | alert/high, medium FP |
| Remote `/node:` (7773…) | adopted | no positive corpus sample | 0/23,695 (0%) | hunt/low, medium FP |
| Zeek XSL HTTP (0952…) | existing local | not testable on EVTX | not measurable | hunt/low, medium FP |
| Suricata XSL HTTP (7168…) | existing local | not testable on EVTX | not measurable | hunt/low, medium FP |

The fixed broad local rule remained at 0/23,695 process-creation baseline
events (0.0%; measured floor low), so its medium/hunt/low disposition did not
change. The 20,136/6,923,967 values are the catalog's superseded pre-correction
figures; current measurements use 23,695/6,611,183. A no-positive-sample verdict is not represented
as a detection hit. Detailed two-way comparisons—what upstream covers that
each local rule does not, and vice versa—are in
`evidence/upstream-comparison.md`; measurements are in
`evidence/rule-measurements.json`, and the full sanitized matrix is in
`evidence/format-filter-falsification.json`.

No broad VBScript registry rule was added because the benign `/node:` query
set the same telemetry. No TLS rule was added because the observed JA3/JA3S,
SNI, and certificate describe reusable stack/service properties rather than
WMIC-specific behavior.

## Safety and evidence handling

Every accepted flow has a distinct operator log and a post-run scope verdict
of `PASS` under `evidence/safety/`. The pre-run scenario checker had no
critical finding and requested review only for the declared lab-only
`certutil.lab` name. Failed attempts and the transparent readjudication of
three self-address/local-name checker false positives are retained and
explained in `evidence/safety/README.md`.

The 14-row local matrix has its own aggregate operator record and one post-run
scope report per row; all 14 are `PASS`. No packet capture was needed or
fabricated. The checker received each unfiltered bounded Sysmon JSON and
`wmic.exe` attribution. VM 104 was rolled back before and after every row and
the final baseline check found no fixture directory, disposable account, or
marker.

Raw PCAP, EVTX, event exports, NSM logs, credentials, and host data are not
committed. The repository contains selected sanitized telemetry fields,
capture hashes/counts, benign fixtures, and checker proofs. Kali listeners
were stopped, and VM 104 was rolled back to `win_verify_baseline` before and
after every run.

The current LOLBAS Wmic entry was checked separately after the slug-based
scenario-reference query returned zero matches. It documents the URL/SMB XSL
forms and adjacent process-create, `/node:`, and ADS forms. ADS process
creation is recorded as a future scenario, not silently counted as covered.

## Merge gate

For this format-filter run, iteration 1 at `27b9066` BLOCKED until the
extensionless `/format:list` boundary was measured. That added negative row
showed built-in output, exit 0, and no marker despite a planted CWD
`list.xsl`, closing the blocker empirically.

Iteration 2 at `9d1c0df` PASSed with exit 0: 11 rules, zero blocking rule
verdicts, safety `safe`, and scenario `expand` at 5/7 grounded in-scope use
cases (71%, above the 60% floor). The harness outcomes were five pass, four
no-corpus-coverage, and two not-testable-on-EVTX. Seven findings were
non-blocking. The auditor recommended treating the separate JScript registry
telemetry rule's FP likelihood as medium pending benign built-in-format
controls; that unrelated rule was not changed after the PASS measurement.
