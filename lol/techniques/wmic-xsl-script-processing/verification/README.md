# WMIC XSL script-processing verification

Seven isolated-lab flows completed successfully, including the optional HTTPS
flow. The most important result is a blind spot: a medium-integrity standard
user can apply a scripted XSL from `AppData\Local\Temp` without producing any
HTTP, SMB, TLS, URL, or Internet-cache signal. The strongest surviving signals
were the local `/format:` process command, a direct WMIC-to-cmd child, and
JScript engine telemetry.

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

## Detection disposition

SigmaHQ `master` commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993` was the comparison point. The
former local remote-XSL process rule was retired in favor of upstream ID
`8d63dadf-b91b-4187-87b6-34a1114577ea`, whose logic already handles URL and
UNC sources, executable identity hashes, and `/format:` through `|windash`.
The three corpus-grounded adjacent rules were likewise adopted from master.

Only one new rule was authored: a high-confidence user-Temp narrowing of
SigmaHQ's broad local-XSL rule, against its unmeasured precision gap. The broad
local rule is now adopted as hunt/low, so other local paths remain covered.
Existing process-child, cache, registry, Zeek, and Suricata rules were retained
as independently measured sensor dimensions. The dead
`service: sysmon` qualifiers were removed from file/registry rules, slash
arguments use `|windash`, and no condition uses a numeric quantifier above
`1 of`. Network rules are hunt/low because their precision cannot be measured
on EVTX. Broad process-create and `/node:` rules are also hunt/low.

| Rule | Origin | Measurement | FP/category | Role/level |
|---|---|---|---:|---|
| SquiblyTwo remote `/format:` (8d63…) | adopted | pass, positive hit | 0/23,695 (0%) | alert/high |
| Broad local XSL (05c3…) | adopted | no positive corpus sample | 0/23,695 (0%) | hunt/low, medium FP |
| Local user Temp XSL (5b4b…) | precision-gap narrowing | no positive corpus sample | 0/23,695 (0%) | alert/high |
| WMIC XSL spawns shell (ac2c…) | existing local | pass, positive hit | 0/23,695 (0%) | alert/high |
| WMIC cache XSL (e329…) | existing local, repaired logsource | pass, positive hit | 0/542,441 (0%) | alert/high |
| WMIC JScript telemetry (59a1…) | existing local, repaired logsource | no positive corpus sample | 0/1,151,508 (0%) | alert/high |
| Generic process call create (526b…) | adopted | pass, positive hit | 0/23,695 (0%) | hunt/low, medium FP |
| Suspicious process call create (3c89…) | adopted | pass, positive hit | 0/23,695 (0%) | alert/high |
| Remote `/node:` (7773…) | adopted | no positive corpus sample | 0/23,695 (0%) | hunt/low, medium FP |
| Zeek XSL HTTP (0952…) | existing local | not testable on EVTX | not measurable | hunt/low, medium FP |
| Suricata XSL HTTP (7168…) | existing local | not testable on EVTX | not measurable | hunt/low, medium FP |

Zero matches are measured against the per-category denominators, not the
6,611,183-event whole corpus. A no-positive-sample verdict is not represented
as a detection hit. Detailed two-way comparisons—what upstream covers that
each local rule does not, and vice versa—are in
`evidence/upstream-comparison.md`; measurements are in
`evidence/rule-measurements.json`.

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

Raw PCAP, EVTX, event exports, NSM logs, credentials, and host data are not
committed. The repository contains selected sanitized telemetry fields,
capture hashes/counts, benign fixtures, and checker proofs. Kali listeners
were stopped, and VM 104 was rolled back to `win_verify_baseline` before and
after every run.

The current LOLBAS Wmic entry was checked separately after the slug-based
scenario-reference query returned zero matches. It documents the URL/SMB XSL
forms and adjacent process-create, `/node:`, and ADS forms. ADS process
creation is recorded as a future scenario, not silently counted as covered.
