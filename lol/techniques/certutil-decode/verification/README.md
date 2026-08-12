# Certutil decode verification

This verification covers **Deobfuscate/Decode Files or Information (T1140)**
with the Microsoft-signed `certutil.exe`. Four endpoint-observed runs expanded
the behavioral evidence: `-decodehex`, `-f -decode` to an inert DLL-named
file, a non-admin standard-user decode, and `/decode`. Together they cover five
of six grounded use cases because the latter three include ordinary base64
decode. Decode-then-execute remains a separately scoped future scenario. Every
run began from a fresh `win_verify_baseline` rollback, decoded only the same
42-byte inert marker, and never loaded or executed its output. No packet capture
was taken, so post-run network safety is **NOT PROVEN**.

## Run results

| Run | Network | Files | Registry | Process | Parent-child |
|---|---|---|---|---|---|
| `-decodehex` as SYSTEM | Hand-authored EID 3/22 = 0 assertion; no pcap | EID 11 `.bin` | 3 EID 12 + 3 EID 13 OID leaf changes | EID 1 matched process rule | PowerShell parent; no direct child |
| `-f -decode` to `.dll` as SYSTEM | Hand-authored EID 3/22 = 0 assertion; no pcap | EID 11 `.dll`; first executable/script-tier positive | 3 EID 12 + 3 EID 13 OID leaf changes | EID 1 matched process rule | PowerShell parent; output not loaded or executed |
| `-decode` as standard user | Hand-authored EID 3/22 = 0 assertion; no pcap | EID 11 under `C:\Users\certlab` | No three OID leaf writes; OID ancestor attempts and per-user MuiCache activity instead | EID 1 at Medium integrity matched process rule | Task Scheduler parent; only `conhost.exe` child |
| `/decode` as SYSTEM | Hand-authored EID 3/22 = 0 assertion; no pcap | EID 11 `.bin` | 3 EID 12 + 3 EID 13 OID leaf changes | Old selector missed; `windash` rule matches | PowerShell parent; no direct child |

The standard-user comparison shows that the SYSTEM-only OID leaf writes are
privilege-context initialization rather than a stable decode invariant. The
user output moved from the SYSTEM runs' `C:\lab` paths to
`C:\Users\certlab\decoded-marker-user.txt`; the user process did not create any
of the three `311.60.3.x` leaf keys or their `Name` values.

## Sigma coverage

| Tier | Logsource | Role | Rule |
|---|---|---|---|
| 1 | `windows/process_creation` | alert | `win_process_creation_certutil_decode.yml` |
| 1 | `windows/file_event` | medium-level hunt, executable/script tier | `win_file_event_certutil_suspicious_output.yml` |
| 1 | `windows/file_event` | low-level hunt, ambient data/text tier | `win_file_event_certutil_data_output.yml` |

The process rule uses `windash` and trailing-space-only decode verbs, so the
verified slash form is covered. The file rule is split: `.exe .dll .ps1 .bat
.cmd .vbs .js .hta` remain the higher-confidence correlation tier, while `.zip
.bin .dat .txt` are an explicitly ambient hunt tier. `.txt` no longer shapes the
high-confidence rule merely because the original lab fixture used that suffix.

The clean-corpus zeroes are null results: controls found no certutil process
start or certutil file write anywhere in the relevant clean categories. The
process rule's low FP judgement therefore rests on the documented decode abuse
verbs. The executable/script tier has one attack-corpus positive and uses a
medium-FP, medium-level hunt posture; the ambient data/text tier remains a
high-FP, low-level hunt. Both require process, path, signer, size, or follow-on-
execution context.

## Safety and cleanup

`evidence/safety/lab-scope.json` now records `NOT_PROVEN`. No packet capture was
taken, and `evidence/safety/nsm-local-only/` contains only a README rather than
Zeek logs. The previous `PASS` was computed against that empty input and is
invalid. `evidence/endpoint-signals.json` records zero EID 3 and zero EID 22 for
the windows, but it is a hand-authored sanitized assertion, not mechanical
proof of what the target sent. Consequently this verification cannot claim
that no traffic attributable to the declared attack left the lab or supply a
manifest of everything else that did.

The required passing claim would be: *no traffic attributable to the declared
attack left the lab, and everything else that did is in the manifest.* This
verification cannot make that claim from the retained evidence.

VM 104 was finally rolled back to `win_verify_baseline`. Sysmon was running with
the expected config, and the temporary account, task, fixtures, outputs, runner
scripts, and telemetry directories were absent.

Historical audit gate iteration 3 passed at commit `e78ed8b`: safety `safe`, two rules
`pass`, the ambient data/text tier at non-blocking `no-corpus-coverage`, zero
blocking findings, and scenario coverage 5/6 (83%, above the 60% floor).
That safety decision relied on the invalid empty-input `PASS` and is superseded
by this `NOT_PROVEN` correction.
