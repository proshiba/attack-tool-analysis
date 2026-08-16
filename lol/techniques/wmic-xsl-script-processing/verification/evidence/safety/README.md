# Safety evidence notes

`scenario-scope-pre-run.json` returned `REVIEW` with no critical finding. The
review item is the declared lab-only name `certutil.lab`; the scenarios state
its temporary mapping to `192.168.1.50`. The final scenario check explicitly
allowed that internal name and returned `PASS` in `scenario-scope-final.json`.
Every accepted flow has its own
operator record and final `*-lab-scope.json` verdict of `PASS`.

Failed attempts are retained rather than hidden. Flow 1 includes unsuccessful
standard-user scheduling/quoting attempts; all post-attempt scope checks
passed. Flow 4's credentialed self-connection failed because Windows forbids
explicit credentials for local connections. Its first scope report is also
retained: the checker labeled the literal self address, local hostname, and
the self-address reverse name as external DNS names. The companion
`flow4-credentialed-self-attempt-readjudicated-lab-scope.json` uses the
checker's supported `--allow-domain` inputs for exactly those declared local
names (and normalizes only the reverse name's terminal dot) and returns
`PASS`. No external name was allowlisted.

The accepted flow 4 did not use credentials and its independent
`flow4-node-self-lab-scope.json` verdict is `PASS`. Unfiltered captures retain
ordinary Windows/Defender traffic in each manifest as informational,
non-tool-attributed activity; it is not silently removed or judged as attack
traffic.

## 2026-08-16 format-filter falsification

`scenario-scope-format-filter-pre-run.json` was produced before any WMIC
execution. The first checker invocation returned `REVIEW` only because the
older HTTPS scenario contains the explicitly lab-mapped `certutil.lab` name;
the committed report uses the checker's supported `--allow-domain
certutil.lab` input and reads `PASS` with no findings.

`format-filter-operator-log.json` contains the exact local-only WMIC commands,
time windows, accounts, exit codes, and marker results for 14 accepted rows.
Each `format-filter-*-lab-scope.json` report was computed from that record and
the row's full, unfiltered bounded event JSON with `--tool-image wmic.exe`.
All 14 verdicts are `PASS`: no traffic attributable to the declared attack
left the lab. The Zeek directory was empty because these were deliberately
local flows with no packet capture; the reports retain the checker's warning
that zero packet rows alone prove nothing. Sysmon EID 3/22 attribution—not a
pre-filtered capture—is the available network evidence.

Failed setup attempts (Task Scheduler batch-logon precondition, result-file
sharing race, archive-path quoting, and one collector rendering failure) were
not entered into the result matrix. Each was followed by a successful
`win_verify_baseline` rollback before retry. The unquoted absolute-path row and
the `.txt`/`.jpg` rows are retained because they are valid collected negative
results: WMIC executed as a process but refused the stylesheet, and no marker
was written.

The disposable local-account password used at runtime is not committed. The
reusable `invoke-format-filter-flow.ps1` fixture therefore accepts it as a
base64-transported mandatory parameter; base64 is transport, not storage or
protection. Raw archive hashes in `format-filter-falsification.json` identify
the exact collected artifacts retained outside the repository.

After gate iteration 1 requested the extensionless `/format:list` boundary,
`scenario-scope-format-filter-iteration2-pre-run.json` returned `PASS` before
execution. The new row's post-run scope report also returned `PASS`, and VM 104
was rolled back to `win_verify_baseline` afterward.
`scenario-scope-format-filter-iteration2-final.json` then returned `PASS` over
the completed 14-row scenario and evidence set.
