# SigmaHQ master comparison

Baseline: local SigmaHQ `master` commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993`. Each rule was parsed and
measured on VM 107 against evtx-baseline v0.8.4. The `positive corpus` column
is the public audit corpus result; `lab result` is a separate evaluation against
the retained Run A/B/C telemetry. SigmaHQ rules are not copied into this tree.

| Upstream rule (modified) | Clean FP / category denominator | Positive corpus | Upstream -> exact lab form | Lab/local -> upstream difference and disposition |
|---|---:|---|---|---|
| `4fc0deee` Potential System DLL Sideloading From Non System Locations (2026-07-10) | 0 / 727,396 image loads (0%) | hit | Hit Run A `version.dll` from the mounted drive and Run B `uxtheme.dll` from ProgramData. | Upstream covers far more system-DLL basenames than the lab. Adopt its mismatch logic; no parallel local sideload rule. Suggested precision: medium / hunt / medium because the large name set can match legitimate application-local DLLs despite the clean floor. |
| `c1344fa2` Defender Exclusions Added - PowerShell (2022-11-26) | 0 / 322 PowerShell script blocks (0%) | no hit | Not evaluable in Run A: the collector recorded zero EID 4104 events. | The lab adds no ScriptBlockText coverage. Retain as a sensor-dependent complement; suggested medium / hunt / medium. |
| `17769c90` PowerShell Defender Exclusion (2022-05-12) | 0 / 23,695 process starts (0%) | no hit | Hit the Run A `Add-MpPreference` process command line. | Upstream already covers both exclusion-process and exclusion-path forms. Adopt; no local duplicate. Suggested medium / hunt / medium for legitimate administration. |
| `29e1c216` Suspicious Mount-DiskImage (2022-02-01) | 0 / 322 PowerShell script blocks (0%) | no hit | No hit because EID 4104 was absent, although EID 1 preserved the command. | Local `a270163b` adds the missing process-creation dimension. Upstream remains richer when Script Block Logging is present. Suggested upstream medium / hunt / low. |
| `902cedee` Suspicious Invoke-Item From Mount-DiskImage (2022-02-01) | 0 / 322 PowerShell script blocks (0%) | no hit | No hit: EID 4104 was absent and the observed chain mounted then launched separately rather than using `Invoke-Item` in one block. | Local `a270163b` covers the base mount command but does not claim the upstream rule's more specific invoke correlation. Retain upstream as complementary, low / alert / medium when its required telemetry exists. |
| `92626ddd` Scheduled Task Creation Via Schtasks.EXE (2025-10-22) | 16 / 23,695 process starts (0.067525%) | hit | Missed Run B because its `User` filter suppresses localized `NT AUTHORITY\\SYSTEM`, the exact injected context. | Local `e9958859` retains SYSTEM and requires `/Create` plus `/XML`; it hit Run B but measured 37 / 23,695 (0.156151%), so it is high-likelihood / hunt / low. Upstream is broader for non-SYSTEM creation and remains medium / hunt / low. |
| `cbec226f` Suspicious Process Parents (2022-09-08) | 0 / 23,695 process starts (0%) | hit | Hit the anomalous `notepad.exe -> cmd.exe` edge in Run B. | Upstream covers suspicious parents beyond Notepad; the local XML rule adds task-import semantics beyond its parent-only logic. Adopt as low / alert / high; no duplicate parent rule. |
| `431a1fdb` New Kernel Driver Via SC.EXE (2025-10-07) | 0 / 23,695 process starts (0%) | no hit | Hit the canonical Run B `sc create ... type= kernel` event. | Its optional Avira filters consume attacker-controlled service names, paths, and arguments. A synthetic condition test made the upstream result false while local `c253bb68` stayed true. The no-filter local rule measured 6 / 23,695 (0.025322%), medium / hunt / low. Do not adopt the upstream filters unchanged. |
| `dd3ee8cc` Registry Modification of MS-settings Protocol Handler (2026-01-24) | 0 / 23,695 process starts (0%) | no hit | Hit both Run B `reg.exe add` process forms. | Upstream covers PowerShell registry cmdlets beyond the lab's `reg.exe` form. Adopt as low / alert / high; no local duplicate. |
| `152f3630` Shell Open Registry Keys Manipulation (2022-01-13) | 0 / 2,865,735 registry events (0%) | hit | Hit Run B default-value and `DelegateExecute` telemetry. | Upstream covers `exefile` and symbolic-link variants beyond the lab. Adopt as low / alert / high; no local duplicate. Its empty-default filter cannot suppress the exact chain because `DelegateExecute` independently matches. |
| `a1a144b7` Remote Thread Creation In Uncommon Target Image (2025-07-04) | 0 / 694 create-remote-thread events (0%) | hit | Hit Run B's ProgramData source into System32 Notepad, with no filter match. | Upstream covers other uncommon targets; local rules instead cover the subsequent CLR loads. Adopt as low / alert / medium; no duplicate EID 8 rule. |
| `4508a70e` DotNet CLR DLL Loaded By Scripting Applications (2023-02-23) | 0 / 727,396 image loads (0%) | no hit | Missed all verified hosts because its source list contains scripting applications, not Notepad or arbitrary native loaders. | Local `e84012d1` adds Notepad (0 / 727,396, low / alert / high); local `856329b4` adds user-writable image roots (18 / 727,396, 0.002475%, medium / hunt / low). Upstream still covers its scripting-host set, which the local rules do not. |

## Filter audit

The five local rules have no `filter_*` blocks. The upstream rules were audited
without silently inheriting their filters. The one confirmed attacker-string
off switch is `431a1fdb`: both optional exclusions are entirely command-line
substrings chosen by the service creator. The deterministic two-case result is
in `filter-evasion-test.json`; the locally derived SC rule removes those filters
and reports the resulting six baseline matches instead of hiding them.

The scheduled-task SYSTEM exclusion is not a user-supplied string, but it is a
proven context gap: the July 31 chain and the lab's injected payload both create
the task as SYSTEM. The local `/Create` + `/XML` rule fills that gap honestly at
a high measured FP likelihood. No upstream report or external PR was opened in
this verification; the repository contains a reproducible finding for later
submission.

SigmaHQ's audit verdict for the twelve unchanged upstream files was
`needs-work` solely because upstream omits this repository's required precision
fields. Those unchanged files are comparison inputs, not proposed local rules.
