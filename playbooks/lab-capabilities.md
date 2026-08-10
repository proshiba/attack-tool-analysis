# What this lab can and cannot verify

A scenario audit scores coverage against how a technique is used in the real world. Some of those uses
this lab **physically cannot run**. Those are not scenario gaps the author can close — no amount of
work in this repo produces a macOS host — and counting them as missing coverage would hold merges
hostage to hardware that does not exist.

So they are recorded here instead, and the auditor **excludes them from the coverage denominator** and
reports them as **lab-capability gaps**. Excluded is not hidden: a verification whose technique has a
real-world form this lab cannot reach must still say so in `scenarios.md`, so a reader is never left
believing the verified flow is the whole technique.

## The lab

| VM | Role | Verifiable |
|---|---|---|
| 100 `kali` | attacker, payload/C2 host (`192.168.1.50`) | Linux attacker tooling, staged payloads, lab-hosted C2 |
| 103 `ubuntu` | Linux target (`linux_verify_baseline`: Sysmon + auditd + tcpdump) | Linux implants, GTFOBins, Linux post-exploitation |
| 104 `win10` | Windows target (Win10 LTSC, `win_verify_baseline`) | Windows endpoint techniques, LOLBAS, Sysmon telemetry |
| 105 `remnux` | malware RE | static/dynamic analysis of artefacts |
| 106 `nsm` | Zeek/Suricata | network dimension, JA3/JARM, beacon periodicity |

## Cannot be verified here

| Not available | Consequence | Status |
|---|---|---|
| **macOS host** | macOS implants and macOS-specific payloads cannot be run | **Skipped by decision (2026-08-10)** — no VM, none planned |
| **Active Directory domain controller** | DCSync, Kerberoasting, silver/golden ticket, NTDS extraction and GPO-push delivery cannot be exercised | not built |
| **A second Windows host** | Windows-to-Windows lateral movement (SMB/WMI/WinRM to a peer) cannot be exercised | not built |
| **Windows Server** | server-role techniques (IIS/Exchange/AD CS) cannot be exercised | not built |
| **Cloud tenant / SaaS account** | cloud identity and SaaS abuse cannot be exercised | out of scope |
| **vmbr2 airgap segment** | fully detonation-isolated runs are not yet possible; bounded runs use snapshot + rollback instead | designed, not built |

## How to use this file

**Author** — when a grounded use-case falls in the table above, write it in `scenarios.md` under the
future/out-of-scope section with the reason ("macOS implant: the lab has no macOS host"), rather than
silently omitting it. Do not claim coverage the run does not have.

**Auditor** — a use-case that this file marks unavailable leaves the coverage denominator. Report it in
`missing_use_cases` prefixed `LAB-CAPABILITY:` so it stays visible, and do not let it push a
`coverage_ratio` below the floor or turn a verdict into `redo`. A use-case the lab CAN run and the
author skipped is a normal scenario gap and is scored normally.

**Anyone changing the lab** — when a capability arrives, move the row out of the table. The gap becomes
real work again the moment the hardware exists.
