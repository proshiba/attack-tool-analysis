# Seatbelt

> C# host survey / situational-awareness tool that runs dozens of 'safety checks' from both offensive and defensive perspectives (OS config, security products, credentials on disk, network, user data).

| | |
|---|---|
| **Categories** | Discovery / Situational Awareness |
| **Platforms** | windows |
| **Language** | C# |
| **License** | BSD-3-Clause |
| **Type** | dotnet-assembly |
| **Repository** | https://github.com/GhostPack/Seatbelt |
| **Homepage** | https://github.com/GhostPack/Seatbelt |
| **Status** | active |
| **First seen** | 2018 |
| **Last reviewed** | 2026-08-08 |

## Overview

Seatbelt (GhostPack) is the standard local enumeration tool for red teams on Windows. It bundles many collection commands (AV/EDR presence, AppLocker/WDAC, UAC/LAPS config, PowerShell logging, saved RDP/Wi-Fi creds, browser data, cloud credentials, scheduled tasks) so an operator can quickly understand a foothold and find escalation or looting opportunities.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) |
| Account Discovery | [T1087](https://attack.mitre.org/techniques/T1087/) |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |

## Usage examples

```text
Seatbelt.exe -group=all
Seatbelt.exe -group=user
Seatbelt.exe -group=remote -computername=host2
Seatbelt.exe OSInfo AntiVirus PowerShell
```

## Detection

- In-memory .NET assembly execution (execute-assembly) - CLR load into non-managed processes; ETW/AMSI .NET telemetry.
- Burst of diverse registry/WMI/file reads characteristic of mass enumeration.
- Signature/YARA on the assembly when dropped to disk.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/GhostPack/Seatbelt)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
