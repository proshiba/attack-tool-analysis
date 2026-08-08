# PowerUp / SharpUp

> Windows local privilege-escalation checks. PowerUp is the PowerShell original; SharpUp is the C# port that enumerates common misconfigurations (unquoted service paths, weak service/registry ACLs, DLL hijack candidates, AlwaysInstallElevated).

| | |
|---|---|
| **Categories** | Privilege Escalation, Discovery / Situational Awareness |
| **Platforms** | windows |
| **Language** | PowerShell, C# |
| **License** | BSD-3-Clause |
| **Type** | script-and-dotnet-assembly |
| **Repository** | https://github.com/GhostPack/SharpUp |
| **Homepage** | https://github.com/PowerShellMafia/PowerSploit |
| **Status** | maintenance |
| **First seen** | 2014 |
| **Last reviewed** | 2026-08-08 |

## Overview

PowerUp (from PowerSploit's Privesc module) and its GhostPack C# port SharpUp automate discovery of common Windows privilege-escalation vectors: modifiable services and service binaries, unquoted service paths, weak registry ACLs, writable %PATH% directories, AlwaysInstallElevated, and stored credentials. PowerUp additionally offers abuse functions to weaponise several findings.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Hijack Execution Flow: Services File Permissions Weakness | [T1574.010](https://attack.mitre.org/techniques/T1574/010/) |
| Hijack Execution Flow: Services Registry Permissions Weakness | [T1574.011](https://attack.mitre.org/techniques/T1574/011/) |
| Hijack Execution Flow: Path Interception by Unquoted Path | [T1574.009](https://attack.mitre.org/techniques/T1574/009/) |
| Boot or Logon Autostart Execution: Registry Run Keys | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |

## Usage examples

```text
Import-Module .\PowerUp.ps1; Invoke-AllChecks
SharpUp.exe audit
SharpUp.exe   # default = run all checks
```

## Detection

- Rapid enumeration of service configs and ACLs (sc.exe, WMI, registry reads).
- PowerShell script-block logging (Event ID 4104) matching PowerUp function names.
- AMSI / signature detection of the well-known script and assembly.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [SharpUp repository](https://github.com/GhostPack/SharpUp)
- [PowerSploit (PowerUp)](https://github.com/PowerShellMafia/PowerSploit)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
