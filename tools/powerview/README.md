# PowerView

> PowerShell tool for Active Directory reconnaissance: users, groups, ACLs, GPOs, trusts, sessions and local admin access, without needing RSAT.

| | |
|---|---|
| **Categories** | Discovery / Situational Awareness |
| **Platforms** | windows |
| **Language** | PowerShell |
| **License** | BSD-3-Clause |
| **Type** | script |
| **Repository** | https://github.com/PowerShellMafia/PowerSploit |
| **Homepage** | https://powersploit.readthedocs.io/ |
| **MITRE ATT&CK Software** | [S0194](https://attack.mitre.org/software/S0194/) |
| **Status** | maintenance |
| **First seen** | 2014 |
| **Last reviewed** | 2026-08-08 |

## Overview

PowerView (part of PowerSploit, and continued in the 'dev' branch / PowerView.py) provides a rich set of Get-Domain* / Find-* cmdlets for enumerating Active Directory relationships and hunting for user sessions and local-admin access. It is a long-standing staple of AD recon and the conceptual precursor to BloodHound collection.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) |

## Usage examples

```text
Import-Module .\PowerView.ps1
Get-DomainUser -SPN            # find kerberoastable accounts
Find-DomainUserLocation        # hunt for target-user sessions
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs
```

## Detection

- PowerShell script-block logging (4104) matching PowerView function names.
- Bulk LDAP enumeration and SAMR session queries from a workstation.
- AMSI detection of the module content.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [PowerSploit repository](https://github.com/PowerShellMafia/PowerSploit)
- [MITRE ATT&CK S0194 (PowerSploit)](https://attack.mitre.org/software/S0194/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
