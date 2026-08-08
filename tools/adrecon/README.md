# ADRecon

> PowerShell tool that gathers Active Directory information and produces a consolidated Excel (or CSV/JSON) report covering users, groups, computers, GPOs, trusts, ACLs and security posture.

| | |
|---|---|
| **Categories** | Discovery / Situational Awareness |
| **Platforms** | windows |
| **Language** | PowerShell |
| **License** | GPL-3.0 |
| **Type** | script |
| **Repository** | https://github.com/adrecon/ADRecon |
| **Homepage** | https://github.com/adrecon/ADRecon |
| **Status** | maintenance |
| **First seen** | 2018 |
| **Last reviewed** | 2026-08-08 |

## Overview

ADRecon extracts a broad, structured snapshot of an Active Directory environment and generates an analyst-friendly report. It is popular for both offensive recon and defensive assessments / audits because the single report highlights weak configurations (Kerberos policy, delegation, stale accounts, ACL issues).

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) |
| Group Policy Discovery | [T1615](https://attack.mitre.org/techniques/T1615/) |

## Usage examples

```text
.\ADRecon.ps1
.\ADRecon.ps1 -DomainController dc01 -Credential corp\user
.\ADRecon.ps1 -OutputType CSV,JSON
```

## Detection

- Large single-session LDAP enumeration touching most directory partitions.
- PowerShell logging of ADRecon function names / module import.
- Excel/COM automation spawned from PowerShell on a non-analyst host.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/adrecon/ADRecon)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
