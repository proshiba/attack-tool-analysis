# SharpHound / BloodHound

> Active Directory attack-path mapping. SharpHound is the collector; BloodHound ingests the data into a graph so operators can find shortest paths to Domain Admin and other high-value targets.

| | |
|---|---|
| **Categories** | Discovery / Situational Awareness |
| **Platforms** | windows, linux, macos |
| **Language** | C#, TypeScript |
| **License** | Apache-2.0 |
| **Type** | collector-and-server |
| **Repository** | https://github.com/SpecterOps/BloodHound |
| **Homepage** | https://bloodhound.specterops.io/ |
| **MITRE ATT&CK Software** | [S0521](https://attack.mitre.org/software/S0521/) |
| **Status** | active |
| **First seen** | 2016 |
| **Last reviewed** | 2026-08-08 |

## Overview

BloodHound uses graph theory to reveal hidden and unintended relationships in an Active Directory (and Azure AD/Entra) environment. SharpHound (C#) collects sessions, ACLs, group memberships, trusts, GPOs and more; the BloodHound UI then computes attack paths (e.g. 'who can reach Domain Admin'). Both attackers and defenders (and the Community Edition / legacy versions) use it.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) |

## Usage examples

```text
SharpHound.exe -c All
SharpHound.exe --collectionmethods Session,LoggedOn --loop
# import the resulting zip into the BloodHound GUI and run built-in queries
```

## Detection

- High-volume LDAP queries enumerating users/groups/ACLs from a single host.
- SAMR / network session enumeration (SharpHound Session/LoggedOn) across many hosts.
- 4662 with broad property reads; ldap traffic anomalies; honeytoken objects.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [BloodHound repository](https://github.com/SpecterOps/BloodHound)
- [Documentation](https://bloodhound.specterops.io/)
- [MITRE ATT&CK S0521](https://attack.mitre.org/software/S0521/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
