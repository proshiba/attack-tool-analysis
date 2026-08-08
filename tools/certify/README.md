# Certify

> C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) - the ESC1-ESC8 escalation paths.

| | |
|---|---|
| **Categories** | Privilege Escalation, Credential Access, Discovery / Situational Awareness |
| **Platforms** | windows |
| **Language** | C# |
| **License** | BSD-3-Clause |
| **Type** | dotnet-assembly |
| **Repository** | https://github.com/GhostPack/Certify |
| **Homepage** | https://posts.specterops.io/certified-pre-owned-d95910965cd2 |
| **Status** | active |
| **First seen** | 2021 |
| **Last reviewed** | 2026-08-08 |

## Overview

Certify (GhostPack) finds vulnerable certificate templates and CA misconfigurations in AD CS and can request certificates that allow authentication as arbitrary users (domain escalation). It pairs with Rubeus / ForgeCert to turn issued certificates into Kerberos TGTs. It operationalises the ESC1-ESC8 techniques from the 'Certified Pre-Owned' research.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Steal or Forge Authentication Certificates | [T1649](https://attack.mitre.org/techniques/T1649/) |
| Unsecured Credentials: Private Keys | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |

## Usage examples

```text
Certify.exe find /vulnerable
Certify.exe request /ca:CA01\corp-CA /template:VulnTemplate /altname:administrator
# convert the resulting .pfx to a TGT with Rubeus asktgt /certificate:
```

## Detection

- AD CS certificate issuance events (4886/4887) with a subject alternative name that differs from the requester.
- Certificate-based logons (4768 with certificate info) for privileged accounts.
- Audit and lock down template enrollment permissions and 'supply subject in request'.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Certify repository](https://github.com/GhostPack/Certify)
- [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
