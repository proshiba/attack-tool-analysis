# Rubeus

> C# toolset for raw Kerberos interaction and abuse: ticket requests, Kerberoasting, AS-REP roasting, pass-the-ticket, overpass-the-hash, delegation abuse, and S4U.

| | |
|---|---|
| **Categories** | Credential Access, Lateral Movement, Privilege Escalation |
| **Platforms** | windows |
| **Language** | C# |
| **License** | BSD-3-Clause |
| **Type** | dotnet-assembly |
| **Repository** | https://github.com/GhostPack/Rubeus |
| **Homepage** | https://github.com/GhostPack/Rubeus |
| **Status** | active |
| **First seen** | 2018 |
| **Last reviewed** | 2026-08-08 |

## Overview

Rubeus (part of GhostPack) is the go-to tool for Active Directory Kerberos attacks. It can request and renew TGTs/TGSs, harvest and inject tickets, perform Kerberoasting and AS-REP roasting for offline cracking, and abuse constrained / unconstrained / resource-based constrained delegation.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Steal or Forge Kerberos Tickets: Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| Use Alternate Authentication Material: Pass the Ticket | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| Steal or Forge Kerberos Tickets: Golden Ticket | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| Domain Policy Modification: Domain Trust Modification | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) |

## Usage examples

```text
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe asreproast /format:hashcat
Rubeus.exe asktgt /user:svc /rc4:<ntlm> /ptt   # overpass-the-hash
Rubeus.exe s4u /user:... /rc4:... /impersonateuser:administrator /msdsspn:...
```

## Detection

- 4769 (TGS requests) with RC4 (etype 0x17) for many SPNs from one host -> Kerberoasting.
- 4768 AS-REQ for accounts with 'do not require pre-auth' -> AS-REP roasting.
- Ticket-granting activity that does not correlate with normal interactive logons.
- Honeypot service accounts / SPNs to catch roasting attempts.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/GhostPack/Rubeus)
- [harmj0y - Rubeus intro](https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
