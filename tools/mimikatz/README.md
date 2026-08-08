# mimikatz

> Post-exploitation toolkit for extracting plaintext passwords, hashes, PINs and Kerberos tickets from Windows memory, and for abusing Kerberos (pass-the-hash, pass-the-ticket, golden/silver tickets, DCSync).

| | |
|---|---|
| **Categories** | Credential Access, Privilege Escalation, Lateral Movement |
| **Platforms** | windows |
| **Language** | C |
| **License** | CC-BY-4.0 |
| **Type** | standalone-binary |
| **Repository** | https://github.com/gentilkiwi/mimikatz |
| **Homepage** | https://blog.gentilkiwi.com/mimikatz |
| **MITRE ATT&CK Software** | [S0002](https://attack.mitre.org/software/S0002/) |
| **Status** | active |
| **First seen** | 2007 |
| **Last reviewed** | 2026-08-08 |

## Overview

mimikatz is the reference tool for Windows credential theft. Its `sekurlsa` module reads secrets from the LSASS process (plaintext passwords via WDigest, NTLM hashes, Kerberos tickets). Other modules cover LSA secrets, the DPAPI master keys, the SAM database, Kerberos ticket forging (golden/silver tickets), and directory replication abuse (`lsadump::dcsync`). It is bundled into almost every offensive framework and drives a large share of real-world AD compromises.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| OS Credential Dumping: Security Account Manager | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) |
| OS Credential Dumping: LSA Secrets | [T1003.004](https://attack.mitre.org/techniques/T1003/004/) |
| OS Credential Dumping: DCSync | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Steal or Forge Kerberos Tickets: Golden Ticket | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| Steal or Forge Kerberos Tickets: Silver Ticket | [T1558.002](https://attack.mitre.org/techniques/T1558/002/) |
| Use Alternate Authentication Material: Pass the Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) |
| Use Alternate Authentication Material: Pass the Ticket | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

## Usage examples

```text
privilege::debug            # acquire SeDebugPrivilege
sekurlsa::logonpasswords    # dump creds/tickets from LSASS memory
lsadump::sam                # dump local SAM hashes
lsadump::dcsync /user:krbtgt  # pull hashes via DC replication
kerberos::golden /user:... /domain:... /sid:... /krbtgt:... /ptt
```

## Detection

- Monitor for non-standard processes opening a handle to lsass.exe with PROCESS_VM_READ (Sysmon Event ID 10; target lsass.exe).
- Sensitive-privilege use / SeDebugPrivilege assignment (Windows Event ID 4673/4703).
- Enable and alert on 4662 (directory replication, 'DS-Replication-Get-Changes') from non-DC accounts to catch DCSync.
- Golden/silver tickets: TGTs with anomalous lifetimes, encryption downgrade (RC4), and 4769 requests without a preceding 4768.
- Credential Guard / LSASS PPL (RunAsPPL) raise the bar for sekurlsa memory reads.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/gentilkiwi/mimikatz)
- [MITRE ATT&CK S0002](https://attack.mitre.org/software/S0002/)
- [adsecurity.org - Unofficial mimikatz guide](https://adsecurity.org/?page_id=1821)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
