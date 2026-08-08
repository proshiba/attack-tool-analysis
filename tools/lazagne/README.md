# LaZagne

> Open-source application that recovers passwords stored locally by a wide range of software (browsers, mail clients, Wi-Fi, databases, sysadmin tools) on Windows, Linux and macOS.

| | |
|---|---|
| **Categories** | Credential Access |
| **Platforms** | windows, linux, macos |
| **Language** | Python |
| **License** | LGPL-3.0 |
| **Type** | standalone-binary |
| **Repository** | https://github.com/AlessandroZ/LaZagne |
| **Homepage** | https://github.com/AlessandroZ/LaZagne |
| **MITRE ATT&CK Software** | [S0349](https://attack.mitre.org/software/S0349/) |
| **Status** | active |
| **First seen** | 2015 |
| **Last reviewed** | 2026-08-08 |

## Overview

LaZagne aggregates dozens of per-application credential recovery routines into a single tool. Rather than touching LSASS, it harvests secrets from application stores: browsers, chats, databases, git/svn, Wi-Fi, and OS keyrings. Useful for situational credential collection that complements memory-based dumpers.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) |
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) |

## Usage examples

```text
lazagne.exe all              # run every module
lazagne.exe browsers         # only browser modules
lazagne.exe all -oJ          # write results as JSON
```

## Detection

- Read access to browser credential stores (e.g. Login Data, key4.db/logins.json) by unexpected processes.
- Known-bad hashes / AV signatures for the packaged PyInstaller binary.
- Bulk access to many application config paths in a short window.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/AlessandroZ/LaZagne)
- [MITRE ATT&CK S0349](https://attack.mitre.org/software/S0349/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
