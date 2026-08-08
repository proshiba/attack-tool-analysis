# Covenant

> .NET (C#) collaborative C2 framework with a web interface. Uses 'Grunt' implants and 'Elite'/Task tasking; historically important as an early open .NET C2, now in maintenance.

| | |
|---|---|
| **Categories** | Command & Control (Remote Ops) |
| **Platforms** | windows, linux |
| **Language** | C# |
| **License** | GPL-3.0 |
| **Type** | c2-framework |
| **Repository** | https://github.com/cobbr/Covenant |
| **Homepage** | https://github.com/cobbr/Covenant/wiki |
| **Status** | maintenance |
| **First seen** | 2019 |
| **Last reviewed** | 2026-08-08 |

## Overview

Covenant is a .NET command-and-control framework that emphasises usability and collaboration. Its Grunt implants run on .NET (Framework/Core), tasking is done through a web UI, and it pioneered accessible .NET post-exploitation tooling. Development has largely stalled (maintenance), but it remains a common lab/training C2 and a useful reference implementation.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) |

## Usage examples

```text
dotnet run   # or run via the provided Docker image
# create an HTTP listener, generate a Grunt launcher, task Grunts from the web UI
```

## Detection

- Default Grunt HTTP profiles (URIs, cookies, response formats).
- Well-known JA3/certificate and staging indicators.
- Community Sigma/YARA rules; EDR .NET in-memory execution telemetry.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/cobbr/Covenant)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
