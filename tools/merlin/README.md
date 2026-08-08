# Merlin

> Cross-platform post-exploitation C2 written in Go, notable for early adoption of HTTP/2 and HTTP/3 (QUIC) channels.

| | |
|---|---|
| **Categories** | Command & Control (Remote Ops) |
| **Platforms** | windows, linux, macos |
| **Language** | Go |
| **License** | GPL-3.0 |
| **Type** | c2-framework |
| **Repository** | https://github.com/Ne0nd0g/merlin |
| **Homepage** | https://merlin-c2.readthedocs.io/ |
| **Status** | active |
| **First seen** | 2018 |
| **Last reviewed** | 2026-08-08 |

## Overview

Merlin is an OSS C2 framework focused on modern web transports. Agents are written in Go and run on Windows/Linux/macOS, communicating over HTTP/1.1, HTTP/2 and HTTP/3 (QUIC). It supports in-memory .NET assembly execution, BOFs, and modules, and is often used to study detection of newer protocol channels.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) |

## Usage examples

```text
./merlinServer-Linux-x64
# generate an agent, start an https/h2/h3 listener, interact with agents
```

## Detection

- HTTP/2 and HTTP/3 (QUIC) egress from unusual client processes.
- Default agent JA3/JA3S and URL patterns.
- Beaconing analysis; community Sigma rules.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/Ne0nd0g/merlin)
- [Documentation](https://merlin-c2.readthedocs.io/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
