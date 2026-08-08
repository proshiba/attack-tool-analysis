# Sliver

> Open-source, cross-platform adversary-emulation / C2 framework by Bishop Fox. Supports implants over mTLS, WireGuard, HTTP(S) and DNS, with multiplayer operations, staging, and a large post-exploitation feature set.

| | |
|---|---|
| **Categories** | Command & Control (Remote Ops), Lateral Movement |
| **Platforms** | windows, linux, macos |
| **Language** | Go |
| **License** | GPL-3.0 |
| **Type** | c2-framework |
| **Repository** | https://github.com/BishopFox/sliver |
| **Homepage** | https://sliver.sh/ |
| **MITRE ATT&CK Software** | [S1068](https://attack.mitre.org/software/S1068/) |
| **Status** | active |
| **First seen** | 2019 |
| **Last reviewed** | 2026-08-08 |

## Overview

Sliver is a mature, actively developed OSS Command-and-Control framework and a common free alternative to Cobalt Strike. Implants are compiled in Go for Windows/Linux/macOS and communicate over mutually-authenticated TLS, WireGuard, HTTP(S) or DNS. It provides an armory of extensions, BOF/COFF loading, in-memory .NET execution, SOCKS/pivots, and multiplayer team operation via gRPC.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) |

## Usage examples

```text
# server console
generate --mtls example.com --os windows --save ./implant.exe
https --lport 443            # start an HTTPS listener
sessions ; use <id> ; interactive
armory install <extension>
```

## Detection

- JARM/JA3(S) and default certificate fingerprints of Sliver listeners.
- Named-pipe and staging patterns; known default HTTP URIs/headers (tunable, so not reliable alone).
- Beaconing/jitter analysis on egress; DNS tunneling volume anomalies.
- Community Sigma/Suricata rules and the Sliver detection research from Immunefi/Microsoft; EDR detections for BOF/execute-assembly behaviour.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/BishopFox/sliver)
- [Documentation / wiki](https://sliver.sh/docs)
- [MITRE ATT&CK S1068](https://attack.mitre.org/software/S1068/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
