# Mythic

> Plug-n-play, multi-agent C2 framework with a web UI. Payloads ('agents') and communication channels ('C2 profiles') are containerised and swappable (Apollo, Poseidon, Medusa, etc.).

| | |
|---|---|
| **Categories** | Command & Control (Remote Ops) |
| **Platforms** | linux |
| **Language** | Python, Go, JavaScript |
| **License** | BSD-3-Clause |
| **Type** | c2-framework |
| **Repository** | https://github.com/its-a-feature/Mythic |
| **Homepage** | https://docs.mythic-c2.net/ |
| **Status** | active |
| **First seen** | 2018 |
| **Last reviewed** | 2026-08-08 |

## Overview

Mythic is a modular, collaborative C2 platform built around Docker. The core provides operator UI, task/response tracking and reporting, while agents and C2 profiles are separate installable components. This lets teams mix an OS-specific agent (e.g. Apollo for Windows/.NET, Poseidon for cross-platform Go) with an arbitrary transport, and to extend the framework cleanly.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) |

## Usage examples

```text
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo
sudo ./mythic-cli start
# browse to the web UI, generate a payload, create a C2 profile instance
```

## Detection

- Per-agent indicators (Apollo/Poseidon/Medusa each have their own signatures).
- C2-profile defaults when unmodified; beaconing analysis on the chosen transport.
- SpecterOps and community detections published per agent.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/its-a-feature/Mythic)
- [Documentation](https://docs.mythic-c2.net/)
- [Mythic agents org](https://github.com/MythicAgents)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
