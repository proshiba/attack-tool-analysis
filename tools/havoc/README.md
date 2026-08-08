# Havoc

> Modern, open-source C2 framework with a Qt GUI team server, a malleable-style profile, sleep obfuscation, and an extensible agent ('Demon') written in C.

| | |
|---|---|
| **Categories** | Command & Control (Remote Ops) |
| **Platforms** | windows, linux |
| **Language** | Go, C, Python |
| **License** | GPL-3.0 |
| **Type** | c2-framework |
| **Repository** | https://github.com/HavocFramework/Havoc |
| **Homepage** | https://havocframework.com/ |
| **Status** | active |
| **First seen** | 2022 |
| **Last reviewed** | 2026-08-08 |

## Overview

Havoc is a free C2 framework aimed at red teams and researchers. Its 'Demon' agent features indirect syscalls, sleep obfuscation (Ekko/Foliage-style), return-address spoofing, and support for object-file (BOF) execution. The team server is written in Go with a Python/C extensibility layer and a cross-platform GUI client.

## Related TTPs (MITRE ATT&CK)

| Technique | ID |
|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) |
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) |

## Usage examples

```text
./havoc server --profile ./profiles/havoc.yaotl -v
# connect with the GUI client, create an HTTP/HTTPS listener
# build a Demon agent and use built-in / BOF post-ex commands
```

## Detection

- Default Demon agent indicators / signatures (research by security vendors).
- Sleep-obfuscation memory artifacts; unbacked executable memory with periodic RW->RX.
- Malleable profile defaults (URIs, headers) when operators do not customise them.
- Community YARA and Sigma rules for the Demon agent.

## Update / release history

_See `CHANGELOG.md` in this folder. Structured release data lives in `metadata.json` -> `release_history` (populated by the refresh workflow)._

## References

- [Official repository](https://github.com/HavocFramework/Havoc)
- [Project site](https://havocframework.com/)

---

_This file is generated from `metadata.json` by `generate_index.py`. Edit the JSON, not this file._
