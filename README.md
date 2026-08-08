# attack-tool-analysis

A curated, structured catalog of **free / open-source post-exploitation tooling** and **living-off-the-land (LOL) methodology references** for authorized penetration testing and red team work.

For each tool the catalog records **what it is, how it is used, related TTPs (MITRE ATT&CK), detection guidance, and update history**. Everything is stored as JSON so it can be queried, diffed, and kept current over time.

> Intended for defensive research, detection engineering, and authorized offensive security assessments only.

## Repository layout

```
index.json              Aggregate catalog (generated) - tools + LOL sites
tools/<id>/
    metadata.json       Source of truth for a tool
    README.md           Human-readable page (generated)
    CHANGELOG.md        Update history for the catalog entry
lol/
    sites/<id>.json     Source of truth for a LOL reference site
    README.md           Overview (generated)
schema/                 JSON Schemas for the above
generate_index.py       Rebuilds index.json + README files from metadata
build_seed.py           One-off seed of the initial dataset
```

**Current contents:** 14 tools, 9 LOL reference sites.

## Tools by category

### Command & Control (Remote Ops)

| Tool | Platforms | Language | Summary |
|---|---|---|---|
| [Covenant](tools/covenant/) | windows, linux | C# |  |
| [Havoc](tools/havoc/) | windows, linux | Go, C, Python | Modern, open-source C2 framework with a Qt GUI team server, a malleable-style profile, sleep obfuscation, and ... |
| [Merlin](tools/merlin/) | windows, linux, macos | Go | Cross-platform post-exploitation C2 written in Go, notable for early adoption of HTTP/2 and HTTP/3 (QUIC) chan... |
| [Mythic](tools/mythic/) | linux | Python, Go, JavaScript | Plug-n-play, multi-agent C2 framework with a web UI |
| [Sliver](tools/sliver/) | windows, linux, macos | Go | Open-source, cross-platform adversary-emulation / C2 framework by Bishop Fox |

### Credential Access

| Tool | Platforms | Language | Summary |
|---|---|---|---|
| [Certify](tools/certify/) | windows | C# | C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) - the ESC1-E... |
| [LaZagne](tools/lazagne/) | windows, linux, macos | Python | Open-source application that recovers passwords stored locally by a wide range of software (browsers, mail cli... |
| [mimikatz](tools/mimikatz/) | windows | C | Post-exploitation toolkit for extracting plaintext passwords, hashes, PINs and Kerberos tickets from Windows m... |
| [Rubeus](tools/rubeus/) | windows | C# | C# toolset for raw Kerberos interaction and abuse: ticket requests, Kerberoasting, AS-REP roasting, pass-the-t... |

### Discovery / Situational Awareness

| Tool | Platforms | Language | Summary |
|---|---|---|---|
| [ADRecon](tools/adrecon/) | windows | PowerShell | PowerShell tool that gathers Active Directory information and produces a consolidated Excel (or CSV/JSON) repo... |
| [Certify](tools/certify/) | windows | C# | C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) - the ESC1-E... |
| [PowerUp / SharpUp](tools/powerup-sharpup/) | windows | PowerShell, C# | Windows local privilege-escalation checks |
| [PowerView](tools/powerview/) | windows | PowerShell | PowerShell tool for Active Directory reconnaissance: users, groups, ACLs, GPOs, trusts, sessions and local adm... |
| [Seatbelt](tools/seatbelt/) | windows | C# | C# host survey / situational-awareness tool that runs dozens of 'safety checks' from both offensive and defens... |
| [SharpHound / BloodHound](tools/sharphound-bloodhound/) | windows, linux, macos | C#, TypeScript | Active Directory attack-path mapping |

### Lateral Movement

| Tool | Platforms | Language | Summary |
|---|---|---|---|
| [mimikatz](tools/mimikatz/) | windows | C | Post-exploitation toolkit for extracting plaintext passwords, hashes, PINs and Kerberos tickets from Windows m... |
| [Rubeus](tools/rubeus/) | windows | C# | C# toolset for raw Kerberos interaction and abuse: ticket requests, Kerberoasting, AS-REP roasting, pass-the-t... |
| [Sliver](tools/sliver/) | windows, linux, macos | Go | Open-source, cross-platform adversary-emulation / C2 framework by Bishop Fox |

### Privilege Escalation

| Tool | Platforms | Language | Summary |
|---|---|---|---|
| [Certify](tools/certify/) | windows | C# | C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) - the ESC1-E... |
| [mimikatz](tools/mimikatz/) | windows | C | Post-exploitation toolkit for extracting plaintext passwords, hashes, PINs and Kerberos tickets from Windows m... |
| [PowerUp / SharpUp](tools/powerup-sharpup/) | windows | PowerShell, C# | Windows local privilege-escalation checks |
| [Rubeus](tools/rubeus/) | windows | C# | C# toolset for raw Kerberos interaction and abuse: ticket requests, Kerberoasting, AS-REP roasting, pass-the-t... |

## Living Off The Land references

Technique / methodology catalogs (not standalone tools). See [`lol/`](lol/).

| Site | Platform | Focus |
|---|---|---|
| [Filesec.io](https://filesec.io/) | windows | File extensions abused by attackers (for delivery, execution, defense  |
| [GTFOBins](https://gtfobins.github.io/) | unix | Unix binaries that can be abused to bypass local security restrictions |
| [HijackLibs](https://hijacklibs.net/) | windows | Catalog of DLL hijacking opportunities: which legitimate executables l |
| [LOLBAS](https://lolbas-project.github.io/) | windows | Signed/native Windows binaries, scripts and libraries that can be abus |
| [LOLC2](https://lolc2.github.io/) | cross-platform | Legitimate third-party services (SaaS, cloud, collaboration platforms) |
| [LOLDrivers](https://www.loldrivers.io/) | windows | Known vulnerable and malicious Windows drivers (BYOVD |
| [LOTS Project](https://lots-project.com/) | cross-platform | Legitimate, trusted domains that attackers abuse for phishing, downloa |
| [MalAPI.io](https://malapi.io/) | windows | Windows API functions commonly used by malware, grouped by capability  |
| [WTFBins](https://wtfbins.wtf/) | cross-platform | Benign binaries that exhibit malware-like behaviour (network beacons,  |

## Maintaining the catalog

1. Add or edit a tool: create/modify `tools/<id>/metadata.json` (see `schema/tool.schema.json`).
2. Add or edit a LOL site: create/modify `lol/sites/<id>.json` (see `schema/lol-site.schema.json`).
3. Regenerate derived files: `python3 generate_index.py`.
4. Record notable upstream changes in the tool's `CHANGELOG.md` and, when known, in `metadata.json` -> `release_history`.

`index.json`, every `tools/<id>/README.md`, and `lol/README.md` are **generated** - edit the JSON, then rerun the generator.

## Disclaimer

This repository documents offensive security tooling for **lawful, authorized** testing and defensive research. Do not use these tools against systems you do not own or lack explicit permission to test.
