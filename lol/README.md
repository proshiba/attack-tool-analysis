# Living Off The Land (LOL) reference sites

Curated catalog of *methodology* references - community projects that document living-off-the-land techniques, abusable binaries/services, and related tradecraft. These are techniques and knowledge bases, not standalone tools (which live under [`../tools`](../tools)).

Each entry has a machine-readable source file in [`sites/`](sites/).

| Site | Platform | Focus | Link |
|---|---|---|---|
| **Filesec.io** | windows | File extensions abused by attackers (for delivery, execution, defense evasion),  | [https://filesec.io/](https://filesec.io/) |
| **GTFOBins** | unix | Unix binaries that can be abused to bypass local security restrictions | [https://gtfobins.github.io/](https://gtfobins.github.io/) |
| **HijackLibs** | windows | Catalog of DLL hijacking opportunities: which legitimate executables load which  | [https://hijacklibs.net/](https://hijacklibs.net/) |
| **LOLBAS** | windows | Signed/native Windows binaries, scripts and libraries that can be abused for exe | [https://lolbas-project.github.io/](https://lolbas-project.github.io/) |
| **LOLC2** | cross-platform | Legitimate third-party services (SaaS, cloud, collaboration platforms) abused as | [https://lolc2.github.io/](https://lolc2.github.io/) |
| **LOLDrivers** | windows | Known vulnerable and malicious Windows drivers (BYOVD | [https://www.loldrivers.io/](https://www.loldrivers.io/) |
| **LOTS Project** | cross-platform | Legitimate, trusted domains that attackers abuse for phishing, download, data ex | [https://lots-project.com/](https://lots-project.com/) |
| **MalAPI.io** | windows | Windows API functions commonly used by malware, grouped by capability (injection | [https://malapi.io/](https://malapi.io/) |
| **WTFBins** | cross-platform | Benign binaries that exhibit malware-like behaviour (network beacons, odd proces | [https://wtfbins.wtf/](https://wtfbins.wtf/) |

## Filesec.io

- **URL:** https://filesec.io/
- **Repository:** https://github.com/mttaggart/filesec
- **Platform:** windows
- **Content type:** reference-catalog
- **Focus:** File extensions abused by attackers (for delivery, execution, defense evasion), with notes on how each is used and mitigations.
- **Data format:** JSON/site entries per extension.
- **ATT&CK mapping:** Maps to phishing/execution/defense-evasion techniques (e.g. T1204 User Execution).
- **Examples:** .lnk, .iso, .hta, .one
- **Notes:** Handy for phishing-payload and email-filtering discussions.

## GTFOBins

- **URL:** https://gtfobins.github.io/
- **Repository:** https://github.com/GTFOBins/GTFOBins.github.io
- **Platform:** unix
- **Content type:** technique-catalog
- **Focus:** Unix binaries that can be abused to bypass local security restrictions - SUID/sudo privesc, shell escape, file read/write, reverse shells.
- **Data format:** Markdown + YAML front matter per binary (repo /_gtfobins).
- **ATT&CK mapping:** Function tags (shell, command, file-read, suid, sudo, capabilities) rather than ATT&CK IDs.
- **Examples:** find (sudo/SUID shell), vim (shell escape), tar (command execution)
- **Notes:** The Unix counterpart to LOLBAS; essential for Linux privilege escalation.

## HijackLibs

- **URL:** https://hijacklibs.net/
- **Repository:** https://github.com/wietze/HijackLibs
- **Platform:** windows
- **Content type:** technique-catalog
- **Focus:** Catalog of DLL hijacking opportunities: which legitimate executables load which DLLs from hijackable search-order locations.
- **Data format:** YAML per entry mapping vulnerable executable -> hijackable DLL and expected path.
- **ATT&CK mapping:** T1574.001 (DLL Search Order Hijacking), T1574.002 (DLL Side-Loading).
- **Examples:** Signed apps vulnerable to DLL search-order hijacking / sideloading
- **Notes:** Directly supports both offensive persistence/execution and defensive detection.

## LOLBAS (Living Off The Land Binaries, Scripts and Libraries)

- **URL:** https://lolbas-project.github.io/
- **Repository:** https://github.com/LOLBAS-Project/LOLBAS
- **Platform:** windows
- **Content type:** technique-catalog
- **Focus:** Signed/native Windows binaries, scripts and libraries that can be abused for execution, download, upload, credential theft, UAC bypass, etc.
- **Data format:** YAML per entry (repo /yml), machine-consumable; site is a searchable index.
- **ATT&CK mapping:** Each entry lists abuse commands and maps to MITRE ATT&CK where relevant (e.g. T1218 Signed Binary Proxy Execution).
- **Examples:** certutil.exe (download), regsvr32.exe (execute), msbuild.exe (execute)
- **Notes:** The canonical Windows LOLBin reference. Community-maintained, actively updated via PRs.

## LOLC2 (Living Off the Land Command and Control)

- **URL:** https://lolc2.github.io/
- **Repository:** https://github.com/lolc2/lolc2.github.io
- **Platform:** cross-platform
- **Content type:** technique-catalog
- **Focus:** Legitimate third-party services (SaaS, cloud, collaboration platforms) abused as covert C2 channels - e.g. Slack, Discord, Telegram, GitHub, Google/Microsoft services.
- **Data format:** Structured entries listing the abused service, the C2 project/tool that uses it, and references.
- **ATT&CK mapping:** Aligns with T1102 (Web Service) and T1071 (Application Layer Protocol).
- **Examples:** Slack as C2, Google Sheets as C2, GitHub as C2
- **Notes:** Focuses on C2-over-trusted-service tradecraft and which tools implement each channel.

## LOLDrivers (Living Off The Land Drivers)

- **URL:** https://www.loldrivers.io/
- **Repository:** https://github.com/magicsword-io/LOLDrivers
- **Platform:** windows
- **Content type:** technique-catalog
- **Focus:** Known vulnerable and malicious Windows drivers (BYOVD - Bring Your Own Vulnerable Driver) used to disable EDR, escalate to kernel, etc.
- **Data format:** YAML per driver with hashes, signatures and detections; provides Sigma/YARA and blocklist material.
- **ATT&CK mapping:** T1068 (Exploitation for Privilege Escalation), T1211/T1562 (impair defenses via BYOVD).
- **Examples:** Vulnerable signed drivers (e.g. RTCore64.sys), malicious drivers
- **Notes:** Includes ready-to-use detection artifacts and hash lists for blocklisting.

## LOTS Project (Living Off Trusted Sites)

- **URL:** https://lots-project.com/
- **Repository:** https://github.com/mrd0x/lots-project.com
- **Platform:** cross-platform
- **Content type:** technique-catalog
- **Focus:** Legitimate, trusted domains that attackers abuse for phishing, download, data exfiltration and C2 because traffic to them blends in.
- **Data format:** Site entries per trusted domain/service.
- **ATT&CK mapping:** T1102 (Web Service), T1567 (Exfiltration Over Web Service).
- **Examples:** github.com, pastebin.com, *.blob.core.windows.net
- **Notes:** Complements LOLC2: which trusted domains blend into normal traffic.

## MalAPI.io

- **URL:** https://malapi.io/
- **Repository:** https://github.com/mrd0x/malapi
- **Platform:** windows
- **Content type:** reference-catalog
- **Focus:** Windows API functions commonly used by malware, grouped by capability (injection, evasion, credential access, etc.).
- **Data format:** Site entries per API with category and description.
- **ATT&CK mapping:** Capability groupings align to ATT&CK tactics (e.g. Process Injection T1055).
- **Examples:** VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- **Notes:** Useful for malware analysis and for building behavioural detections.

## WTFBins

- **URL:** https://wtfbins.wtf/
- **Repository:** https://github.com/wtfbins/wtfbins.github.io
- **Platform:** cross-platform
- **Content type:** reference-catalog
- **Focus:** Benign binaries that exhibit malware-like behaviour (network beacons, odd process trees) - useful for tuning detections and reducing false positives, the inverse of a LOLBin catalog.
- **Data format:** Structured entries describing the confusing behaviour.
- **ATT&CK mapping:** N/A - defensive false-positive reference.
- **Examples:** Legit apps that beacon or inject and look malicious
- **Notes:** Complements LOLBAS: what looks bad but is actually normal.

---

_Generated from `sites/*.json` by `generate_index.py`._
