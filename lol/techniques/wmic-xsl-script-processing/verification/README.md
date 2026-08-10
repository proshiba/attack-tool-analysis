# WMIC XSL script-processing verification

This verification exercised **XSL Script Processing (T1220)** with the
Microsoft-signed `WMIC.exe`. A benign 571-byte stylesheet was served only on
the isolated lab network. WMIC fetched it through `/format:`, executed its
embedded JScript, returned `benign-wmic-xsl`, and launched `cmd.exe` solely to
write a marker.

The measured operator window was
`2026-08-10T01:46:10.3315182Z`–`2026-08-10T01:46:11.3628034Z` under
`NT AUTHORITY\SYSTEM`; WMIC exited 0. The transform invoked the JScript
function twice in this flow, producing two direct cmd children and one marker
overwrite. This behavior is retained in the evidence rather than collapsed.

## Five-dimension result

| Dimension | Result |
|---|---|
| Network | Observed: one WMIC-attributed Sysmon EID 3 connection; no EID 22 because an IP literal was used. Zeek and Suricata decoded one successful XSL GET with a legacy MSIE 7.0/Trident 7.0 User-Agent. |
| Files | Observed: WMIC cached `benign[1].xsl`; two cmd children wrote the marker, with one overwrite-delete event. |
| Registry | Observed: 15 relevant EID 12 and 13 EID 13 records. The strongest signal was `JScriptSetScriptStateStarted` for `wmic.exe`; generic WMI and URL-cache state was not used alone. |
| Process | Observed: EID 1 captured signed WMIC identity, remote `/format:` URL, hash, user, and integrity. |
| Parent-child | Observed: controlled PowerShell→WMIC ancestry and two direct WMIC→cmd children from the XSL transform. |

The full-packet capture contained 346 packets with zero Zeek capture loss. Raw
PCAP, EVTX, event exports, and NSM logs remain outside the repository.

## Sigma coverage

| Tier | Logsource | Rule |
|---|---|---|
| 1 | `windows/process_creation` | `win_process_creation_wmic_remote_xsl.yml` |
| 1 | `windows/process_creation` | `win_process_creation_wmic_xsl_spawns_shell.yml` |
| 1 | `zeek/http` | `network_zeek_wmic_remote_xsl.yml` |
| 1 | `suricata/http` | `network_suricata_wmic_remote_xsl.yml` |
| 1 | `windows/sysmon/file_event` | `win_file_event_wmic_xsl_cache.yml` |
| 2 | `windows/sysmon/registry_set` | `win_registry_set_wmic_jscript_telemetry.yml` |

All six rules parsed successfully with pySigma 1.5.0. No rule contains the
lab IP or port.

Kali staging and its HTTP listener were removed. VM 104 was rolled back to
`win_verify_baseline`; the marker, PCAP, and telemetry directory were absent,
and Sysmon was running with the expected config hash while Defender real-time
protection remained off.
