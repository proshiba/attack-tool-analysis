# Regsvr32 remote-scriptlet verification

This verification exercised **System Binary Proxy Execution: Regsvr32
(T1218.010)** with a benign 412-byte SCT served only on the isolated lab
network. The Microsoft-signed `regsvr32.exe` fetched the SCT through
`scrobj.dll`; its JScript launched `cmd.exe` solely to write a marker.

The measured operator window was
`2026-08-10T01:39:28.9484335Z`–`2026-08-10T01:39:29.9952831Z` under
`NT AUTHORITY\SYSTEM`. The intended action succeeded and the marker contained
`benign-regsvr32-marker`. Regsvr32 returned 5 after taking the `/u`
unregister path; its exact cause was not separately diagnosed, and the
nonzero exit is retained rather than hidden.

## Five-dimension result

| Dimension | Result |
|---|---|
| Network | Observed: one regsvr32-attributed Sysmon EID 3 connection; no EID 22 because an IP literal was used. Zeek and Suricata decoded one successful SCT GET with a legacy MSIE 7.0/Trident 7.0 User-Agent. |
| Files | Observed: regsvr32 cached `benign[1].sct`; its cmd child created the marker. |
| Registry | Observed: 12 relevant EID 12 and 14 EID 13 records. The strongest signal was `JScriptSetScriptStateStarted` for `regsvr32.exe`; generic URL/cache state was not used alone. |
| Process | Observed: EID 1 captured the signed regsvr32 identity, remote `/i:` URL, `scrobj.dll`, hash, user, and integrity. |
| Parent-child | Observed: the controlled PowerShell wrapper launched regsvr32, which directly launched `cmd.exe`. |

The full-packet capture contained 102 packets with zero Zeek capture loss. Raw
PCAP, EVTX, event exports, and NSM logs remain outside the repository.

## Sigma coverage

| Tier | Logsource | Rule |
|---|---|---|
| 1 | `windows/process_creation` | `win_process_creation_regsvr32_remote_scriptlet.yml` |
| 1 | `windows/process_creation` | `win_process_creation_regsvr32_spawns_shell.yml` |
| 1 | `zeek/http` | `network_zeek_regsvr32_remote_sct.yml` |
| 1 | `suricata/http` | `network_suricata_regsvr32_remote_sct.yml` |
| 1 | `windows/sysmon/file_event` | `win_file_event_regsvr32_sct_cache.yml` |
| 2 | `windows/sysmon/registry_set` | `win_registry_set_regsvr32_jscript_telemetry.yml` |

All six rules parsed successfully with pySigma 1.5.0. No rule contains the
lab IP or port.

Kali staging and its HTTP listener were removed. VM 104 was rolled back to
`win_verify_baseline`; the marker, PCAP, and telemetry directory were absent,
and final batch validation found Sysmon running with the expected config hash
and Defender real-time protection still off.
