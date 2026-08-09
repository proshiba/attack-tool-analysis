# Sliver verification scenarios

Sliver is a multi-transport C2 framework, so a useful verification must cover
an operator flow rather than a bare process launch. The lab considered the
following contained use cases.

| Scenario | ATT&CK mapping | Status in this run |
| --- | --- | --- |
| TLS foothold, host survey, command execution, and small file transfer | T1573.002, T1105, T1033, T1082, T1057, T1083, T1059.003, T1041 | Verified with an mTLS beacon |
| HTTPS C2 using a web profile | T1071.001, T1573.002 | Future scenario; not claimed for raw mTLS |
| DNS beaconing/tunneling | T1071.004, T1572 | Future scenario; not claimed for literal-IP mTLS |
| Named-pipe pivot or lateral movement | T1090, T1021, T1572 | Future scenario; no pipe event occurred here |
| In-memory BOF, .NET, or process-injection tasking | T1055 and task-specific techniques | Future higher-risk scenario |

## Verified scenario

The selected scenario was a bounded mTLS C2 foothold and host survey:

1. Roll Windows VM 104 back to `win_verify_baseline` and verify Defender is
   off, Sysmon 15.21 is running, and the collection toolset is present.
2. On Kali VM 100, start official Sliver v1.7.3 with isolated state, create an
   mTLS listener on the contained lab interface, and generate one Windows amd64
   beacon with a 10-second interval and 3-second jitter.
3. Deliver the exact implant to `C:\lab` through chunked, out-of-band
   `lab-push`; reassemble it and prove its target SHA-256 matches Kali.
4. Start full-packet pktmon capture, launch the beacon as SYSTEM, and confirm
   it in the Sliver operator console.
5. Run `getuid`, `info`, `ls C:\lab`, and `ps`; perform one benign
   `cmd.exe` marker creation; download that fixed 19-byte marker over C2.
6. Stop and convert the capture, export endpoint EVTX, and process the pcap on
   NSM VM 106 with Zeek, JA3/JA3S, Suricata, and ET Open rules.

The observed technique mapping is intentionally narrower than Sliver's full
capability set:

- T1573.002: the beacon used mutually authenticated TLS 1.3.
- T1105: the implant was transferred into the target over the contained
  out-of-band lab channel.
- T1033 and T1082: `getuid` and `info` returned SYSTEM and host information.
- T1057 and T1083: `ps` and `ls` performed process and directory discovery.
- T1059.003: the implant directly spawned `cmd.exe` for a benign command.
- T1041: a fixed non-host-data marker was downloaded through the C2 channel.

T1071.001 and T1071.004 are documented because Sliver supports HTTPS and DNS,
but neither is falsely marked observed: raw mTLS produced no HTTP log, and the
literal-IP listener produced no implant-attributed DNS query.

## Safety boundaries

The implant contacted only Kali `192.168.1.50` on vmbr1. The marker contained
fixed lab text, no credential or host content was collected, and no injection,
privilege escalation, persistence, lateral movement, or external C2 was used.
Raw implants, pcap, ETL, EVTX, C2 state, operator configurations, cookies, and
certificate/private-key material are excluded from the repository.
