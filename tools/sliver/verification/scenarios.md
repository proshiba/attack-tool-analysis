# Sliver verification scenarios

## Scope

### Linux extension (verified 2026-08-10)

- **VM 100 — `kalivm` — `192.168.1.50` — attacker, staging, Sliver
  server/operator, and C2 host.** It hosted the generated Linux implants on
  TCP 18080, HTTP C2 on TCP 8080, HTTPS C2 on TCP 8443, and raw mTLS C2 on TCP
  31337. Sliver's operator control remains loopback-only on VM 100.
- **VM 103 — `ubuntu` — `192.168.1.51` — Linux target.** It will be restored
  to `linux_verify_baseline` before and after the run, fetched only from
  `192.168.1.50:18080`, and initiate C2 only to the listed VM 100 listeners.
- **VM 106 — `nsm` — management-side offline analyzer.** It receives saved
  pcaps through `nsm-analyze`; it is not an attack, payload, beacon, or active
  measurement destination. Active JARM measurements, if supported, target
  only the listeners on `192.168.1.50`.
- **Destinations.** Every new delivery, C2, beacon, session, and active
  fingerprint destination is either `192.168.1.50` or loopback. No attack
  traffic may target a public address, hostname, `10.9.0.0/24`, VM 102, or VM
  108. The official Sliver repository/release URLs are provenance citations
  and acquisition sources before the run, never implant or C2 destinations.
- **Bounded actions.** The Linux flow is limited to identity, host survey,
  directory listing, and transfer of one fixed small lab marker. It excludes
  privilege escalation, credential access, persistence, lateral movement,
  injection, self-propagation, destructive actions, and collection of
  unrelated target content. A systemd user unit is deferred because persistence adds no
  necessary network evidence and rollback alone is not a reason to exercise
  an optional technique.

Verified Linux transport flows were: (1) realistic HTTP delivery followed by a
beacon using Sliver's HTTP transport on TCP 8080 so its URI, header, User-Agent,
and periodicity are directly observable; (2) a bounded HTTPS beacon on TCP
8443 so TLS fingerprints can be measured without pretending encrypted request
fields are visible; and (3) one bounded raw mTLS session on TCP 31337 for
JA3/JA3S/JARM and flow-shape comparison. Each flow receives its own full-packet
capture and telemetry window. The clear HTTP and HTTPS beacons used a
10-second interval plus 0-3 seconds jitter. The raw mTLS implant used session
mode, so its distinguishing flow shape was one long-lived connection rather
than a periodic callback series.

- **macOS — lab-capability gap, not a scenario gap.** Sliver supports macOS,
  but `playbooks/lab-capabilities.md` records no macOS host. No macOS run is
  therefore claimed or placed on the scenario backlog.

- **VM 100 — `kalivm` — `192.168.1.50` — attacker, Sliver server/operator,
  implant build host, and C2 host.** It generated the Windows beacon and
  hosted the raw mTLS listener on TCP 31337.
- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target.** It ran the beacon
  as `NT AUTHORITY\SYSTEM`, performed the bounded tasks, and hosted the local
  implant and fixed marker files.
- **VM 106 — `nsm` — `10.9.0.20` (the only address recorded) — NSM.** It
  analyzed the packet capture offline and made the documented active JARM
  measurement against the Kali listener. It was not a beacon or C2
  destination.
- **AI-VM — VMID and address not recorded — transfer reconstruction host.**
  The deployment record says bounded implant chunks were reconstructed on an
  `AI-VM` between Kali and the target, but it does not identify that VM more
  precisely.
- **Destinations.** The beacon's only remote destination was
  `192.168.1.50:31337` on VM 100. The active JARM measurement also targeted
  that same lab listener. Sliver's local server/client control used
  `127.0.0.1:31338` on VM 100 and did not leave that host. Thus every remote
  run destination was inside `192.168.1.0/24`, and nothing outside the lab was
  contacted; VM 106's recorded `10.9.0.20` address was not a run destination.
- **Hosting and references.** VM 100 hosted the generated implant, Sliver
  server, operator client, and mTLS C2; the implant was then staged locally on
  VM 104 through the recorded out-of-band guest-agent workflow. No public
  payload, stager, or C2 host was used. The BishopFox Sliver release and
  Salesforce JA3 repository URLs in `verification.json` are provenance
  citations, not run destinations. The record does not state the operating
  accounts used for the Kali Sliver service/client, NSM analysis, or the
  AI-VM reconstruction hop, and it does not record the NSM source address used
  for the JARM measurement.

Sliver is a multi-transport C2 framework, so a useful verification must cover
an operator flow rather than a bare process launch. The lab considered the
following contained use cases.

| Scenario | ATT&CK mapping | Status in this run |
| --- | --- | --- |
| Linux HTTP delivery, HTTP beacon, host survey, directory listing, and small file download | T1105, T1071.001, T1033, T1082, T1083, T1041 | Verified on VM 103; primary flow |
| Linux HTTPS beacon, host survey, and directory listing | T1105, T1071.001, T1573.002, T1033, T1082, T1083 | Verified on VM 103; encrypted web profile fields were not passively visible |
| Linux raw mTLS session, host survey, directory listing, and small file download | T1105, T1573.002, T1033, T1082, T1083, T1041 | Verified on VM 103; session flow was not periodic |
| Prior Windows TLS foothold, host survey, command execution, and small file transfer | T1573.002, T1105, T1033, T1082, T1057, T1083, T1059.003, T1041 | Verified with an mTLS beacon on VM 104 |
| DNS beaconing/tunneling | T1071.004, T1572 | Future scenario; not claimed for literal-IP mTLS |
| Named-pipe pivot or lateral movement | T1090, T1021, T1572 | Future scenario; no pipe event occurred here |
| In-memory BOF, .NET, or process-injection tasking | T1055 and task-specific techniques | Future higher-risk scenario |

## Verified Linux scenarios

VM 103 was rolled back to `linux_verify_baseline` before any implant ran. Each
flow had a separate `collect-run.sh` window and a full-packet tcpdump on VM
103. For all three flows, the target used `curl` to fetch a differently named
artifact from the Kali staging HTTP server, verified its expected SHA-256,
set mode 0700, and executed it. This is the observed realistic delivery chain;
`lab-push` was not used for any Linux implant.

The primary HTTP beacon checked in every 10+0-3 seconds. The operator ran
`getuid`, `info`, and `ls /tmp`, then downloaded the fixed 24-byte
`SLIVER_LINUX_LAB_MARKER` file. The HTTPS beacon used the same interval and
jitter; the operator ran `getuid`, `info`, and `ls /var/tmp`. The raw mTLS
session used one persistent connection; the operator ran `getuid`, `info`,
`ls /opt/lab`, and downloaded the same fixed marker. No unrelated host file
was transferred.

The HTTP pcap exposed Sliver's randomized script-like paths, one-letter query
keys, digit-heavy nonce values, POST/GET pairs, response status and MIME
variation, and stable Linux Chrome-like User-Agent. HTTPS encrypted all HTTP
request fields. HTTPS and raw mTLS unexpectedly produced the same JA3
`2196848d251b217de8b2c037e356c11d`, JA3S
`f4febc55ea12b31ae17cfb7e614afda8`, and all-zero JARM in this v1.7.3 run;
their useful difference was repeated short HTTPS flow cadence versus one
long-lived mTLS session. This result does not support a transport-specific
JA3, JA3S, or JARM rule.

No implant spawned a child process for the selected tasks; Sliver handled the
survey, directory listing, and download in-process. Linux file and process
signals came from the curl/write/chmod/exec delivery chain, while network
ownership came from `collect-run.sh`'s auditd-correlated attribution, not raw
Sysmon EID 3. Registry is `not_applicable` on Linux. The optional systemd user
unit remained deferred because it adds no required transport evidence and
would broaden the run into persistence.

## Prior Windows verified scenario

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
privilege escalation, persistence, lateral movement, or off-lab C2 was used.
Raw implants, pcap, ETL, EVTX, C2 state, operator configurations, cookies, and
certificate/private-key material are excluded from the repository.
