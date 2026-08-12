# Sliver verification scenarios

## Scope

### Windows safety re-grounding and coverage expansion (verified 2026-08-11)

- **VM 100 — `kalivm` — `192.168.1.50` — the only C2, DNS, pivot-service,
  build, and operator host.** Sliver server/client control is loopback-only.
  The target-facing services are raw mTLS on TCP 31337, the lab DNS service on
  UDP/TCP 53, a fixed inert HTTP pivot destination on TCP 18084, reviewed
  artifact staging on TCP 18085, and named HTTPS C2 on TCP 18443. The
  client-side SOCKS5 listener binds only to
  `127.0.0.1:1081`. No listener binds a public or management-plane address.
- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — the only execution
  target.** It starts from and returns to `win_verify_baseline`. Before capture,
  its outbound firewall is restricted to loopback and `192.168.1.0/24`, and
  its only DNS resolver is Kali `192.168.1.50`. The lab-only name
  `c2.sliver.lab` resolves exclusively to `192.168.1.50` with no forwarding or
  fallback resolver.
- **VM 110 — `remnux-malware` — static analysis only.** Generated binaries
  may be transferred to it from Kali solely for hashing, PE metadata,
  strings, imports, and disassembly. No sample or Sliver component is executed
  there. VM 110 is never a payload, beacon, pivot, DNS, or C2 destination.
- **VM 109 — `malware-analyst` — not used.** Nothing executes there and it is
  not a run destination.
- **VM 106 — `nsm` — offline packet analysis only.** `nsm-analyze` receives
  the saved full-packet capture out of band. Any active JARM measurement may
  address only Kali `192.168.1.50:18443`; VM 106 is never a payload, beacon,
  DNS, pivot, or C2 destination.
- **VM 102 and VM 108 — not used for execution.** The AI workspace may retain
  sanitized evidence and lab-authored source, but no Sliver binary, generated
  implant, inert assembly, or sideload DLL is executed on either host.
- **Destinations.** Every connection, DNS query, C2 message, SOCKS request,
  and pivoted request attributable to the declared attack terminates at Kali
  `192.168.1.50`; local operator control and the SOCKS listener terminate at
  loopback. The official
  Sliver repository and release URLs are provenance citations/acquisition
  sources before the run, never implant, pivot, or C2 destinations. Public
  hosts, `10.9.0.0/24`, and any second target are forbidden.
- **Bounded actions.** The run uses one renamed Windows mTLS session for a
  foothold, fixed discovery and shell-marker tasks, one SOCKS5 request to a
  fixed Kali-hosted marker, and one lab-authored .NET assembly injected into a
  newly created benign `notepad.exe`. It separately runs one signed baseline
  `WerFault.exe` copy with a lab-authored inert `faultrep.dll`, and one renamed
  HTTPS beacon using the lab-only hostname and a lab root/intermediate/leaf
  certificate chain. No credential access, privilege escalation, persistence,
  lateral movement, unrelated-file collection, self-propagation, destructive
  action, public DNS, ACME, Armory, update check, or alternate/fallback C2 is
  permitted.

The five flow entries in the single baseline visit are:

| Flow | Exact bounded action | ATT&CK | Expected evidence decision |
| --- | --- | --- | --- |
| Windows mTLS foothold re-grounding | Use PowerShell to fetch the reviewed session from Kali TCP 18085 under an unrelated filename, verify its SHA-256, launch it, run `getuid`, `info`, `ls C:\\lab`, one fixed `cmd.exe` marker command, and transfer only that marker. | T1105, T1573.002, T1033, T1082, T1083, T1059.003, T1041 | Re-ground the three existing Windows file/process rules and mechanically account for every responder with Zeek plus Sysmon EID 3. |
| SOCKS5 pivot | Start Sliver SOCKS5 on Kali loopback and request one fixed marker from Kali `192.168.1.50:18084` through the implant; stop the proxy immediately afterward. | T1572 | Measure the extra implant-attributed target-to-service flow and tunnel shape; no second victim or public destination exists. |
| In-memory execute-assembly | Execute a lab-authored assembly that only prints `SLIVER_IN_MEMORY_INERT_MARKER`, using newly created `C:\\Windows\\System32\\notepad.exe` as the sacrificial process and without AMSI/ETW bypass flags. | T1055 | Measure sacrificial-process creation, cross-process access/injection telemetry, and the absence of assembly-on-disk or network behavior. |
| Inert DLL sideload | Copy the baseline Microsoft-signed `WerFault.exe` into `C:\\lab\\sliver-sideload`, place lab-authored `faultrep.dll` beside it, execute `WerFault.exe -?`, and verify its fixed marker. | T1574.001, T1036.005 | Reuse the established inert signed-host pattern; expect file/process evidence and no network or registry behavior. |
| Named HTTPS C2 | Use PowerShell to fetch the reviewed beacon from Kali TCP 18085 under an unrelated filename, resolve `c2.sliver.lab` only through Kali DNS, then run it to TCP 18443 with the Windows WinINet driver and a Kali-served lab root/intermediate/leaf chain; task only `getuid` and `ls C:\\lab`. | T1105, T1071.001, T1573.002, T1033, T1083 | Produce DNS, SNI, passive x509-chain, and TLS fingerprint evidence absent from literal-IP flows; compare JA3/JA3S/JARM before deciding whether any TLS rule is justified. |

One continuous full-packet pktmon capture and one endpoint collection window
cover all five flows, with UTC action boundaries retained so each flow can be
reported separately. The raw capture is analyzed once with `nsm-analyze`; the
post-run scope gate consumes that complete Zeek output and the same-window
Sysmon JSON, not selected C2-only rows.

The verified capture contained 65 Zeek connections with zero capture-loss
gaps. Fifty-nine rows terminated at Kali: 14 DNS, one pivot marker, three
artifact staging, 40 named HTTPS, and one raw mTLS connection. Six remaining
rows represented three public responders. In every such row the target sent
zero packets; none was attributed by Sysmon to a declared tool, so the rows
are retained as manifest-only OS/background traffic. The resulting schema-v3
scope record is `PASS`: no traffic attributable to the declared attack left
the lab, and everything else that did is in the manifest. The manifest also
retains Windows notification, telemetry, and settings names queried through
the in-lab resolver.

The mTLS flow re-grounded all three load-bearing Windows rules. The SOCKS flow
added an implant-owned connection to a second lab service without a second
victim. Execute-assembly created a short-lived SYSTEM `notepad.exe` child and
returned the inert marker, but emitted no related Sysmon EID 10 or EID 7 and
wrote no assembly on the target. The sideload created a marker through a
copied Microsoft-signed `WerFault.exe` and inert `faultrep.dll`, with no
network behavior. Named HTTPS supplied six DNS observations, SNI, a leaf and
intermediate certificate, and distinct WinINet/SChannel JA3/JA3S values. No
new TLS rule was justified because those values describe generic platform
stacks rather than Sliver, the resumed JA3S overlaps the AdaptixC2 run, and
JARM was all zero.

### Linux extension (verified 2026-08-10)

- **VM 100 — `kalivm` — `192.168.1.50` — attacker, staging, Sliver
  server/operator, and C2 host.** It hosted the generated Linux implants on
  TCP 18080, HTTP C2 on TCP 8080, HTTPS C2 on TCP 8443, and raw mTLS C2 on TCP
  31337, plus the observed DNS C2 listener on UDP 53. Sliver's operator control
  remained loopback-only on VM 100.
- **VM 103 — `ubuntu` — `192.168.1.51` — Linux target.** It was restored
  to `linux_verify_baseline` before and after each run, fetched only from
  `192.168.1.50:18080`, and initiated C2 only to the listed VM 100 listeners.
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
JA3/JA3S/JARM and flow-shape comparison; and (4) a DNS beacon through the
exclusive Kali resolver on UDP 53. Each flow received its own full-packet
capture and telemetry window. The clear HTTP and HTTPS beacons used a
10-second interval plus 0-3 seconds jitter, as did the DNS beacon. The raw
mTLS implant used session mode, so its distinguishing flow shape was one
long-lived connection rather than a periodic callback series.

- **macOS — lab-capability gap, not a scenario gap.** Sliver supports macOS,
  but `playbooks/lab-capabilities.md` records no macOS host. No macOS run is
  therefore claimed or placed on the scenario backlog.

### Audit iteration 2 expansion — DNS C2 (verified 2026-08-10)

To close the audit gate's highest-value grounded transport gap, one additional
bounded Linux DNS-beacon flow used parent domain `c2.sliver.lab.` and a
Sliver DNS listener bound only to Kali `192.168.1.50:53` (observed on UDP). Before the
implant started, VM 103 was restored again to `linux_verify_baseline`; its
link resolver was changed temporarily and exclusively to `192.168.1.50`, so
every tunneled query goes directly to the contained authoritative listener.
The lab-only name is not publicly delegated and no fallback resolver was
configured. A target-wide IPv4/IPv6 output guard additionally allowed only
loopback and `192.168.1.0/24`. Implant staging remained an HTTP fetch from
`192.168.1.50:18080`; a separate full-packet tcpdump and `collect-run.sh`
window covered delivery, DNS beaconing, `getuid`, cached `info`, `ls /opt/lab`,
and one 7-byte `/etc/hostname` download response. VM 103 was rolled back to
`linux_verify_baseline` immediately after collection. No SOCKS/port
forwarding, injection, persistence, public DNS, or additional target was
added.

The first launch attempt was stopped before operator tasking because
`resolvectl status eth0` still advertised a public baseline link resolver.
Its evidence was preserved: tcpdump recorded zero off-lab packets and
`check-lab-scope.py` passed. VM 103 was rolled back again before the successful
retry. The retry did not execute until `eth0` displayed only
`192.168.1.50`, the target egress guard was active, and the official generated
implant had passed REMnux static review and `poc-triage.py`.

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
  run destination was inside `192.168.1.0/24`. The 2026-08-11 re-grounding
  now supports the narrower mechanical claim: no traffic attributable to the
  declared attack left the lab, and everything else that did is in the
  manifest. VM 106's recorded `10.9.0.20` address was not a run destination.
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
| Linux DNS C2 beacon through a direct lab-only resolver | T1105, T1071.004, T1572, T1033, T1082, T1083, T1041 | Verified on VM 103; encoded A/TXT bursts were measurable and no TLS fingerprint existed |
| Windows mTLS foothold, host survey, command execution, and small file transfer | T1573.002, T1105, T1033, T1082, T1083, T1059.003, T1041 | Re-verified with a renamed mTLS session on VM 104 and schema-v3 safety evidence |
| SOCKS5 pivot to a fixed lab-internal HTTP service | T1572 | Verified on VM 104; one 30-byte marker response, no second target |
| In-memory execute-assembly in a newly created benign process | T1055 | Verified with inert output in notepad.exe; no related EID 10/EID 7 or target assembly write |
| Inert DLL sideload from a copied signed Windows host | T1574.001, T1036.005 | Verified with WerFault.exe and lab-authored faultrep.dll; no network behavior |
| Named HTTPS C2 through lab DNS and a lab certificate chain | T1071.001, T1573.002 | Verified with DNS, SNI, x509 chain, and platform-generic TLS fingerprints |
| Named-pipe pivot or lateral movement | T1090, T1021, T1572 | Future scenario; no pipe event occurred here |
| In-memory BOF, .NET, or process-injection tasking | T1055 and task-specific techniques | Future higher-risk scenario |

## Verified Linux scenarios

VM 103 was rolled back to `linux_verify_baseline` before any implant ran. Each
flow had a separate `collect-run.sh` window and a full-packet tcpdump on VM
103. For all four flows, the target used `curl` to fetch a differently named
artifact from the Kali staging HTTP server, verified its expected SHA-256,
set mode 0700, and executed it. This is the observed realistic delivery chain;
`lab-push` was not used for any Linux implant.

The primary HTTP beacon checked in every 10+0-3 seconds. The operator ran
`getuid`, `info`, and `ls /tmp`, then downloaded the fixed 24-byte
`SLIVER_LINUX_LAB_MARKER` file. The HTTPS beacon used the same interval and
jitter; the operator ran `getuid`, `info`, and `ls /var/tmp`. The raw mTLS
session used one persistent connection; the operator ran `getuid`, `info`,
`ls /opt/lab`, and downloaded the same fixed marker. No unrelated host file
was transferred in those flows. The DNS beacon used the same 10+0-3 second
schedule; the operator ran `getuid`, cached `info`, `ls /opt/lab`, and one
small `/etc/hostname` download task.

The HTTP pcap exposed Sliver's randomized script-like paths, one-letter query
keys, digit-heavy nonce values, POST/GET pairs, response status and MIME
variation, and stable Linux Chrome-like User-Agent. HTTPS encrypted all HTTP
request fields. HTTPS and raw mTLS unexpectedly produced the same JA3
`2196848d251b217de8b2c037e356c11d`, JA3S
`f4febc55ea12b31ae17cfb7e614afda8`, and all-zero JARM in this v1.7.3 run;
their useful difference was repeated short HTTPS flow cadence versus one
long-lived mTLS session. This result does not support a transport-specific
JA3, JA3S, or JARM rule. DNS produced 73 A/TXT queries in 15 bursts, with
burst starts 10.212-13.521 seconds apart. Twenty-three queries used two
63-character encoded labels followed by an 18-63-character label; this
address- and domain-independent structure underpins the Zeek and Suricata DNS
rules. DNS has no JA3, JA3S, JARM, or HTTP request profile.

No implant spawned a child process for the selected tasks; Sliver handled the
survey, directory listing, and download in-process. Linux file and process
signals came from the curl/write/chmod/exec delivery chain, while network
ownership came from `collect-run.sh`'s auditd-correlated attribution, not raw
Sysmon EID 3. Registry is `not_applicable` on Linux. The optional systemd user
unit remained deferred because it adds no required transport evidence and
would broaden the run into persistence.

The iteration-1 audit split its remaining gaps before any new execution. DNS
C2 was the only gap selected for immediate verification because it raises
grounded coverage from 5/10 (50%) to 6/10 (60%), the gate floor, and adds a
distinct network dimension.
That Linux-only run deferred named HTTPS/SNI, SOCKS tunnelling, DLL delivery,
and in-memory tasking; the 2026-08-11 Windows run now verifies all four in
bounded form. Shellcode delivery, named-pipe pivoting, macOS, and
Windows-to-Windows lateral movement remain unverified; the latter two remain
lab-capability gaps (no macOS host and no second Windows host), not executable
scenario gaps.

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
