# Sliver cross-platform verification with NSM

The 2026-08-11 Windows expansion re-grounded the mTLS foothold and added four
bounded flows in one `win_verify_baseline` visit: SOCKS5 pivoting to one Kali
marker service, inert execute-assembly in a newly created `notepad.exe`, an
inert `faultrep.dll` sideload through a copied Microsoft-signed `WerFault.exe`,
and named HTTPS C2 at `c2.sliver.lab` with a lab root/intermediate/leaf chain.
The full 310,804,832-byte pktmon capture produced 65 Zeek connections and zero
capture-loss gaps.

The schema-v3 scope check is `PASS`: no traffic attributable to the declared
attack left the lab, and everything else that did is in the manifest. Fifty-nine
Zeek rows terminated at Kali services. Six rows covered three public responders
but carried zero target-origin packets and no declared-tool attribution; the
manifest also retains Windows telemetry names queried through the in-lab DNS
resolver. The check consumed all renamed images, `notepad.exe`, server/listener
records, and operator transcripts rather than a filtered capture.

Named HTTPS exposed six DNS observations, SNI, a visible leaf/intermediate
chain, JA3 `a0e9f5d64349fb13191bc781f81f42e1`, full-handshake JA3S
`a3080493c64c675cef762b91f46aa81a`, resumed JA3S
`326de7c6719a77bb7ef65f6cac962193`, and all-zero JARM. No new TLS rule was
shipped: the client is generic WinINet/SChannel, the resumed JA3S also appeared
in the AdaptixC2 run, and JARM supplied no discriminator. Raw mTLS re-fired the
existing generic Go crypto/tls hunts and is still not claimed as a Sliver
signature.

Audit iteration 1 passed at commit `5498dff`: safety `safe`, zero blockers,
three Windows rules passed the EVTX harness, and nine network/Linux rules were
correctly `not-testable-on-evtx`. Grounded lab-runnable coverage is 8/13
(61.5%), above the 60% floor. The in-memory and sideload cases use inert
lab-authored proxies; execute-assembly emitted no related EID 10/EID 7, and the
sideload reused the existing AdaptixC2 `faultrep.dll` file-event rule.

The 2026-08-10 extension adds renamed Linux amd64 implants on Ubuntu VM 103
across clear HTTP beacon, HTTPS beacon, DNS beacon, and raw mTLS session
transports. Each
implant was fetched realistically from the contained Kali HTTP staging server,
then hashed, chmodded, and executed while Sysmon for Linux, auditd, and tcpdump
collected separate flow windows. VM 103 was restored to
`linux_verify_baseline` before and after the run.

The network result is deliberately transport-aware. Clear HTTP exposed a
stable Linux Chrome-like User-Agent, randomized script-like paths, one-letter
nonce queries, POST/GET pairs, and a measured 10.061-12.907 second steady-state
cadence. HTTPS exposed the same cadence but encrypted its HTTP fields. HTTPS
and raw mTLS unexpectedly shared JA3
`2196848d251b217de8b2c037e356c11d`, JA3S
`f4febc55ea12b31ae17cfb7e614afda8`, and all-zero JARM; their discriminating
shape was repeated short HTTPS connections versus one 60.057947-second mTLS
session flow. DNS exposed 73 A/TXT queries in 15 bursts, with burst starts
10.212-13.521 seconds apart. Twenty-three queries had the rename-, address-,
and parent-domain-independent structure used by the new DNS rules: two
63-character restricted-alphabet labels followed by an 18-63-character label.

Linux endpoint additions are rename-resilient and deliberately narrow:

- auditd file-event coverage for curl writing a hidden object in a transient
  directory, filling the upstream wget-only file-event form;
- hidden `/var/tmp` execution, filling a form left by upstream's existing
  `/tmp` and `/dev/shm` rules; and
- Zeek and Suricata HTTP request-profile rules with a documented rolling-window
  periodicity requirement; and
- Zeek and Suricata DNS encoded-query rules with the same backend correlation
  requirement.

The combined `check-lab-scope.py` evidence is `PASS`. Process ownership was
proved with `collect-run.sh`'s auditd-correlated network attribution because
raw Sysmon EID 3 can carry a stale pre-exec image. For DNS, auditd attributed
72 successful implant connects to the local resolver stub, while the exclusive
resolver configuration and pcap proved the resolver leg terminated on Kali.
macOS remains a
lab-capability gap because the lab has no macOS host; it is not recorded as a
scenario gap. The detailed Linux record is in `verification.json`,
`scenarios.md`, and the two `evidence/linux-*-signals.json` files.

## Prior Windows mTLS verification

Official Sliver v1.7.3 was verified end to end in the contained vmbr1 lab.
Kali VM 100 (`192.168.1.50`) hosted a raw mTLS listener; Windows 10 VM 104
(`192.168.1.52`) ran the generated amd64 beacon from the clean
`win_verify_baseline`; NSM VM 106 (`10.9.0.20`) processed the full-packet
capture with Zeek 8.2.1, Salesforce JA3, Suricata 7.0.10, and 52,234 ET Open
alert rules.

The implant SHA-256 was
`A0961CB48E51E2B898578658B4AC582D7816F8C65396D983617A82127F24BD9C`.
It used TLS 1.3 mTLS with a 10-second beacon interval and 3-second jitter. The
Sliver beacon was confirmed as SYSTEM, and all bounded survey, execute, and
download tasks completed.

## What the NSM layer added

| Question | Endpoint-only evidence | New NSM evidence |
| --- | --- | --- |
| Which process connected? | Sysmon EID 3 attributed 18 connections to the implant | Zeek and Suricata independently reconstructed 18 TLS flows |
| Was it actually TLS? | EID 3 showed only TCP | TLS 1.3, `TLS_AES_128_GCM_SHA256`, and `X25519MLKEM768` were parsed |
| Can the encrypted channel be fingerprinted? | No TLS client/server fingerprint fields | JA3 `2196848d251b217de8b2c037e356c11d` and JA3S `f4febc55ea12b31ae17cfb7e614afda8` |
| Was there SNI, HTTP, DNS C2, or visible x509? | No implant EID 22 query | No SNI, no HTTP log, no hostname C2, and no passively visible C2 certificate chain/x509 row |
| Was the traffic periodic? | Repeated EID 3 connections, but no aggregate timing proof | 16 inter-flow gaps ranged 10.04–12.79 seconds, matching the configured 10+0–3 second schedule |
| Did IDS content rules fire? | Not answerable | No ET Open Sliver/content alert; only pktmon checksum-offload decoder events fired |

The active JARM measurement was run from NSM VM 106 while the listener was
live. It returned the all-zero value
`00000000000000000000000000000000000000000000000000000000000000`
because generic JARM probes could not complete Sliver's client-authenticated
mTLS handshake. That negative result is recorded honestly and is not used as a
detection key. JA3/JA3S are the actionable passive fingerprints for this run.

## Detection coverage

Endpoint Tier 1 rules cover:

- an unversioned executable launched by a script/command host;
- a generic executable parent spawning a shell or script utility; and
- a script-oriented writer creating a Windows executable payload.

Network rules cover:

- the observed JA3+JA3S pair in Zeek TLS logs;
- the same pair in Suricata EVE TLS events; and
- the observed long encoded DNS query structure in Zeek and Suricata; and
- a lower-confidence Zeek hunt for repeated TLS 1.3 with no SNI or passively
  visible certificate chain.

No rule hardcodes the lab C2 address or listener port. Beacon periodicity is
documented as a correlation requirement because a single-event Sigma rule
cannot express rolling inter-arrival timing. No named pipe, implant-attributed
registry event, or deep process-access event occurred, so no unsupported Tier
2 endpoint detection was added.

## Evidence and sanitization

`evidence/endpoint-signals.json` contains only the process, parent-child, file,
network, DNS, registry, and Tier 2 fields needed to support the endpoint rules.
`evidence/network-signals.json` contains only TLS fingerprints, aggregate flow
timing/volume, NSM versions, IDS alert summaries, and capture provenance.

The raw 812,176-byte pcapng, ETL, EVTX, 154 MB endpoint JSON, Suricata EVE,
Zeek logs, implant, Sliver database, operator profile, and TLS key material are
not committed. No credential, token, cookie, private certificate material, or
unrelated host data is present in this directory.

## Cleanup

After PR creation, the isolated Sliver server and mTLS listener were stopped on
Kali, ports 31337/31338 were confirmed closed, and `/tmp/sliver-nsm` was
deleted; pre-existing `/root/.sliver` state was preserved. VM 104 was rolled
back to `win_verify_baseline` with Proxmox task result `OK`. After startup, the
implant, marker, packet capture, telemetry exports, delivery chunks, helper
scripts, and implant process were absent; pktmon was stopped; Sysmon 15.21 was
running with the canonical config hash; and the Defender-off baseline state
was intact.
