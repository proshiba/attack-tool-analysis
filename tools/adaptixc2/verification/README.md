# AdaptixC2 v1.2 cross-platform verification

## 2026-08-12 Linux expansion

The reviewed v1.2 tag and current upstream `main` both resolve to commit
`a4b80bf370f704d6843e69433bfb5c06274f57df`. Source review found a material
platform constraint: `beacon_agent` is a MinGW Windows PE builder, including
its HTTP/S and DNS/DoH connectors. The separate `gopher_agent` emits Linux ELF
but accepts only Gopher TCP/mTLS profiles. The Censys payload table is
consistent with this: its Linux payload is Gopher while the listed Beacons are
Windows executables. The Linux HTTP/S and DNS Beacon combinations requested by
the scenario therefore cannot be generated from this release and were not
emulated or mislabeled.

The genuine Linux substitute was a 6,717,602-byte static amd64 Gopher ELF,
SHA-256
`42dcfa4ade2d29146126455d00fe1e3de3c8cb1886c414b3123aad64d72ce16e`.
It was separately triaged and reviewed before execution, then fetched from the
Kali HTTP server as `/opt/lab/run/.cache/telemetry-helper`. The renamed agent
connected only to Kali `192.168.1.50:19443` over TLS 1.3. `pwd`, `ls`, `ps`,
and the fixed 30-byte marker download all completed. Adaptix reported sleep and
jitter as 0/0; the configured ten seconds was reconnect delay. Gopher retained
a 57.605435-second task connection, so no Beacon-style callback periodicity was
available to measure.

The mTLS JA3 `2196848d251b217de8b2c037e356c11d` and JA3S
`f4febc55ea12b31ae17cfb7e614afda8` exactly match the existing Sliver Linux Go
TLS evidence in this repository. That is useful cross-family evidence that the
pair is a generic Go `crypto/tls` characteristic, not an Adaptix signature; no
duplicate TLS rule was authored.

The persistence flow replaced `/etc/systemd/system/sysmon.service`. Its
description still claimed `Sysmon event logger`, but its `ExecStart` was the
hidden renamed ELF instead of the baseline
`/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service`. Neither the unit nor
the substituted target was owned by a dpkg package. Auditd captured the unit
creation, `systemctl enable`, `systemctl start`, PID 1 execution, and the
Kali-only connect. The real Sysmon sensor remained running under a temporary
`lab-sysmon-sensor.service` so the transition stayed observable.

SigmaHQ's generic `Systemd Service Creation` rule caught the masquerading
unit. In the primary window it also caught the benign temporary sensor unit,
demonstrating the noise cost of treating any systemd unit creation as the
signal. The local high-confidence rule instead describes the invariant:
`sysmon.service` content whose `ExecStart` is not a known Sysmon binary. A
second, deliberately low-level hunt covers PID 1 executing from a hidden path.
The latter has `fp_likelihood: high`, `recommended_role: hunt`, and `level:
low` as required. The upstream crond masquerade rule and hacktool-name rule did
not fire. A security-service identity/ExecStart mismatch analogue is worth an
upstream proposal after broader path/package testing; adding an Adaptix agent
filename is not.

For DNS, VM 103's resolver was set exclusively to Kali, IPv4 allowed only
loopback and `192.168.1.50`, and IPv6 allowed loopback only. Those guards were
verified before each listener start. The non-forwarding BeaconDNS listener
used only the lab parent `adaptix.lab`. Five source-faithful heartbeat probes
produced twelve resolver-duplicated A query rows with this shape:

```text
<8 hex sid>.<operation>.<8 hex seq>.<8 hex index>.<20-char Base32 data>.<parent>
```

All answers were authoritative `0.0.0.0`; four unrelated background packets
were rejected by the target guard. The observed unique sequence gaps were
2.020946–2.023118 seconds because the operator deliberately sent probes two
seconds apart. That is not agent cadence. The two DNS rules are accordingly
described as source-plus-listener validation, not Linux implant evidence.

The existing Sliver DNS expressions matched zero Adaptix probe rows. Both
families use Base32-like multi-label DNS, but Sliver's captured shape used two
63-character labels plus an 18–63-character label and 10.212–13.521-second
burst gaps, whereas the Adaptix heartbeat has fixed hex metadata and a
20-character data label. A generalized cross-family Base32 tunnel rule may be
more valuable than branded near-duplicates, but these captures do not yet
justify a precise common expression. SigmaHQ master has essentially no Linux
DNS-tunnel/DoH behavior coverage; the nearest DoH rules are Windows registry
and `curl.exe` process rules. The local Zeek and Suricata rules add resolver-,
port-, parent-domain-, and implant-name-independent query-structure coverage.

DoH was not runnable. The reviewed connector defaults name public resolvers,
and the lab has no compatible hosted DoH endpoint. Public endpoints were never
used. macOS and Azure Blob dead-drop C2 remain lab-capability gaps.

Every full capture was passed to `nsm-analyze`; all reported zero kernel drops.
The first persistence safety check returned `INCONCLUSIVE`, not a violation,
because normal Ubuntu MOTD traffic reached its public resolver/HTTPS endpoint
while Sysmon was being re-homed and no owner telemetry existed for those rows.
That unfiltered capture and its manifest are retained. The persistence sequence
was repeated under the verified target egress guard and returned `PASS`.
The agent and both DNS checks also returned `PASS`. The supported claim is:
*no traffic attributable to the declared attack left the lab, and everything
else that did is in the manifest.* Linux network ownership uses
`collect-run.sh` auditd correlation; raw Sysmon EID 3 alone is never trusted.

The original gate covered five of eight grounded use cases. This expansion
raises honest fully verified coverage to seven of eight: a genuine Linux agent
and the masquerading service are now grounded. DNS listener safety and source
shape are validated, but Linux DNS/DoH agent transport remains an upstream
platform/lab-endpoint gap and is not counted as fully verified.

Cleanup is confirmed. Kali's teamserver, Gopher/DNS listeners, and staging
server were stopped; their ports closed; the review/build/runtime was removed;
the Adaptix egress chains were deleted; and the pre-existing Sliver firewall
hooks were restored. Proxmox rolled VM 103 back to `linux_verify_baseline`
with `qmrollback` and `qmstart` both reporting `OK`. After boot,
`/opt/lab/run`, the resolver drop-in, and Adaptix guard chains were absent;
Sysmon and auditd were active/enabled with audit lost count zero; the genuine
Sysmon unit was restored; and all four instrumentation hashes matched
`prepare-linux-target.md`.

## Historical Windows verification

AdaptixC2 v1.2 was verified in the contained Windows lab across a clear HTTP
Beacon, an HTTPS Beacon, the server/listener 404 fingerprints, a modified-header
claim test, and a lab-authored inert DLL sideload. Kali VM 100 was the exclusive
C2/build host and Windows VM 104 was restored to `win_verify_baseline` before
and after execution.

The highest-value result is the listener response body. The raw default body
was exactly 180 bytes with no final newline:

```html
<!DOCTYPE html>
<html>
<head>
<title>ERROR 404 - Nothing Found</title>
</head>
<body>
<h1 class="cover-heading">ERROR 404 - PAGE NOT FOUND</h1>
</div>
</div>
</div>
</body>
</html>
```

Its SHA-256 was
`464816fd640d5bdd848e7c4340f378f873c406c641d9d6c1477c4d83ddbdacf2`.
The default response had only Date, Content-Length 180, and
`Content-Type: text/html; charset=utf-8`. After adding `Server: nginx` and
`X-Lab-Profile: modified`, the body stayed byte-identical. The same native
Suricata response-body rule fired once on each pcap, confirming the Censys
claim for this v1.2 listener.

The TLS teamserver had a separate default 404 surface: `Server: AdaptixC2`,
`Adaptix-Version: v1.2`, `Content-Type: text/html; charset=UTF-8`, and a
1,133-byte page containing `AdaptixC2 404` and the connection-details message.
Its exact captured headers and body are retained under `evidence/network/`.

The clear Beacon made 11 POSTs while rotating `/api/v1/status`,
`/updates/check.php`, and `/content.html` with the default Firefox 20 profile.
All five bounded tasks completed. Nine steady gaps were 9.992320–10.015900
seconds, so the configured 20% jitter did not manifest. The HTTPS Beacon made
repeated short TLS 1.2 connections with 23 steady gaps of
9.999420–10.016400 seconds.

The HTTPS JA3 was `72a589da586844d7f0818ce684948eea` and JA3S was
`326de7c6719a77bb7ef65f6cac962193`. The full JA3 lacks hybrid group 4588 and
does not match the supplied stock Go 1.24+ fingerprint. This is consistent with
the C++ Beacon using Windows WinINet/SChannel. Active JARM returned all zeros.
Neither TLS result is shipped as an AdaptixC2 rule.

For the sideload case, a valid Microsoft-signed copy of WerFault.exe loaded the
lab-authored inert `faultrep.dll` beside it. WerFault itself created the fixed
marker. File and process events were strong; network and registry signals were
absent. Sysmon image-load logging was disabled, so no EID 7 was available.

SigmaHQ master commit `8eaafff1f2845a696050e05e72ba1140ee190698`
contained zero Adaptix mentions. Three generic upstream location-anomaly rules
matched the copied/executed WerFault host. The generic callback-port and service
rules did not fire; the generic image-load sideload rule was not observable
without EID 7. The new rules focus on the verified listener body, default HTTP
profile, `faultrep.dll` file creation, and a rename-resistant unversioned-agent
execution hunt.

`check-lab-scope.py` was re-run against every retained full `nsm/` input rather
than the target-to-Kali `scope-nsm/` subsets used by the earlier report. The
declared images include both generated Beacon names and the executed aliases
`survey-host.exe` and `telemetry-check.exe`. Every flow returned `PASS`. The
supported claim is: *no traffic attributable to the declared attack left the
lab, and everything else that did is in the manifest.*

The manifest now exposes what the filtered report hid. The HTTP capture records
1,181 bytes to `52[.]123[.]129[.]14:443`, attributed by Sysmon EID 3 to
`MpDefenderCoreService.exe`, plus an unattributed 2-byte `OTH` flow to
`4[.]213[.]25[.]241:443`. The HTTPS capture also records that 2-byte flow and two
responder-only, zero-byte `RSTRH` flows to `72[.]145[.]35[.]105:443` and
`72[.]145[.]35[.]115:443`. None is attributed to a declared Adaptix image. No
operator log or configuration was present in the retained flow directories.

Raw pcaps, EVTX, endpoint JSON, generated agents, operator database, heartbeat
values, session keys, certificates, and unrelated host data are not committed.
Sanitized evidence, hashes, exact HTTP responses, source/agent reviews, safety
results, and rule measurements are retained here.

Audit gate: **PASS on iteration 2** at measured commit `f4020a0`, with zero
blocking rule defects. The harness measured four rules: one Windows process
rule passed with 3 clean-corpus matches (0.012661% of 23,695 events), the
Windows file rule had 0 matches in 542,441 events but no positive corpus
sample, and both Suricata rules were correctly classified as not testable on
EVTX. The independent scenario review rated coverage `expand` at 5/8 (62.5%),
above the 60% merge floor; Linux, service-persistence, and DNS/DoH coverage
remain non-blocking future work.
