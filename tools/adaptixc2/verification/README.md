# AdaptixC2 v1.2 Windows verification

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
