# Certutil decode scenarios

## Scope

- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target and local fixture
  host.** The recorded run decoded the fixture here as
  `NT AUTHORITY\SYSTEM`. No attacker or NSM VM is named in this verification.
- **Destinations.** The evidence records no Sysmon network-connection or DNS
  events, and the run used only local input and output paths. Its only
  scenario host was `192.168.1.52`, inside `192.168.1.0/24`; nothing outside
  the lab was contacted.
- **Hosting and references.** The inert input fixture was staged locally at
  `C:\lab\benign-marker.b64` on VM 104. No payload, stager, C2, download
  source, or external citation was used. The record does not state where the
  fixture was created or which host staged it before the run.

`certutil.exe` is a Microsoft-signed certificate utility that can decode
base64 or hexadecimal content into an arbitrary output file. Attackers can use
that legitimate capability to turn an encoded staging artifact into its usable
form, mapping to **Deobfuscate/Decode Files or Information (T1140)**.

## Verified flow: local benign base64 decode

1. Windows VM 104 started from `win_verify_baseline`.
2. A 114-byte PEM-style base64 fixture was staged at
   `C:\lab\benign-marker.b64`. Its decoded bytes were the benign string
   `benign-certutil-decode-marker-2026-08-10` followed by CRLF.
3. The SYSTEM account invoked:

   ```text
   C:\Windows\System32\certutil.exe -decode C:\lab\benign-marker.b64 C:\lab\decoded-marker.txt
   ```

4. Certutil reported successful completion and wrote a 42-byte output whose
   SHA-256 matched the expected decoded bytes.
5. Endpoint telemetry was collected and VM 104 was rolled back. No packet
   capture was required because the scenario was fully local and produced no
   network events.

## Other scenarios considered

- `-decodehex` against a benign hexadecimal fixture would exercise the same
  ATT&CK technique with different command syntax.
- Decoding into a script, DLL, or executable extension would raise detection
  confidence but was intentionally avoided in favor of inert text.
- A two-stage flow could separately verify transfer followed by decode, but it
  should not be conflated with the already-completed certutil remote-download
  technique.
- A user-context run could compare output paths and registry initialization
  with this SYSTEM-context run.

Encoding (`-encode` or `-encodehex`) and URL-cache download are distinct
behaviors and are outside this verification.
