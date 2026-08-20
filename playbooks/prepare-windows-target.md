# Playbook: Prepare a Windows target for attack-tool verification

Audience: the lab orchestrator (Codex on the AI VM). Goal — bring a Windows analysis VM to a
clean, **richly instrumented** baseline so an attack tool can be run and its telemetry captured
**comprehensively** for detection engineering (Sigma).

## Inputs
- **Target VM**: default `104` = `WIN10-ANALYSIS`, `192.168.1.52` (Windows 10 LTSC).
- **Helpers**: `~/bin/lab-exec <vmid> <cmd...>`, `~/bin/lab-push`, `~/bin/lab-pull`
  (lab-pull is Windows-capable — it uses native PowerShell Base64 for Windows targets).
- **Proxmox API creds**: `~/.config/lab/pve.env` (node `analysis-proxmox`).
- **Canonical baseline snapshot**: **`win_verify_baseline`** (Defender-off + verification-grade
  Sysmon + the C:\Tools collection toolset).

## Running Windows commands over the guest agent
For multi-line PowerShell, base64-encode a UTF-16LE script and run
`powershell -NoProfile -EncodedCommand <B64>`, or `lab-push` a `.ps1` to `C:\lab\`. Always parse
the guest-agent JSON (`out-data`/`err-data`/`exitcode`). PowerShell CLIXML progress on stderr is
noise, not an error.

## Steps (verify each; print evidence)
1. **Confirm** the VM is running and its guest agent responds.

2. **Defender OFF — prerequisite: Tamper Protection.** Signature-detected hacktools (mimikatz,
   LaZagne, …) are blocked while real-time protection is on, and **a path exclusion alone is NOT
   enough** (confirmed: mimikatz → `HackTool:Win32/Mimikatz`, Defender EID 1116/1117, no process,
   no telemetry).
   - **Tamper Protection must be turned off first, and this is MANUAL (by design)** — it cannot be
     disabled programmatically. Toggle it once in the GUI: *Windows Security → Virus & threat
     protection → Manage settings → Tamper Protection → Off*. Confirm `(Get-MpComputerStatus).IsTamperProtected`
     is `False`.
   - Then: `Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true`
     `-DisableScriptScanning $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend`.
   - **Persist across reboot**: Windows re-enables real-time protection on reboot unless backed by
     local policy (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`). Verify it stays off after
     a reboot.

3. **Sensor: Sysmon with a VERIFICATION-GRADE config.** A verification VM runs one tool briefly in
   a clean state, so **completeness beats noise-reduction** — do NOT use a production-tuned config
   that filters telemetry. (The stock SwiftOnSecurity config heavily filters network events and
   WILL miss arbitrary C2.) Use a permissive config — Olaf Hartong `sysmon-modular` (full), or
   SwiftOnSecurity with the network/file/registry exclusions removed — that captures, unfiltered,
   the **five observation dimensions** used for detection:
   - **Process creation (EID 1)** — Image, OriginalFileName, **CommandLine**, Hashes, and the
     **parent** (ParentImage / ParentCommandLine / ParentProcessGuid), User, IntegrityLevel.
   - **Network (EID 3) + DNS (EID 22)** — log **ALL** connections and queries (destination
     IP/host/port, QueryName). Do not filter.
   - **File (EID 11 create, EID 23/26 delete, EID 15 stream hash)** — broad.
   - **Registry (EID 12 key/value create+delete, EID 13 value set, EID 14 rename)** — broad.
   - **LSASS ProcessAccess (EID 10)** — keep the `lsass.exe` include-rule (credential-access depth).
   - Image load (EID 7) may remain filtered (high volume; Tier-2 signal — see verify-tool.md).
   Verify `Sysmon64` is Running and `Microsoft-Windows-Sysmon/Operational` is receiving these EIDs.

4. **Additional telemetry** (make it reboot-persistent via policy, not just runtime):
   - PowerShell **Script Block + Module + Transcription** logging
     (transcripts → `C:\Tools\Logs\pstranscripts`) via `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\*`.
   - Process-creation **command-line auditing** (`ProcessCreationIncludeCmdLine_Enabled=1`).
   - `auditpol` for **Process Creation, Handle Manipulation, Sensitive Privilege Use, Logon** (success+failure).

5. **Collection toolset** at `C:\Tools`:
   - **Sysinternals Suite** → `C:\Tools\Sysinternals` (EULAs pre-accepted, on PATH) — Procmon
     (deep file/reg/proc trace), Autoruns, Handle, Sigcheck, Process Explorer, Tcpview, PsTools.
   - **Network capture**: built-in **`pktmon`** for a **full-packet** pcap of network/C2 tool runs
     (`pktmon start --capture --pkt-size 0 -f cap.etl` → `pktmon stop` → `pktmon pcapng cap.etl -o
     cap.pcapng`). The `.pcapng` is analyzed off-host by the **NSM VM 106** (Zeek+Suricata+JA3) via
     the AI-VM helper `~/bin/nsm-analyze` — see verify-tool.md step 4. (Npcap+tshark optional; free
     Npcap has no unattended silent installer.)
   - **`C:\Tools\collect-run.ps1 -StartUtc <iso8601> -EndUtc <iso8601> -OutDir <path>`** — exports
     the `Microsoft-Windows-Sysmon/Operational`, `Security`, `Microsoft-Windows-PowerShell/Operational`,
     and `Microsoft-Windows-Windows Defender/Operational` channels (time-filtered EVTX) plus a
     combined `events.json`. This standardizes telemetry collection for a run window.

6. **Snapshot** the clean instrumented baseline as **`win_verify_baseline`** (fs-frozen, via the
   Proxmox API). Every verification run rolls back to this snapshot afterward.

## Optional run-scoped ImageLoad instrumentation

The shipped `win_verify_baseline` deliberately has **no Sysmon EID 7 ImageLoad collection**. For a
verification that makes any `image_load` claim, copy
`instrumentation/windows/sysmon-verification-imageload.xml` to the target and apply it with
`Sysmon64.exe -c <file>` during that run's provisioning. The optional configuration is identical to
the baseline configuration except that an empty `<ImageLoad onmatch="exclude">` block logs every
image load.

Prove the change before the scenario starts by dumping the active Sysmon configuration into the run
evidence and capturing a positive EID 7 from a benign process. Record the total EID 7 volume in the
run window. This is intentionally run-scoped: do not re-take `win_verify_baseline`; the mandatory
post-run rollback restores the baseline. **Every image-load claim in this repository depends on this
step and its per-run proof.**

## Output / report
Defender/Tamper state (and reboot-persistence); Sysmon status + which of the five dimensions the
active config captures (and any config change made); the collection toolset installed; the
`collect-run.ps1` interface; and the `win_verify_baseline` snapshot result. **Do not run the
attack tool in this playbook** — provisioning only.
