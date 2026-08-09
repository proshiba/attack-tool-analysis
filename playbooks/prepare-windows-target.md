# Playbook: Prepare a Windows target for attack-tool verification

Audience: the lab orchestrator (Codex on the AI VM). Goal — bring a Windows
analysis VM to a **clean, instrumented baseline** so an attack tool can be run and
its telemetry captured for detection engineering (Sigma).

## Inputs
- **Target VM**: default `104` = `WIN10-ANALYSIS`, `192.168.1.52` (Windows 10 LTSC).
- **Helpers on the AI VM**: `~/bin/lab-exec <vmid> <cmd...>` (run a command in a VM via
  the QEMU guest agent), `~/bin/lab-push <vmid> <local> <remote>`, `~/bin/lab-pull`.
  Inspect the scripts if unsure of argument handling.
- **Proxmox API creds**: `~/.config/lab/pve.env` (`PVE_HOST`, `PVE_TOKENID`, `PVE_TOKEN`).
  Node = `analysis-proxmox`.

## Running Windows commands over the guest agent
Run PowerShell via the guest agent. For multi-line scripts the reliable pattern is to
**base64-encode a UTF-16LE script** and run `powershell -NoProfile -EncodedCommand <B64>`,
or `lab-push` a `.ps1` to `C:\lab\` and execute it. Always parse the guest-agent JSON
result (`out-data` / `err-data` / `exitcode`). PowerShell writes CLIXML progress to
stderr — that is noise, not an error.

## Steps (verify each; print evidence)
1. **Confirm** VM is running and its Windows guest agent responds.
2. **Install Sysmon** (the primary sensor):
   - Create `C:\lab\`.
   - Sysmon: download `https://download.sysinternals.com/files/Sysmon.zip`, expand to
     `C:\lab\sysmon\` → `Sysmon64.exe`.
   - Config: `https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml`
     → `C:\lab\sysmonconfig.xml` (SwiftOnSecurity baseline; Olaf Hartong `sysmon-modular`
     is an alternative).
   - Install: `C:\lab\sysmon\Sysmon64.exe -accepteula -i C:\lab\sysmonconfig.xml`.
   - **CRITICAL**: ensure Sysmon logs **ProcessAccess (Event ID 10) targeting `lsass.exe`**
     — credential-access tools (mimikatz, etc.) depend on it. If the config lacks a
     ProcessAccess include-rule for `lsass.exe`, add one and re-apply
     (`Sysmon64.exe -c C:\lab\sysmonconfig.xml`), e.g.
     `<ProcessAccess onmatch="include"><TargetImage condition="end with">lsass.exe</TargetImage></ProcessAccess>`.
   - Verify: `Sysmon64` service **Running**; `Microsoft-Windows-Sysmon/Operational` log exists.
   - *(Optional but recommended)* enable PowerShell ScriptBlock logging + relevant
     Security-log auditing (process creation w/ command line, handle/privilege use).
3. **Handle AV** for tools that will be flagged — document this as environment setup;
   the VM is isolated and snapshotted:
   - `Set-MpPreference -DisableRealtimeMonitoring $true`; `Add-MpPreference -ExclusionPath C:\lab`.
   - Verify `(Get-MpComputerStatus).RealTimeProtectionEnabled` is `False`. If **Tamper
     Protection** blocks it, report clearly (fallback: path exclusions only).
4. **Snapshot the clean instrumented baseline** via the Proxmox API
   (`POST .../nodes/analysis-proxmox/qemu/<vmid>/snapshot`, `snapname=sysmon_baseline`,
   a description, fs-frozen). Every verification run rolls back to this snapshot afterward.

## Output / report
Sysmon service status; whether lsass **EID 10** ProcessAccess is covered (and any config
augmentation you made); Defender `RealTimeProtectionEnabled`; and the `sysmon_baseline`
snapshot result. **Do not run the attack tool in this playbook** — provisioning only.
