# DonutLoader verification

The lab-authored equivalent chain executed successfully without acquiring an
incident sample. Donut v1.1 received a `safe-to-run-in-lab` review restricted
to x64 embedded, no-bypass, no-compression, no-encryption generation. The
generator, loader, sideload DLLs, payload sources, executables, opaque blobs,
certificate, key, pcaps, EVTX, and raw event JSON are not published here.

## Execute / detect matrix

| Scenario | Execution outcome | Detection outcome | Refuted or limited assumption |
|---|---|---|---|
| A: exclusion preamble, ISO mount, mounted-volume sideload, `.dat`, fixed marker | Success: exclusion and mount exit 0; host exit 0; marker and lab-only POST observed. | SigmaHQ process Defender-exclusion and sideload logic hit; local process Mount-DiskImage hit; CLR image loads and marker file event survived. | Zero EID 4104 meant both upstream script-block mount rules were unavailable. Defender was already off, so no evasion was proven. |
| B initial | Injection and marker succeeded; invalid XML prevented task registration. | Process tree existed in Security 4688, but EID 8 was absent under the first broad configuration. Scope PASS, then rollback. | Hand-authored `ServiceAccount` LogonType was invalid. This run is diagnostic, not canonical. |
| B retry: `.ttf`, Notepad injection, XML task, registry, kernel service | Success: task and registry forms present; service created; unsigned driver start failed with error 577 as expected. | EID 8 = 1, EID 10 source-to-Notepad present, EID 25 = 0; Notepad loaded `mscoree`, `clr`, and `amsi`; upstream sideload, remote-thread, suspicious-parent, and registry rules hit; local XML-task and no-filter SC rules hit. | EID 25 did not describe this CreateRemoteThread technique. No named pipe was attributable to the chain. |
| C: approved Mimikatz only in Donut memory | Success: host exit 0 and one 0x1010 LSASS ProcessAccess event. | Existing `proc_creation_mimikatz_cmdline.yml` stayed silent (0 visible tokens). Existing `process_access_lsass_read.yml` hit; the ProgramData CLR-hosting hunt hit. | Only `mscoree.dll` loaded; `clr.dll`, `amsi.dll`, EID 8, EID 25, named pipes, and chain-attributed network were absent. |
| NSM across A/B/C | Full pcaps analyzed; all attack destinations remained in `192.168.1.0/24`. | Zeek saw ISO GET metadata and Run A's marker POST. Suricata identified the Python server plus capture diagnostics, not Donut. | Clear HTTP produced no JA3. Neither engine could infer the PE reconstructed in memory or observe sideload/injection/persistence semantics. |

## Detection conclusion

The filename thesis is supported for execution and injection: the two host
names, two impersonated DLL names, `.dat` and `.ttf` extensions, and the Run C
host rename changed while the structural signals survived. The technique-name
exception also held: SigmaHQ's system-DLL basename plus non-system-location
logic detected both sideload variants without naming Donut.

The inert-looking data file is useful correlation context, not a standalone
portable Sigma discriminator. A file event cannot prove that adjacent bytes
became code, and the extension changed without affecting execution. The stable
coverage was the unsigned/unversioned non-system DLL load, CLR activation in an
unexpected host, EID 8/10, an anomalous Notepad child, and persistence behavior.

For Mimikatz, the structural blind spot is now measured. The process command
line contained only the stand-in host path, so the module-token rule could not
fire. The replacement was the existing name-independent LSASS ProcessAccess
rule on `TargetImage=lsass.exe` and `GrantedAccess=0x1010`, enriched by an
unusual ProgramData source and an in-memory call-trace address. Credential
output was never captured or inspected.

## Precision and upstream disposition

The five local rules were measured against their own categories. Image-load
denominator: 727,396; process-creation denominator: 23,695.

| Local rule | Clean matches | FP share | Role / level |
|---|---:|---:|---|
| CLR in Notepad | 0 | 0% | low, alert / high |
| CLR from a user-writable staging root | 18 | 0.002475% | medium, hunt / low |
| PowerShell Mount-DiskImage process fallback | 0 | 0% | medium qualitative raise, hunt / low |
| Schtasks `/Create` + `/XML`, retaining SYSTEM | 37 | 0.156151% | high, hunt / low |
| SC kernel-driver creation without CLI filters | 6 | 0.025322% | medium, hunt / low |

Twelve SigmaHQ rules were compared in both directions at commit `3c0d351`.
Most were adopted as upstream logic and not duplicated. Local authorship is
limited to measured gaps: missing process telemetry for mount, SYSTEM task XML,
attacker-controlled SC filters, and CLR hosts absent from upstream's scripting
application list. Details and upstream measurements are in
`evidence/upstream-comparison.md`.

## Safety and rollback

The design scope gate returned REVIEW only for grounding citations and found no
critical scope defect. Donut's PoC review verdict was `safe-to-run-in-lab` with
the restrictions above. Each post-run lab-scope check returned PASS with zero
attack-attributed violations. VM 104 was restored to `win_verify_baseline`
before and after each run; after Run C, the run directory was absent and Sysmon
was running. No security control was weakened to load the unsigned driver.
