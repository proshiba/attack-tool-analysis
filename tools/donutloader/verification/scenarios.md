# DonutLoader verification scenarios

## Scope declaration

- **VM 100 — Kali — `192.168.1.50` — only delivery, listener, build, and operator host.** Every delivery URL and the single bounded HTTP marker receiver bind explicitly to `192.168.1.50`. Kali serves only lab-authored inert artifacts prepared for these runs. It never resolves or contacts an incident IOC.
- **VM 104 — WIN10-ANALYSIS — `192.168.1.52` — only execution target.** Every execution visit starts from and returns to `win_verify_baseline`. It fetches the lab ISO only from Kali, mounts it locally, and may send only a fixed non-secret marker to the Kali listener.
- **VM 106 — NSM — offline pcap analysis only.** It receives an unfiltered full-packet capture out of band through `nsm-analyze`; it is not a delivery or C2 destination.
- **VM 107 — audit — gate execution only.** It receives the pushed Git branch through the audit harness and is never an attack destination. VM 110 may receive compiled artifacts out of band for static inspection only. Nothing executes on VM 102, VM 108, VM 105, VM 106, VM 107, or VM 110.
- **Destinations.** All attack-generated delivery, callback, and marker traffic is confined to `192.168.1.0/24`, specifically between Kali and the Windows target. The management network is never an attack destination. The four `source_url` values below and all public IOC strings in the research corpus are grounding citations only: they are never resolved, contacted, copied into a payload, listener, configuration, or command, or submitted to an online service.
- **Bounded behavior.** Lab-authored payloads write fixed markers, create inert persistence definitions, and send a fixed non-secret marker. The only credential-access payload is the lab's already-approved Mimikatz build; its output is discarded and never collected. There is no propagation, lateral movement, credential retention, destructive action, external account, or third-party service interaction.

## Grounding corpus and falsifiable thesis

- `source_url: https://x.com/bomccss/status/2077318455716679970` — 2026-07-16: archive-to-disk-image delivery, `Mount-DiskImage`, a legitimate executable plus a sideloaded DLL, staging under the NetTokenBroker program-data directory, and a Defender-exclusion preamble.
- `source_url: https://x.com/tdatwja/status/2082761360321200396` — 2026-07-31: a legitimate executable plus a differently named sideloaded DLL, Donut shellcode in a separate `.dat`, injection into Notepad, XML scheduled-task creation below the injected host, and an `ms-settings` shell-open registry form.
- `source_url: https://x.com/bomccss/status/2083123859537137838` — 2026-08-01: a different signed host and sideload name, followed by kernel-service creation and start.
- `source_url: https://x.com/bomccss/status/2088132641665249556` — 2026-08-15: a further DonutLoader instance with a `.ttf`-named data file, demonstrating that the staging extension is not an executable-type invariant.

The identifying-artifact thesis is tested as follows: the same lab-authored behavior is run with two unrelated host/DLL/data names and with `.dat` and `.ttf` staging. A useful rule must survive those renames. The empirical corpus itself changes the sideload DLL, data, host, service, and staging names across every case. No Donut rule may key on a brought-in tool filename or `OriginalFileName`. A sideload rule may use an impersonated system-DLL name only as one half of the technique-defining mismatch: system DLL basename plus a user-writable non-system path and unsigned or unversioned image.

## Run A — mounted-image delivery, sideload, local in-memory execution, and exclusion telemetry

1. Roll VM 104 back to `win_verify_baseline`; confirm Defender's baseline state and verification-grade Sysmon.
2. On Kali, serve one lab-created ISO and bind a fixed-marker HTTP receiver to `192.168.1.50` only. Record the listener definition and operator transcript.
3. On VM 104, use the inbox Windows HTTP client to fetch the ISO from Kali, write its local path to `C:\Windows\path.txt`, and run `powershell.exe -ex bypass -command Mount-DiskImage -ImagePath (gc C:\Windows\path.txt)`.
4. Run the lab-authored, ephemeral-certificate-signed host from the mounted volume. Its adjacent lab-authored sideload DLL reads Donut-generated shellcode from a separate `.dat`; the managed payload writes a fixed marker and sends a fixed non-secret marker to the Kali listener. The payload is never written to disk as an executable.
5. Before host execution, run the observed `powershell.exe -ep bypass -w hidden -c` form with `Add-MpPreference -ExclusionProcess` and `Add-MpPreference -ExclusionPath` against the lab stand-in and lab staging directory. Defender is already off by baseline design, so this proves telemetry only; it does not prove an evasion or protection bypass.
6. Capture full packets and endpoint telemetry, dismount the image, collect, run the post-run scope gate, and roll back immediately.

Expected ATT&CK: T1105, T1553.005, T1574.001, T1027.009, T1562.001, and in-process memory execution. Expected observations include PowerShell script/process telemetry, ISO download/mount, execution from a mounted volume, a signed host in a non-system path, adjacent inert-looking data, image load if EID 7 is enabled, the marker, and HTTP without a transferred PE response body.

## Run B — renamed `.ttf` staging, remote-thread injection, and three persistence forms

1. Roll VM 104 back to the baseline and stage a differently named host/DLL pair plus a `.ttf`-named Donut blob under `C:\ProgramData\Microsoft\NetTokenBroker\`.
2. The lab-authored sideload DLL starts Notepad and uses the bounded `OpenProcess`/`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` sequence to execute a lab-authored payload inside Notepad. Pass the signed stand-in, both DLL names, both data names, and `notepad.exe` to the post-run scope gate as declared tool images.
3. The injected payload writes a marker and creates one child: `cmd.exe /C schtasks.exe /Create /TN "WindowsFontCacheRestore" /XML "C:\ProgramData\Microsoft\NetTokenBroker\fontcache_task.xml" /F`. The XML action is inert and scheduled so it does not execute during the run.
4. From the same bounded operator script, create the `HKCU\Software\Classes\ms-settings\Shell\open\command` default value and empty `DelegateExecute` value with an inert command. Do not launch a UAC-bypass host.
5. Create a service that points at the lab-authored unsigned native-subsystem stand-in in the public-users directory with `type= kernel`, then call `sc start`. Do not disable driver-signature enforcement, enable test-signing, or alter Secure Boot. Record the expected start failure and the service-creation telemetry; if the failure has another cause, state it rather than claiming DSE was tested.
6. Record Sysmon EID 8, EID 10, and EID 25 presence or absence; preserve the Notepad-to-command-shell-to-scheduled-task process tree; collect, scope-check, and roll back.

Expected ATT&CK: T1055, T1053.005, T1543.003, T1546.001, T1574.001, and T1027.009. The falsification test renames the host, sideload DLL, and data file while preserving the structural relationships.

## Run C — Mimikatz converted to Donut shellcode and run only in memory

1. Roll VM 104 back to the baseline. Use only the exact already-approved Mimikatz binary identity documented by `tools/mimikatz/verification/`; do not acquire another build.
2. On Kali, convert that approved binary to Donut shellcode without embedding Mimikatz module tokens in any Windows process command line. Stage only the opaque data blob next to the lab-authored loader; never place Mimikatz on VM 104 as an executable.
3. Execute `privilege::debug sekurlsa::logonpasswords exit` inside the loader process, discard all native output, and collect only telemetry fields. The success criterion is behavioral evidence such as LSASS ProcessAccess; recovered credentials are outside scope and must not be viewed, pulled, or committed.
4. Measure `tools/mimikatz/verification/sigma/proc_creation_mimikatz_cmdline.yml` against this run. It should remain silent because the relevant strings are not in process-creation command lines; this is a structural blind-spot test, not an assertion.
5. Determine which signals survive: unexpected-source LSASS EID 10, CLR/`clr.dll`/`mscoree.dll`/`amsi.dll` image loads into a non-.NET host, EID 8/25 if present, and named pipes if present. Absence is a valid result.
6. Collect, scope-check with every loader name and any injected host declared, then roll back.

Expected ATT&CK: T1055 and T1003.001. This run closes the existing Mimikatz verification backlog only if the command-line miss and at least one replacement behavioral signal are measured from the captured events.

## Upstream comparison plan for LOLBIN-like components

For each observed form, compare the lab telemetry against SigmaHQ `master` at baseline commit `3c0d35188942eb6a8c373e4f4973ac7e84116993` in both directions: whether the upstream rule sees the exact lab form, and whether the lab-derived logic adds any signal upstream lacks. The candidates are Defender exclusions in process and PowerShell-script telemetry, `Mount-DiskImage`, scheduled-task creation, new kernel driver via `sc.exe`, and `ms-settings` protocol-handler modification in process and registry telemetry. A local rule is permitted only for a lab-proven form, logsource, precision, or observation-dimension gap.

Every adopted or authored filter is audited for attacker-controlled bypasses. No filter may trust a user-writable filename, directory component, or command argument. Anchored operating-system paths or intrinsic event metadata are acceptable only when the test demonstrates they cannot serve as an attacker-controlled off switch.

## Network dimension hypothesis

The Kali HTTP server and marker listener produce a full, unfiltered packet capture. Zeek and Suricata should see the ISO transfer and the fixed callback request, including flow, HTTP method/path, headers, and transferred object bytes. They should not infer that the `.dat` or `.ttf` blob becomes a PE in memory, observe remote-thread injection, or recover the absent on-disk payload executable. Clear HTTP has no JA3; if no TLS occurs, the correct JA3 result is not applicable rather than zero detections.

## Future scenarios and capability gaps

- A genuine vendor-signed application with a naturally vulnerable import graph would improve fidelity beyond the ephemeral lab certificate, but acquiring and publishing a third-party binary is unnecessary for the technique-level test.
- Cross-architecture injection and process hollowing are distinct T1055 variants and are deferred.
- A properly built unsigned WDK driver would isolate driver-signature enforcement more cleanly if the native-subsystem stand-in fails earlier in image validation. Security posture will not be weakened to force a successful load.
- Encrypted delivery would add TLS metadata and JA3/JA3S measurement; this run intentionally uses clear lab HTTP so transferred-object visibility can be measured directly.
