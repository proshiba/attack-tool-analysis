# Seatbelt verification

GhostPack publishes no official Seatbelt releases or tags, so the exact upstream
`master` commit `392171df84472591d4eae7ebd5b1cdc96ba91377` was built from source
inside VM 104. The source archive SHA-256 was
`57026EA5FF6121AB8B794FBF9CA354737E3F53CFA1E5C7DA2FFA3390C6702AD9`.
Microsoft Visual Studio Build Tools 2022 (MSBuild 17.14.51) compiled the
unmodified source in Release/Any CPU mode with a command-line .NET Framework
v4.7.2 target override. The resulting unsigned, locally built `Seatbelt.exe`
has `OriginalFileName=Seatbelt.exe`, file version `1.0.0.0`, and SHA-256
`D5D5B5C724F7F509BF685952A58D5B9C4C3C46C0E6A6DCB68BAD72FDD21D38E8`.

The supplied `lab-push` helper was attempted but cannot transfer to this Windows
guest because it invokes `bash` in the target. The source archive was therefore
sent in bounded chunks over the same QEMU guest-agent channel with `lab-exec`;
the reassembled guest hash matched the source archive. Telemetry was compressed
in the guest and retrieved with `lab-pull`.

The test began from `win_verify_baseline` on VM 104. Defender real-time
protection was off and Sysmon 15.21 was running with verification config
SHA-256 `5435642464A05B06B0AAD58C04E682336D0FBAA05786179FCA9292EAEA4F6D71`.
From `C:\lab`, `NT AUTHORITY\SYSTEM` ran at System integrity:

```text
Seatbelt.exe -group=all -q -outputfile=C:\lab\seatbelt-run.json
```

The final measured execution ran from `2026-08-09T08:25:02.0183486Z` through
`2026-08-09T08:25:04.7370978Z` and exited with code 0. Collection covered
`2026-08-09T08:25:00Z` through `2026-08-09T08:25:07Z`.

## Observed telemetry

| Dimension | Seatbelt-attributed observation |
|---|---|
| Network | One EID 3 loopback TCP connection to RPC endpoint mapper (`127.0.0.1:135`) and one EID 22 query for `localhost`. These are real but too generic for a standalone rule. |
| Files | One EID 11 for the explicit `C:\lab\seatbelt-run.json` output; no EID 23. |
| Registry | 29 EID 12 and eight EID 13 write-class events; no EID 14. They include WMI, TCP/IP, Recycle Bin, and Internet ZoneMap keys. Sysmon does not expose the survey's broader reads. |
| Process identity | One EID 1 with `Image=C:\lab\Seatbelt.exe`, `OriginalFileName=Seatbelt.exe`, the `-group=all` command line, and System integrity. |
| Parent-child | The same EID 1 shows PowerShell as the parent, including the wrapper that changed the working directory to `C:\lab` and invoked Seatbelt. |

Two additional EID 10 events showed Seatbelt accessing `lsass.exe`; the
`0x1410` event included a managed .NET `System.ni.dll` call trace. This supports
a rename-resilient Tier 2 process-access rule. `pktmon` was not used because the
only network behavior was local host enumeration and Sysmon captured both the
loopback connection and DNS query.

## Sigma detections

- Tier 1 / `process_creation`: the invariant `-group=` syntax or at least two
  distinctive Seatbelt check names in one command line. The rule has no image
  or original-filename dependency and survives executable renaming. A renamed
  run with only one innocuous check is intentionally not covered because a
  single check-name match would be too noisy.
- Tier 2 / Sysmon `process_access`: managed .NET access to LSASS with `0x1410`,
  independent of the source executable name.

The former survey-output file rule was removed. Once the Seatbelt filename is
removed, an arbitrary executable writing JSON or text has no useful detection
specificity; retaining the name would instead make the rule trivial to evade by
renaming the brought-in tool.

No registry or network rule was authored: those dimensions produced real
events, but the observed targets and loopback RPC behavior were not distinctive
enough for useful standalone detections.

The 332,489-byte Seatbelt survey output was never inspected or pulled from the
VM. Only selected telemetry fields are committed; no credential, browser,
cloud, Wi-Fi, RDP, token, or other harvested content is present here.

After collection, VM 104 was rolled back through Proxmox to
`win_verify_baseline` and started for confirmation. Sysmon was running with the
same config hash, Defender real-time protection remained off, and Seatbelt, its
survey output, and the temporary Build Tools installation were absent.
