# DLL sideloading and proxying scenarios

## Scope

- **VM 100 — Kali — `192.168.1.50` — lab build, staging, and C2 host.** It compiles only the
  lab-authored proxy/marker sources, hosts any modeled delivery set, and runs the existing lab Sliver
  listener. Every listener binds to this analysis-network address.
- **VM 104 — Windows target — `192.168.1.52` — only execution target.** Every execution visit begins
  and ends with rollback to `win_verify_baseline`. The run-scoped Sysmon ImageLoad configuration is
  applied and proved after each pre-run rollback; the post-run rollback removes it.
- **VM 106 — NSM — management address `10.9.0.20` — offline packet analysis only.** It is never a
  scenario destination. `nsm-analyze` sends a completed capture there only after the target run.
- **VM 107 — audit — offline dataset and gate host.** It is never a scenario destination and runs no
  scenario payload.
- **VM 102 — AI VM — provisioning and orchestration only.** It downloads the official VLC archive,
  verifies VideoLAN's published SHA-256, and mechanically screens the archive. No sideload set,
  proxy DLL, marker DLL, shellcode, or scenario process executes here.
- **Permitted attack destinations.** The only network destination allowed to any planted component is
  Kali `192.168.1.50`. All scenario traffic is confined to `192.168.1.0/24`; public hosts and the
  management network are forbidden scenario destinations.
- **Payload provenance.** VLC 3.x is official signed provisioning material from VideoLAN. The proxy
  and marker payloads are authored in this lab from documented PE export-forwarding behavior. The C2
  tier uses only the lab's existing Sliver server and its previously generated lab implant configured
  for Kali, wrapped as shellcode by the repository's already verified Donut generator. The article's
  generator, repository, and shellcode are never fetched, built, or executed.

The public URLs below are citations used for grounding only. No scenario retrieves a payload, tool,
or second stage from them.

## Run order and instrumentation invariant

Every run follows this order: rollback VM 104; provision the exact official VLC set; apply
`instrumentation/windows/sysmon-verification-imageload.xml`; dump the active Sysmon configuration;
launch a benign process and prove a positive Sysmon EID 7; start the bounded capture; execute only the
listed row(s); collect endpoint and, where applicable, full-packet telemetry; run
`check-lab-scope.py` with every planted/renamed image and the operator record; require `PASS`; then
rollback VM 104 again. A refused launch is recorded as non-execution, never as evasion.

## Like-for-like matrix

Rows sharing a comparison group change exactly the input named in **Changed input**. “Interactive”
means an out-of-band guest-agent launch equivalent to a local command prompt; it is not a network
scenario destination.

| ID | Comparison | Host exe | Install path | DLL form | Payload tier | Launch | Changed input | Expected signals by dimension |
|---|---|---|---|---|---|---|---|---|
| C0 | benign-default | genuine `vlc.exe` | `C:\Program Files\VideoLAN\VLC` | legitimate original | none | interactive, play lab WAV | control | EID 1 signed VLC; EID 7 signed `libvlc.dll` under default path; media opens/exits normally; no marker, persistence, or C2 |
| M1 | form | genuine `vlc.exe` | `%LOCALAPPDATA%\VLC-Lab` | plain sideload | marker | interactive | baseline | EID 1 plus EID 7 unsigned `libvlc.dll`; bounded marker; VLC loader/application failure; no network or persistence |
| M2 | form | genuine `vlc.exe` | `%LOCALAPPDATA%\VLC-Lab` | proxy + `libvlc_org.dll` | marker | interactive | DLL form only vs M1 | M1 signals plus signed renamed original EID 7; marker; normal media play/exit demonstrates proxy continuity |
| M3 | host-name | renamed `updater.exe` | `%LOCALAPPDATA%\VLC-Lab` | proxy + `libvlc_org.dll` | marker | interactive | host filename only vs M2 | Same DLL/image-load signals as M2; EID 1 and any name-keyed process detection change to `updater.exe` |
| P1 | launch | renamed `updater.exe` | `%LOCALAPPDATA%\VLC-Lab` | proxy + `libvlc_org.dll` | marker | Run key | launch only vs M3 | M3 image loads plus Run-key EID 12/13 and host process start |
| P2 | launch | renamed `updater.exe` | `%LOCALAPPDATA%\VLC-Lab` | proxy + `libvlc_org.dll` | marker | scheduled task | launch only vs M3 | M3 image loads plus task registration/process telemetry and task-engine ancestry |
| N1 | payload | renamed `updater.exe` | `%LOCALAPPDATA%\VLC-Lab` | proxy + `libvlc_org.dll` | Sliver shellcode self-thread | interactive | payload tier only vs M3 | Same proxy EID 7 shape; host-attributed EID 3 to `192.168.1.50`; Sliver flow/fingerprint evidence if observable; no public/mgmt connection |
| C1 | benign-user-app | genuine legitimate app | `%LOCALAPPDATA%` | app's own legitimate DLLs | none | interactive | control | Candidate FP shape for the name-independent hunt; if no installed app can produce it, record the control as an unexecuted lab gap |
| H2A | path-form | genuine `vlc.exe` | `C:\PROGRA~1\VideoLAN\VLC-Lab` | proxy + renamed original | marker | interactive | 8.3 path only vs M2 | Record loader success/refusal and the normalized EID 7 path; test filter, never infer from the command string |
| H2B | path-form | genuine `vlc.exe` | `\\?\C:\Users\Public\VLC-Lab` | proxy + renamed original | marker | interactive | device-path prefix only | Record success/refusal and normalized EID 7; user-writable target remains outside default VLC path |
| H2C | path-form | genuine `vlc.exe` | `\\127.0.0.1\C$\Users\Public\VLC-Lab` | proxy + renamed original | marker | interactive | loopback UNC path only | Record whether execution is refused or needs Administrator; if it loads, evaluate the EID 7 value actually emitted |
| H2D | path-form | genuine `vlc.exe` | `C:\Program Files\VideoLAN\VLC` | proxy + renamed original | marker | interactive | default-prefix case only | Administrator-only plant; successful filtered load would be an evasion with an elevated precondition, not a standard-user bypass |
| H2E | path-form | genuine `vlc.exe` | case-varied default VLC prefix | proxy + renamed original | marker | interactive | path casing only vs H2D | Test Sigma/backend case handling and the EID 7 path representation; requires Administrator to plant |
| H2F | path-form | genuine `vlc.exe` | default-path junction to `%LOCALAPPDATA%\VLC-Lab` | proxy + renamed original | marker | interactive | junction only vs H2D | Administrator-only junction creation; result depends on whether Sysmon reports the link or resolved target |
| H2G | path-form | genuine `vlc.exe` | default-path symlink to `%LOCALAPPDATA%\VLC-Lab` | proxy + renamed original | marker | interactive | symlink only vs H2D | Record privilege requirement, success/refusal, and emitted path separately |
| H2H | path-form | genuine `vlc.exe` | non-`C:` writable drive | proxy + renamed original | marker | interactive | drive only vs M2 | If no writable non-`C:` volume exists, record capability gap; otherwise upstream libvlc name rule should remain eligible |

## Hypothesis decision criteria

- **H1/H3/H4.** Replay upstream rules against each row's sanitized EID 7/1 evidence. A hit is based on
  the event fields, not a source-code reading. Compare M1/M2 and M2/M3 directly.
- **H2.** For each H2 row classify exactly one of: `evaded` (successful sideload and filter suppresses
  it), `detected anyway` (successful sideload and rule remains eligible), or `execution refused`.
  Separately record whether setup/launch required Administrator. A filter match without payload
  execution is not evasion.
- **H5.** Record `OriginalFileName`, `Description`, `Company`, `Signed`, and `SignatureStatus` for the
  on-disk `libvlc_org.dll`. If identity and disk name differ, test an enumerated naming-convention hunt
  and state that Sigma cannot compare two fields.
- **H6.** The local behavioral rule must not enumerate `libvlc.dll`, VLC, or any host executable. EID 7
  can establish that both paths are under user-writable roots and that the loaded DLL is untrusted; it
  cannot prove same-directory equality or that the host is signed. Those are explicit correlation and
  enrichment requirements.
- **H7.** Attribute C2 using host EID 3 plus full NSM analysis. Compare all 12 existing
  `tools/sliver/verification/sigma` rules before considering any new network rule.
- **H8.** P1 and P2 test persistence launches; adopt upstream persistence coverage where it already
  matches rather than cloning it.
- **H9.** C0 is mandatory. C1 is attempted only with software already present at baseline; its absence
  is reported rather than manufactured with another attacker-authored binary.

## Recall samples

Every locally authored rule is replayed without sample-specific tuning against the four named EVTX
files in `/data/datasets/EVTX-ATTACK-SAMPLES` on VM 107: APT10 JJS sideload/service persistence,
WWLIB sideload, timestomp plus DLL sideload/Run persistence, and rundll32 sideload/injection/C2. Each
sample receives an explicit hit or miss.

## Grounding sources

- Technique and proxy form: [Zero Trace Lab, “DLL Sideloading & Proxying”](https://zerotracelab.com/blog/dll-sideloading-proxying) (`source_url`; citation only).
- In-the-wild libvlc use: [Trend Micro, Earth Preta updated stealthy strategies](https://www.trendmicro.com/en_us/research/23/c/earth-preta-updated-stealthy-strategies.html) (`source_url`; citation only).
- Vulnerable library catalog entry: [HijackLibs `libvlc.dll`](https://hijacklibs.net/entries/3rd_party/vlc/libvlc.html) (`source_url`; citation only).
- Technique taxonomy and mitigations: [MITRE ATT&CK T1574.001](https://attack.mitre.org/techniques/T1574/001/) and [T1574.002](https://attack.mitre.org/techniques/T1574/002/) (`source_url`; citations only).

## Limits and future work

- The lab has one Windows target and cannot measure enterprise allowlisting, domain software
  deployment, or cross-host SMB delivery. These are future scenarios and are not counted as covered.
- The article's unknown-provenance generator and payload are permanently out of scope.
- C1 depends on a legitimate per-user application already present in the baseline. If none produces
  the shape, the missing FP control remains an explicit gap.
