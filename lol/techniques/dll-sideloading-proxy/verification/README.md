# DLL sideloading and proxying verification

The upstream SigmaHQ libvlc rule is the right primary detection for this exact DLL and is adopted,
not copied. It fired on the plain sideload, the working export-forwarding proxy, and the same proxy
with `vlc.exe` renamed to `updater.exe`. The proven cross-application gap is addressed by one new
name-list-independent, low-level hunt for an untrusted DLL loaded from a common user-writable root,
regardless of the loading executable's path.

This is a technique verification, not brought-in tooling: the unknown-provenance article repository,
its generator, and its shellcode were never fetched, built, or executed. `generate_index.py` indexes
`tools/<id>` and `lol/sites`; because this work uses a lab-authored DLL and verifies behavior, it is
placed under `lol/techniques/dll-sideloading-proxy/verification` and deliberately does not change
`index.json`.

Adding the observed benign per-user-app control and container-delivery execution raises grounded
lab-runnable coverage from 8/12 to **10/12 (83%)**. Windows service persistence from the delivered
set and a validly signed malicious DLL remain explicit future/out-of-scope rows.

## Execute/detect matrix

| ID | Execute result | Upstream libvlc | Local behavioral hunt | Other result |
|---|---|---|---|---|
| C0 | signed default VLC played the lab WAV, exit 0 | silent | silent | benign control passed |
| M1 | marker ran; plain host stalled and was killed at 20 s | hit | hit | application broke |
| M2 | marker ran; proxy played WAV, exit 0 | hit | hit | signed renamed original loaded |
| M3 | same as M2 with `updater.exe`, exit 0 | hit | hit | host rename did not matter |
| P1 | HKLM Run value pointed at the proxy set | hit when launched shape is present | hit when launched shape is present | persistence registration observed |
| P2 | SYSTEM task launched `updater.exe`, exit 0, marker created | hit | hit | task launch proved |
| N1 | proxy lived 45 s; self-thread opened Kali mTLS connection | hit | hit | EID 3 attributed `updater.exe`; usable Sliver session did not establish |
| C1 VS Code | normal per-user install; opened a local text file | n/a | merged 0; relaxed 0 | no positive |
| C1 Evernote | normal per-user install and bounded launch | n/a | merged 7; relaxed 7 | five unsigned application DLL names; observed benign positive |
| D1 | browser-fetched lab ZIP extracted and launched; marker success | hit | hit | EID 11 co-write cluster; ZIP MOTW did not propagate |
| H2A 8.3 | proxy/marker success, exit 0 | detected anyway | outside local hunt root | short path preserved |
| H2B `\\?\` | payload success; VLC timed out | detected anyway | hit after normalization | degraded execution, not refusal |
| H2C UNC | proxy/marker success, exit 0 | detected anyway | outside local hunt root | loopback admin share required Administrator |
| H2D default prefix | proxy/marker success, exit 0 | **evaded** | outside local hunt root | Administrator-only plant |
| H2E case variation | proxy/marker success, exit 0 | **evaded** | outside local hunt root | canonical casing emitted; Administrator-only plant |
| H2F junction | proxy/marker success, exit 0 | detected anyway | hit | Sysmon emitted resolved user-writable target |
| H2G symlink | proxy/marker success, exit 0 | detected anyway | hit | Sysmon emitted resolved user-writable target |
| H2H non-C | not executed | not tested | not tested | no writable secondary filesystem; capability gap, not refusal/evasion |

The upstream-family replay loaded all 59 sideload-named rules (53 image-load, four process-creation,
two file-event); two conceptual image-load neighbours outside that filename family were also
compared. It returned exactly three family findings—all the libvlc rule on M1/M2/M3—and zero C0
findings. The other rules required other DLL, host, or path literals. The application-breaking
plain form and normally working proxy form produced the same two primary detections, so neither
detection depends on VLC breaking. Full comparisons are in `evidence/upstream-comparison.md` and
the emitted H2 paths are in `evidence/h2-results.json`.

## Instrumentation and endpoint findings

The shipped baseline has no Sysmon EID 7. Every run applied
`instrumentation/windows/sysmon-verification-imageload.xml`, dumped the active configuration, and
proved a benign notepad.exe EID 7 before the scenario. EID 7 volumes were 491 (C0), 1,608
(M1–M3), 3,243 (H2), 1,612 (accepted persistence), and 1,800 (accepted C2). These are sensor-volume
figures, never FP denominators. The added C1 control recorded 2,770 EID 7 events; the accepted D1
record-ID-bounded export recorded 1,879. Both used and proved the same committed config hash,
`af80508a3374adfd27d9eca0cfaca21fff6442af6439390167156d3d208e79a8`.

The official VLC 3.0.21 archive matched VideoLAN's published SHA-256 and its three inspected PEs had
valid VideoLAN signatures. Static export enumeration found ordinal base 1 and 316 named exports. The
lab proxy forwarded all 316 to `libvlc_org.<name>` while DllMain started the bounded marker or Sliver
loader on a separate thread. Neither binaries nor build/payload source are committed.

H5 was refuted. Sysmon reported the renamed signed DLL as:

| Disk name | OriginalFileName | Description | Company | Signed | SignatureStatus |
|---|---|---|---|---|---|
| `libvlc_org.dll` | `-` | `VLC media player` | `VideoLAN` | `true` | `Valid` |

PE inspection likewise found an empty OriginalFilename. There is no `libvlc.dll` identity mismatch
to detect in VLC 3.0.21, so no proxy-specific rule was authored. Even where both values exist, Sigma
cannot compare `OriginalFileName` with the basename in `ImageLoaded`; that would require backend
enrichment or an enumerated naming convention.

## Name-independent hunt, precision, and recall

`sigma/image_load_unsigned_dll_from_user_writable_path.yml` has no DLL-name list, no host-name list,
and no exclusions. It requires an unsigned/untrusted loaded DLL under a common user-writable root,
but does not constrain the loading executable's path. Sysmon EID 7 describes the DLL signature, not
the executable signature, and Sigma cannot compare directories, so the rule cannot actually prove a
signed host or same-directory equality. Those are correlation/enrichment steps, stated in the rule
instead of being implied.

The auditor's variants were reproduced independently. The merged form measured **505 / 727,396**
image-load events (**0.069426%**, 694.257 per million). Removing only the process-path selection
measured **516 / 727,396** (**0.070938%**, 709.380 per million): eleven additional events, a 2.18%
relative increase. Removing both path selections measured **29,906 / 727,396** (**4.111378%**),
about 59.2 times the merged form. The loaded-DLL path carries almost all measured precision, so the
process-path selection was removed. This recovers a Program Files host loading a user-writable DLL;
it does not recover H2D/H2E because those rows planted the DLL itself in Program Files. The measured
FP floor remains medium; judgement remains `fp_likelihood: high`, `recommended_role: hunt`,
`level: low`. The adopted libvlc rule measured **0 / 727,396** (0.0%), but its exact-name scope
cannot answer the article's “choose a less watched third-party app” advice.

Explicit four-sample recall, with no tuning to the samples, is unchanged by the relaxation:

| EVTX sample | Result | Matches |
|---|---|---:|
| APT10 JJS sideload/service persistence | hit | 2 |
| WWLIB sideload | hit | 1 |
| timestomp + sideload + Run persistence | hit | 1 |
| rundll32 sideload/injection/C2 | **miss** | 0 |

The APT10 hit is the strongest result: `jjs.exe` loaded unsigned `jli.dll` from the same user path
without either name appearing in the rule. The miss is retained and the rule was not broadened to
fit it. See `evidence/recall.json`.

## Benign-positive and archive-delivery findings

VS Code 1.134.0 and Evernote 11.29.2 were installed through their signed vendor-supported per-user
installers and used normally. VS Code produced zero matches under either local-rule form. Evernote
produced seven under both: `ffmpeg.dll` twice, `vk_swiftshader.dll` twice, and `vulkan-1.dll`,
`libEGL.dll`, and `libGLESv2.dll` once each. Every event reported `Signed=false`, `Signature=-`, and
`SignatureStatus=Unavailable`. No exclusion was added because every observed file and directory
name is attacker-controlled in the sideload threat model. This observed benign positive, rather
than the eleven-event relaxation alone, is why the rule remains a low-level, high-FP hunt.

D1 delivered the genuine renamed VLC host, lab-authored proxy, signed renamed original, and
dependencies in one lab-authored ZIP over `http://192.168.1.50:18090`. The downloaded hash matched,
`updater.exe` loaded unsigned `libvlc.dll` once, and the bounded marker ran. PowerShell extraction
created the host plus six DLL/companion files in one user-writable directory within ten seconds.
The baseline probe measured that generic correlation at **278 / 542,441 file events** (0.051250%,
512.498 clusters per million); Evernote produced three benign clusters of the same shape. It has no
technique-specific discriminator, so no file-event rule ships.

The D1 ZIP carried `ZoneId=3` and EID 15 observed its zone stream, but `Expand-Archive` did not
propagate MOTW to `updater.exe`, `libvlc.dll`, `libvlc_org.dll`, or `libvlccore.dll`. The C1 outputs
also carried no MOTW; their installers arrived out of band, so the installer-level comparison is
not like-for-like. MOTW identifies the delivered container but does not separate the eventual
ImageLoad. Exact results are in `evidence/c1-results.json` and `evidence/d1-delivery-results.json`.

## C2 and NSM

The proxy self-thread loaded the lab's own Sliver implant inside signed, renamed `updater.exe`.
Sysmon EID 3 attributed its initiated connection to `192.168.1.50:31337` directly to that process.
The completed-TLS diagnostic exposed TLS 1.3, no SNI or visible certificate chain, JA3
`2196848d251b217de8b2c037e356c11d`, and JA3S `f4febc55ea12b31ae17cfb7e614afda8`.
Those values match the existing Zeek and Suricata Sliver mTLS-pair rules, and the existing broad Zeek
TLS-no-SNI hunt also matches. DNS/HTTP-profile rules correctly miss raw mTLS; the versioned VLC host
correctly misses the unversioned-implant process rule; no child-shell rule fires because no operator
tasking was sent. No Sliver rule was duplicated.

The honest limitation is that a usable C2 session did not establish. With the wrong server state,
TLS completed and Sliver rejected the post-TLS protocol. With the matching isolated state, the
server accepted TCP and the connection remained established for the observation window, but it sent
no TLS bytes before the host was stopped. NSM can expose flow, TLS, and fingerprints; it cannot name
`updater.exe`, prove self-injection, or see encrypted tasking. See `evidence/network-signals.json`.

## Safety, failures, and cleanup

Every accepted post-run scope report reads `PASS` with zero attack-attributed violations. Full
captures retained background off-lab attempts in their manifests; default routes had been removed,
and none was attributed to a declared planted image. Two earlier reports are intentionally retained
as `INCONCLUSIVE`: the initial C0 timing attempt and a persistence attempt with no attributable EID
3. Neither is represented as evidence of safety; each received a fresh rolled-back replacement.
The H2, two C2 attempts, C1, both D1 attempts, and all accepted controls/marker/persistence runs
have PASS reports. The first D1 attempt reached its marker but an over-broad recovery query caused
the high-volume EID 7 log to overwrite the scenario events. It was scope-checked, rejected as
evidence, rolled back, and repeated. On the accepted retry, `collect-run.ps1` exported the other
channels but an empty time-filtered Sysmon EVTX; the independent record-ID-bounded Sysmon export was
intact and is the source of all D1 endpoint counts and fields.

The final VM 104 rollback returned `OK`: Sysmon is running, ImageLoad is disabled again, the baseline
omission is present, the default route is restored, and no marker or `VLC-Lab*` directory remains.
Kali HTTP/Sliver listeners are inactive. Three temporary build-swap files totaling 16 GiB were
deleted after the direct Sliver shellcode build proved too memory-hungry; they contained paging data
only and are not recoverable. The temporary C1 installer copies and D1 ZIP/build directory were also
deleted after their hashes and sanitized evidence were retained. The C2 retry instead used the repository's already verified Donut
generator to wrap the existing lab Sliver implant with no entropy, compression, or AMSI/ETW bypass.

Raw PCAP, EVTX, combined host exports, NSM logs, VLC/proxy binaries, shellcode, source payloads,
certificates, keys, and credentials are not committed. The committed evidence is selected telemetry
fields, hashes, aggregate measurements, decisions, and safety verdicts only.
