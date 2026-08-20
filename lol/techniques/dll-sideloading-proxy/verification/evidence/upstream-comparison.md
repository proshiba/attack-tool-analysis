# Upstream comparison and adoption decision

The comparison used SigmaHQ commit `8eaafff1f2845a696050e05e72ba1140ee190698` on VM 107. The
candidate set was built before local rule authoring and contained every upstream Windows file whose
name matched the sideload families in scope: 53 `image_load_side_load_*` rules, four
`proc_creation_win_*sideload*`/`*side_load*` rules, and two `file_event_win_*sideload*` rules (59
family rules). The family was replayed together against the complete marker-run Sysmon EVTX and the
benign default-install control EVTX. Two conceptual neighbours outside that filename family were
also compared, for 61 relevant rules total: `image_load_susp_unsigned_dll.yml` (`b5de0c9a`) and the
threat-hunting `image_load_win_signed_dll_no_metadata.yml` (`2a297820`). Other unsigned image-load
rules were scoped to a specific host or subsystem such as LSASS, Node.js, ClickOnce, or THOR and do
not cover an arbitrary signed third-party host in a user-writable directory.

## Like-for-like result

| Form | Host image | Upstream rules hit | Name-independent local hunt |
|---|---|---|---|
| C0 legitimate default VLC | `C:\Program Files\VideoLAN\VLC\vlc.exe` | none | none |
| M1 plain sideload, broken app | `%LOCALAPPDATA%\VLC-Lab-Plain\vlc.exe` | `Potential Libvlc.DLL Sideloading` | hit |
| M2 proxy, app works | `%LOCALAPPDATA%\VLC-Lab-Proxy\vlc.exe` | `Potential Libvlc.DLL Sideloading` | hit |
| M3 proxy, renamed host, app works | `%LOCALAPPDATA%\VLC-Lab-Proxy\updater.exe` | `Potential Libvlc.DLL Sideloading` | hit |

`evtx-sigma-checker` returned exactly three upstream findings in the attack EVTX, all from
`image_load_side_load_libvlc.yml` (`bf9808c4-d24f-44a2-8398-b65227d406b6`), one for each of M1, M2,
and M3. It returned zero upstream-family findings in C0. The other 52 image-load rules required a
different DLL, host, or path literal. The four process-creation rules required DeviceEnroller,
VMware xfer, MpCmdRun, or OfflineScannerShell shapes, and the two file-event rules required their
space-path or `iphlpapi.dll` shapes; none matched any form. Conversely, the local rule does not
replace those specific-name detections: it matched this unsigned/user-writable shape and three
different real-sample DLL names, but it missed the fourth recall sample.

This proves H1 and H3: the existing libvlc rule covers the exact article DLL name in a user-writable
directory and survives `vlc.exe` being renamed. A process rule keyed to `vlc.exe` would miss M3, but
no such upstream process rule fired on M1 or M2 either. There is no reason to clone or lightly edit
the upstream libvlc rule, so it is adopted by reference. The local rule exists only for H6's proven
cross-application gap.

The unsigned-DLL neighbour `b5de0c9a` requires one of five named LOLBIN hosts, so it misses VLC,
the renamed host, and the three name-independent recall hits. The signed-DLL/no-metadata hunt
`2a297820` covers a form the local hunt intentionally misses, but requires the loaded DLL's metadata
fields to be empty; the signed renamed VLC original has VideoLAN description and company metadata.
Conversely, upstream `6b98b92b` covers phantom System32-DLL hijacks and `4fc0deee` covers enumerated
system-DLL names outside system directories, including Program Files plants. Those upstream forms
are not replaced by the local user-writable/unsigned hunt.

## Application continuity and signal dependence

M1 loaded the unsigned marker `libvlc.dll` and wrote the bounded marker, then failed to exit within
20 seconds and was killed. M2 and M3 loaded the unsigned proxy plus signed `libvlc_org.dll`, wrote
the same marker, played the Kali-hosted WAV, and exited normally with code 0. The upstream rule and
the local behavioral hunt hit all three forms. Neither detection depends on the application
breaking; the extra signed renamed-original load is proxy-only evidence, not a prerequisite.

## Filter falsification

The adopted rule's only exclusion is based on attacker-influenced `ImageLoaded` text. H2 tested it
by execution rather than YAML inspection of any prior pull request. Short path, device path,
loopback UNC, junction, and symlink forms were detected anyway. A malicious DLL physically planted
under the exact default prefix was suppressed, including when launched with case variation; both
successful plants required Administrator. Sysmon resolved junction and symlink loads to the
user-writable target, so those did not evade. The non-C test was not executable because the baseline
had no writable secondary filesystem. Full classifications and emitted paths are in
`evidence/h2-results.json`.

The local behavioral hunt has no exclusions, so it has no filter off switch to test.

Relaxing only the local hunt's loading-process path does not make H2D or H2E visible: in both rows
the malicious `libvlc.dll` itself was planted in Program Files, so it still fails the retained
loaded-DLL user-writable-path selection. The relaxed form does recover the distinct and dominant
real-world shape in which a Program Files application loads an untrusted DLL from a user-writable
directory. The retained H2 EID 7 field summary produced three matches under both forms. The raw H2
`sysmon.zip` retained from the previous run is zero bytes, so this part of revalidation is explicitly
based on the retained selected-field summary rather than raw EVTX; raw marker and C0 EVTX were
available and replayed directly.

## Precision measurements

- Adopted upstream libvlc rule `bf9808c4`: **0 / 727,396** baseline image-load events, **0.0%**.
  The raw upstream file received a harness `needs-work` result only because upstream does not carry
  this repository's mandatory precision metadata and the generic attack corpus did not supply a
  libvlc positive. The three lab hits provide the missing positive evidence; this repository does
  not modify the upstream YAML.
- Upstream enumerated system-DLL rule `4fc0deee`: **0 / 727,396**, **0.0%**, with an attack-corpus
  hit.
- Upstream signed-DLL/no-version-metadata hunt `2a297820`: **200 / 727,396**, **0.027495%**
  (274.953 per million), with no matching attack-corpus sample in the harness. It remains a measured
  upstream mitigation for the validly signed form that this run does not execute.
- Upstream WWLIB rule `e2e01011`: **0 / 727,396**, **0.0%**, with an attack-corpus hit.
- Upstream named-Windows-utility unsigned-DLL rule `b5de0c9a`: **0 / 727,396**, **0.0%**, with an
  attack-corpus hit.
- The merged local name-independent hunt measured **505 / 727,396**, **0.069426%** (694.257 per
  million). Removing only its process-path selection measured **516 / 727,396**, **0.070938%**
  (709.380 per million): eleven more events, or a 2.18% relative increase. Removing both path
  selections measured **29,906 / 727,396**, **4.111378%**, about 59.2 times the merged form. The
  loaded-DLL path is carrying the precision, so the process-path selection was removed. Explicit
  four-sample recall is unchanged at three samples and four events. The measured floor remains
  `medium`; analyst judgement keeps `fp_likelihood: high`, `recommended_role: hunt`, and
  `level: low` because legitimate portable software and per-user updaters have the same shape.

The denominator is the `image_load` value read from
`audit/catalog/baseline-category-metrics.json`, not the target's run volume. Per-run EID 7 volumes
are informational sensor-load measurements only. These measurements are the contribution for the
five adopted-by-reference upstream rules; none of their YAML was edited or cloned.

C1 then supplied the missing observed benign positive. VS Code produced zero merged-form and zero
relaxed-form matches. Evernote produced seven under both forms: two each for `ffmpeg.dll` and
`vk_swiftshader.dll`, and one each for `vulkan-1.dll`, `libEGL.dll`, and `libGLESv2.dll`. Every DLL
reported `Signed=false`, `Signature=-`, and `SignatureStatus=Unavailable`. This is the exact hunt
shape, so it supports the high FP judgement. No exclusion was added: all observed names and paths
are attacker-controlled in a sideload.

## File-delivery comparison and decision

The two upstream sideload-named `file_event` rules were compared again before considering a
delivery rule. `1908fcc1` detects a single `iphlpapi.dll` drop in Teams or OneDrive folders;
`b6f91281` detects a DLL beneath an additional-space Program Files path. Neither binds one writer,
an executable and DLL, the same directory, or a time window. Conversely, the proposed generic
co-write correlation would miss both upstream forms unless their separate executable write also
appeared in the same ten-second window, and it would not preserve their useful filename/path
specificity. They are complementary, so neither was cloned or edited.

The independent baseline probe then measured the proposed correlation—one `ProcessGuid` writing at
least one EXE and one DLL into the same user-writable directory within ten seconds—at **278 clusters
/ 542,441 file events** (**0.051250%**, 512.498 clusters per million). The broad prerequisite matched
4,152 events and the qualifying clusters contained 2,237 events. Top writers and locations were
ordinary 7-Zip extraction stubs, VS Code, Eclipse/JRE extraction, OneDrive, browser installers,
Defender, and Malwarebytes. C1 reproduces this same benign installer shape. Although the rate could
support a low hunt numerically, the correlation contains no technique-specific discriminator and
the true-positive and benign-installer populations converge. No file-event rule is shipped.

The accepted D1 ZIP run also reproduced it: one PowerShell `Expand-Archive` process wrote
`updater.exe`, `libvlc.dll`, `libvlc_org.dll`, `libvlccore.dll`, `axvlc.dll`, `npvlc.dll`, and
`vlc-cache-gen.exe` to the same user-writable directory inside ten seconds. The same run produced
one merged-form and one relaxed-form ImageLoad match on `updater.exe` loading unsigned
`libvlc.dll`. Its downloaded ZIP carried a `Zone.Identifier` with `ZoneId=3`, and EID 15 recorded
two writes to that stream, but `Expand-Archive` propagated no stream to the extracted host, proxy,
renamed original, or `libvlccore.dll`. The legitimate C1 outputs also carried no stream (their
installers were provisioned out of band and therefore are not a like-for-like browser-download
control). MOTW is useful at the container boundary here, but does not separate the eventual
sideload files or make the generic file-event correlation shippable.
