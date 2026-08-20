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

## Precision measurements

- Adopted upstream libvlc rule: **0 / 727,396** baseline image-load events, **0.0%**. The raw upstream
  file received a harness `needs-work` result only because upstream does not carry this repository's
  mandatory precision metadata and the generic attack corpus did not supply a libvlc positive. The
  three lab hits provide the missing positive evidence; this repository does not modify the upstream
  YAML.
- Local name-independent hunt: **505 / 727,396**, **0.069426%** (694.257 per million image-load
  events), with positive-corpus and three-of-four explicit recall-sample hits. The measured floor is
  `medium`; analyst judgement raises `fp_likelihood` to `high`, keeps `recommended_role: hunt`, and
  keeps `level: low` because legitimate portable software and per-user updaters can have the same
  shape.

The denominator is the `image_load` value read from
`audit/catalog/baseline-category-metrics.json`, not the target's run volume. Per-run EID 7 volumes
are informational sensor-load measurements only.
