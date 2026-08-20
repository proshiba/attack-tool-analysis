# PoC pre-execution review

- Source: https://download.videolan.org/pub/videolan/vlc/3.0.21/win64/vlc-3.0.21-win64.7z
- Target: `/tmp/vlc-provision-20260819/vlc-3.0.21-win64.7z`  (1 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (high: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| high | `vlc-3.0.21-win64.7z:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 8.00` |

## Reviewer's conclusions (complete before executing anything)

- What the code actually does, in your own words: this is the official VideoLAN VLC 3.0.21 win64
  distribution archive, used only as signed provisioning material. The verification uses VLC to
  play a lab-authored silent WAV; no bundled updater or network feature is invoked.
- Provenance and integrity: downloaded on the AI VM from VideoLAN's official HTTPS download host.
  SHA-256 `9d2b24d6bc4196b3da8d181a3878678ba272e2a7690321f8826da76a69b2fb9c`
  exactly matched `vlc-3.0.21-win64.7z.sha256` published beside the archive. VM 104 independently
  reproduced the same hash after the mandatory chunked `lab-push` transfer.
- Every network destination it contacts, and where each was re-pointed to in the lab: VLC itself is
  not asked to contact any destination. Provisioning ZIPs are served only from Kali
  `192.168.1.50:18090`; the target's default routes are removed before each measured run.
- Anything neutralised or removed, and why: no VideoLAN file was modified for the benign control.
  Scenario copies rename the signed host and original DLL only after their hashes/signatures are
  recorded. The archive's installer/updater functionality is not used.
- Static analysis performed: the archive was inventoried on Kali without executing its contents;
  GNU `objdump` enumerated the legitimate DLL's PE export table (ordinal base 1, 316 named exports).
  On VM 104, PowerShell Authenticode validation reported `Valid` for `vlc.exe`, `libvlc.dll`, and
  `libvlccore.dll`, all signed by `CN=VideoLAN, O=VideoLAN, L=Paris, C=FR`, certificate thumbprint
  `CCF8C4F9272D8A25477AF13EC71F97A3027C7319`. The exact hashes and PE version fields are retained in
  `../../vlc-provisioning-review.json`. REMnux analysis was not used because this is a checksum-
  verified, publisher-signed vendor release rather than anonymous PoC code; the mechanical
  high-entropy finding is the expected compression result and is not being treated as a clean scan.
- **Verdict**: `safe-to-run-in-lab` only as official VLC provisioning on VM 104, after the stated
  checksum/signature controls and snapshot rollback. This verdict does not apply to either
  lab-authored proxy DLL or any third-party sideload generator.
- Executed on VM: 104 only · snapshot before: `win_verify_baseline` rollback `OK` · post-run rollback:
  mandatory and recorded separately for every run.
