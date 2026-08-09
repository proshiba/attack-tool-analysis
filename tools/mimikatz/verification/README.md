# mimikatz verification

Official mimikatz `2.2.0-20220919` was verified on VM 104
(`WIN10-ANALYSIS`, Windows 10 Enterprise LTSC build 19044) from the
filesystem-frozen `sysmon_baseline_defoff` baseline. Defender Tamper Protection
and real-time protection were off; Sysmon 15.21 was running with targeted LSASS
ProcessAccess and mimikatz ImageLoad coverage.

The first post-run cold rollback showed Windows re-enabling real-time protection.
The canonical baseline was therefore corrected with a local-policy-backed
real-time monitoring disablement, cold-boot tested, and recreated under the same
snapshot name after confirming that no mimikatz artifacts remained. A final
rollback preserved Defender-off and Sysmon-on state.

The bounded run executed from `C:\lab` as `NT AUTHORITY\SYSTEM`:

```text
mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```

The process ran from `2026-08-09T05:27:51.0700727Z` through
`2026-08-09T05:27:52.0925087Z` and exited with code 0. Sysmon recorded one EID 1
process creation, 62 EID 7 image loads, and one EID 10 in which mimikatz opened
`lsass.exe` with `GrantedAccess=0x1010`. No Defender events occurred in the
collection window.

The committed evidence contains only the single EID 10 ProcessAccess event used
by the Sigma rule. It includes the source/target process metadata, access mask,
and CallTrace. Mimikatz credential-dump output was redirected to a secret-only
file, never inspected or pulled from the VM, and deleted immediately after the
run. No harvested credentials or hashes are present in this directory.

The experimental Sigma rule detects LSASS access with memory-read-capable access
masks without relying on the source process name, path, or file hash. Expected
false positives include endpoint security products and authorized diagnostic or
crash-dump tooling.
