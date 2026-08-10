# Verification scenarios

## Scope

- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — target and local
  executable host.** The recorded run executed `C:\lab\mimikatz.exe` here as
  `NT AUTHORITY\SYSTEM`. No attacker or NSM VM is named in this verification.
- **Destinations.** The evidence records no Sysmon network-connection or DNS
  events in the run window, so this local-only run contacted no network
  destination. Its only scenario host was `192.168.1.52`, inside
  `192.168.1.0/24`; nothing outside the lab was contacted.
- **Hosting and references.** The executable was staged and run locally on VM
  104; no stager or C2 was used. The GitHub release and release-asset URLs in
  `verification.json` record upstream provenance and are not destinations the
  scenario run contacted. The record does not state which host acquired or
  transferred the executable before it appeared at `C:\lab\mimikatz.exe`.

## Verified: post-compromise LSASS credential theft

An operator with local administrator/SYSTEM rights runs mimikatz
`sekurlsa::logonpasswords` to read LSASS memory and harvest cleartext or NTLM
credential material for lateral movement. This maps to ATT&CK
**T1003.001 — OS Credential Dumping: LSASS Memory**. The verification focuses
on process, parent-child, file, registry, network/DNS, and LSASS ProcessAccess
telemetry; it does not retain credential output.

## Future scenarios (not executed)

- `sekurlsa::pth`: pass the hash — T1550.002.
- `lsadump::sam`: local SAM credential material — T1003.002.
- `lsadump::secrets`: LSA Secrets — T1003.004.
- `lsadump::dcsync`: directory replication credential theft — T1003.006.
- `kerberos::golden`: forged Golden Ticket — T1558.001.
- `crypto::*` and certificate/private-key theft: verify certificate-store,
  file, registry, and follow-on authentication telemetry.

For each extension, begin from the same clean snapshot, isolate a narrow UTC
window, attribute every event to the run, and retain telemetry only—never the
recovered secret material.
