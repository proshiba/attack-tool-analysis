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
- **In-memory extension.** The 2026-08-16 closure run used VM 100 at
  `192.168.1.50` only to host the lab ISO, VM 104 as the only execution target,
  VM 106 for offline pcap analysis, and VM 107 for audit only. The target fetched
  from `192.168.1.50`; no public IOC was resolved or contacted. VM 102 and VM
  108 were not used. The exact approved binary hash below was converted on Kali;
  Mimikatz never appeared on VM 104 as an executable.

## Verified: post-compromise LSASS credential theft

An operator with local administrator/SYSTEM rights runs mimikatz
`sekurlsa::logonpasswords` to read LSASS memory and harvest cleartext or NTLM
credential material for lateral movement. This maps to ATT&CK
**T1003.001 — OS Credential Dumping: LSASS Memory**. The verification focuses
on process, parent-child, file, registry, network/DNS, and LSASS ProcessAccess
telemetry; it does not retain credential output.

## Verified: Donut in-memory execution closes the command-line blind spot

The already-approved x64 binary with SHA-256
`61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1`
was converted to an opaque Donut data blob and executed inside a lab-authored
host under ProgramData. The host exited 0 and Sysmon recorded one EID 10 access
to LSASS with `GrantedAccess=0x1010`.

The existing `proc_creation_mimikatz_cmdline.yml` produced no match: no
Mimikatz process existed and none of its module tokens appeared in any EID 1
command line. The existing `process_access_lsass_read.yml` did match the EID 10
event and is the surviving name-independent control. Only `mscoree.dll` loaded
into the host; `clr.dll`, `amsi.dll`, EID 8, EID 25, attributed named pipes, and
attributed network activity were absent. Credential output was never captured,
viewed, pulled, or committed.

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
