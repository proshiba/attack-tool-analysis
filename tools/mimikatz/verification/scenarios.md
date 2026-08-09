# Verification scenarios

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
