# Verification scenarios

## Scope

- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — only execution target.**
  Current verification proof comes from the two 2026-08-16 in-memory runs.
  The 2026-08-09 disk observation is retained as historical telemetry but is
  explicitly withdrawn as safety proof because it predates the required
  post-run `check-lab-scope.py` artifact.
- **Current-run destinations.** VM 100 at
  `192.168.1.50` was used only to host the lab ISO, VM 104 was the only
  execution target, VM 106 was used for offline pcap analysis, and VM 107 for
  audit only. The target fetched
  from `192.168.1.50`; no public IOC was resolved or contacted. VM 102 and VM
  108 were not used. No C2 was configured. The exact approved binary hash below
  was converted on Kali; Mimikatz never appeared on VM 104 as an executable.
- **Provenance references.** GitHub URLs in `verification.json` are provenance
  citations, never run destinations. Donut's review is
  `poc-reviews/donut/poc-review.md`; the Run C and Run D evidence records link
  their PASS post-run scope checks and operator logs directly.

## Historical observation: disk execution (not current safety proof)

The 2026-08-09 observation ran mimikatz
`sekurlsa::logonpasswords` to read LSASS memory and harvest cleartext or NTLM
credential material for lateral movement. This maps to ATT&CK
**T1003.001 — OS Credential Dumping: LSASS Memory**. Its sanitized telemetry is
still useful, but the run has no post-run scope-check artifact and is therefore
not used to claim current execution or safety verification.

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

Run C's PASS scope report is linked from
`evidence/in-memory-donut-execution.json`. It read unfiltered EID 3/EID 22
telemetry and includes the renamed host, adjacent DLL/data file, and embedded
Mimikatz image in the declared image set.

## Verified: SAM and LSA Secrets modules in memory

Run D changed only Donut's clear module-argument field and executed
`lsadump::sam` plus `lsadump::secrets` inside a renamed ProgramData host. The
host completed within the bound. On-target reduction found three SAM success
markers, five Secrets success markers, and zero module-error markers. The
transient 3,908-byte stdout was reduced automatically on target and deleted
before evidence packaging; it was never pulled or human-viewed, and no secret
or credential value is committed.

The existing command-line rule again had zero matches when evaluated with its
actual `module::` tokens. The process-access rule did not match this run because
these modules did not open LSASS; that absence differentiates registry-backed
credential stores from `sekurlsa` memory access. The full-pcap scope check read
41 EID 3 and 19 EID 22 events and returned PASS with zero attack-attributed
violations. VM 104 was rolled back before and after the run.

## Future scenarios (not executed)

- `sekurlsa::pth`: pass the hash — T1550.002.
- `sekurlsa::minidump`: parse a lab-authored offline LSASS dump — T1003.001.
- `lsadump::dcsync`: directory replication credential theft — T1003.006.
- `kerberos::golden`: forged Golden Ticket — T1558.001.
- `crypto::*` and certificate/private-key theft: verify certificate-store,
  file, registry, and follow-on authentication telemetry.

For each extension, begin from the same clean snapshot, isolate a narrow UTC
window, attribute every event to the run, and retain telemetry only—never the
recovered secret material.
