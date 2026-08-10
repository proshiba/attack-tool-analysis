# Sliver v1.7.3 generated DNS implant review

- Source: `https://github.com/BishopFox/sliver/releases/tag/v1.7.3`
- Release tag: `v1.7.3`
- Source commit: `3bbaf805104dcc4a75414ee0084e8de50702cad4`
- Generated Linux amd64 ELF SHA-256:
  `2d8c61ff160c7f7e371c85a51958d5dc55ce5ee179df8d3588d64354df20a523`
- Size: 32,407,700 bytes
- Configured C2: `dns://c2.sliver.lab.` through the VM 103 resolver, which
  was set exclusively to Kali `192.168.1.50`

`safety/poc-triage.py` ran on REMnux VM 105 before target execution and
returned `NEEDS-HUMAN-REVIEW` with one encoded-binary finding and four apparent
IPv4 strings. `file`, `readelf`, SHA-256 verification, and printable-string
inspection identified the expected stripped, static x86-64 ELF. The four
scanner strings are overlapping byte interpretations of an embedded X.509 OID
sequence, not configured socket destinations. Source review of Sliver's DNS
transport and inspection of the generated configuration found only the
operator-supplied parent `c2.sliver.lab.`.

Verdict: **`safe-to-run-in-lab`** only with the canonical VM 103 snapshot,
exclusive lab resolver, target and Kali egress guards, full packet capture,
and immediate rollback. The implant was executed only on VM 103; no Sliver
code ran on VM 102 or VM 108.
