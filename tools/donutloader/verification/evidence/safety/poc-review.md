# Donut pre-execution review verdict

- Source: `https://github.com/TheWover/donut`
- Commit/tag: `47758d787209dd1744f58c140102ac91b649df16` / `v1.1`
- Source-archive SHA-256: `dcf6b6658402ae28f5008022d861c17f05c0f621a24d68f743cebba1a9c79e86`
- Mechanical screen: `donut-triage/poc-review.json` and `donut-triage/mechanical-triage.md`
- Complete source and static-analysis review: `../../../../../poc-reviews/donut/poc-review.md`

The source, build files, loader paths, bypass paths, HTTP client, injectors, and bundled opaque artifacts were reviewed. Opaque archives, PE support binaries, and decoded loader arrays were inspected statically on VM 110; bundled PE files and test shellcode are excluded from execution. Donut is built only from the reviewed source on Kali. The run forces x64 embedded modules, no HTTP staging, no AMSI/WLDP/ETW bypass, no compression, no encryption, no module overloading, and inputs limited to lab-authored inert assemblies plus the exact previously approved Mimikatz binary.

**Verdict: `safe-to-run-in-lab`** for the bounded restrictions in the complete review. A changed source commit or relaxation of any restriction requires a new review. No `do-not-run` condition was found.
