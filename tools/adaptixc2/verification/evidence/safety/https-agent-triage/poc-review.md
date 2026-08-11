# Generated AdaptixC2 HTTPS Beacon pre-execution review

- Generator source: AdaptixC2 `v1.2`, commit `a4b80bf370f704d6843e69433bfb5c06274f57df`
- Generator source URL: `https://github.com/Adaptix-Framework/AdaptixC2/tree/a4b80bf370f704d6843e69433bfb5c06274f57df/AdaptixServer/extenders/beacon_agent`
- Generated on: Kali VM 100 only
- Original generator filename: `agent.x64.exe`
- Lab filename: `https-beacon-lab.exe` (not a detection invariant)
- Size: 105,472 bytes
- SHA-256: `4e39b0f0c83675943e87543214937a5c4061e1ecb929d93205a1b927be6899a5`
- Configuration: Windows x64 executable, HTTPS callback only to Kali `192.168.1.50:18443`, 10-second sleep, 20% jitter, sequential rotation, no proxy, no DNS/DoH fields, no kill date, no working-time restriction, no service format, no sideloading, no IAT-hiding option.

## Mechanical and static analysis

`safety/poc-triage.py` returned `NEEDS-HUMAN-REVIEW` with one high finding: the exact file is a compiled PE with entropy 5.53. No separate external-endpoint, credential, persistence, destructive, install-hook, or second-stage finding was produced.

REMnux VM 105 independently reproduced the SHA-256. `file` identified a stripped nine-section PE32+ Windows GUI x86-64 executable; `diec` identified no known packer. `objdump -p` listed only `KERNEL32.dll` and `msvcrt.dll`, consistent with the reviewed runtime API-resolution design. Printable-string review found no URL, public resolver, proxy, or alternate callback.

Ghidra 12.1.2 headless imported the PE as `x86:LE:64:default:windows`, identified its TLS callback, completed enabled analysis in five seconds, and reported both analysis and import success. The expected MinGW pseudo-relocation warning and absent local Windows libraries/PDB did not prevent analysis. The reviewed generation path serialized exactly one HTTPS listener profile and linked the HTTP connector and Beacon objects. The PE was not executed on VM 102, VM 108, Kali, or REMnux.

## Controls and verdict

The only embedded callback is `192.168.1.50:18443`. Kali’s IPv4/IPv6 OUTPUT guard remains active. VM 104 will execute this exact hash only after the prior HTTP process has stopped, with a new full-packet capture. Operator tasking is limited to `getuid` and `ls C:\\lab`; no download, shell, PowerShell, BOF, injection, tunnel, credential, persistence, removal, or arbitrary upload task is allowed.

**Verdict: `safe-after-modification`** for one bounded HTTPS execution on VM 104 with the exact SHA-256, lab callback, full capture, endpoint attribution, and required post-run rollback. Regeneration or configuration change invalidates this verdict.
