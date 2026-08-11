# Generated AdaptixC2 HTTP Beacon pre-execution review

- Generator source: AdaptixC2 `v1.2`, commit `a4b80bf370f704d6843e69433bfb5c06274f57df`
- Generator source URL: `https://github.com/Adaptix-Framework/AdaptixC2/tree/a4b80bf370f704d6843e69433bfb5c06274f57df/AdaptixServer/extenders/beacon_agent`
- Generated on: Kali VM 100 only
- Original generator filename: `agent.x64.exe`
- Lab filename: `http-beacon-lab.exe` (not a detection invariant)
- Size: 105,472 bytes
- SHA-256: `d8ee6fe9e5eb9e497024ffee7a41620e02d2334501382bb599cd4aed5fc9be38`
- Configuration: Windows x64 executable, HTTP callback only to Kali `192.168.1.50:18081`, 10-second sleep, 20% jitter, sequential rotation, no proxy, no DNS/DoH fields, no kill date, no working-time restriction, no service format, no sideloading, no IAT-hiding option.

## Mechanical triage

`safety/poc-triage.py` returned `NEEDS-HUMAN-REVIEW` with one high finding: the file is a compiled PE (entropy 5.53). The scanner found no separate credential, persistence, external-endpoint, destructive, install-hook, or second-stage finding. Compiled output is never cleared mechanically, so the exact hash was transferred out of band to REMnux VM 105.

## REMnux static analysis

REMnux independently reproduced the SHA-256 and identified a stripped PE32+ Windows GUI executable for x86-64 with nine sections. `diec` identified no known packer. `objdump -p` showed only `KERNEL32.dll` and `msvcrt.dll` imports, consistent with the reviewed source’s runtime API resolution. Printable-string review found no URL, public resolver, proxy, or additional callback endpoint. The literal callback is stored inside the generated packed profile rather than as a printable string.

Ghidra 12.1.2 headless imported the exact PE with the `x86:LE:64:default:windows` language, identified its TLS callback, completed all enabled analyzers in seven seconds, and reported `Analysis succeeded` / `Import succeeded`. It reported no PDB and the expected missing local Windows libraries. The MinGW pseudo-relocation analyzer warning did not prevent analysis.

The source-to-output path was reviewed in `../poc-review.md`: the teamserver serialized exactly one listener profile, compiled it into `config.o`, and linked only the prebuilt HTTP connector and Beacon objects. The generated file was never executed on the AI VM, orchestrator, Kali, or REMnux.

## Network controls and task boundary

The only embedded callback is the literal lab listener `192.168.1.50:18081`. Kali’s runtime OUTPUT guard rejects all IPv4 except loopback and `192.168.1.0/24` and rejects all non-loopback IPv6. VM 104 will capture the full flow and post-run `check-lab-scope.py` must return `PASS` with Sysmon EID 3 process attribution.

Permitted operator commands are limited to `getuid`, `pwd`, `ls C:\\lab`, `ps list`, and `download C:\\lab\\adaptix-fixed-marker.txt`. No shell, PowerShell, BOF, injection, tunnel, credential, persistence, removal, arbitrary upload, or unrelated-file task is permitted.

## Verdict

**`safe-after-modification`** for one execution on Windows VM 104 after the documented baseline rollback, using only the exact SHA-256 above, the literal lab callback, full-packet capture, the bounded task allowlist, and immediate post-collection rollback. Any regenerated or reconfigured PE requires a new hash, mechanical triage, and static review.
