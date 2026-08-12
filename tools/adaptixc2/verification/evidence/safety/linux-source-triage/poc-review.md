# PoC pre-execution review

- Source: https://github.com/Adaptix-Framework/AdaptixC2
- Target: `/opt/lab/adaptix-linux-review/source`  (252 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (critical: 2, high: 23, medium: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| critical | `AdaptixServer/extenders/gopher_agent/src_gopher/functions/functions_mac.go:193` | credential-theft | reads credentials or secrets belonging to the machine that runs it | `process.Env = append(os.Environ(),` |
| critical | `AdaptixServer/extenders/gopher_agent/src_gopher/functions/functions_unix.go:197` | credential-theft | reads credentials or secrets belonging to the machine that runs it | `process.Env = append(os.Environ(),` |
| high | `AdaptixServer/extenders/beacon_agent/ax_config.axs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `1.1.1.1, 8.8.8.8, 9.9.9.9, cloudflare-dns.com, dns.google, dns.quad9.net` |
| high | `AdaptixServer/extenders/beacon_agent/pl_utils.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `cloudflare-dns.com, dns.google, dns.quad9.net` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/beacon.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/beacon.vcxproj:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/beacon.vcxproj.filters:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/beacon.vcxproj.user:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `schemas.microsoft.com` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/miniz.cpp:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `altdevblogaday.org, gist.github.com, unlicense.org, www.geocities.com` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/miniz.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.ietf.org` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/ntdll.h:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `www.acc.umu.se, www.nirsoft.net` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/files/stub.x64.bin:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.42` |
| high | `AdaptixServer/extenders/beacon_agent/src_beacon/files/stub.x86.bin:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.38` |
| high | `AdaptixServer/extenders/gopher_agent/ax_config.axs:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `qwe.zip` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/binutil/r_byteslice_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/binutil/r_readerat_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/boffer/boffer_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/coffer/coffer_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/coffer/file_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/coffer/section_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/coffer/symbol_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/defwin/defwin_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `AdaptixServer/extenders/gopher_agent/src_gopher/bof/memory/memory_windows.go:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `github.com` |
| high | `LICENSE:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `fsf.org, www.gnu.org` |
| high | `README.md:0` | external-endpoint | hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC | `adaptix-framework.gitbook.io, github.com` |
| medium | `AdaptixServer/extenders/gopher_agent/src_gopher/config.go:4` | obfuscation | large encoded or escaped blob - review its decoded content before running | `// []byte("\x8b\x90\xbe\xbd\x3e\x69\x97\x65\xe1\x82\x97\x43\x93\xbe\x5a\x7d\x41\xf1\x5f\x59\x9d\xc3\x7a\xf0\xa9\xdc\xef\x35\x72\x37\xeb\x42\xb7\xac\x2e\xbd\x45\xdc\x04\xad\xe8\x75\x23\x08\x23\x50\xa1\` |

## Reviewer's conclusions (complete before executing anything)

- What the code actually does, in your own words:
- Every network destination it contacts, and where each was re-pointed to in the lab:
- Anything neutralised or removed, and why:
- Static analysis performed on REMnux for compiled/obfuscated parts:
- **Verdict**: `safe-to-run-in-lab` / `safe-after-modification` / `rejected`
- Executed on VM: ____  · snapshot before: ____  · rolled back after: ____
