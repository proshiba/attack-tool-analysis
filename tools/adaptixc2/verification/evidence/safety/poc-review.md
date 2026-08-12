# AdaptixC2 v1.2 pre-execution review

- Source repository: `https://github.com/Adaptix-Framework/AdaptixC2`
- Source tag: `v1.2` (lightweight tag)
- Source commit: `a4b80bf370f704d6843e69433bfb5c06274f57df`
- Commit date: `2026-03-04T20:36:06Z`
- Source archive: `https://github.com/Adaptix-Framework/AdaptixC2/archive/refs/tags/v1.2.tar.gz`
- Source archive SHA-256: `a96eb3fa9bb02c92449e6e9d365734dd7b322560cb7301f99d072854b314197d`
- Files mechanically screened: 1,062
- Linux/server subset transfer SHA-256: `cde3455dcef71526a0d1a920a89feca067b6e14a008df17fb6d836a844da2d07` (`AdaptixServer`, top-level `Makefile`, `LICENSE`, and `README.md`; 252 files)

## Mechanical triage

`safety/poc-triage.py` screened the complete official source archive before any build, dependency install, server startup, or generated-agent execution. The report at `source-triage/poc-review.json` returned `NEEDS-HUMAN-REVIEW`: 233 findings (3 critical, 229 high, 1 medium). This is expected for a repository containing offensive C2 source, embedded shellcode stubs, image assets, vendored libraries, executable-task handlers, external documentation links, and installers.

The three mechanical critical findings were read in context. `DialogCredential.cpp` contains credential-manager storage category labels; it does not read the build host’s credentials. `functions_mac.go` and `functions_unix.go` append `os.Environ()` when an operator explicitly tasks a Gopher shell process; they do not transmit environment variables at build or startup. Gopher was excluded from the original Windows run; the Linux expansion permits it only with shell tasking excluded.

For the Linux expansion, the 252-file server/extension subset was transferred out of band to Kali VM 100 and screened again before build. `evidence/safety/linux-source-triage/poc-review.json` returned `NEEDS-HUMAN-REVIEW`: 26 findings (2 critical, 23 high, 1 medium). The two critical findings are the same explicit Gopher shell-task environment inheritance described above. Shell tasking is excluded. The high findings include the Beacon DNS/DoH UI defaults (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `dns.google`, `cloudflare-dns.com`, and `dns.quad9.net`); none may be embedded in or contacted by a run.

## Source review

The reviewed execution path is the Go teamserver plus the BeaconHTTP listener and Beacon agent extenders. The source review covered:

- `Makefile`, `Dockerfile`, and `pre_install_linux_all.sh`: build targets, package/download behavior, cleanup targets, and the Go toolchain path. The installer downloads Go and a separate Windows-7 fork and is not run. Docker targets are not run. Only existing Kali distribution tools and direct `make server-ext` build targets are permitted.
- `AdaptixServer/main.go`, `core/server/server.go`, `core/connector/connector.go`, `core/profile/`, and `profile.yaml`: profile parsing, JWT authentication, teamserver bind address, TLS server, operator API, default error middleware, and exact default headers/body source.
- `extenders/beacon_listener_http/`: listener configuration validation, bind and callback fields, request routing, response headers, default error and payload pages, TLS certificate generation, and request decryption/dispatch.
- `extenders/beacon_agent/`: agent profile generation, literal callback embedding, sleep/jitter, proxy and DNS/DoH options, MinGW build command construction, task packing, HTTP connector, and the bounded `getuid`, `pwd`, `ls`, `ps list`, and download task handlers.
- Generated-agent build stubs and bundled object inputs: source and Makefiles explain the PE output path. Any generated PE is still treated as unknown-malicious until separately hashed, mechanically triaged, and statically reviewed on REMnux before VM 104 runs it.
- `extenders/gopher_agent/pl_main.go`, `src_gopher/main.go`, `tasks.go`, and `functions/functions_unix.go`: the only official v1.2 Linux payload is a Go Gopher ELF. Its profile accepts only the Gopher TCP/mTLS listener, collects basic session identity at startup, maintains a single task connection, and inherits the environment only for an explicitly tasked shell. The run permits only built-in working-directory, directory, process, and fixed-marker download tasks; no shell task is issued.
- `extenders/beacon_agent/pl_main.go`, `src_beacon/Makefile`, and `ConnectorDNS.cpp`: the Beacon builder is Windows-only (MinGW compiler, Windows objects, PE/service/DLL/shellcode output). DNS/DoH support exists only in that Windows Beacon path. A Linux HTTP/S or DNS/DoH Beacon therefore cannot be generated from this reviewed release, despite the broad platform wording in the project README and Censys article.
- `extenders/beacon_listener_dns/pl_main.go` and `pl_transport.go`: the listener binds UDP/TCP DNS on the configured Kali address, is non-forwarding, parses a minimum five-label Adaptix protocol, returns a generic `TXT OK` for shorter/unrecognised requests, and sets authoritative answers. A bounded lab-only listener probe is safe, but it is not represented as Linux-agent transport telemetry.

The repository deliberately supports capabilities excluded here: credential collection/storage, arbitrary process execution, BOFs, shell and PowerShell, file removal, service payloads, DNS/DoH, SMB/TCP pivots, SOCKS/forwarding, screenshots, and Gopher tasking. None is required by server startup. Operator commands are API-driven and limited to the scenario allowlist.

## Network destinations and modifications

Source defaults that name public DNS/DoH resolvers are not used. The installation script, Docker build, update-like documentation links, proxy settings, and external callback examples are excluded from runtime. The Linux expansion permits only the reviewed Gopher TCP/mTLS path and a non-forwarding BeaconDNS listener preflight; no DoH endpoint or public resolver is used.

The lab profile will:

- bind the teamserver and HTTP/S Beacon listeners only to Kali `192.168.1.50` or loopback;
- embed only literal Kali callback addresses in generated agents;
- disable proxy use and omit all DNS/DoH configuration paths;
- use a fixed isolated Kali state directory and non-default lab password;
- apply a Kali OUTPUT guard allowing only loopback and `192.168.1.0/24` before any AdaptixC2 server or agent runtime;
- apply VM 103 IPv4 and IPv6 OUTPUT guards allowing only loopback and Kali `192.168.1.50`, verify the blocks and exclusive Kali resolver before the DNS listener probe, and keep the full capture unfiltered;
- host every payload and marker on Kali; and
- stop services and remove the temporary OUTPUT guard after collection.

## Verdict

**`safe-after-modification`** for the exact bounded flows in `scenarios.md`, subject to all listed network controls, a committed design-time scope report with no critical finding, separate mechanical and static review of the generated Linux ELF before target execution, and pre/post rollback of VM 103. Execution is permitted only on Kali VM 100 and Ubuntu VM 103 for this expansion. REMnux VM 105 may perform static inspection only. No AdaptixC2 build, dependency, server, client, extender, or agent may run on VM 102, VM 108, VM 109, or VM 110. The impossible Linux Beacon transport combinations are not emulated or mislabeled.
