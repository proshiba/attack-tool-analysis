# AdaptixC2 v1.2 pre-execution review

- Source repository: `https://github.com/Adaptix-Framework/AdaptixC2`
- Source tag: `v1.2` (lightweight tag)
- Source commit: `a4b80bf370f704d6843e69433bfb5c06274f57df`
- Commit date: `2026-03-04T20:36:06Z`
- Source archive: `https://github.com/Adaptix-Framework/AdaptixC2/archive/refs/tags/v1.2.tar.gz`
- Source archive SHA-256: `a96eb3fa9bb02c92449e6e9d365734dd7b322560cb7301f99d072854b314197d`
- Files mechanically screened: 1,062

## Mechanical triage

`safety/poc-triage.py` screened the complete official source archive before any build, dependency install, server startup, or generated-agent execution. The report at `source-triage/poc-review.json` returned `NEEDS-HUMAN-REVIEW`: 233 findings (3 critical, 229 high, 1 medium). This is expected for a repository containing offensive C2 source, embedded shellcode stubs, image assets, vendored libraries, executable-task handlers, external documentation links, and installers.

The three mechanical critical findings were read in context. `DialogCredential.cpp` contains credential-manager storage category labels; it does not read the build host’s credentials. `functions_mac.go` and `functions_unix.go` append `os.Environ()` when an operator explicitly tasks a Gopher shell process; they do not transmit environment variables at build or startup. Gopher is excluded from the run in any event.

## Source review

The reviewed execution path is the Go teamserver plus the BeaconHTTP listener and Beacon agent extenders. The source review covered:

- `Makefile`, `Dockerfile`, and `pre_install_linux_all.sh`: build targets, package/download behavior, cleanup targets, and the Go toolchain path. The installer downloads Go and a separate Windows-7 fork and is not run. Docker targets are not run. Only existing Kali distribution tools and direct `make server-ext` build targets are permitted.
- `AdaptixServer/main.go`, `core/server/server.go`, `core/connector/connector.go`, `core/profile/`, and `profile.yaml`: profile parsing, JWT authentication, teamserver bind address, TLS server, operator API, default error middleware, and exact default headers/body source.
- `extenders/beacon_listener_http/`: listener configuration validation, bind and callback fields, request routing, response headers, default error and payload pages, TLS certificate generation, and request decryption/dispatch.
- `extenders/beacon_agent/`: agent profile generation, literal callback embedding, sleep/jitter, proxy and DNS/DoH options, MinGW build command construction, task packing, HTTP connector, and the bounded `getuid`, `pwd`, `ls`, `ps list`, and download task handlers.
- Generated-agent build stubs and bundled object inputs: source and Makefiles explain the PE output path. Any generated PE is still treated as unknown-malicious until separately hashed, mechanically triaged, and statically reviewed on REMnux before VM 104 runs it.

The repository deliberately supports capabilities excluded here: credential collection/storage, arbitrary process execution, BOFs, shell and PowerShell, file removal, service payloads, DNS/DoH, SMB/TCP pivots, SOCKS/forwarding, screenshots, and Gopher tasking. None is required by server startup. Operator commands are API-driven and limited to the scenario allowlist.

## Network destinations and modifications

Source defaults that name public DNS/DoH resolvers are not used. The installation script, Docker build, update-like documentation links, Gopher, DNS/DoH listeners, proxy settings, and external callback examples are excluded from runtime.

The lab profile will:

- bind the teamserver and HTTP/S Beacon listeners only to Kali `192.168.1.50` or loopback;
- embed only literal Kali callback addresses in generated agents;
- disable proxy use and omit all DNS/DoH configuration paths;
- use a fixed isolated Kali state directory and non-default lab password;
- apply a Kali OUTPUT guard allowing only loopback and `192.168.1.0/24` before any AdaptixC2 server or agent runtime;
- host every payload and marker on Kali; and
- stop services and remove the temporary OUTPUT guard after collection.

## Verdict

**`safe-after-modification`** for the exact bounded flows in `scenarios.md`, subject to all listed network controls, a committed design-time scope report with no critical finding, a separate review of every generated PE before target execution, and pre/post rollback of VM 104. Execution is permitted only on Kali VM 100 and Windows VM 104. No AdaptixC2 build, dependency, server, client, extender, or agent may run on VM 102 or VM 108.
