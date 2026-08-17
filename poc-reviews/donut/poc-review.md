# Donut v1.1 pre-execution review

## Provenance

- Canonical source: `https://github.com/TheWover/donut`
- Reviewed commit: `47758d787209dd1744f58c140102ac91b649df16`
- Tag at commit: `v1.1`
- Commit subject/date: `Only publish sdist`, 2024-10-23
- Commit identity: TheWover; committed through GitHub. The local environment lacked GPG, so the commit signature could not be independently verified and is not represented as verified.
- Deterministic `git archive --format=tar HEAD` SHA-256: `dcf6b6658402ae28f5008022d861c17f05c0f621a24d68f743cebba1a9c79e86`
- Reviewed tree: 141 files, 20,697 lines across executable C/C#/Python/build sources and headers.
- Mechanical screen: `tools/donutloader/verification/evidence/safety/donut-triage/poc-review.json` and `mechanical-triage.md`; 68 findings (`high=67`, `medium=1`) requiring human review.

The source was cloned for inspection only. No upstream release binary or incident sample was downloaded, submitted, or executed.

## What the code does

`donut.c` is a local generator. It parses a supplied PE, .NET assembly, or script; optionally compresses and encrypts it; combines the module with an x86/x64 loader template; and writes position-independent code in one of several output formats. The generated loader resolves Windows APIs by hash, maps the embedded module into memory, and dispatches to the .NET CLR host, a native-PE mapper, or ActiveScript. The .NET path creates or selects an AppDomain, copies the assembly into a `SAFEARRAY`, calls `AppDomain.Load_3`, invokes the entry point, then erases its copy.

The source contains intentionally offensive optional features:

- an HTTP staging mode using WinINet;
- AMSI, WLDP, and ETW patching;
- PE-header overwriting and module overloading;
- test injectors using process access, remote allocation/write, and a remote thread;
- test programs containing pre-generated shellcode.

It does not contain credential discovery, credential-file access, registry or service persistence, scheduled-task creation, self-propagation, destructive file operations, or an autonomous C2. The only `system()` call is `system("pause")` in a `DEBUG`-only development loader main. `setup.py` declares the extension build and metadata; it has no custom command class, dependency downloader, or install-time network action.

## Mechanical findings resolved

Most endpoint findings are documentation links, source comments, XML namespace identifiers, version quads, or examples printed by `--help`. The executable source has no fixed runtime destination. HTTP is enabled only when the operator supplies `-s`; otherwise the module is embedded. The sole example address printed by the CLI is private and is not a default. The reviewed run will omit `-s`, so Donut's network client is unreachable by configuration.

The dynamic-evaluation finding in `DonutTest/Program.cs` is real: that test decodes and runs embedded shellcode. Neither `DonutTest` nor any bundled support executable is built or run. Image files are inert documentation assets. The bundled `encode.exe` and `rundotnet.exe` are excluded from execution.

## Source review and static analysis

The review covered the generator/configuration flow, PE-type validation, loader-template construction, file output, option parsing, .NET and native in-memory loaders, HTTP client, API resolver, compression/decompression, encryption/hash code, bypass implementations, source injectors, support tools, build files, Python extension setup, and all literal endpoint/persistence/credential searches.

Opaque content was inspected statically on VM 110 only:

| Artifact | SHA-256 | Static result |
| --- | --- | --- |
| `lib/aplib64.a` | `45dba76acce3ef2f33b5842a56af63caa7b68305f0f788cde9ce546f7fdddfca` | Ten archive members expose only aPLib compression/decompression/CRC symbols. There are no initializer/constructor sections and no external OS/API relocations; strings identify aPLib 1.1.1. |
| `lib/aplib32.a` | `ee26d6cc70205e01eb7a2fa4f3f450f7f25442e8653def3cde132d0f100b1a44` | Same bounded archive purpose for x86; not selected by the x64 Linux generator build. |
| decoded x64 loader array | `da0ac2320629d45cd2669a4a21003ecde56bd11f73fa8bfb21abec3863407a1f` | 13,430 bytes of raw position-independent x64 code; indirect-call-heavy structure matches the reviewed API-table loader. No embedded hostname or URL string was found. |
| decoded x86 loader array | `0c29cccff1b027d57c467564a333e9ade455144649909a4b797b09b43002ac71` | 11,647 bytes of raw position-independent x86 code; excluded from the x64-only run. |
| `loader/encode/encode.exe` | `09ae0d452b28399928ff4dcca806bf07ce6bc87663aa76f3188323b5b1f6af7c` | Imports match the reviewed file-map/Base64 converter plus ordinary runtime support; excluded from execution. |
| `DonutTest/rundotnet.exe` | `09ee3a11ce0547603a8ae71d4fe4c85d9465ce6937a00a167be0d9f7fefd7994` | Imports `CorBindToRuntime`, OLE automation, and ordinary runtime/file APIs, matching its reviewed source; excluded from execution. |

The run will rebuild the x64 loader template and generator from the reviewed source on Kali after this review is committed. The aPLib archive must be linked by the upstream build, but the run forces compression `1` (none), so no aPLib function is called.

## Mandatory run restrictions

1. Build and run Donut only on Kali VM 100. Execute generated shellcode only on Windows VM 104 after rollback to `win_verify_baseline`. VM 110 is static-analysis only. Nothing executes on VM 102 or VM 108.
2. Generate only x64 embedded modules: `-a 2`; never supply `-s`.
3. Disable Donut's defense bypasses with `-b 1`. Do not patch AMSI, WLDP, or ETW.
4. Disable compression with `-z 1`; use `-e 1` for transparent, reproducible non-encrypted instances. Do not use module overloading or header-decoy options.
5. Inputs are limited to lab-authored inert assemblies and the exact previously approved Mimikatz binary. No incident sample or downloaded payload is permitted.
6. Donut's bundled test injectors, support executables, pre-generated shellcode, Python installer, Dockerfile, and submodule are excluded. Remote injection is performed only by the separately reviewed lab-authored bounded DLL described in the scenario.
7. All payload delivery and marker traffic binds to or targets Kali at `192.168.1.50`; the post-run gate receives operator logs and every planted or injected image name.

## Verdict

**`safe-to-run-in-lab`** for the exact reviewed commit, source-built artifacts, inputs, options, VMs, and bounded scenarios above. This is not a general clearance for Donut or its test programs. A changed commit, enabled `-s`, enabled bypasses, non-lab input, regenerated artifact without hash review, or any unexplained static-analysis difference requires a new review. A `do-not-run` condition was not found.
