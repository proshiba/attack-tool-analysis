# ShieldBreak static PoC review

## Review scope and safety

This is a review-only assessment of the 14 files tracked at the pinned upstream commit below. The
checkout was downloaded only to read and hash it. Nothing was compiled, no dependency was
installed, no Visual Studio project was opened in a build tool, and no PoC component was executed.
VM 104 was not touched. `Warden.dll` was transferred by the QEMU guest agent to VM 110
(`remnux-malware`) and imported into Ghidra as data for static analysis; it was never loaded or
invoked. After analysis, the imported program, transfer copy, and transfer fragments were removed
from VM 110. The ZIP was parsed in memory on the AI VM without extracting a member to disk.

No upstream source, executable, DLL, ZIP, WER report, icon, resource cache, or other sample is
committed here. The only upstream-derived artifact committed with this review is the JSON output of
the repository's trusted `safety/poc-triage.py` scanner. In particular, this review does not retain
the personal path strings disclosed by the WER/PDB artifacts.

## Provenance

| Field | Observed value |
|---|---|
| Exact clone URL | `https://github.com/MSNightmare/ShieldBreak.git` |
| Resolved upstream commit | `be016d8c18c8355a12753286c1ce9d5a48a0dab4` |
| Upstream default branch | `main` |
| Upstream tag at that commit | `1.0.0` |
| Review date | 2026-08-12 UTC |
| Reviewer | OpenAI Codex (static review) |
| Tracked-file count | 14 |

The hashes cover every path returned by `git ls-tree -r --name-only HEAD`; `.git` metadata is not
repository content.

| File | Size (bytes) | SHA-256 |
|---|---:|---|
| `LICENSE` | 1,075 | `5797d842ae200473ba2c6d474dadc7478d0eddec3f9fd5b836f74ded0d5d92b7` |
| `README.md` | 604 | `359b8733a876f0e01de411e9a6214fbae9dfc67839088cfad1d96205cad6c435` |
| `Report.wer` | 9,252 | `5a508e371dfe58f5f2d307fd9b9a7608908b37f965200cad42ecbe27b2dfe07f` |
| `ShieldBreak.aps` | 443,856 | `db90494aff270057e3b782b82bc88afbe8889ce635ec01a506bafa77959b5767` |
| `ShieldBreak.cpp` | 47,318 | `782ead4756247d05541e8ae1291851fdcb4d3491407ffa3df11879dadfad3889` |
| `ShieldBreak.rc` | 4,252 | `0ca78a35cbd52e2b2459efaade75f1a6ada1011209786417446cd10bfddbed7f` |
| `ShieldBreak.slnx` | 208 | `0d15f457e91ab1c6ee7df3a6a97d7721d3f2223d3c0b687fc48289496aad4fdf` |
| `ShieldBreak.vcxproj` | 7,412 | `daf4aa48edda125f70e4639eb97ab9658e6ccab13d752976815973adc3edc18f` |
| `ShieldBreak.vcxproj.filters` | 1,544 | `20d3fb308ae4eb06bb195be13a90d6ac7103a5ef08bea069ac9993f14e616486` |
| `ShieldBreak.vcxproj.user` | 168 | `c06a75b13f855a94d46616796e024c52b499f8f92cf00ccb571ddbc6ff574676` |
| `Warden.dll` | 107,008 | `691857f3f28049a7e33f5767d4e4eb3d739e1aa76c2a43c8cccadf871cfa7c1a` |
| `eicar_com.zip` | 107,127 | `87cc7ad5f7e8d70250bff5c92c8316f3a508c089eb81e9921c8941eca5a741d6` |
| `resource.h` | 634 | `4092cba451e55d832efb2b156c5ee6cd39432a002625dc6c73ef394a0b804553` |
| `shlbrk.ico` | 171,330 | `96119e15a334fd857eaed4d98669653579cf41102427a5056148318a956acea6` |

### Repository and account history

Facts observed through Git and the public GitHub API on 2026-08-12:

- The `MSNightmare` account was created on 2026-06-08. It had five public owner repositories,
  2,471 followers, and followed one account. The repositories were `RoguePlanet` (1,585 stars/606
  forks), `GreatXML` (621/243), `LegacyHive` (297/88), `BrokenArrow` (79/5), and `ShieldBreak`
  (288/81). It is a recent account, but not a single-repository account.
- GitHub reports that ShieldBreak was created on 2026-08-11 at 19:35:37 UTC and last pushed at
  19:47:21 UTC. At review time it had 288 stars, 81 forks, three subscribers, and three open
  issues. The task's supplied 287-star figure had increased by one.
- The repository exposes one branch (`main`) and one tag (`1.0.0`), both at the reviewed commit.
  Its history consists of three commits over about 11 minutes: an initial LICENSE/README commit,
  one bulk web upload of all 12 remaining paths, and a README edit. The commits are authored as
  `INFINITE NIGHTMARE` using the account's Proton Mail address, associated by GitHub with
  `MSNightmare`, and reported by GitHub as validly verified.
- All code and binary/resource artifacts arrived together in the single upload commit
  `76713ef359581c14d8c66f37874cf3ca43b42b6f`; only the README changed afterward. This is a very
  short, upload-shaped history with no incremental development record.

Stars, forks, GitHub verification, and account age establish provenance; none establishes safety.

## Mechanical triage

After reading the trusted local scanner, it was run against the temporary checkout with:

```text
python3 safety/poc-triage.py /tmp/shieldbreak-review.3VuZhS/ShieldBreak --out poc-reviews/shieldbreak --source-url https://github.com/MSNightmare/ShieldBreak.git
```

It exited 1. Its stdout, verbatim, was:

```text
NEEDS-HUMAN-REVIEW: 10 findings across 14 files (high=10)
  [high    ] README.md:0 external-endpoint - github.com
  [high    ] Report.wer:0 binary-artifact - entropy 3.78
  [high    ] ShieldBreak.aps:0 binary-artifact - entropy 7.98
  [high    ] ShieldBreak.rc:0 binary-artifact - entropy 2.90
  [high    ] ShieldBreak.vcxproj:0 external-endpoint - schemas.microsoft.com
  [high    ] ShieldBreak.vcxproj.filters:0 external-endpoint - schemas.microsoft.com
  [high    ] ShieldBreak.vcxproj.user:0 external-endpoint - schemas.microsoft.com
  [high    ] Warden.dll:0 binary-artifact - entropy 6.19
  [high    ] eicar_com.zip:0 binary-artifact - entropy 7.99
  [high    ] shlbrk.ico:0 binary-artifact - entropy 1.17
```

The scanner's 14-file count matches the pinned Git tree. The GitHub screenshot URL and Microsoft
XML namespace URIs are passive data, not destinations used by the PoC. The binary findings were
investigated manually; scanner output is not clearance.

## Build-system hook review

The full `.vcxproj`, `.vcxproj.user`, `.slnx`, `.rc`, `.filters`, and `resource.h` were read as data.

### Commands and dependency acquisition

**No committed pre-build, pre-link, post-build, custom-build, Exec task, shell/PowerShell command,
download, package manager, NuGet reference, project reference, or dependency-acquisition action is
present.** The solution names the one local project only. The `.vcxproj.user` contains an empty
property group. The `.filters` file changes only Visual Studio display grouping.

An ordinary build would invoke the standard locally installed MSVC/Windows SDK compiler, resource
compiler, manifest tool, and linker through imported Microsoft targets. It would not execute an
author-supplied command. It uses C++20 and Visual Studio platform toolset `v145` for Debug/Release
Win32/x64; Release x64 statically links the MSVC runtime. Source-level linker directives request
the locally installed `ntdll.lib`, `CldApi.lib`, `onecore.lib`, and `taskschd.lib`. There are no
external package URLs or repository-supplied import libraries.

### Every referenced path

- MSBuild property imports: `$(VCTargetsPath)\Microsoft.Cpp.Default.props`,
  `$(VCTargetsPath)\Microsoft.Cpp.props`, and `$(VCTargetsPath)\Microsoft.Cpp.targets`.
- For all four configurations, the optional per-user property sheet
  `$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props`. This is normal Visual Studio behavior but
  means a build also trusts the builder's pre-existing local user property sheet.
- Local project inputs: `ShieldBreak.cpp`, `resource.h`, `ShieldBreak.rc`, and `shlbrk.ico`.
- The project lists `eicar_com.zip`, `Report.wer`, `Warden.dll`, and missing `ShellDll.dll` as
  `None`. `ShellDll.dll` does not exist as a root file; a file of that name exists only inside the
  ZIP and is byte-identical to `Warden.dll`.
- The resource script embeds `eicar_com.zip` as resource 101/type `zip`, `Warden.dll` as resource
  102/type `dll`, `Report.wer` as resource 103/type `wer`, and the icon as resource 105. Thus a
  successful build incorporates the ZIP, DLL, and WER bytes into the produced executable.
- `ShieldBreak.aps` is Visual Studio's compiled resource-editor cache. It independently contains
  exact copies of the ZIP, DLL, and WER, plus an author-local source path. It is not a declared
  build input and adds no build command, but it duplicates the hostile payload material.

The build system would therefore execute no hidden author command or download. It would, however,
compile an executable containing the supplied binary payloads. This review did not build it.

## `eicar_com.zip`: misleading name and actual contents

The ZIP itself has the provenance hash recorded above. Its central directory was parsed and each
member was decompressed only in memory for hashing/comparison; no member was written to disk.

| Member | Compressed bytes | Uncompressed bytes | SHA-256 | Finding |
|---|---:|---:|---|---|
| `ShellDll.dll` | 53,295 | 107,008 | `691857f3f28049a7e33f5767d4e4eb3d739e1aa76c2a43c8cccadf871cfa7c1a` | PE32+ DLL, byte-for-byte identical to committed `Warden.dll` |
| `bfsvc.exe` | 53,236 | 147,456 | `bd31d3888a0cfed3c1f89eec6233016a4a305afce7075834748c0ca53a990afb` | PE32+ x64 Windows Boot File Servicing Utility image; not separately committed or documented |
| `eicar.com` | 70 | 68 | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | Exact standard 68-byte EICAR test string |

So this is **not** merely the standard EICAR ZIP. It is a custom archive containing EICAR and two
executables. Static PE metadata for the concealed `bfsvc.exe` shows no Authenticode certificate
table despite Microsoft version-resource branding, and its nonsensical 2045 PE timestamp makes its
origin unverifiable from metadata alone. It was not imported into Ghidra because the requested
binary-analysis scope named `Warden.dll`, but its concealment and participation in the scan are
verdict-relevant unresolved risk.

The archive's role is clear from source: the cloud placeholder initially reports the ZIP's size,
the first fetch callback supplies the entire ZIP, and the program asks Defender to scan that
placeholder. EICAR guarantees a known-bad result and drives Defender into its remediation path; the
two PE members make the object being remediated materially more than an AV test string. The
callback later changes the placeholder size and supplies standalone `Warden.dll` bytes. On a host
with live AV, creating or extracting this archive or its EICAR member is expected to trigger
quarantine. This review intentionally avoided extraction to disk.

## `Warden.dll` static analysis (VM 110)

The committed file was transferred to VM 110 with its hash verified there, then auto-analyzed in
Ghidra 12.1.2 as `/shieldbreak-be016d8/shieldbreak-be016d8-Warden.dll`. No dynamic analysis
occurred.

### Format, signing, timestamp, and toolchain

- PE32+ x86-64 DLL, little-endian, image base `0x180000000`, Windows GUI subsystem, entry RVA
  `0x1540`; Ghidra recognized `x86:LE:64:default` and 308 functions.
- Unsigned: the PE Security/Authenticode directory is absent, so there is no signer.
- COFF timestamp: 2026-08-09 03:29:03 UTC. This is unauthenticated metadata, not proof of build
  time.
- MSVC linker 14.51, C++ runtime/security-cookie and exception-unwind artifacts, CFG helper
  routines, Link-Time Code Generation feature record, and a CodeView RSDS record. The PDB basename
  is `ShellDll.pdb`; its author-local path discloses the Windows username `admin` and a Visual
  Studio source tree. The report omits the full personal path.
- Seven conventional sections: `.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `.rsrc`, and
  `.reloc`. Per-section Shannon entropy was 6.385, 4.677, 1.900, 4.518, 0.000, 4.739, and 4.862
  bits/byte respectively. Names, permissions, sizes, imports, strings, unwind data, and clean
  decompilation are consistent with a normal MSVC image, not a packed/encoded executable. No RWX
  section, overlay payload, TLS callback, or encoded blob was identified.

### Exports, imports, strings, and network capability

- There is no PE export directory and no named exported function. Ghidra reports only the module
  entry point. Consequently the C++ cannot import/call an application-specific exported routine.
- The only imported DLLs are `KERNEL32.dll` and `ADVAPI32.dll`. The behavior-relevant imports are
  `CreateFileW`, `GetNamedPipeServerSessionId`, `GetCurrentProcess`, `OpenProcessToken`,
  `DuplicateTokenEx`, `SetTokenInformation`, `CreateProcessAsUserW`, `CloseHandle`, and
  `ExitProcess`. Remaining imports are MSVC runtime, console, heap, locale, file-enumeration,
  exception/unwind, and process-startup support.

  Complete import inventory:

  - `ADVAPI32.dll`: `SetTokenInformation`, `DuplicateTokenEx`, `OpenProcessToken`,
    `CreateProcessAsUserW`.
  - `KERNEL32.dll`: `CloseHandle`, `GetNamedPipeServerSessionId`, `ExitProcess`, `WriteConsoleW`,
    `GetCurrentProcess`, `CreateFileW`, `QueryPerformanceCounter`, `GetCurrentProcessId`,
    `GetCurrentThreadId`, `GetSystemTimeAsFileTime`, `InitializeSListHead`,
    `SetUnhandledExceptionFilter`, `GetStartupInfoW`, `GetModuleHandleW`, `RtlUnwindEx`,
    `InterlockedFlushSList`, `GetLastError`, `SetLastError`, `FlsAlloc`, `FlsGetValue`,
    `FlsSetValue`, `FlsFree`, `EnterCriticalSection`, `LeaveCriticalSection`,
    `InitializeCriticalSectionEx`, `DeleteCriticalSection`, `RtlLookupFunctionEntry`,
    `EncodePointer`, `RaiseException`, `RtlPcToFileHeader`, `TerminateProcess`, `FreeLibrary`,
    `GetModuleHandleExW`, `GetProcAddress`, `GetModuleFileNameW`, `IsProcessorFeaturePresent`,
    `RtlCaptureContext`, `RtlVirtualUnwind`, `IsDebuggerPresent`, `UnhandledExceptionFilter`,
    `HeapAlloc`, `HeapFree`, `FindClose`, `FindFirstFileExW`, `FindNextFileW`, `IsValidCodePage`,
    `GetACP`, `GetOEMCP`, `GetCPInfo`, `GetCommandLineA`, `GetCommandLineW`,
    `MultiByteToWideChar`, `WideCharToMultiByte`, `GetEnvironmentStringsW`,
    `FreeEnvironmentStringsW`, `VirtualProtect`, `LoadLibraryExW`, `LCMapStringW`,
    `GetProcessHeap`, `GetStdHandle`, `GetFileType`, `GetStringTypeW`, `HeapSize`, `HeapReAlloc`,
    `SetStdHandle`, `FlushFileBuffers`, `WriteFile`, `GetConsoleOutputCP`, `GetConsoleMode`, and
    `SetFilePointerEx`.
- Notable embedded strings are the local NT named pipe `\??\pipe\SHIELDBREAK`, fixed child path
  `C:\Windows\System32\conhost.exe`, the `ShellDll.pdb` build artifact, DLL/import names, and the
  standard Segment Heap application manifest URI.
- No Winsock, WinHTTP, WinINet, DNS, URLMon, RPC networking, pipe-client redirection to a remote
  host, public host/IP, C2 string, or other network API exists. Ghidra's IOC extraction returned
  only the manifest schema URI plus imported DLL names. The DLL has local IPC, not network
  capability.

### Actual behavior and role in the PoC

The meaningful routine runs from DLL process attach. In order, it:

1. Opens the already-created local `SHIELDBREAK` named pipe as a client.
2. Obtains the pipe server's Windows session ID.
3. Opens the current process token with broad token rights and duplicates it as a primary token.
4. Sets the duplicate token's session ID to the named-pipe server's session.
5. Calls `CreateProcessAsUserW` to start `C:\Windows\System32\conhost.exe` under that token, closes
   handles, and exits the loader process.

This is a session-bridging privileged shell-launch payload. It does not itself exploit Defender,
contact a network, steal credentials, or install persistence; it assumes the surrounding
ShieldBreak technique causes a privileged process to load it and that the named pipe server is
waiting.

The C++ **does need its bytes as the final payload for the published end-to-end success path, but it
does not link against, call, or explicitly `LoadLibrary` the DLL.** It embeds `Warden.dll` as a
resource and the cloud-file callback returns those bytes after the first ZIP hydration. The DLL is
therefore loaded indirectly by the Windows component reached through the race. Its only explicit
coordination with the C++ is the shared named-pipe name. Removing it would leave the race/scanning
primitive but remove the published conhost-spawn and named-pipe success signal.

`IsDebuggerPresent` is imported, but Ghidra shows it only in the standard MSVC unhandled-exception
reporting path alongside `SetUnhandledExceptionFilter`/`UnhandledExceptionFilter`; it does not gate
or alter the payload routine. This is compiler runtime behavior, not a deliberate anti-analysis
check in the DLL's functional path.

## `Report.wer`: disclosure and technique role

The embedded WER file is a 2018 crash report, not evidence of a 2026 ShieldBreak run. It summarizes
an access-violation crash (`0xc0000005`) in `combase.dll` version `10.0.17134.112` by a custom test
executable whose timestamp corresponds to 2018-12-25. The machine was Windows 10 Professional x64,
build 17134.228 (`rs4_release`), English locale, with 8 GiB RAM and a roughly 59 GiB system volume.
It discloses an author-local two-letter directory, a custom executable name, report/session GUIDs,
and extensive loaded-module/OS inventory. It does not contain a `C:\Users\<name>` path or machine
hostname, so no Windows username or machine name is directly present. Those personal identifiers
and GUIDs are intentionally not reproduced here.

The current source writes this old report verbatim under
`C:\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_c0000000_A_B_C-C-D-E-<GUID>`, then invokes
the built-in `\Microsoft\Windows\Windows Error Reporting\QueueReporting` scheduled task. That shows
the WER artifact is a trigger/input chosen to make the privileged reporting workflow consume the
crafted queue entry; it is not generated by the PoC on the target and does not substantiate the
README's supported-version claims.

## What `ShieldBreak.cpp` actually does

The complete 1,410-line source was read. It accepts **no command-line arguments** and requests no
operator path or credentials. It relies on Defender being enabled and functional, the current
process having enough rights for Cloud Files sync-root and Object Manager operations, access to the
administrative loopback share used in its link target, and the built-in WER task being available.

In order, its operational path is:

1. Refuses to proceed if `C:\Windows\System32\phoneinfo.dll` already exists. It raises its process
   and thread priorities and creates local named pipe `SHIELDBREAK`.
2. Creates hidden, GUID-named `C:\ShieldBreak_<GUID>` with an Everyone full-control DACL; registers
   it as Cloud Files provider `Flubber`, connects a fetch callback, and creates placeholder
   `BERLIN`, initially sized like embedded `eicar_com.zip`.
3. Builds Object Manager target/shadow directories and `WD_SCAN` links. The initial scan route
   reaches the work directory; the alternate route reaches a CLFS path. It asks Defender's
   `MpClient.dll` RPC API to resource-scan the globalroot path to `BERLIN`, enumerate the known-bad
   threat, and start remediation.
4. Opens the placeholder and copies the system `ntdll.dll` into alternate data stream
   `BERLIN:stream`. Its callback supplies the full custom ZIP on the first fetch.
5. Watches the directory for CLFS-created file names, switches the Object Manager link, locks a
   CLFS file, and creates a nested link targeting the loopback administrative share path to
   `C:\Windows\System32\phoneinfo.dll`.
6. Restarts placeholder hydration with the standalone `Warden.dll` size; the callback supplies the
   DLL bytes on the later fetch. It hydrates the placeholder, repeatedly opens
   `phoneinfo.dll:stream`, creates an executable image mapping, and maps it. It then tells Defender
   cleanup to stop and signals its scan thread.
7. Writes the embedded old `Report.wer` into a GUID-named WER ReportQueue directory, connects to the
   Task Scheduler COM service, fetches the built-in Windows Error Reporting `QueueReporting` task,
   and runs it. It then waits for `Warden.dll` to connect to the named pipe. The DLL uses the pipe's
   session to spawn `conhost.exe`; the C++ treats pipe connection as exploit success.
8. On the success path it releases task objects, disconnects/unregisters the sync root, and attempts
   to delete the WER file/directory, scan path, and work directory and close Object Manager/pipe
   objects. Numerous earlier error/exception paths have no common cleanup, so hidden directories,
   permissive ACLs, Cloud Files registration, WER queue content, mapped files, or system-file
   effects can remain after failure.

Relevant APIs include `FindResource`/`LoadResource`, `NtCreateFile`, Object Manager native APIs,
Cloud Files (`CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfCreatePlaceholders`, `CfExecute`,
`CfHydratePlaceholder`), `ReadDirectoryChangesW`, `CopyFile`, file mapping, Defender `MpClient.dll`
exports resolved with `GetProcAddress`, Task Scheduler COM, named pipes, and ordinary file APIs.
There is no downloader or operator-controlled payload path.

## README versus code

The code is directionally consistent with the README's high-level claim that it targets Defender
remediation after the RoguePlanet patch, but the README omits essentially all security-relevant
behavior and provides no usage, prerequisites, side effects, or payload disclosure.

| README statement or omission | What the reviewed repository shows |
|---|---|
| Calls this a Defender patch-bypass PoC with 100% success on Windows 11 25H2/Canary and Server 2025. | Static inspection confirms a Defender scan/remediation race and a privileged payload goal, but cannot validate success rate, patch status, or OS coverage. There are no tests, logs, version checks, or build/run instructions. |
| Says Windows 10/server editions are vulnerable but unsupported by the PoC. | Code contains no OS-build gate. Its only explicit initial compatibility check is whether `phoneinfo.dll` already exists. This review does not infer or document how to adapt it to another OS. |
| Describes no payload. | The executable embeds and delivers unsigned `Warden.dll`, whose purpose is to duplicate a privileged token into the operator session and launch `conhost.exe`. This is central to the PoC's success indication. |
| Calls the archive `eicar_com.zip` by implication of its filename. | It is a custom three-member archive: exact EICAR plus `Warden.dll` under another name and an undocumented `bfsvc.exe`. This is the most material README/repository discrepancy. |
| Describes no system changes. | Code creates an Everyone-writable hidden sync root, alternate data stream, Cloud Files registration/placeholders, Object Manager links, CLFS interactions, a `phoneinfo.dll` path/stream, a WER queue report, runs a built-in scheduled task, maps an executable image, and may leave state on failure. |
| Describes no operator needs. | No arguments or credentials are accepted, but the environment must supply functional Defender, required Windows components/APIs, sufficient local rights, and access to the loopback administrative share. |

The README therefore does **not** adequately describe what the shipped PoC does. The hidden extra
PE inside the allegedly EICAR archive and the undisclosed session-bridging DLL are decisive.

## Analyst-attacking checklist

| Requested pattern | Present / absent | Evidence and conclusion |
|---|---|---|
| Network activity in source and `Warden.dll` | **Local/loopback only; no external network or C2 found.** | Source contains no socket/HTTP/DNS/download API. It names `127.0.0.1` in a UNC administrative-share target and uses local Defender RPC, Task Scheduler COM, and a local named pipe. `Warden.dll` imports no networking library/API and contains no host/IP/C2 string. Documentation/XML contain passive GitHub/Microsoft URLs. |
| Embedded blobs, shellcode, or encoded payloads | **Present.** | Resource 101 embeds the custom ZIP with EICAR and two PE files; resource 102 embeds the unsigned DLL again; resource 103 embeds WER input. `.aps` duplicates all three. No shellcode or base64/XOR decoder was found. The DLL is not packed. |
| Obfuscation, anti-analysis, anti-debug | **Absent as intentional PoC behavior.** | Source and DLL strings/APIs are readable; DLL structure is conventional and decompiles. DLL's `IsDebuggerPresent` reference is confined to MSVC exception reporting rather than its payload path. No VM/sandbox checks, timing evasion, API hashing, string encryption, or packing was found. |
| File/registry writes beyond the described technique | **Present and almost entirely omitted by README.** | Hidden Everyone-writable work directory, Cloud Files registration/state, `BERLIN` placeholder and ADS, CLFS-related files, target `phoneinfo.dll` path/stream, WER queue directory/report, and cleanup attempts. Registry is queried for Defender install location; no unrelated explicit registry value write appears in source. |
| Credentials, tokens, SSH keys, browser data, cloud metadata | **Token manipulation present; credential/token theft absent.** | Source takes no credentials. `Warden.dll` opens/duplicates the current privileged process token, changes its session ID, and uses it to create `conhost.exe`. No GH token/environment-secret, SSH, browser, LSASS/SAM, cloud credential, or metadata access/exfiltration was found. |
| Persistence | **No deliberate autorun persistence found; residual state risk is present.** | No service, task creation, Run key, startup item, or account creation. It runs an existing Microsoft task. Cloud Files registration, WER queue material, permissive work directory, or system file effects can remain if the program exits on an error path. |
| Build-time hooks | **Absent.** | No pre/post/custom build command, Exec task, install hook, or download. Standard MSBuild imports and optional local user property sheets are the only indirect build inputs. The build embeds hostile artifacts but does not execute them at build time. |

## Lab capability

This claim cannot be meaningfully verified in the current lab. The only Windows target is VM 104,
Windows 10 LTSC build 19044, while the author says this PoC does not support Windows 10. More
fundamentally, the `win_verify_baseline` snapshot has Defender disabled. A Defender remediation
bypass run against a machine with Defender disabled cannot exercise or prove the claimed
vulnerability. VM 104 was not touched during this review.

A real verification would require a disposable, isolated Windows 11 25H2/Canary or Windows Server
2025 target at an explicitly recorded patch level with Defender enabled, current signatures and
the required Windows services/components; a pre-run snapshot and mandatory rollback; synthetic
data/accounts; hard egress denial; endpoint and network telemetry; and an independently verified
clean baseline showing the same EICAR-bearing test object is detected/remediated without the race.
Because the ZIP includes undocumented PE material and an unsigned concealed executable, those
components would also require full static clearance before any run. No attempt should be made to
port or modify the PoC for the available Windows 10 VM.

## Verdict

**`do-not-run`**.

Two facts decide the verdict:

1. The file named `eicar_com.zip` is materially misleading: besides exact EICAR it conceals an
   unsigned duplicate of `Warden.dll` and an undocumented, separately unhashed-by-upstream PE
   (`bfsvc.exe`). The source feeds that archive into Defender and later replaces the hydration data
   with the standalone DLL. One concealed executable remains unresolved.
2. `Warden.dll` is not a harmless support library. It is the undisclosed privilege-to-interactive-
   session payload: when loaded by the exploited privileged path, it duplicates the current token
   into the named-pipe server's session and launches `conhost.exe`. The README does not disclose it
   or the extensive system changes.

The source and analyzed DLL show no credential theft, external C2, downloader, or deliberate
persistence, and the build files contain no execution hook. Those absences reduce evidence of an
analyst-targeting implant, but they do not overcome the concealed executable content, incomplete
binary accounting, destructive system-level race, poor cleanup, misleading documentation, and the
lab's inability to validate the claim. Do not build or execute this upstream commit in this lab.
