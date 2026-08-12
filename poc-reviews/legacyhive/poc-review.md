# LegacyHive static PoC review

## Review scope and safety

This is a source-only review of the three files tracked at the upstream commit below. The
LegacyHive source was downloaded only for reading and hashing. It was not compiled or executed,
none of its dependencies were installed, and no lab VM was contacted. In particular, nothing was
run on AI VM 102, orchestrator VM 108, static-analysis VM 109 (`malware-analyst`), or VM 110
(`remnux-malware`). No PoC source or compiled artifact is included in this repository.

## Provenance

| Field | Observed value |
|---|---|
| Exact clone URL | `https://github.com/MSNightmare/LegacyHive.git` |
| Resolved upstream commit | `8aea0d33ad024dc131e56ad5dd6553b3849176a0` |
| Upstream default branch | `main` |
| Review date | 2026-08-12 UTC |
| Reviewer | OpenAI Codex (static source review) |
| Tracked-file count | 3 |
| Committed binaries | None |

The hashes below cover every file returned by `git ls-tree -r --name-only HEAD`; `.git` metadata is
not upstream repository content and is excluded.

| File | Size (bytes) | SHA-256 |
|---|---:|---|
| `LICENSE` | 1,074 | `95fcc6991d2502fa948b6a88064172d5f78bf6c69b51d5343c4987107dc7791d` |
| `LegacyHive.cpp` | 14,409 | `549ea0aa58fcfe2a27f247aed4c27e316c1d5959079ba47fb57b10192f52fc17` |
| `README.md` | 868 | `8dd97c25536d0c0a37f5a1c6000270765fa473f0f8643d78d45da62c1d3bdbea` |

### Repository and account history

Facts observed through Git and the public GitHub API on 2026-08-12:

- The `MSNightmare` account was created on 2026-06-08 at 20:13:51 UTC, approximately 64 days
  before this review. It had 5 public owner repositories, 2,421 followers, followed 1 account,
  and used the profile URL `https://github.com/MSNightmare`.
- Its five public repositories were `RoguePlanet` (created 2026-06-09; 1,582 stars/606 forks),
  `GreatXML` (2026-06-11; 618/243), `LegacyHive` (2026-07-14; 292/87), `BrokenArrow`
  (2026-07-25; 75/3), and `ShieldBreak` (2026-08-11; 170/50). Thus this is a recently created
  account, but not a single-repository account.
- GitHub reports that LegacyHive was created on 2026-07-14 at 05:27:18 UTC. At review time it had
  292 stars, 87 forks, and 14 subscribers. That is 292 stars over the repository's approximately
  29-day lifetime (about 10 per day when averaged across its entire age). The task's supplied
  289-star/85-fork figures had increased by review time.
- The repository has one published branch (`main`), no tags, and a four-commit linear history. All
  four commits were made on 2026-07-14 in a roughly 12-hour span, authored as
  `Nightmare-Eclipse <msnightmare@proton.me>` through GitHub's `web-flow` committer, associated by
  the API with `MSNightmare`, and reported by GitHub as validly verified.
- The commit sequence is: initial `LICENSE`/README
  (`eb01f6c21ab9343c8da98577fc7a1a0368c1e4b9`), a README edit
  (`cc86f2a4ca2f7f5eade63939a1b51b38219179d9`), the sole upload of `LegacyHive.cpp`
  (`f08115be9deb0fb257ea3b262a39f71386408192`), and the final README expansion at the reviewed
  commit. The C++ file has not changed since its upload. This is a short, upload-shaped history,
  but it is not a single-commit repository.

These facts establish provenance and history shape; stars, forks, verification status, and account
age are not evidence that the code is safe.

## Mechanical triage

The trusted repository copy of `safety/poc-triage.py` was read first and then run against the
temporary checkout with:

```text
python3 safety/poc-triage.py /tmp/legacyhive-static-review.OQ5B4gbE/LegacyHive --out poc-reviews/legacyhive --source-url https://github.com/MSNightmare/LegacyHive.git
```

It exited 1. Its output, verbatim, was:

```text
NEEDS-HUMAN-REVIEW: 1 findings across 3 files (high=1)
  [high    ] README.md:0 external-endpoint - github.com
```

The emitted machine-readable record is `poc-review.json`. The finding is the README's GitHub-hosted
screenshot URL. It is passive documentation, not a destination used by the C++ code. The scanner
reported no finding in `LegacyHive.cpp`; that result is not treated as clearance.

## What the code actually does

The following accounts for the complete 474-line `LegacyHive.cpp` at the reviewed commit. Line
references refer to that upstream file, not to source committed here.

### Load-time declarations and link inputs (lines 1-45)

- The translation unit includes Windows, UserEnv, ACL, native API, console, and Offline Registry
  headers. `offreg.h` is referenced but not present upstream.
- Five MSVC linker directives name `ntdll.lib`, `userenv.lib`, `advapi32.lib`, `offreg.lib`, and
  `Rpcrt4.lib`. The repository supplies none of them and contains no project file.
- During program initialization it calls `GetModuleHandle(L"ntdll.dll")`, then `GetProcAddress`
  for the plainly named exports `NtCreateSymbolicLinkObject` and `NtCreateDirectoryObjectEx`.
  The indirection is used for native Object Manager APIs; it is not accompanied by name encoding
  or behavior hiding.
- `HVarg` holds pointers to the operator-supplied username and password plus process/thread handles.

### `GenGUID` (lines 47-55)

`UuidCreate` creates a UUID and `UuidToStringW` renders it. The result is copied into the caller's
buffer and later used for both a `C:\\<GUID>` work directory and an Object Manager directory name.
The allocated RPC string is not freed, which is a small process-lifetime leak rather than hidden
behavior.

### `CreateDirectoryWithPermissiveDACL` (lines 57-104)

In order, this function:

1. Calls `AllocateAndInitializeSid` for the Everyone SID.
2. Calls `SetEntriesInAcl` to grant Everyone `GENERIC_ALL` on the directory and inherited children.
3. Allocates and initializes a security descriptor with `LocalAlloc`,
   `InitializeSecurityDescriptor`, and `SetSecurityDescriptorDacl`.
4. Calls `CreateDirectory` with that security descriptor, then frees the SID, ACL, and descriptor.

`wmain` passes the generated `C:\\<GUID>` path. The intentionally permissive directory is part of
the race setup, but it temporarily exposes the copied hive data to other local users and permits
them to add content to that directory.

### `ThrowFunc` and `RaiseExceptionInThread` (lines 106-123)

`ThrowFunc` throws the integer `1`. `RaiseExceptionInThread` calls `SuspendThread`,
`GetThreadContext`, replaces the x64 `RIP` with the address of `ThrowFunc`, calls
`SetThreadContext`, and resumes the thread. The helper thread uses this unusual control-flow
mechanism to force the caller toward error handling. It assumes x64 and is fragile: the catch in
`wmain` is declared as `DWORD`, while the thrown object is an `int`, and a null `HVarg` path would
dereference the null pointer before trying to redirect the caller. This is unsafe error handling,
not anti-debugging; there is no debugger check.

### `HiveLoaderThread` (lines 125-144)

This helper calls `CreateProcessWithLogonW` with the supplied username/password,
`LOGON_WITH_PROFILE`, the fixed command `C:\\Windows\\notepad.exe`, and `CREATE_SUSPENDED`. The
profile-loading flag is what asks ProfSvc to load the credentialed user's profile while the main
thread holds the race. Notepad never resumes. On success the helper closes the new process's thread
handle and gives its process handle to `wmain`; cleanup later terminates that process. On failure it
prints the Win32 error and invokes the thread-redirection error path above.

There is a material API-initialization defect: `STARTUPINFO si` is zeroed, but `si.cb` is never set.
Microsoft [documents `cb` as the structure size](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa),
and its official
[`CreateProcessWithLogonW` example](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)
sets `si.cb = sizeof(STARTUPINFO)` before the call. The published code therefore does not follow the
documented calling pattern at the function that triggers ProfSvc. Static review cannot determine
whether every claimed Windows version rejects or tolerates the zero value, but rejection would make
the helper fail before the advertised race. No runtime test was performed to resolve that question.

### `wmain`: inputs and constructed paths (lines 146-224)

The program accepts exactly three operator arguments:

```text
LegacyHive.exe <username> <password> <target_user_hive>
```

Despite the argument name, the third value is a username/path component, not a hive filename. It
is inserted into the fixed path
`C:\\Users\\<third-argument>\\AppData\\Local\\Microsoft\\Windows`. The first two arguments are
plaintext credentials for an account that can log on interactively. The code does not check that
this account is a standard rather than administrative user, and the password remains in the
process command line/argument memory.

The function calls `GetVersionEx`, makes a UUID, and constructs:

- the disk work directory `C:\\<GUID>`;
- work files `C:\\<GUID>\\ntuser.dat` and `C:\\<GUID>\\UsrClass.dat`;
- `\\BaseNamedObjects\\Restricted\\<GUID>` and
  `\\BaseNamedObjects\\Restricted\\Microsoft` Object Manager directory names;
- one Object Manager link target for `C:\\<GUID>` and one for the fixed target user's Windows
  profile subdirectory; and
- the replacement `Local AppData` value
  `\\\\.\\globalroot\\BaseNamedObjects\\Restricted`.

### `wmain`: Object Manager redirection (lines 225-264)

After opening its own thread with `OpenThread`, the program calls:

1. `NtCreateDirectoryObjectEx` to create
   `\\BaseNamedObjects\\Restricted\\<GUID>`.
2. `NtCreateDirectoryObjectEx` to create
   `\\BaseNamedObjects\\Restricted\\Microsoft`, using the first directory as its shadow directory.
3. `NtCreateSymbolicLinkObject` to create a `Windows` link under the `Microsoft` directory that
   initially resolves to `C:\\<GUID>`.
4. `NtCreateSymbolicLinkObject` to create a `Windows` link under the shadow directory that resolves
   to the fixed target user's `...\\Microsoft\\Windows` directory.
5. `CreateDirectoryWithPermissiveDACL` for the on-disk work directory.

The two `Windows` links provide the race switch: while the explicit link handle exists, path
resolution reaches the work directory; after that handle is closed, the shadow directory's link
can resolve the same suffix to the target user's directory.

### `wmain`: credentialed user's profile-hive replacement (lines 265-334)

The code next:

1. Calls `LogonUser` with `LOGON32_LOGON_INTERACTIVE`, then `ImpersonateLoggedOnUser`.
2. Calls `ExpandEnvironmentStringsForUser` twice to obtain the credentialed account's fixed
   `NTUSER.DAT` and `UsrClass.dat` paths.
3. Opens that account's `NTUSER.DAT` with `CreateFile`, reads its entire original content into a
   heap buffer using `GetFileSizeEx` and `ReadFile`, and retains the buffer for restoration.
4. Rewinds the file and uses the Offline Registry APIs `OROpenHiveByHandle`, `OROpenKey`, and
   `ORSetValue` to replace
   `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Local AppData`
   with the Object Manager `GLOBALROOT` path above.
5. Calls `ORSaveHive` to write the modified hive to `C:\\<GUID>\\ntuser.dat`, closes the Offline
   Registry handles, and calls `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` to replace the
   credentialed account's actual `NTUSER.DAT`. Only after replacement does it set its restoration
   flag.
6. Calls `CopyFile` to place a copy of the credentialed account's `UsrClass.dat` at
   `C:\\<GUID>\\UsrClass.dat`.

This is an offline mutation and replacement of the credentialed account's profile hive, not an
unrelated live-registry write. It is nevertheless a material and potentially corrupting disk
change.

### `wmain`: oplock race and success check (lines 336-381)

The program opens the copied `UsrClass.dat` with `CreateFile`, creates an event with `CreateEvent`,
and requests `FSCTL_REQUEST_BATCH_OPLOCK` with asynchronous `DeviceIoControl`. It requires
`ERROR_IO_PENDING`; otherwise it aborts.

It then creates `HiveLoaderThread`. `GetOverlappedResult(..., TRUE)` waits until ProfSvc's profile
load touches the copied hive and breaks the oplock. At that point the program closes the explicit
Object Manager `Windows` link and the locked file. Subsequent resolution through the shadow link
points at the third argument's fixed `UsrClass.dat` location. The main thread waits for the helper,
then calls `RegOpenUserClassesRoot` with the credentialed user's token and `MAXIMUM_ALLOWED`. A
successful open is the PoC's only proof that a classes hive was loaded; the handle is immediately
closed. The program does not inspect or change a key through that handle, create an elevated token,
launch an elevated process, or execute a payload. In particular, opening a classes-root handle
without reading target-specific content does not by itself prove that the third user's hive, rather
than an ordinary classes-root view, is what backs the handle.

### Cleanup (lines 382-474)

Success and most failures enter the same cleanup path, which first waits for a keypress. It then:

- closes the classes-root handle if present;
- terminates and closes the helper thread if still live;
- terminates the suspended Notepad process and closes it;
- closes the oplock event, Object Manager symbolic links/directories, file, and Offline Registry
  handles;
- if the replacement flag was set, reopens the credentialed user's current `NTUSER.DAT` and calls
  `WriteFile` once with the original in-memory bytes;
- calls `RevertToSelf`;
- deletes the work `UsrClass.dat` and `ntuser.dat` if present, closes the logon token, and removes
  the work directory.

The restoration is best effort and its result is not checked. It does not call `SetEndOfFile`, so
it would not remove trailing bytes if the replacement hive were longer than the original. A crash,
forced termination, failure to reopen/write, short write, or failure to delete/remove the
world-writable work directory can leave modified profile state or copied data behind. Snapshot
rollback must therefore be the recovery mechanism; the program's cleanup must not be trusted.

## README versus code

Overall, the code matches the README's deliberately limited core claim: it requires supplied
credentials, fixes the substituted hive type to `UsrClass.dat`, and uses a third username to make
that user's classes hive appear under the credentialed user's classes-root mapping. No hidden
second payload or unrelated analyst-targeting behavior contradicts the README. The following
qualifications and discrepancies matter:

| README statement or omission | What the reviewed code shows |
|---|---|
| Title describes an “arbitrary hive load elevation of privileges vulnerability.” | The published code is not arbitrary-hive tooling: its paths are fixed to `UsrClass.dat`. It demonstrates the load primitive but does not itself obtain an elevated token, run privileged code, or execute a payload; its success check only opens and closes the credentialed user's classes root. |
| It “requires another standard user credentials.” | It requires a plaintext username/password accepted by both `LogonUser` and `CreateProcessWithLogonW`, but performs no group or privilege check. “Standard user” is an operator constraint, not one enforced by code. |
| A third username can be an administrator and the target hive ends up in “current user classes root.” | The third argument is used only in the fixed target profile path. `RegOpenUserClassesRoot` is called with the separate credentialed user's token while the process is impersonating that user. “Current user” therefore means the supplied credential account's classes-root view at that point, not necessarily the original process caller's profile. |
| The README presents the PoC as fully functional on supported July 2026-patched desktop/server installations. | Static inspection cannot validate OS-version coverage or patch status. More importantly, the helper leaves `STARTUPINFO.cb` at zero despite Microsoft's documented/example initialization, and the success check does not inspect target-specific content. These are concrete reasons the broad functionality claim remains unsubstantiated. No build or runtime test was performed. |
| Build prerequisites are not documented. | `offreg.h` and `offreg.lib` are required but absent, and the repository contains no Visual Studio project or other build definition. The source is x64-specific because it edits `CONTEXT.Rip`. |
| Side effects are not described. | The program replaces the credentialed account's `NTUSER.DAT`, creates an Everyone-full-control work directory, copies `UsrClass.dat`, creates and terminates suspended Notepad, and only then attempts best-effort cleanup/restoration. |

The review deliberately does not reconstruct the author's removed functionality, generalize the
hive target, or analyze how the credential requirement could be removed.

## Explicit analyst-attack findings

| Pattern requested for review | Present / absent | Evidence and conclusion |
|---|---|---|
| Network activity: sockets, HTTP, DNS, URL strings, hosts, or IPs | **Absent from executable code.** One passive URL is present in documentation. | `LegacyHive.cpp` has no network headers, socket/WinINet/WinHTTP/DNS APIs, URL/host/IP literals, or network library. `Rpcrt4` is used only for local UUID generation. `README.md` embeds one `https://github.com/user-attachments/...` screenshot URL; this produced the triage finding but the program never reads it. |
| Embedded blobs, shellcode, base64/XOR/encoded payloads, resources, or runtime decoding | **Absent.** | All tracked content is text. There are no arrays or strings containing executable blobs, no resources, decoding loops, crypto/unpacking stage, shellcode allocation, or indirect payload execution. No binaries are committed. |
| Obfuscation, anti-analysis, or anti-debug behavior | **Absent.** | API and object/path strings are readable. The two native APIs are resolved by their plaintext names. There are no debugger, VM, sandbox, timing-evasion, environment-fingerprint, packing, or behavior-switch checks. Thread-context redirection is fragile error control, not conditional anti-analysis. |
| File or registry writes beyond the described technique | **No unrelated writes; technique-related writes are present and material.** | The code creates `C:\\<GUID>`, saves/replaces/restores the supplied account's `NTUSER.DAT`, copies/deletes `UsrClass.dat`, and removes the directory. The only value change is `Local AppData` in an offline copy of that hive. These writes are integral to the published race, but failed cleanup can leave them behind. It does not directly write the target user's `UsrClass.dat`. |
| Credentials, tokens, SSH keys, browser data, or cloud metadata | **Operator-supplied credential handling is present; discovery/theft is absent.** | The username and plaintext password from `argv` are passed to `LogonUser` and `CreateProcessWithLogonW`, and the returned logon token is used for impersonation/profile APIs. There is no search for or access to SSH keys, GitHub/cloud tokens, environment secrets, browser stores, LSASS/SAM, or metadata endpoints, and no exfiltration path. The command-line password is locally observable and must be a disposable lab credential. |
| Persistence | **Absent.** | No Run keys, services, scheduled tasks, startup folders, WMI subscriptions, permanent accounts, autoruns, or durable Object Manager object are created. The temporary profile mutation can persist accidentally after failure, but it is not an intentional persistence mechanism. |
| Build-time hooks or dependency acquisition | **Static linker directives are present; executable hooks/downloads are absent.** | Lines 10-14 contain `#pragma comment(lib, ...)` directives for five libraries. There is no `.vcxproj`, `CMakeLists.txt`, script, package manifest, pre/post-build command, custom build step, downloader, or committed library/binary. `offreg.h`/`offreg.lib` are missing, so any separately acquired copy is outside this review and must be independently sourced, hashed, and reviewed before a future build. |

## Destructive potential and containment

Running the published code changes the Windows VM in ways that can damage the credentialed lab
profile even when the exploit does not succeed:

- The account's real `NTUSER.DAT` is replaced with an altered hive. The in-process backup and
  restoration are vulnerable to crashes, write failures, short writes, and lack of truncation.
- A temporary Everyone-full-control directory at `C:\\<GUID>` contains copies/derivatives of user
  hive data. Other local principals can read or alter it during the run, and they can prevent clean
  directory removal by adding files.
- ProfSvc/registry state is manipulated, temporary Object Manager objects are held, and a suspended
  Notepad process is created and terminated. The source makes no direct file-API call against the
  third user's `UsrClass.dat`; it causes ProfSvc to open/load that path through the redirection.
- The program blocks for a keypress even on many error paths, so an unattended run can leave the
  modified state live indefinitely.

A rollback to a known pre-run VM snapshot reverses the VM-local disk, registry, process, and Object
Manager state described above. Snapshot rollback does not retract a password recorded in shell,
automation, or console logs, so only newly created, disposable, VM-local credentials may be used.

There is no code path for network communication, self-propagation, or changes to another host. With
VM egress denied and only synthetic VM-local accounts/data, the reviewed program has no identified
way to affect anything outside the VM. Egress should still be mechanically blocked and observed;
absence in source is not a reason to relax lab scope controls, and unrelated Windows profile/OS
telemetry must not be allowed to become attack traffic.

## Verdict

**`safe-to-run-in-lab`**, narrowly and only for the exact reviewed commit's published,
`UsrClass.dat`-limited behavior.

The deciding facts are that every executable source line is explainable and contains no network,
second-stage, analyst-credential discovery, persistence, obfuscation, or build-command behavior;
and that the material destructive state is confined to the Windows host and recoverable by a
mandatory snapshot rollback. This is not a claim that execution is safe on a normal system or that
the author's cleanup is reliable.

A future lab run would require all of the following:

- use only the isolated Windows target VM authorized by the lab (VM 104), never VM 102, 108, 109,
  or 110;
- take a named clean snapshot immediately before the run and roll it back afterward regardless of
  apparent success or cleanup;
- use disposable, local-only source and target accounts with synthetic profiles and a password
  never used elsewhere, keeping the plaintext password out of orchestration logs;
- deny egress and retain network/process/file/registry evidence sufficient to confirm scope;
- build, if later authorized, only in a disposable isolated lab environment from the exact hashes
  above; obtain the missing Offline Registry build inputs from a trusted source and review/hash
  them separately, with no build on the AI/orchestrator/static-analysis hosts; and
- run the reviewed public behavior unchanged: no restoration of removed functionality, no
  generalization beyond `UsrClass.dat`, and no attempt to remove the credential requirement.

The July 2026 support/patch claim and exploit reliability remain unverified because this review
compiled and executed nothing.
