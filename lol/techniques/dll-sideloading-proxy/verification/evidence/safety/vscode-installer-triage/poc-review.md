# PoC pre-execution review

- Source: https://vscode.download.prss.microsoft.com/dbazure/download/stable/110a328ea54b42367b803ec53ee0bf52ef26b419/VSCodeUserSetup-x64-1.134.0.exe
- Target: `/tmp/dll-c1-provision/VSCodeUserSetup-x64-1.134.0.exe`  (1 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (high: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| high | `VSCodeUserSetup-x64-1.134.0.exe:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 6.47` |

## Reviewer's conclusions (complete before executing anything)

- What the code actually does, in your own words: official Microsoft VS Code 1.134.0 x64 user
  installer. It performs the vendor-supported per-user install under
  `%LOCALAPPDATA%\Programs\Microsoft VS Code`; it is benign provisioning for C1 and is never paired
  with a payload.
- Provenance and integrity: the official update API at
  `https://update.code.visualstudio.com/api/update/win32-x64-user/stable/latest` published SHA-256
  `d564bc373ed3d94eedc813d5c0865e4ef40a40323e856bc838ae5a29723f2fb9`, which matched the downloaded
  231,465,552-byte file. `osslsigncode 2.9` reproduced the embedded SHA-256 Authenticode digest and
  validated the signing chain to the official Microsoft Root Certificate Authority 2011; signer
  subject `Microsoft Corporation`, issuer `Microsoft Code Signing PCA 2024`. Timestamp and online CRL
  status are not claimed because the Linux trust store lacked the Microsoft timestamp root and the
  CRL endpoint returned an incompatible content type.
- Every network destination it contacts, and where each was re-pointed to in the lab: no destination
  was modified. This ordinary signed software is provisioning, not a scenario component; normal
  vendor update traffic is recorded but is not attack traffic. It is never used to carry or launch a
  payload.
- Anything neutralised or removed, and why: nothing; the installer is used exactly as published.
- Static analysis performed on REMnux for compiled/obfuscated parts: not required by the task's
  explicit benign-software provisioning exception. The mechanical binary flag is resolved by the
  independent official hash plus valid publisher signature, not by treating an opaque PoC as safe.
- **Verdict**: `safe-to-run-in-lab` as ordinary vendor provisioning on VM 104 only, after rollback,
  with post-run rollback mandatory.
- Executed on VM: 104 only · snapshot before: `win_verify_baseline` · rolled back after: mandatory
