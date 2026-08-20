# PoC pre-execution review

- Source: https://win.desktop.evernote.com/builds/Evernote-11.29.2-win-ddl-stage-20260808001127-dee6c971e60e7844aaef9b26f4d5e9e0b0ab5dbf-setup.exe
- Target: `/tmp/dll-c1-provision/Evernote-11.29.2-setup.exe`  (1 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (high: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| high | `Evernote-11.29.2-setup.exe:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 5.93` |

## Reviewer's conclusions (complete before executing anything)

- What the code actually does, in your own words: official Evernote 11.29.2 desktop installer. The
  vendor-supported `/currentuser` mode installs under `%LOCALAPPDATA%\Programs\Evernote`; it is benign
  provisioning for C1 and is never paired with a payload.
- Provenance and integrity: Microsoft winget-pkgs' `Evernote.Evernote` 11.29.2 installer manifest
  published SHA-256 `b69ea1e0af323eb6b4ed55054643dbe5805b1c0536bcd16f1b3421f86aa97524`, which matched the downloaded
  367,308,480-byte official Evernote file. `osslsigncode 2.9` reproduced the embedded SHA-256
  Authenticode digest for both embedded signatures and validated both chains and CRLs to signer
  subject `Evernote Corporation`, issuer `Entrust Extended Validation Code Signing CA - EVCS2`.
- Every network destination it contacts, and where each was re-pointed to in the lab: no destination
  was modified. This ordinary signed software is provisioning, not a scenario component; normal
  vendor update traffic is recorded but is not attack traffic. It is never used to carry or launch a
  payload.
- Anything neutralised or removed, and why: nothing; the installer is used exactly as published.
- Static analysis performed on REMnux for compiled/obfuscated parts: not required by the task's
  explicit benign-software provisioning exception. The mechanical binary flag is resolved by the
  independent published hash plus fully valid publisher signatures, not by treating an opaque PoC as
  safe.
- **Verdict**: `safe-to-run-in-lab` as ordinary vendor provisioning on VM 104 only, after rollback,
  with post-run rollback mandatory.
- Executed on VM: 104 only · snapshot before: `win_verify_baseline` · rolled back after: mandatory
