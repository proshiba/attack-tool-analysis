# Certutil decode scenarios

## Scope

- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — sole execution target
  and local fixture host.** Every current verified command runs on this VM from
  a separate `win_verify_baseline` rollback. The four current runs use SYSTEM
  except for the explicitly named standard-user scenario.
- **Destinations.** All four current runs are local file-to-file transforms. Inputs and
  outputs are under `C:\lab` or the temporary standard user's local
  `C:\Users\certlab` directory on VM 104. They name no network destination and
  must produce no certutil-attributed Sysmon EID 3 or EID 22 activity. No
  command may contact the management network `10.9.0.0/24`, a public address,
  or any address outside the analysis network `192.168.1.0/24`.
- **Hosting.** The inert base64 and hexadecimal fixtures are staged locally on
  VM 104 through the out-of-band guest agent. There is no payload, stager, C2,
  download source, attacker VM, or third-party code.
- **Execution boundary.** The decoded bytes are inert marker text. The output
  named `.dll` is only a filename used to exercise file telemetry; it is never
  loaded or executed. The retained endpoint summary asserts zero Sysmon EID 3
  and EID 22 events, but no packet capture was taken, so it is not a mechanical
  post-run lab-scope proof.
- **External references.** The LOLBAS Certutil page is a citation used to ground
  command syntax, not a host contacted during a run.

`certutil.exe` is a Microsoft-signed certificate utility that can decode
base64 or hexadecimal content into an arbitrary output file. Attackers can use
that legitimate capability to turn an encoded staging artifact into its usable
form, mapping to **Deobfuscate/Decode Files or Information (T1140)**.

## Superseded historical context: original base64 decode

1. Windows VM 104 started from `win_verify_baseline`.
2. A PEM-style base64 fixture containing an inert marker was staged at
   `C:\lab\benign-marker.b64`.
3. The SYSTEM account invoked:

   ```text
   C:\Windows\System32\certutil.exe -decode C:\lab\benign-marker.b64 C:\lab\decoded-marker.txt
   ```

4. Certutil reported successful completion and wrote output whose SHA-256
   matched the expected decoded bytes.
5. Endpoint telemetry was collected and VM 104 was rolled back. This run had no
   retained raw export and cannot independently prove post-run network scope.
   It is not current verification evidence and is not counted in coverage. The
   four runs below replace its behavioral coverage with endpoint-observed
   executions, but they do not backfill the unprovable network-safety claim.

## Verified flow 1: hexadecimal decode

The SYSTEM account decodes an inert hexadecimal marker. This exercises LOLBAS
Decode command 2 and the process rule's previously untested `-decodehex` branch:

```text
C:\Windows\System32\certutil.exe -decodehex C:\lab\benign-marker.hex C:\lab\decoded-marker.bin
```

The output is hashed but never executed.

## Verified flow 2: forced decode to a payload extension

The SYSTEM account uses the `-f` variant and names the inert result with a DLL
extension so the executable/script tier of the file-event rule receives a
positive telemetry sample:

```text
C:\Windows\System32\certutil.exe -f -decode C:\lab\benign-marker.b64 C:\lab\decoded-marker.dll
```

The `.dll` output is hashed but never loaded or executed.

## Verified flow 3: standard-user base64 decode

A local, non-administrator standard account decodes the same inert base64
fixture to a user-specific local path:

```text
C:\Windows\System32\certutil.exe -decode C:\lab\benign-marker.b64 C:\Users\certlab\decoded-marker-user.txt
```

If the baseline has no suitable account, a local standard account is created as
environment setup without administrator-group membership. The output path and
the three `HKLM\SOFTWARE\Microsoft\Cryptography\OID` writes are compared with
the SYSTEM flow. The output is not executed.

## Verified flow 4: slash-form base64 decode

The SYSTEM account exercises the Windows slash form accepted by this build of
certutil, producing the sample needed to test the Sigma `windash` modifier:

```text
C:\Windows\System32\certutil.exe /decode C:\lab\benign-marker.b64 C:\lab\decoded-marker-slash.bin
```

The output is hashed but never executed.

## Coverage and future scenarios

The four current flows cover five of six grounded local-decode use cases identified
by the audit: ordinary `-decode`, `-decodehex`, `-f` with a high-confidence
output extension, standard-user execution, and `/decode`. The sixth use case is
decode followed by execution. The forced-DLL and
standard-user flows both exercise ordinary base64 decode, while the former also
covers `-f` and the extension tier. All four completed successfully, so current
scenario coverage is 5/6 (83%), above the 60% gate floor. The unprovable
historical run is not counted.

The next future scenario is **decode then execute**: decode inert-but-executable
content and launch the produced file to observe the process chain. It is
explicitly out of scope here because executing decoded content changes the
safety profile and requires its own bounded scenario, pre-run scope gate,
post-run lab-scope proof, and target rollback.

Every future run of this technique must take a packet capture even when no
network activity is expected. The capture exists to show what the target did,
not what the command or tool was intended to do.

Additional future hardening scenarios are a renamed copy of certutil to exercise
the `OriginalFileName` identity branch, and a realistic `cmd.exe /c certutil`
chain writing to a user-writable staging path. Neither is counted as current
coverage.

Encoding (`-encode` or `-encodehex`), URL-cache download, and transfer followed
by decode are distinct behaviors and remain outside this verification.
