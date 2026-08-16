# SigmaHQ master comparison

Comparison point: SigmaHQ `master` commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993` on 2026-08-15. No
LOLBAS-pinned snapshot was used.

## T1220 rules

### `proc_creation_win_wmic_squiblytwo_bypass.yml` — adopted upstream

Upstream ID/path: `8d63dadf-b91b-4187-87b6-34a1114577ea`,
`rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml`
(modified 2026-01-24).
Upstream covers both URL and UNC remote sources, WMIC identity through image,
original filename and five import hashes, and canonical slash arguments via
`|windash`. Local coverage adds no detection logic to this adopted copy; it
adds the precision fields, zero-of-23,695 baseline measurement, and lab proof
for HTTP, SMB, VBScript HTTP, and HTTPS. Because the corpus has only three
WMIC events and no benign `/format:` population, the gate reconciled the
measured low floor to medium FP likelihood while retaining alert/high. The
retired local remote-XSL rule had
required `.xsl` text but missed upstream's source breadth, identity hashes,
and slash normalization, so it had no defensible unique gap and was removed.

### `win_process_creation_wmic_local_user_writable_xsl.yml` — locally authored

Nearest upstream rules: local-XSL ID
`05c36dd6-79d6-4a9a-97da-3db20298ab2d`,
`rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml`;
ID `8d63dadf-b91b-4187-87b6-34a1114577ea` at the path above; and image-load
ID `06ce37c2-61ab-4f05-9ff5-b1a96d18ae32`,
`rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml`.
Upstream 05c covers local `/format:` from any path without requiring an
extension and filters built-in format aliases; upstream 8d covers URL/UNC
sources and stronger executable identity; upstream 06 detects JScript/VBScript
DLL loads independent of source text. This local rule does not claim a new
form. It covers upstream's unmeasured precision gap by narrowing to the
lab-proven `AppData\Local\Temp` plus XSL/XSLT subset at alert/high; it misses
all other local paths that adopted 05c retains as hunt/low. The image-load
alternative was not adopted because verification Sysmon does not collect EID
7, its upstream rule documents normal-WMIC false positives, and there is no
measured precision basis here.

### `win_process_creation_wmic_xsl_spawns_shell.yml` — local measured logic

Nearest upstream: ID 8d/path above. Upstream covers a remote `/format:`
attempt without requiring successful script execution and does not require an
extension. This rule covers what upstream does not: a direct WMIC-to-command
or script-interpreter child, proving an execution consequence, and it works
for local as well as remote XSL without requiring a stylesheet extension. It
can miss script that produces no listed child.

### `win_file_event_wmic_xsl_cache.yml` — local measured logic

Nearest upstream: ID 8d/path above. Upstream covers remote URL and UNC command
lines and remains useful when no cache event is collected. This rule covers a
WMIC-attributed Internet-cache XSL file without depending on process-command
retention; lab HTTP and HTTPS produced it. It is blind to the local and SMB
forms. The dead `service: sysmon` qualifier was removed so the category/product
mapping is live.

### `win_registry_set_wmic_jscript_telemetry.yml` — local measured logic

Nearest upstream: IDs 8d and 06/path above. Upstream 8d covers remote attempts
for either script language; upstream 06 covers JScript and VBScript module
loads but needs image-load telemetry. This rule covers actual WMIC JScript
engine initialization for both local and remote XSL, independent of URL,
extension, retrieval, or child process. It deliberately does not broaden to
VBScript: the benign `/node:` caption query produced the same VBScript-start
value, demonstrating a precision gap. The dead `service: sysmon` qualifier
was removed.

### `network_zeek_wmic_remote_xsl.yml` and `network_suricata_wmic_remote_xsl.yml`

Nearest upstream: ID 8d/path above. Upstream ties the signal to WMIC identity,
covers URL/UNC and HTTPS command lines, and survives encrypted payload
content. These rules cover a different sensor-only gap: plaintext HTTP XSL
retrieval using the legacy MSIE 7.0/Trident 7.0 Windows URL-moniker profile
without requiring endpoint logs. They are blind to local, SMB, and encrypted
HTTPS content and therefore remain hunt/low; EVTX cannot measure them.

No TLS rule was added. SNI/certificate observations identify the lab service,
and JA3/JA3S identify a reusable client/server stack rather than WMIC abuse.

## Adopted local T1220 and adjacent T1047 rules

### `proc_creation_win_wmic_xsl_script_execution.yml`

Upstream ID/path: `05c36dd6-79d6-4a9a-97da-3db20298ab2d`,
`rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml`
(modified 2026-01-24), pinned here from SigmaHQ commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993`.

The 2026-08-16 falsification found a defect in the adopted upstream logic. Its
`filter_main_known_format` used a plain `CommandLine|contains` match for text
such as `Format:List` and `Format:csv`. A standard user placed the lab-authored
scripted stylesheet in a user-writable current directory and executed:

```text
"C:\Windows\System32\wbem\WMIC.exe" os get Caption /format:list.xsl
```

WMIC exited 0 and wrote the marker, but the original rule did not fire. The
same result was measured for relative `csv.xsl`, `table.xsl`, `value.xsl`, and
dash-form `-format:list.xsl`. The selector-only diagnostic matched all 13
initial rows; the known-format-filter diagnostic matched exactly those five;
the remote-operation filter matched none. This is therefore a filter-caused
false negative on successful T1220 execution, not a rule-reading inference.

Gate iteration 1 challenged whether `/format:list` could also load a planted
`list.xsl` from the CWD and remain suppressed by `endswith`. The added
standard-user row refuted that extensionless variant: WMIC exited 0, returned
its normal built-in list output, did not write the marker, and both original
and fixed rules stayed silent. Across the resulting 14 rows, selector-only
matched 14, known-format filter matched the five explicit-filename evasions
plus this one benign built-in invocation, and the remote filter matched zero.

Our copy narrows the filter to `CommandLine|endswith` for the actual built-in
tokens. The fixed rule matched 13 of 14 captured WMIC format events, restoring
the five successful scripted-XSL findings while continuing to suppress the
benign extensionless built-in row. The trade-off is deliberate: a
benign command that places another argument after a built-in format token may
now alert, while a filename suffix can no longer activate the suppression.
The filter remains present, so ordinary terminal `/format:list`-style commands
retain their noise suppression.

Clean-corpus precision did not move: 0 of 23,695 process-creation events
(0.0%; measured floor `low`), and the public attack corpus still has no
positive sample (`no-corpus-coverage`). The declared `medium` FP likelihood,
`hunt` role, and `low` level remain because arbitrary approved custom local
stylesheets are still within the selection. The task's 20,136-of-6,923,967
figures are the superseded catalog values; the current repository catalog
documents 23,695 of 6,611,183 as the authoritative per-file measurement.

This defect was not sent outside the repository. A proposed upstream change
and evidence summary are staged in `evidence/upstream-report-draft.md` for the
orchestrator to review.

### `proc_creation_win_wmic_process_creation.yml`

Upstream ID/path: `526be59f-a573-4eea-b5f7-f0973207634d`,
`rules/windows/process_creation/proc_creation_win_wmic_process_creation.yml`
(modified 2023-02-14).
Detection logic is identical and covers all WMIC `process call create`
attempts, including benign administration; the T1220-local rules do not cover
this primitive. The local copy adds per-category precision measurement and
the lab observation that the resulting process was parented by WmiPrvSE. It
adds no detection breadth, so it remains hunt/low.

### `proc_creation_win_wmic_susp_process_creation.yml`

Upstream ID/path: `3c89a1e8-0fba-449e-8f1b-8409d6267ec8`,
`rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml`
(modified 2023-02-14).
Detection logic is identical and adds a suspicious interpreter/LOLBIN or
user-writable-path constraint beyond the generic rule; it hit the lab's
`cmd.exe /c` command. The local copy covers nothing upstream lacks except
measured precision and lab validation.

### `proc_creation_win_wmic_remote_execution.yml`

Upstream ID/path: `7773b877-5abb-4a3e-b9c9-fd0369b59b00`,
`rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml`
(modified 2025-10-22).
Detection logic is identical, including `|windash` and localhost filters. It
covers `/node:` command intent, which the T1220 rules do not. The local copy
adds precision metadata and a negative lab finding: `/node:192.168.1.52`
matched but produced no DCOM TCP flow, so the rule cannot itself prove remote
execution and remains hunt/low.
