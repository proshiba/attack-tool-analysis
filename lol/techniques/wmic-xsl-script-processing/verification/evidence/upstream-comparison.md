# SigmaHQ master comparison

Comparison point: SigmaHQ `master` commit
`3c0d35188942eb6a8c373e4f4973ac7e84116993` on 2026-08-15. No
LOLBAS-pinned snapshot was used.

## T1220 rules

### `proc_creation_win_wmic_squiblytwo_bypass.yml` — adopted upstream

Upstream ID/path: `8d63dadf-b91b-4187-87b6-34a1114577ea`,
`rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml`.
Upstream covers both URL and UNC remote sources, WMIC identity through image,
original filename and five import hashes, and canonical slash arguments via
`|windash`. Local coverage adds no detection logic to this adopted copy; it
adds the precision fields, zero-of-23,695 baseline measurement, and lab proof
for HTTP, SMB, VBScript HTTP, and HTTPS. The retired local remote-XSL rule had
required `.xsl` text but missed upstream's source breadth, identity hashes,
and slash normalization, so it had no defensible unique gap and was removed.

### `win_process_creation_wmic_local_user_writable_xsl.yml` — locally authored

Nearest upstream rules: ID `8d63dadf-b91b-4187-87b6-34a1114577ea` at the
path above and image-load ID `06ce37c2-61ab-4f05-9ff5-b1a96d18ae32`,
`rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml`.
Upstream 8d covers URL/UNC sources and stronger executable identity; upstream
06 detects JScript/VBScript DLL loads independent of source text. This local
rule covers the proven missing form: `/format:` plus an XSL/XSLT under a
per-user `AppData\Local\Temp` path, with no URL, UNC, network, or cache. The
image-load alternative was not adopted because verification Sysmon does not
collect EID 7, its upstream rule documents normal-WMIC false positives, and
there is no measured precision basis here.

### `win_process_creation_wmic_xsl_spawns_shell.yml` — local measured logic

Nearest upstream: ID 8d/path above. Upstream covers a remote `/format:`
attempt without requiring successful script execution and does not require an
extension. This rule covers what upstream does not: a direct WMIC-to-command
or script-interpreter child, proving an execution consequence, and it works
for local as well as remote XSL. It can miss script without a listed child or
without `.xsl`/`.xslt` in the parent command.

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

## Adjacent T1047 rules — adopted upstream

### `proc_creation_win_wmic_process_creation.yml`

Upstream ID/path: `526be59f-a573-4eea-b5f7-f0973207634d`,
`rules/windows/process_creation/proc_creation_win_wmic_process_creation.yml`.
Detection logic is identical and covers all WMIC `process call create`
attempts, including benign administration; the T1220-local rules do not cover
this primitive. The local copy adds per-category precision measurement and
the lab observation that the resulting process was parented by WmiPrvSE. It
adds no detection breadth, so it remains hunt/low.

### `proc_creation_win_wmic_susp_process_creation.yml`

Upstream ID/path: `3c89a1e8-0fba-449e-8f1b-8409d6267ec8`,
`rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml`.
Detection logic is identical and adds a suspicious interpreter/LOLBIN or
user-writable-path constraint beyond the generic rule; it hit the lab's
`cmd.exe /c` command. The local copy covers nothing upstream lacks except
measured precision and lab validation.

### `proc_creation_win_wmic_remote_execution.yml`

Upstream ID/path: `7773b877-5abb-4a3e-b9c9-fd0369b59b00`,
`rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml`.
Detection logic is identical, including `|windash` and localhost filters. It
covers `/node:` command intent, which the T1220 rules do not. The local copy
adds precision metadata and a negative lab finding: `/node:192.168.1.52`
matched but produced no DCOM TCP flow, so the rule cannot itself prove remote
execution and remains hunt/low.
