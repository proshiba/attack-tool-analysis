# Draft upstream report — do not send

Status: **prepared only**. No SigmaHQ issue, pull request, message, or other
external contact was made.

## Summary

SigmaHQ rule ID `05c36dd6-79d6-4a9a-97da-3db20298ab2d`,
`rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml`,
at commit `3c0d35188942eb6a8c373e4f4973ac7e84116993` can suppress a successful
scripted-XSL execution when the local stylesheet filename begins with a WMIC
built-in format name.

The filter is currently a substring match:

```yaml
filter_main_known_format:
  CommandLine|contains:
    - 'Format:List'
    - 'Format:htable'
    - 'Format:hform'
    - 'Format:table'
    - 'Format:mof'
    - 'Format:value'
    - 'Format:rawxml'
    - 'Format:xml'
    - 'Format:csv'
```

Because Sigma string matching is case-insensitive, `/format:list.xsl` contains
`Format:List`. The filter therefore excludes the process even though WMIC
loads and executes the file as scripted XSL.

## Reproduction and evidence

On Windows 10 LTSC VM 104, a medium-integrity standard user placed a benign
lab-authored JScript stylesheet in the current working directory. The script
only wrote `%TEMP%\wmic-format-filter-marker.txt`. Sysmon recorded:

```text
"C:\Windows\System32\wbem\WMIC.exe" os get Caption /format:list.xsl
```

Observed result:

- WMIC exit code: `0`
- marker: created with `benign-wmic-format-filter-test`
- original rule: no finding
- selector-only diagnostic: finding
- known-format-filter diagnostic: finding
- remote-operation-filter diagnostic: no finding
- fixed rule: finding

Relative `/format:csv.xsl`, `/format:table.xsl`, `/format:value.xsl`, and
`-format:list.xsl` behaved identically. A quoted absolute
`/format:"C:\Users\FmtStd\AppData\Local\Temp\list.xsl"` executed but did not
activate the loose filter because the path separates `Format:` from `list`.

Relative resolution does not require administrator rights: current-directory
copies executed as both standard user and administrator. If the current
directory has no copy, WMIC also falls back to `%SystemRoot%\System32\wbem`;
planting that fallback location requires elevated write access.

Sanitized evidence is in `evidence/format-filter-falsification.json`. Raw EVTX
was retained outside the repository and is represented by SHA-256 hashes.

## Proposed change

```diff
 filter_main_known_format:
-  CommandLine|contains:
+  CommandLine|endswith:
     - 'Format:List'
     - 'Format:htable'
     - 'Format:hform'
     - 'Format:table'
     - 'Format:mof'
     - 'Format:value'
     - 'Format:rawxml'
     - 'Format:xml'
     - 'Format:csv'
```

This retains suppression for a built-in token at the end of the command line
but prevents a longer filename such as `list.xsl` from activating it. The
trade-off is that an unusual legitimate command with another argument after
the built-in format token may alert. That is narrower than removing the filter
and safer than the existing filename-triggerable substring exclusion.

The change passes sigma-cli 3.1.0/pySigma parsing. Against the captured matrix,
the original rule produced 8 findings and the proposed rule 13, restoring all
five successful evasion rows. Clean-corpus FP remained 0/23,695 process-creation
events (0.0%).
