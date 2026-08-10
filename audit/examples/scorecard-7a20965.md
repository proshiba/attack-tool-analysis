# Rule scorecard - `7a20965`

27 rules across 7 verifications. Verdicts: **fail** 1, **needs-work** 18, **not-testable-on-evtx** 8

FP share is a percentage of the events in the rule's OWN logsource category, measured on a clean corpus. `floor` is the lowest defensible `fp_likelihood`: an auditor may raise it, never lower it.

| Verification | Rule | Category | FP hits | FP share % | floor | declared | role | level | detection | verdict |
|---|---|---|---|---:|---|---|---|---|---|---|
| tools/seatbelt | `win_process_creation_seatbelt_enumeration.yml` | process_creation | - | - | - | - | - | high | - | **fail** |
| tools/sliver | `proc_creation_untrusted_parent_spawns_shell.yml` | process_creation | 321 | 1.354716 | high | - | - | medium | hit | **needs-work** |
| tools/sliver | `proc_creation_unversioned_executable_from_script_host.yml` | process_creation | 3 | 0.012661 | medium | - | - | medium | hit | **needs-work** |
| tools/sliver | `file_event_script_host_writes_executable.yml` | file_event | 64 | 0.011799 | medium | - | - | medium | hit | **needs-work** |
| lol/techniques/certutil-decode | `win_file_event_certutil_suspicious_output.yml` | file_event | 0 | 0.0 | low | - | - | low | no-hit | **needs-work** |
| lol/techniques/certutil-decode | `win_process_creation_certutil_decode.yml` | process_creation | 0 | 0.0 | low | - | - | medium | hit | **needs-work** |
| lol/techniques/certutil-remote-download | `win_file_event_certutil_urlcache_content.yml` | file_event | 0 | 0.0 | low | - | - | medium | no-hit | **needs-work** |
| lol/techniques/certutil-remote-download | `win_process_creation_certutil_remote_download.yml` | process_creation | 0 | 0.0 | low | - | - | high | hit | **needs-work** |
| lol/techniques/regsvr32-remote-scriptlet | `win_file_event_regsvr32_sct_cache.yml` | file_event | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| lol/techniques/regsvr32-remote-scriptlet | `win_process_creation_regsvr32_remote_scriptlet.yml` | process_creation | 0 | 0.0 | low | - | - | high | hit | **needs-work** |
| lol/techniques/regsvr32-remote-scriptlet | `win_process_creation_regsvr32_spawns_shell.yml` | process_creation | 0 | 0.0 | low | - | - | high | hit | **needs-work** |
| lol/techniques/regsvr32-remote-scriptlet | `win_registry_set_regsvr32_jscript_telemetry.yml` | registry_set | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| lol/techniques/wmic-xsl-script-processing | `win_file_event_wmic_xsl_cache.yml` | file_event | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| lol/techniques/wmic-xsl-script-processing | `win_process_creation_wmic_remote_xsl.yml` | process_creation | 0 | 0.0 | low | - | - | high | hit | **needs-work** |
| lol/techniques/wmic-xsl-script-processing | `win_process_creation_wmic_xsl_spawns_shell.yml` | process_creation | 0 | 0.0 | low | - | - | high | hit | **needs-work** |
| lol/techniques/wmic-xsl-script-processing | `win_registry_set_wmic_jscript_telemetry.yml` | registry_set | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| tools/mimikatz | `proc_creation_mimikatz_cmdline.yml` | process_creation | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| tools/mimikatz | `process_access_lsass_read.yml` | process_access | 0 | 0.0 | low | - | - | high | no-hit | **needs-work** |
| tools/seatbelt | `win_sysmon_managed_dotnet_lsass_vm_read.yml` | process_access | 0 | 0.0 | low | - | - | medium | no-hit | **needs-work** |
| lol/techniques/certutil-remote-download | `network_zeek_certutil_cryptoapi_user_agent.yml` | http | - | - | - | - | - | medium | - | **not-testable-on-evtx** |
| lol/techniques/regsvr32-remote-scriptlet | `network_suricata_regsvr32_remote_sct.yml` | http | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| lol/techniques/regsvr32-remote-scriptlet | `network_zeek_regsvr32_remote_sct.yml` | http | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| lol/techniques/wmic-xsl-script-processing | `network_suricata_wmic_remote_xsl.yml` | http | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| lol/techniques/wmic-xsl-script-processing | `network_zeek_wmic_remote_xsl.yml` | http | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| tools/sliver | `network_suricata_sliver_mtls_ja3_pair.yml` | tls | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| tools/sliver | `network_zeek_sliver_mtls_ja3_pair.yml` | tls | - | - | - | - | - | high | - | **not-testable-on-evtx** |
| tools/sliver | `network_zeek_tls13_no_sni_no_visible_cert.yml` | tls | - | - | - | - | - | low | - | **not-testable-on-evtx** |

## Harness notes

- `lol/techniques/certutil-decode` - {"event": "denominator-disagreement", "detail": "corpus denominator 6611183 (measured per file by baseline_metrics.py) disagrees with /opt/audit/catalog/dataset-metrics.json (6923967); using the measured value"}
- `lol/techniques/certutil-remote-download` - {"event": "denominator-disagreement", "detail": "corpus denominator 6611183 (measured per file by baseline_metrics.py) disagrees with /opt/audit/catalog/dataset-metrics.json (6923967); using the measured value"}
- `lol/techniques/regsvr32-remote-scriptlet` - {"event": "denominator-disagreement", "detail": "corpus denominator 6611183 (measured per file by baseline_metrics.py) disagrees with /opt/audit/catalog/dataset-metrics.json (6923967); using the measured value"}
- `tools/seatbelt` - {"event": "rules-excluded-before-measurement", "count": 1, "rules": ["/opt/audit/scratch/attack-tool-analysis/tools/seatbelt/verification/sigma/win_process_creation_seatbelt_enumeration.yml"], "reason": "sigma check failed; excluded so their neighbours still get real numbers"}
