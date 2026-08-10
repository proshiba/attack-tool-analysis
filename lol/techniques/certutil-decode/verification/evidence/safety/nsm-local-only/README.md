# Local-only NSM input

These four scenarios performed local file-to-file transforms and named no
network destination, so the playbook did not require packet capture or NSM
analysis. This intentionally contains no `conn.log` or `dns.log`.

The companion `sysmon-eid3-attribution.json` is the process-attributed network
input to `safety/check-lab-scope.py`; it aggregates the complete EID 3 exports
for all four run windows and contains zero events.
