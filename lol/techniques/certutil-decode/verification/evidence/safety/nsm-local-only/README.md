# No NSM evidence was collected

No packet capture was taken for these local file-to-file runs, so this directory
contains no Zeek `conn.log`, `dns.log`, or other mechanical network evidence.
It must not be passed to `safety/check-lab-scope.py` as though it were an NSM
input. The earlier `PASS` computed against this empty directory was invalid.

`evidence/endpoint-signals.json` records zero Sysmon EID 3 and zero EID 22 for
the run windows, but those values are a hand-authored sanitized assertion, not
a packet-capture proof. Post-run safety is therefore recorded as `NOT_PROVEN`.
