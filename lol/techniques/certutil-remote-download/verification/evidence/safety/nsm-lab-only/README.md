# Sanitized NSM scope input

`conn.log` concatenates only the Zeek connection records and field headers
from the five accepted packet captures. All nine responder addresses are the
Kali lab host `192.168.1.50`; no packet content, HTTP bodies, certificates,
raw pcaps, or unrelated NSM logs are committed. It is retained so
`safety/check-lab-scope.py` can be reproduced against the committed sanitized
Sysmon EID 3 attribution.
