# Excluded safety attempts

Two timing/isolation probes were rejected and are not used as verification
evidence.

1. A longer capture intended to accommodate Sysmon EID 3 ingestion recorded
   Windows background traffic to `1.1.1.1:53`, `52.123.128.14:443`, and public
   Microsoft DNS names. `check-lab-scope.py` returned `VIOLATION`; work stopped
   and VM 104 was rolled back to `win_verify_baseline`.
2. After removing default routes but before clearing pre-existing sockets, a
   short capture contained responder-only packets (`orig_pkts=0`) from
   `52.123.129.14:443` and `23.193.184.154:80`. The scope gate again returned
   `VIOLATION`; work stopped and VM 104 was rolled back.

In both attempts, certutil itself contacted only Kali at `192.168.1.50`.
Neither capture contributes telemetry, measurements, hashes, or rule results
to the accepted verification. The accepted runs cleared the default gateway,
reset the adapter, removed default routes, waited for quiescence, and each
produced a committed aggregate `PASS` proof.
