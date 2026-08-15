# Safety evidence notes

`scenario-scope-pre-run.json` returned `REVIEW` with no critical finding. The
review item is the declared lab-only name `certutil.lab`; the scenarios state
its temporary mapping to `192.168.1.50`. The final scenario check explicitly
allowed that internal name and returned `PASS` in `scenario-scope-final.json`.
Every accepted flow has its own
operator record and final `*-lab-scope.json` verdict of `PASS`.

Failed attempts are retained rather than hidden. Flow 1 includes unsuccessful
standard-user scheduling/quoting attempts; all post-attempt scope checks
passed. Flow 4's credentialed self-connection failed because Windows forbids
explicit credentials for local connections. Its first scope report is also
retained: the checker labeled the literal self address, local hostname, and
the self-address reverse name as external DNS names. The companion
`flow4-credentialed-self-attempt-readjudicated-lab-scope.json` uses the
checker's supported `--allow-domain` inputs for exactly those declared local
names (and normalizes only the reverse name's terminal dot) and returns
`PASS`. No external name was allowlisted.

The accepted flow 4 did not use credentials and its independent
`flow4-node-self-lab-scope.json` verdict is `PASS`. Unfiltered captures retain
ordinary Windows/Defender traffic in each manifest as informational,
non-tool-attributed activity; it is not silently removed or judged as attack
traffic.
