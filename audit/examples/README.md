# Example output

`scorecard-7a20965.md` is the real output of

```bash
python3 lib/audit_suite.py <repo> /opt/audit/results/suite-20260810-0850
```

run against commit `7a20965` of this repository on 2026-08-10 — the first suite run after the
harness fixes described in `../README.md`. It is kept as a worked example of the output
format and as the "before" record for the precision pass that follows it: at that commit no
rule declared `fp_likelihood` / `precision_notes` / `recommended_role`, which is why 18 of 27
rules land on `needs-work` with the code `precision-fields-missing`.

Audit runs are not otherwise committed. Their conclusions belong in each verification's
`verification.json`; the raw run directories stay on the audit host.
