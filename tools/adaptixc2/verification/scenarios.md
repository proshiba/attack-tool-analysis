# AdaptixC2 verification scenarios

## Scope

- **VM 100 — Kali — `192.168.1.50` — only C2, staging, build, and operator host.** The AdaptixC2 source, dependencies, server, extenders, generated agents, listener state, HTTP staging service, and operator API calls remain on this VM. The teamserver and every Beacon listener bind to this address or loopback.
- **VM 104 — Windows — `192.168.1.52` — primary target.** It begins and ends at `win_verify_baseline`. It may fetch a reviewed generated agent and the lab-authored sideload package only from VM 100 and may initiate HTTP/S only to VM 100.
- **VM 105 — REMnux — static-analysis host only.** It may receive generated binaries out of band for `file`, PE metadata, strings, and disassembly review. It never executes an AdaptixC2 component and is not a payload or C2 destination.
- **VM 106 — NSM — offline packet-analysis host.** `nsm-analyze` receives saved pcaps out of band. Any active JARM probe is permitted to address only the listener on `192.168.1.50`.
- **VM 103 is not used.** No Linux target or agent is required, so `linux_verify_baseline` is not touched.
- **Destinations.** Every delivery, server probe, Beacon callback, operator action, and active fingerprint destination is `192.168.1.50`, `192.168.1.52`, or loopback. Public threat-intelligence indicators supplied with the task are citations only: they are neither resolved nor copied into a profile. No attack traffic may target a public host, the management network, VM 102, or VM 108.
- **Bounded actions.** Agent tasking is limited to identity, host/process/directory survey, sleep configuration, and download of one fixed small marker created for the run. The DLL-sideload flow uses a lab-authored inert DLL whose only action is to write a fixed marker. No credential access, privilege escalation, process injection, lateral movement, tunneling, self-propagation, destructive action, unrelated-file collection, or persistence is allowed.

## Grounding and scenario selection

[Censys, “AdaptixC2: fingerprinting an open-source C2 framework at scale”](https://censys.com/blog/adaptixc2-open-source-c2-framework/) reports that the default response headers and default 404 body identify exposed AdaptixC2 infrastructure, and specifically claims the body remains useful when operators change headers. This verification treats that as a falsifiable claim: capture the default response from the target and pcap, modify only the response headers, repeat the probe, and run the same body rule against both flows.

[Group-IB, “JadeProx: Tracing a China-nexus Operation Through an OPSEC Mistake”](https://www.group-ib.com/blog/jadeprox-china-nexus-triback-loader/) documents signed-host DLL sideloading, rotating Win32 callback APIs, and AdaptixC2 delivery. [Seqrite, “Operation Dragon Weave”](https://www.seqrite.com/blog/operation-dragon-weave-uncovering-a-china-linked-campaign-targeting-czech-republic-and-taiwan-using-azure-cloud-c2/) documents ZIP/LNK or Rust-loader delivery converging on a signed executable loading `UnityPlayer.dll`, followed by an Adaptix-derived AZUREVEIL agent. The lab reproduces only the bounded detection surface: a signed binary already on VM 104 loads a lab-authored inert DLL from its application directory. It does not reproduce shellcode, callback-API execution, decryption, lures, or the reported malware.

[Cloud Security Alliance, “TeamPCP: Cascading Supply Chain Attack on AI/ML Tooling”](https://labs.cloudsecurityalliance.org/research/csa-research-note-teampcp-supply-chain-ai-tooling-20260330-c/) is retained as the supplied TeamPCP grounding reference. The task’s reported AdaptixC2 infrastructure pivot used an HTTP header fingerprint and AI-API-looking paths such as `/v1/models` and `/v1/weights`. Those paths are useful examples of operator customization, not defaults, and will not be converted into an AdaptixC2-only signature without observed invariant evidence.

## Planned verified flows

| Flow | Bounded operator actions | ATT&CK | Planned evidence |
| --- | --- | --- | --- |
| Default HTTP Beacon | Host the generated Windows x64 Beacon on Kali, fetch and execute it on VM 104, measure a 10-second sleep with 20% jitter, run `getuid`, `pwd`, `ls`, `ps list`, and download one fixed marker. | T1105, T1071.001, T1033, T1082, T1083, T1057, T1041 | Dedicated full-packet pcap, NSM output, Sysmon five-dimension export. |
| Default server fingerprint | From VM 104, request an unregistered path from the default teamserver and the default BeaconHTTP listener and record exact headers, status, and body. | T1046 detection surface; not claimed as agent behavior | Dedicated pcap plus target-side response capture. |
| Header-modified 404 test | Change only the server’s response-header settings, keep the default 404 body byte-for-byte, and repeat the same target-side request. | Detection validation | Dedicated pcap; rule result compared with the default flow. |
| HTTPS Beacon | Generate a second Windows x64 Beacon with the same 10-second/20% schedule for a TLS listener; run only identity and directory survey. | T1071.001, T1573, T1033, T1083 | Dedicated pcap, JA3/JA3S, JARM, cadence, and explicit comparison to the stock Go JA3 supplied in the task. |
| Inert signed-host DLL sideload | Copy one existing signed Windows binary into a lab directory beside a lab-authored inert DLL, execute the signed host, and verify the DLL marker. | T1574.001, T1036.005 | Sysmon process, image-load/file evidence and signature verification. No AdaptixC2 agent is embedded in the DLL. |

Every network flow receives a separate full-packet capture followed by `nsm-analyze`. The optional persistence flow is deferred: a masquerading service would add persistence and system-state modification without being necessary to validate the higher-value network and sideload detections.

## Deferred and lab-capability gaps

- **Azure Blob dead-drop — lab-capability gap.** The reported AZUREVEIL channel requires a public cloud endpoint. Absolute safety Rule 1 forbids resolving or contacting it, so it can never be executed in this lab topology.
- **macOS agent — lab-capability gap.** The lab has no macOS target.
- **SMB and TCP pivoting — future bounded scenario.** They require a separate scope design and add no evidence needed for the requested HTTP/S and sideload verification.
- **DNS/DoH — future bounded scenario.** Source defaults include public resolver destinations, so this run excludes the transport entirely rather than risk an accidental off-lab query.
- **Persistence service — deferred by risk decision.** It is optional and not necessary to answer the requested fingerprint, transport, or sideload questions.
