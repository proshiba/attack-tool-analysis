# Seatbelt verification scenarios

## Scope

- **VM 104 — `WIN10-ANALYSIS` — `192.168.1.52` — build host, target, and
  local staging host.** The exact upstream source was built here, and the
  recorded run executed `C:\lab\Seatbelt.exe` here as `NT AUTHORITY\SYSTEM`.
  No attacker or NSM VM is named in this verification.
- **Destinations.** Seatbelt made one TCP connection to `127.0.0.1:135` and
  queried `localhost`, which resolved only to loopback addresses on VM 104.
  Loopback never left the target; there was no remote network destination.
  The target's lab address is inside `192.168.1.0/24`, every remote scenario
  destination was therefore confined to that lab subnet, and nothing outside
  the lab was contacted.
- **Hosting and references.** The source and resulting executable were hosted
  locally on VM 104 for the build and run; no payload delivery service,
  stager, or C2 was used. The GhostPack GitHub repository URL is an upstream
  source citation, not a destination contacted by the scenario run. The
  record says the source archive reached the guest through the QEMU
  guest-agent channel, but it does not name or address the host that
  originated that transfer.

## Attack use-cases considered

Seatbelt is a post-compromise situational-awareness tool. Its checks help an
operator understand a new foothold, identify privilege-escalation paths, and
locate data or credentials worth looting. The following mappings describe the
operator objective; some checks support a later technique without performing
the later exploitation step themselves.

| Use-case | Representative Seatbelt checks | ATT&CK mapping |
|---|---|---|
| Identify the host, OS, patches, runtime, and environment | `OSInfo`, `Hotfixes`, `DotNet`, `EnvironmentVariables` | T1082 System Information Discovery |
| Discover AV, EDR, Sysmon, firewall, and script-scanning controls | `AntiVirus`, `WindowsDefender`, `Sysmon`, `AMSIProviders`, `WindowsFirewall` | T1518.001 Security Software Discovery |
| Find UAC, LAPS, AppLocker, WDAC/Credential Guard, PowerShell logging, and audit-policy weaknesses | `UAC`, `LAPS`, `AppLocker`, `CredGuard`, `PowerShell`, `AuditPolicyRegistry` | T1012 Query Registry; supports T1548.002 Bypass User Account Control |
| Enumerate users, groups, sessions, owners, token groups, and privileges | `LocalUsers`, `LocalGroups`, `LogonSessions`, `ProcessOwners`, `TokenGroups`, `TokenPrivileges` | T1087.001 Local Account; T1033 System Owner/User Discovery |
| Survey processes, services, autoruns, and named pipes for escalation or injection opportunities | `Processes`, `InterestingProcesses`, `Services`, `AutoRuns`, `NamedPipes` | T1057 Process Discovery; T1083 File and Directory Discovery |
| Map interfaces, routes, peers, shares, and active connections | `ARPTable`, `DNSCache`, `NetworkProfiles`, `NetworkShares`, `TcpConnections`, `UdpConnections` | T1016 System Network Configuration Discovery |
| Locate credentials in files and configuration stores | `CloudCredentials`, `WindowsCredentialFiles`, `DpapiMasterKeys`, `KeePass`, `FileZilla`, `PuttySessions` | T1552.001 Unsecured Credentials: Credentials In Files; T1555 Credentials from Password Stores |
| Find saved RDP and Wi-Fi access | `RDPSavedConnections`, `RDPSettings`, `WifiProfile`, `WindowsVault` | T1555 Credentials from Password Stores; T1552.001 Unsecured Credentials: Credentials In Files |
| Inventory browser and collaboration data | `ChromiumBookmarks`, `ChromiumHistory`, `FirefoxHistory`, `SlackWorkspaces` | T1217 Browser Bookmark Discovery; T1083 File and Directory Discovery |
| Find scheduled-task escalation or persistence opportunities | `ScheduledTasks` | T1053.005 Scheduled Task/Job: Scheduled Task |
| Stage the survey for later review | `-outputfile=<path>` | T1074.001 Local Data Staging |

## Flow verified here

Scenario: **broad post-compromise host survey with local result staging**.

From `C:\lab`, an elevated local operator ran:

```text
Seatbelt.exe -group=all -q -outputfile=C:\lab\seatbelt-run.json
```

The `all` group invokes the user, system, browser, and miscellaneous checks,
including security-control discovery, user and token enumeration, process and
network discovery, credential-file hunting, browser-data discovery, and
scheduled-task enumeration. The explicit output file also exercises local data
staging. The run is mapped to T1082, T1518.001, T1012, T1087.001, T1033, T1057,
T1016, T1083, T1552.001, T1555, T1217, T1053.005, and T1074.001.

Sysmon cannot show the many registry and file reads that make up most of this
survey. Verification therefore treats process identity, command line, and
parent-child context as the primary signal and records only write-class events
where Sysmon actually observed them.

## Future scenarios

1. Run `OSInfo AntiVirus AppLocker LAPS PowerShell UAC` as both a standard user
   and an administrator to compare focused security-control discovery and
   privilege-dependent coverage.
2. Run `-group=user` against a profile populated only with synthetic RDP,
   Wi-Fi, browser, cloud, and password-store fixtures. Validate detections
   without retaining the fixture values or Seatbelt output.
3. Rename the assembly and execute it through an authorized in-memory
   `execute-assembly` harness to test CLR/ETW detections that do not depend on
   `Seatbelt.exe` or a file write.
4. Exercise `-group=remote` between isolated lab guests and validate the remote
   WMI/RPC and authentication telemetry separately from local enumeration.
5. Compare `-group=all` with and without `-full` and `-outputfile` to measure
   which supporting file and process-access signals remain stable.
