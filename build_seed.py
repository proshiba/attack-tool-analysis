#!/usr/bin/env python3
"""Seed the catalog: write one metadata.json per tool and one json per LOL site.

The generated metadata.json / lol site json files are the source of truth for
the catalog. Run generate_index.py afterwards to (re)build index.json and the
human-readable README.md files from them.

This seed script is idempotent for fields it owns, but it will NOT overwrite a
tool's CHANGELOG.md if one already exists (so hand-maintained history is kept).
"""
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT, "tools")
LOL_SITES_DIR = os.path.join(ROOT, "lol", "sites")

LAST_REVIEWED = "2026-08-08"


def T(tid, name):
    return {"id": tid, "name": name}


TOOLS = [
    # ----------------------------------------------------------------- mimikatz
    {
        "id": "mimikatz",
        "name": "mimikatz",
        "categories": ["credential-access", "privilege-escalation", "lateral-movement"],
        "summary": "Post-exploitation toolkit for extracting plaintext passwords, hashes, PINs and Kerberos tickets from Windows memory, and for abusing Kerberos (pass-the-hash, pass-the-ticket, golden/silver tickets, DCSync).",
        "description": (
            "mimikatz is the reference tool for Windows credential theft. Its `sekurlsa` "
            "module reads secrets from the LSASS process (plaintext passwords via WDigest, "
            "NTLM hashes, Kerberos tickets). Other modules cover LSA secrets, the DPAPI "
            "master keys, the SAM database, Kerberos ticket forging (golden/silver tickets), "
            "and directory replication abuse (`lsadump::dcsync`). It is bundled into almost "
            "every offensive framework and drives a large share of real-world AD compromises."
        ),
        "authors": ["Benjamin Delpy (gentilkiwi)", "Vincent Le Toux"],
        "language": "C",
        "license": "CC-BY-4.0",
        "os": ["windows"],
        "type": "standalone-binary",
        "repository": "https://github.com/gentilkiwi/mimikatz",
        "homepage": "https://blog.gentilkiwi.com/mimikatz",
        "mitre_software_id": "S0002",
        "attack_techniques": [
            T("T1003.001", "OS Credential Dumping: LSASS Memory"),
            T("T1003.002", "OS Credential Dumping: Security Account Manager"),
            T("T1003.004", "OS Credential Dumping: LSA Secrets"),
            T("T1003.006", "OS Credential Dumping: DCSync"),
            T("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
            T("T1558.002", "Steal or Forge Kerberos Tickets: Silver Ticket"),
            T("T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
            T("T1550.003", "Use Alternate Authentication Material: Pass the Ticket"),
        ],
        "usage": [
            "privilege::debug            # acquire SeDebugPrivilege",
            "sekurlsa::logonpasswords    # dump creds/tickets from LSASS memory",
            "lsadump::sam                # dump local SAM hashes",
            "lsadump::dcsync /user:krbtgt  # pull hashes via DC replication",
            "kerberos::golden /user:... /domain:... /sid:... /krbtgt:... /ptt",
        ],
        "detection": [
            "Monitor for non-standard processes opening a handle to lsass.exe with "
            "PROCESS_VM_READ (Sysmon Event ID 10; target lsass.exe).",
            "Sensitive-privilege use / SeDebugPrivilege assignment (Windows Event ID 4673/4703).",
            "Enable and alert on 4662 (directory replication, 'DS-Replication-Get-Changes') from "
            "non-DC accounts to catch DCSync.",
            "Golden/silver tickets: TGTs with anomalous lifetimes, encryption downgrade (RC4), and "
            "4769 requests without a preceding 4768.",
            "Credential Guard / LSASS PPL (RunAsPPL) raise the bar for sekurlsa memory reads.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/gentilkiwi/mimikatz"},
            {"title": "MITRE ATT&CK S0002", "url": "https://attack.mitre.org/software/S0002/"},
            {"title": "adsecurity.org - Unofficial mimikatz guide", "url": "https://adsecurity.org/?page_id=1821"},
        ],
        "status": "active",
        "first_seen": "2007",
    },
    # ------------------------------------------------------------------ LaZagne
    {
        "id": "lazagne",
        "name": "LaZagne",
        "categories": ["credential-access"],
        "summary": "Open-source application that recovers passwords stored locally by a wide range of software (browsers, mail clients, Wi-Fi, databases, sysadmin tools) on Windows, Linux and macOS.",
        "description": (
            "LaZagne aggregates dozens of per-application credential recovery routines into a "
            "single tool. Rather than touching LSASS, it harvests secrets from application "
            "stores: browsers, chats, databases, git/svn, Wi-Fi, and OS keyrings. Useful for "
            "situational credential collection that complements memory-based dumpers."
        ),
        "authors": ["Alessandro Zanni (pixis / AlessandroZ)"],
        "language": "Python",
        "license": "LGPL-3.0",
        "os": ["windows", "linux", "macos"],
        "type": "standalone-binary",
        "repository": "https://github.com/AlessandroZ/LaZagne",
        "homepage": "https://github.com/AlessandroZ/LaZagne",
        "mitre_software_id": "S0349",
        "attack_techniques": [
            T("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers"),
            T("T1555", "Credentials from Password Stores"),
            T("T1552.001", "Unsecured Credentials: Credentials In Files"),
            T("T1003", "OS Credential Dumping"),
        ],
        "usage": [
            "lazagne.exe all              # run every module",
            "lazagne.exe browsers         # only browser modules",
            "lazagne.exe all -oJ          # write results as JSON",
        ],
        "detection": [
            "Read access to browser credential stores (e.g. Login Data, key4.db/logins.json) "
            "by unexpected processes.",
            "Known-bad hashes / AV signatures for the packaged PyInstaller binary.",
            "Bulk access to many application config paths in a short window.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/AlessandroZ/LaZagne"},
            {"title": "MITRE ATT&CK S0349", "url": "https://attack.mitre.org/software/S0349/"},
        ],
        "status": "active",
        "first_seen": "2015",
    },
    # ------------------------------------------------------------------- Rubeus
    {
        "id": "rubeus",
        "name": "Rubeus",
        "categories": ["credential-access", "lateral-movement", "privilege-escalation"],
        "summary": "C# toolset for raw Kerberos interaction and abuse: ticket requests, Kerberoasting, AS-REP roasting, pass-the-ticket, overpass-the-hash, delegation abuse, and S4U.",
        "description": (
            "Rubeus (part of GhostPack) is the go-to tool for Active Directory Kerberos "
            "attacks. It can request and renew TGTs/TGSs, harvest and inject tickets, perform "
            "Kerberoasting and AS-REP roasting for offline cracking, and abuse constrained / "
            "unconstrained / resource-based constrained delegation."
        ),
        "authors": ["Will Schroeder (@harmj0y)", "GhostPack / SpecterOps"],
        "language": "C#",
        "license": "BSD-3-Clause",
        "os": ["windows"],
        "type": "dotnet-assembly",
        "repository": "https://github.com/GhostPack/Rubeus",
        "homepage": "https://github.com/GhostPack/Rubeus",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
            T("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
            T("T1550.003", "Use Alternate Authentication Material: Pass the Ticket"),
            T("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
            T("T1484.002", "Domain Policy Modification: Domain Trust Modification"),
        ],
        "usage": [
            "Rubeus.exe kerberoast /outfile:hashes.txt",
            "Rubeus.exe asreproast /format:hashcat",
            "Rubeus.exe asktgt /user:svc /rc4:<ntlm> /ptt   # overpass-the-hash",
            "Rubeus.exe s4u /user:... /rc4:... /impersonateuser:administrator /msdsspn:...",
        ],
        "detection": [
            "4769 (TGS requests) with RC4 (etype 0x17) for many SPNs from one host -> Kerberoasting.",
            "4768 AS-REQ for accounts with 'do not require pre-auth' -> AS-REP roasting.",
            "Ticket-granting activity that does not correlate with normal interactive logons.",
            "Honeypot service accounts / SPNs to catch roasting attempts.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/GhostPack/Rubeus"},
            {"title": "harmj0y - Rubeus intro", "url": "https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus/"},
        ],
        "status": "active",
        "first_seen": "2018",
    },
    # -------------------------------------------------------- PowerUp / SharpUp
    {
        "id": "powerup-sharpup",
        "name": "PowerUp / SharpUp",
        "categories": ["privilege-escalation", "discovery"],
        "summary": "Windows local privilege-escalation checks. PowerUp is the PowerShell original; SharpUp is the C# port that enumerates common misconfigurations (unquoted service paths, weak service/registry ACLs, DLL hijack candidates, AlwaysInstallElevated).",
        "description": (
            "PowerUp (from PowerSploit's Privesc module) and its GhostPack C# port SharpUp "
            "automate discovery of common Windows privilege-escalation vectors: modifiable "
            "services and service binaries, unquoted service paths, weak registry ACLs, "
            "writable %PATH% directories, AlwaysInstallElevated, and stored credentials. "
            "PowerUp additionally offers abuse functions to weaponise several findings."
        ),
        "authors": ["Will Schroeder (@harmj0y)", "PowerSploit / GhostPack"],
        "language": "PowerShell, C#",
        "license": "BSD-3-Clause",
        "os": ["windows"],
        "type": "script-and-dotnet-assembly",
        "repository": "https://github.com/GhostPack/SharpUp",
        "homepage": "https://github.com/PowerShellMafia/PowerSploit",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1574.010", "Hijack Execution Flow: Services File Permissions Weakness"),
            T("T1574.011", "Hijack Execution Flow: Services Registry Permissions Weakness"),
            T("T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path"),
            T("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
            T("T1078", "Valid Accounts"),
        ],
        "usage": [
            "Import-Module .\\PowerUp.ps1; Invoke-AllChecks",
            "SharpUp.exe audit",
            "SharpUp.exe   # default = run all checks",
        ],
        "detection": [
            "Rapid enumeration of service configs and ACLs (sc.exe, WMI, registry reads).",
            "PowerShell script-block logging (Event ID 4104) matching PowerUp function names.",
            "AMSI / signature detection of the well-known script and assembly.",
        ],
        "references": [
            {"title": "SharpUp repository", "url": "https://github.com/GhostPack/SharpUp"},
            {"title": "PowerSploit (PowerUp)", "url": "https://github.com/PowerShellMafia/PowerSploit"},
        ],
        "status": "maintenance",
        "first_seen": "2014",
    },
    # ------------------------------------------------------------------ Certify
    {
        "id": "certify",
        "name": "Certify",
        "categories": ["privilege-escalation", "credential-access", "discovery"],
        "summary": "C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) - the ESC1-ESC8 escalation paths.",
        "description": (
            "Certify (GhostPack) finds vulnerable certificate templates and CA "
            "misconfigurations in AD CS and can request certificates that allow "
            "authentication as arbitrary users (domain escalation). It pairs with Rubeus / "
            "ForgeCert to turn issued certificates into Kerberos TGTs. It operationalises the "
            "ESC1-ESC8 techniques from the 'Certified Pre-Owned' research."
        ),
        "authors": ["Will Schroeder (@harmj0y)", "Lee Christensen (@tifkin_)", "SpecterOps"],
        "language": "C#",
        "license": "BSD-3-Clause",
        "os": ["windows"],
        "type": "dotnet-assembly",
        "repository": "https://github.com/GhostPack/Certify",
        "homepage": "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1649", "Steal or Forge Authentication Certificates"),
            T("T1552.004", "Unsecured Credentials: Private Keys"),
            T("T1078.002", "Valid Accounts: Domain Accounts"),
        ],
        "usage": [
            "Certify.exe find /vulnerable",
            "Certify.exe request /ca:CA01\\corp-CA /template:VulnTemplate /altname:administrator",
            "# convert the resulting .pfx to a TGT with Rubeus asktgt /certificate:",
        ],
        "detection": [
            "AD CS certificate issuance events (4886/4887) with a subject alternative name that "
            "differs from the requester.",
            "Certificate-based logons (4768 with certificate info) for privileged accounts.",
            "Audit and lock down template enrollment permissions and 'supply subject in request'.",
        ],
        "references": [
            {"title": "Certify repository", "url": "https://github.com/GhostPack/Certify"},
            {"title": "Certified Pre-Owned (SpecterOps)", "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        ],
        "status": "active",
        "first_seen": "2021",
    },
    # ----------------------------------------------------------------- Seatbelt
    {
        "id": "seatbelt",
        "name": "Seatbelt",
        "categories": ["discovery"],
        "summary": "C# host survey / situational-awareness tool that runs dozens of 'safety checks' from both offensive and defensive perspectives (OS config, security products, credentials on disk, network, user data).",
        "description": (
            "Seatbelt (GhostPack) is the standard local enumeration tool for red teams on "
            "Windows. It bundles many collection commands (AV/EDR presence, AppLocker/WDAC, "
            "UAC/LAPS config, PowerShell logging, saved RDP/Wi-Fi creds, browser data, cloud "
            "credentials, scheduled tasks) so an operator can quickly understand a foothold "
            "and find escalation or looting opportunities."
        ),
        "authors": ["Will Schroeder (@harmj0y)", "Lee Christensen (@tifkin_)", "GhostPack"],
        "language": "C#",
        "license": "BSD-3-Clause",
        "os": ["windows"],
        "type": "dotnet-assembly",
        "repository": "https://github.com/GhostPack/Seatbelt",
        "homepage": "https://github.com/GhostPack/Seatbelt",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1082", "System Information Discovery"),
            T("T1518.001", "Software Discovery: Security Software Discovery"),
            T("T1087", "Account Discovery"),
            T("T1083", "File and Directory Discovery"),
            T("T1552.001", "Unsecured Credentials: Credentials In Files"),
        ],
        "usage": [
            "Seatbelt.exe -group=all",
            "Seatbelt.exe -group=user",
            "Seatbelt.exe -group=remote -computername=host2",
            "Seatbelt.exe OSInfo AntiVirus PowerShell",
        ],
        "detection": [
            "In-memory .NET assembly execution (execute-assembly) - CLR load into non-managed "
            "processes; ETW/AMSI .NET telemetry.",
            "Burst of diverse registry/WMI/file reads characteristic of mass enumeration.",
            "Signature/YARA on the assembly when dropped to disk.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/GhostPack/Seatbelt"},
        ],
        "status": "active",
        "first_seen": "2018",
    },
    # --------------------------------------------------- SharpHound / BloodHound
    {
        "id": "sharphound-bloodhound",
        "name": "SharpHound / BloodHound",
        "categories": ["discovery"],
        "summary": "Active Directory attack-path mapping. SharpHound is the collector; BloodHound ingests the data into a graph so operators can find shortest paths to Domain Admin and other high-value targets.",
        "description": (
            "BloodHound uses graph theory to reveal hidden and unintended relationships in an "
            "Active Directory (and Azure AD/Entra) environment. SharpHound (C#) collects "
            "sessions, ACLs, group memberships, trusts, GPOs and more; the BloodHound UI then "
            "computes attack paths (e.g. 'who can reach Domain Admin'). Both attackers and "
            "defenders (and the Community Edition / legacy versions) use it."
        ),
        "authors": ["Andy Robbins", "Rohan Vazarkar", "Will Schroeder", "SpecterOps"],
        "language": "C#, TypeScript",
        "license": "Apache-2.0",
        "os": ["windows", "linux", "macos"],
        "type": "collector-and-server",
        "repository": "https://github.com/SpecterOps/BloodHound",
        "homepage": "https://bloodhound.specterops.io/",
        "mitre_software_id": "S0521",
        "attack_techniques": [
            T("T1087.002", "Account Discovery: Domain Account"),
            T("T1069.002", "Permission Groups Discovery: Domain Groups"),
            T("T1482", "Domain Trust Discovery"),
            T("T1033", "System Owner/User Discovery"),
        ],
        "usage": [
            "SharpHound.exe -c All",
            "SharpHound.exe --collectionmethods Session,LoggedOn --loop",
            "# import the resulting zip into the BloodHound GUI and run built-in queries",
        ],
        "detection": [
            "High-volume LDAP queries enumerating users/groups/ACLs from a single host.",
            "SAMR / network session enumeration (SharpHound Session/LoggedOn) across many hosts.",
            "4662 with broad property reads; ldap traffic anomalies; honeytoken objects.",
        ],
        "references": [
            {"title": "BloodHound repository", "url": "https://github.com/SpecterOps/BloodHound"},
            {"title": "Documentation", "url": "https://bloodhound.specterops.io/"},
            {"title": "MITRE ATT&CK S0521", "url": "https://attack.mitre.org/software/S0521/"},
        ],
        "status": "active",
        "first_seen": "2016",
    },
    # ---------------------------------------------------------------- PowerView
    {
        "id": "powerview",
        "name": "PowerView",
        "categories": ["discovery"],
        "summary": "PowerShell tool for Active Directory reconnaissance: users, groups, ACLs, GPOs, trusts, sessions and local admin access, without needing RSAT.",
        "description": (
            "PowerView (part of PowerSploit, and continued in the 'dev' branch / PowerView.py) "
            "provides a rich set of Get-Domain* / Find-* cmdlets for enumerating Active "
            "Directory relationships and hunting for user sessions and local-admin access. It "
            "is a long-standing staple of AD recon and the conceptual precursor to BloodHound "
            "collection."
        ),
        "authors": ["Will Schroeder (@harmj0y)", "PowerSploit"],
        "language": "PowerShell",
        "license": "BSD-3-Clause",
        "os": ["windows"],
        "type": "script",
        "repository": "https://github.com/PowerShellMafia/PowerSploit",
        "homepage": "https://powersploit.readthedocs.io/",
        "mitre_software_id": "S0194",
        "attack_techniques": [
            T("T1087.002", "Account Discovery: Domain Account"),
            T("T1069.002", "Permission Groups Discovery: Domain Groups"),
            T("T1482", "Domain Trust Discovery"),
            T("T1018", "Remote System Discovery"),
        ],
        "usage": [
            "Import-Module .\\PowerView.ps1",
            "Get-DomainUser -SPN            # find kerberoastable accounts",
            "Find-DomainUserLocation        # hunt for target-user sessions",
            "Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs",
        ],
        "detection": [
            "PowerShell script-block logging (4104) matching PowerView function names.",
            "Bulk LDAP enumeration and SAMR session queries from a workstation.",
            "AMSI detection of the module content.",
        ],
        "references": [
            {"title": "PowerSploit repository", "url": "https://github.com/PowerShellMafia/PowerSploit"},
            {"title": "MITRE ATT&CK S0194 (PowerSploit)", "url": "https://attack.mitre.org/software/S0194/"},
        ],
        "status": "maintenance",
        "first_seen": "2014",
    },
    # ------------------------------------------------------------------ ADRecon
    {
        "id": "adrecon",
        "name": "ADRecon",
        "categories": ["discovery"],
        "summary": "PowerShell tool that gathers Active Directory information and produces a consolidated Excel (or CSV/JSON) report covering users, groups, computers, GPOs, trusts, ACLs and security posture.",
        "description": (
            "ADRecon extracts a broad, structured snapshot of an Active Directory environment "
            "and generates an analyst-friendly report. It is popular for both offensive recon "
            "and defensive assessments / audits because the single report highlights weak "
            "configurations (Kerberos policy, delegation, stale accounts, ACL issues)."
        ),
        "authors": ["Prashant Mahajan (@sense_of_security / Sense of Security)"],
        "language": "PowerShell",
        "license": "GPL-3.0",
        "os": ["windows"],
        "type": "script",
        "repository": "https://github.com/adrecon/ADRecon",
        "homepage": "https://github.com/adrecon/ADRecon",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1087.002", "Account Discovery: Domain Account"),
            T("T1482", "Domain Trust Discovery"),
            T("T1069.002", "Permission Groups Discovery: Domain Groups"),
            T("T1615", "Group Policy Discovery"),
        ],
        "usage": [
            ".\\ADRecon.ps1",
            ".\\ADRecon.ps1 -DomainController dc01 -Credential corp\\user",
            ".\\ADRecon.ps1 -OutputType CSV,JSON",
        ],
        "detection": [
            "Large single-session LDAP enumeration touching most directory partitions.",
            "PowerShell logging of ADRecon function names / module import.",
            "Excel/COM automation spawned from PowerShell on a non-analyst host.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/adrecon/ADRecon"},
        ],
        "status": "maintenance",
        "first_seen": "2018",
    },
    # ------------------------------------------------------------------- Sliver
    {
        "id": "sliver",
        "name": "Sliver",
        "categories": ["command-and-control", "lateral-movement"],
        "summary": "Open-source, cross-platform adversary-emulation / C2 framework by Bishop Fox. Supports implants over mTLS, WireGuard, HTTP(S) and DNS, with multiplayer operations, staging, and a large post-exploitation feature set.",
        "description": (
            "Sliver is a mature, actively developed OSS Command-and-Control framework and a "
            "common free alternative to Cobalt Strike. Implants are compiled in Go for "
            "Windows/Linux/macOS and communicate over mutually-authenticated TLS, WireGuard, "
            "HTTP(S) or DNS. It provides an armory of extensions, BOF/COFF loading, "
            "in-memory .NET execution, SOCKS/pivots, and multiplayer team operation via gRPC."
        ),
        "authors": ["Bishop Fox"],
        "language": "Go",
        "license": "GPL-3.0",
        "os": ["windows", "linux", "macos"],
        "type": "c2-framework",
        "repository": "https://github.com/BishopFox/sliver",
        "homepage": "https://sliver.sh/",
        "mitre_software_id": "S1068",
        "attack_techniques": [
            T("T1071.001", "Application Layer Protocol: Web Protocols"),
            T("T1071.004", "Application Layer Protocol: DNS"),
            T("T1573.002", "Encrypted Channel: Asymmetric Cryptography"),
            T("T1572", "Protocol Tunneling"),
            T("T1055", "Process Injection"),
            T("T1105", "Ingress Tool Transfer"),
        ],
        "usage": [
            "# server console",
            "generate --mtls example.com --os windows --save ./implant.exe",
            "https --lport 443            # start an HTTPS listener",
            "sessions ; use <id> ; interactive",
            "armory install <extension>",
        ],
        "detection": [
            "JARM/JA3(S) and default certificate fingerprints of Sliver listeners.",
            "Named-pipe and staging patterns; known default HTTP URIs/headers (tunable, so "
            "not reliable alone).",
            "Beaconing/jitter analysis on egress; DNS tunneling volume anomalies.",
            "Community Sigma/Suricata rules and the Sliver detection research from Immunefi/"
            "Microsoft; EDR detections for BOF/execute-assembly behaviour.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/BishopFox/sliver"},
            {"title": "Documentation / wiki", "url": "https://sliver.sh/docs"},
            {"title": "MITRE ATT&CK S1068", "url": "https://attack.mitre.org/software/S1068/"},
        ],
        "status": "active",
        "first_seen": "2019",
    },
    # -------------------------------------------------------------------- Havoc
    {
        "id": "havoc",
        "name": "Havoc",
        "categories": ["command-and-control"],
        "summary": "Modern, open-source C2 framework with a Qt GUI team server, a malleable-style profile, sleep obfuscation, and an extensible agent ('Demon') written in C.",
        "description": (
            "Havoc is a free C2 framework aimed at red teams and researchers. Its 'Demon' agent "
            "features indirect syscalls, sleep obfuscation (Ekko/Foliage-style), return-address "
            "spoofing, and support for object-file (BOF) execution. The team server is written "
            "in Go with a Python/C extensibility layer and a cross-platform GUI client."
        ),
        "authors": ["Paul Ungur (@C5pider)", "HavocFramework"],
        "language": "Go, C, Python",
        "license": "GPL-3.0",
        "os": ["windows", "linux"],
        "type": "c2-framework",
        "repository": "https://github.com/HavocFramework/Havoc",
        "homepage": "https://havocframework.com/",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1071.001", "Application Layer Protocol: Web Protocols"),
            T("T1055", "Process Injection"),
            T("T1027", "Obfuscated Files or Information"),
            T("T1620", "Reflective Code Loading"),
            T("T1573", "Encrypted Channel"),
        ],
        "usage": [
            "./havoc server --profile ./profiles/havoc.yaotl -v",
            "# connect with the GUI client, create an HTTP/HTTPS listener",
            "# build a Demon agent and use built-in / BOF post-ex commands",
        ],
        "detection": [
            "Default Demon agent indicators / signatures (research by security vendors).",
            "Sleep-obfuscation memory artifacts; unbacked executable memory with periodic RW->RX.",
            "Malleable profile defaults (URIs, headers) when operators do not customise them.",
            "Community YARA and Sigma rules for the Demon agent.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/HavocFramework/Havoc"},
            {"title": "Project site", "url": "https://havocframework.com/"},
        ],
        "status": "active",
        "first_seen": "2022",
    },
    # ------------------------------------------------------------------- Mythic
    {
        "id": "mythic",
        "name": "Mythic",
        "categories": ["command-and-control"],
        "summary": "Plug-n-play, multi-agent C2 framework with a web UI. Payloads ('agents') and communication channels ('C2 profiles') are containerised and swappable (Apollo, Poseidon, Medusa, etc.).",
        "description": (
            "Mythic is a modular, collaborative C2 platform built around Docker. The core "
            "provides operator UI, task/response tracking and reporting, while agents and C2 "
            "profiles are separate installable components. This lets teams mix an OS-specific "
            "agent (e.g. Apollo for Windows/.NET, Poseidon for cross-platform Go) with an "
            "arbitrary transport, and to extend the framework cleanly."
        ),
        "authors": ["Cody Thomas (@its_a_feature_ / SpecterOps)"],
        "language": "Python, Go, JavaScript",
        "license": "BSD-3-Clause",
        "os": ["linux"],
        "type": "c2-framework",
        "repository": "https://github.com/its-a-feature/Mythic",
        "homepage": "https://docs.mythic-c2.net/",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1071.001", "Application Layer Protocol: Web Protocols"),
            T("T1071.004", "Application Layer Protocol: DNS"),
            T("T1105", "Ingress Tool Transfer"),
            T("T1573", "Encrypted Channel"),
            T("T1055", "Process Injection"),
        ],
        "usage": [
            "sudo ./mythic-cli install github https://github.com/MythicAgents/apollo",
            "sudo ./mythic-cli start",
            "# browse to the web UI, generate a payload, create a C2 profile instance",
        ],
        "detection": [
            "Per-agent indicators (Apollo/Poseidon/Medusa each have their own signatures).",
            "C2-profile defaults when unmodified; beaconing analysis on the chosen transport.",
            "SpecterOps and community detections published per agent.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/its-a-feature/Mythic"},
            {"title": "Documentation", "url": "https://docs.mythic-c2.net/"},
            {"title": "Mythic agents org", "url": "https://github.com/MythicAgents"},
        ],
        "status": "active",
        "first_seen": "2018",
    },
    # ----------------------------------------------------------------- Covenant
    {
        "id": "covenant",
        "name": "Covenant",
        "categories": ["command-and-control"],
        "summary": ".NET (C#) collaborative C2 framework with a web interface. Uses 'Grunt' implants and 'Elite'/Task tasking; historically important as an early open .NET C2, now in maintenance.",
        "description": (
            "Covenant is a .NET command-and-control framework that emphasises usability and "
            "collaboration. Its Grunt implants run on .NET (Framework/Core), tasking is done "
            "through a web UI, and it pioneered accessible .NET post-exploitation tooling. "
            "Development has largely stalled (maintenance), but it remains a common lab/training "
            "C2 and a useful reference implementation."
        ),
        "authors": ["Ryan Cobb (@cobbr_io)"],
        "language": "C#",
        "license": "GPL-3.0",
        "os": ["windows", "linux"],
        "type": "c2-framework",
        "repository": "https://github.com/cobbr/Covenant",
        "homepage": "https://github.com/cobbr/Covenant/wiki",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1071.001", "Application Layer Protocol: Web Protocols"),
            T("T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
            T("T1055", "Process Injection"),
            T("T1105", "Ingress Tool Transfer"),
        ],
        "usage": [
            "dotnet run   # or run via the provided Docker image",
            "# create an HTTP listener, generate a Grunt launcher, task Grunts from the web UI",
        ],
        "detection": [
            "Default Grunt HTTP profiles (URIs, cookies, response formats).",
            "Well-known JA3/certificate and staging indicators.",
            "Community Sigma/YARA rules; EDR .NET in-memory execution telemetry.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/cobbr/Covenant"},
        ],
        "status": "maintenance",
        "first_seen": "2019",
    },
    # ------------------------------------------------------------------- Merlin
    {
        "id": "merlin",
        "name": "Merlin",
        "categories": ["command-and-control"],
        "summary": "Cross-platform post-exploitation C2 written in Go, notable for early adoption of HTTP/2 and HTTP/3 (QUIC) channels.",
        "description": (
            "Merlin is an OSS C2 framework focused on modern web transports. Agents are written "
            "in Go and run on Windows/Linux/macOS, communicating over HTTP/1.1, HTTP/2 and "
            "HTTP/3 (QUIC). It supports in-memory .NET assembly execution, BOFs, and modules, "
            "and is often used to study detection of newer protocol channels."
        ),
        "authors": ["Russel Van Tuyl (@Ne0nd0g)"],
        "language": "Go",
        "license": "GPL-3.0",
        "os": ["windows", "linux", "macos"],
        "type": "c2-framework",
        "repository": "https://github.com/Ne0nd0g/merlin",
        "homepage": "https://merlin-c2.readthedocs.io/",
        "mitre_software_id": None,
        "attack_techniques": [
            T("T1071.001", "Application Layer Protocol: Web Protocols"),
            T("T1573.002", "Encrypted Channel: Asymmetric Cryptography"),
            T("T1105", "Ingress Tool Transfer"),
            T("T1027", "Obfuscated Files or Information"),
        ],
        "usage": [
            "./merlinServer-Linux-x64",
            "# generate an agent, start an https/h2/h3 listener, interact with agents",
        ],
        "detection": [
            "HTTP/2 and HTTP/3 (QUIC) egress from unusual client processes.",
            "Default agent JA3/JA3S and URL patterns.",
            "Beaconing analysis; community Sigma rules.",
        ],
        "references": [
            {"title": "Official repository", "url": "https://github.com/Ne0nd0g/merlin"},
            {"title": "Documentation", "url": "https://merlin-c2.readthedocs.io/"},
        ],
        "status": "active",
        "first_seen": "2018",
    },
]


LOL_SITES = [
    {
        "id": "lolbas",
        "name": "LOLBAS (Living Off The Land Binaries, Scripts and Libraries)",
        "url": "https://lolbas-project.github.io/",
        "repository": "https://github.com/LOLBAS-Project/LOLBAS",
        "platform": "windows",
        "focus": "Signed/native Windows binaries, scripts and libraries that can be abused for execution, download, upload, credential theft, UAC bypass, etc.",
        "data_format": "YAML per entry (repo /yml), machine-consumable; site is a searchable index.",
        "content_type": "technique-catalog",
        "example_entries": ["certutil.exe (download)", "regsvr32.exe (execute)", "msbuild.exe (execute)"],
        "attack_mapping": "Each entry lists abuse commands and maps to MITRE ATT&CK where relevant (e.g. T1218 Signed Binary Proxy Execution).",
        "notes": "The canonical Windows LOLBin reference. Community-maintained, actively updated via PRs.",
    },
    {
        "id": "gtfobins",
        "name": "GTFOBins",
        "url": "https://gtfobins.github.io/",
        "repository": "https://github.com/GTFOBins/GTFOBins.github.io",
        "platform": "unix",
        "focus": "Unix binaries that can be abused to bypass local security restrictions - SUID/sudo privesc, shell escape, file read/write, reverse shells.",
        "data_format": "Markdown + YAML front matter per binary (repo /_gtfobins).",
        "content_type": "technique-catalog",
        "example_entries": ["find (sudo/SUID shell)", "vim (shell escape)", "tar (command execution)"],
        "attack_mapping": "Function tags (shell, command, file-read, suid, sudo, capabilities) rather than ATT&CK IDs.",
        "notes": "The Unix counterpart to LOLBAS; essential for Linux privilege escalation.",
    },
    {
        "id": "lolc2",
        "name": "LOLC2 (Living Off the Land Command and Control)",
        "url": "https://lolc2.github.io/",
        "repository": "https://github.com/lolc2/lolc2.github.io",
        "platform": "cross-platform",
        "focus": "Legitimate third-party services (SaaS, cloud, collaboration platforms) abused as covert C2 channels - e.g. Slack, Discord, Telegram, GitHub, Google/Microsoft services.",
        "data_format": "Structured entries listing the abused service, the C2 project/tool that uses it, and references.",
        "content_type": "technique-catalog",
        "example_entries": ["Slack as C2", "Google Sheets as C2", "GitHub as C2"],
        "attack_mapping": "Aligns with T1102 (Web Service) and T1071 (Application Layer Protocol).",
        "notes": "Focuses on C2-over-trusted-service tradecraft and which tools implement each channel.",
    },
    {
        "id": "loldrivers",
        "name": "LOLDrivers (Living Off The Land Drivers)",
        "url": "https://www.loldrivers.io/",
        "repository": "https://github.com/magicsword-io/LOLDrivers",
        "platform": "windows",
        "focus": "Known vulnerable and malicious Windows drivers (BYOVD - Bring Your Own Vulnerable Driver) used to disable EDR, escalate to kernel, etc.",
        "data_format": "YAML per driver with hashes, signatures and detections; provides Sigma/YARA and blocklist material.",
        "content_type": "technique-catalog",
        "example_entries": ["Vulnerable signed drivers (e.g. RTCore64.sys)", "malicious drivers"],
        "attack_mapping": "T1068 (Exploitation for Privilege Escalation), T1211/T1562 (impair defenses via BYOVD).",
        "notes": "Includes ready-to-use detection artifacts and hash lists for blocklisting.",
    },
    {
        "id": "wtfbins",
        "name": "WTFBins",
        "url": "https://wtfbins.wtf/",
        "repository": "https://github.com/wtfbins/wtfbins.github.io",
        "platform": "cross-platform",
        "focus": "Benign binaries that exhibit malware-like behaviour (network beacons, odd process trees) - useful for tuning detections and reducing false positives, the inverse of a LOLBin catalog.",
        "data_format": "Structured entries describing the confusing behaviour.",
        "content_type": "reference-catalog",
        "example_entries": ["Legit apps that beacon or inject and look malicious"],
        "attack_mapping": "N/A - defensive false-positive reference.",
        "notes": "Complements LOLBAS: what looks bad but is actually normal.",
    },
    {
        "id": "hijacklibs",
        "name": "HijackLibs",
        "url": "https://hijacklibs.net/",
        "repository": "https://github.com/wietze/HijackLibs",
        "platform": "windows",
        "focus": "Catalog of DLL hijacking opportunities: which legitimate executables load which DLLs from hijackable search-order locations.",
        "data_format": "YAML per entry mapping vulnerable executable -> hijackable DLL and expected path.",
        "content_type": "technique-catalog",
        "example_entries": ["Signed apps vulnerable to DLL search-order hijacking / sideloading"],
        "attack_mapping": "T1574.001 (DLL Search Order Hijacking), T1574.002 (DLL Side-Loading).",
        "notes": "Directly supports both offensive persistence/execution and defensive detection.",
    },
    {
        "id": "filesec",
        "name": "Filesec.io",
        "url": "https://filesec.io/",
        "repository": "https://github.com/mttaggart/filesec",
        "platform": "windows",
        "focus": "File extensions abused by attackers (for delivery, execution, defense evasion), with notes on how each is used and mitigations.",
        "data_format": "JSON/site entries per extension.",
        "content_type": "reference-catalog",
        "example_entries": [".lnk", ".iso", ".hta", ".one"],
        "attack_mapping": "Maps to phishing/execution/defense-evasion techniques (e.g. T1204 User Execution).",
        "notes": "Handy for phishing-payload and email-filtering discussions.",
    },
    {
        "id": "malapi",
        "name": "MalAPI.io",
        "url": "https://malapi.io/",
        "repository": "https://github.com/mrd0x/malapi",
        "platform": "windows",
        "focus": "Windows API functions commonly used by malware, grouped by capability (injection, evasion, credential access, etc.).",
        "data_format": "Site entries per API with category and description.",
        "content_type": "reference-catalog",
        "example_entries": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "attack_mapping": "Capability groupings align to ATT&CK tactics (e.g. Process Injection T1055).",
        "notes": "Useful for malware analysis and for building behavioural detections.",
    },
    {
        "id": "lots",
        "name": "LOTS Project (Living Off Trusted Sites)",
        "url": "https://lots-project.com/",
        "repository": "https://github.com/mrd0x/lots-project.com",
        "platform": "cross-platform",
        "focus": "Legitimate, trusted domains that attackers abuse for phishing, download, data exfiltration and C2 because traffic to them blends in.",
        "data_format": "Site entries per trusted domain/service.",
        "content_type": "technique-catalog",
        "example_entries": ["github.com", "pastebin.com", "*.blob.core.windows.net"],
        "attack_mapping": "T1102 (Web Service), T1567 (Exfiltration Over Web Service).",
        "notes": "Complements LOLC2: which trusted domains blend into normal traffic.",
    },
]


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    for tool in TOOLS:
        tdir = os.path.join(TOOLS_DIR, tool["id"])
        os.makedirs(tdir, exist_ok=True)
        meta = dict(tool)
        meta["last_reviewed"] = LAST_REVIEWED
        meta.setdefault("release_history", [])  # filled/updated by refresh automation
        write_json(os.path.join(tdir, "metadata.json"), meta)

        # Seed a CHANGELOG stub only if none exists (preserve hand-edited history).
        changelog = os.path.join(tdir, "CHANGELOG.md")
        if not os.path.exists(changelog):
            with open(changelog, "w", encoding="utf-8") as f:
                f.write(f"# {tool['name']} - catalog change log\n\n")
                f.write(
                    "Track notable upstream releases, new capabilities, and detection "
                    "changes here. See `metadata.json` -> `release_history` for structured "
                    "version data.\n\n"
                )
                f.write(f"## {LAST_REVIEWED}\n\n- Initial catalog entry created.\n")

    for site in LOL_SITES:
        s = dict(site)
        s["last_reviewed"] = LAST_REVIEWED
        write_json(os.path.join(LOL_SITES_DIR, f"{site['id']}.json"), s)

    print(f"Seeded {len(TOOLS)} tools and {len(LOL_SITES)} LOL sites.")


if __name__ == "__main__":
    main()
