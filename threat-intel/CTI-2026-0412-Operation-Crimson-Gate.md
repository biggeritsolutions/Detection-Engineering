# [DEMO] Cyber Threat Intelligence Report — Operation Crimson Gate

> **Portfolio Note:** This report is a demonstration artifact created for professional portfolio purposes.
> All threat actors, infrastructure, and campaign details are fictional composites based on real-world
> DarkGate malware behavior documented in public threat intelligence. No real victims, infrastructure,
> or organizations are identified.

---

## Report Metadata

| Field             | Value                                            |
|-------------------|--------------------------------------------------|
| **Report ID**     | CTI-2026-0412                                    |
| **Series**        | Operation Crimson Gate (CG-3 of 3)               |
| **Date Published**| 2026-02-17                                       |
| **Last Updated**  | 2026-02-17                                       |
| **Version**       | 1.0                                              |
| **TLP**           | TLP:CLEAR                                        |
| **PAP**           | PAP:WHITE                                        |
| **Confidence**    | **HIGH** (7/10) — see Section 9                  |
| **Severity**      | **CRITICAL**                                     |
| **Prepared By**   | David Bigger — github.com/biggeritsolutions     |
| **Reviewed By**   | Self-reviewed (demo artifact)                    |
| **MITRE Groups**  | UNC5211 (Financial Motivated)                    |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Actor Profile](#2-threat-actor-profile)
3. [Campaign Overview](#3-campaign-overview)
4. [Technical Analysis](#4-technical-analysis)
5. [MITRE ATT&CK Mapping](#5-mitre-attck-mapping)
6. [Diamond Model of Intrusion Analysis](#6-diamond-model-of-intrusion-analysis)
7. [Indicators of Compromise](#7-indicators-of-compromise)
8. [Detection & Threat Hunting](#8-detection--threat-hunting)
9. [Mitigation & Remediation](#9-mitigation--remediation)
10. [Confidence Assessment](#10-confidence-assessment)
11. [Conclusion](#11-conclusion)
12. [References](#12-references)

---

## 1. Executive Summary

Between **February 10 and February 15, 2026**, a targeted phishing campaign was observed against
North American small-to-medium businesses (SMBs) across financial services, healthcare, and legal
sectors. The campaign — tracked internally as **Operation Crimson Gate** — deploys **DarkGate v6.2**,
a sophisticated Loader/RAT sold as Malware-as-a-Service (MaaS), to establish persistent access and
stage secondary payloads including credential harvesters and potential ransomware.

### Key Findings

| Finding             | Detail                                                                      |
|---------------------|-----------------------------------------------------------------------------|
| **Initial Vector**  | Spearphishing email with high-urgency "Pending Invoice" lure                |
| **Delivery Method** | Malicious link → ZIP archive → obfuscated VBScript                          |
| **Payload**         | DarkGate v6.2 (Loader/RAT — MaaS)                                          |
| **Hosting**         | Legitimate cloud services (Dropbox, Google Drive) for payload staging       |
| **Persistence**     | Registry Run Key, Startup Folder                                            |
| **C2**              | HTTPS over non-standard port to actor-controlled infrastructure             |
| **Impact**          | Credential theft, keylogging, remote desktop, ransomware pre-staging        |
| **Risk Rating**     | **CRITICAL** — Active campaign, high confidence IOCs, SMB sector targeted   |

### Risk Score Breakdown

```
Threat Actor Capability:   ████████░░  8/10 (MaaS operator, low barrier to entry)
Infrastructure Maturity:   ███████░░░  7/10 (Cloud-hosted, bulletproof hosting mix)
Campaign Sophistication:   ██████░░░░  6/10 (AV evasion, process injection, sandbox checks)
SMB Exposure:              █████████░  9/10 (Low security budgets, limited visibility)
Overall Risk:              CRITICAL
```

---

## 2. Threat Actor Profile

### Attribution: UNC5211

| Attribute         | Detail                                                              |
|-------------------|---------------------------------------------------------------------|
| **Designation**   | UNC5211 (Unclassified — Financial Motivation)                       |
| **Aliases**       | TA800, TG-Crimson (internal tracking)                               |
| **Motivation**    | Financial gain (credential theft → account takeover → wire fraud)   |
| **Origin**        | Eastern Europe (assessed, moderate confidence)                      |
| **Active Since**  | 2024-Q3                                                             |
| **Target Sectors**| SMB Finance, Legal, Healthcare — North America primarily            |
| **Toolset**       | DarkGate MaaS, Lumma Stealer, Cobalt Strike (post-compromise)       |

### Actor History

UNC5211 is a financially motivated threat group that has operated opportunistically since mid-2024.
The group does not develop custom tooling — instead, purchasing access to mature MaaS offerings
(DarkGate, Lumma Stealer) and combining them with commodity phishing infrastructure.

**Prior campaigns attributed to UNC5211:**

- **CG-1 (2025-Q3):** DocuSign lure → Lumma Stealer. Targeted Pacific Northwest law firms.
- **CG-2 (2025-Q4):** Microsoft 365 credential phish → AiTM proxy. Targeted healthcare billing.
- **CG-3 (2026-Feb):** Invoice lure → DarkGate v6.2. *(This report.)*

The shift to DarkGate in CG-3 suggests the actor is expanding beyond stealer-only operations toward
persistent access with ransomware staging potential — a significant escalation from prior activity.

---

## 3. Campaign Overview

### Timeline

```
2026-02-10  ── First phishing emails observed (financial sector, Chicago/Denver)
2026-02-11  ── Payload infrastructure identified (185.156.74[.]12 goes live)
2026-02-12  ── Cloud-hosted staging domain registered: secure-billing-portal[.]top
2026-02-13  ── First confirmed DarkGate C2 beacon observed
2026-02-14  ── IOC shared to community (internal ISAC report)
2026-02-15  ── Campaign volume drops; infrastructure rotation begins
2026-02-17  ── This report published (TLP:CLEAR)
```

### Targeting Profile

- **Geography:** United States (primary), Canada (secondary)
- **Sectors:** Professional services (legal, accounting), healthcare billing, manufacturing
- **Employee Count:** Victims primarily 10–500 employees — consistent with limited IT security staff
- **Lure Theme:** Overdue invoice, payment confirmation, vendor billing dispute

---

## 4. Technical Analysis

### 4.1 Infection Chain Overview

```
[Phishing Email]
  │
  │  "Your invoice #INV-10482 is 14 days overdue — click to view"
  │
  ▼
[Malicious Link — legitimate cloud redirect]
  │  https://dropbox[.]com/s/XXXX/Invoice_10482.zip  ← bypasses email gateway
  │
  ▼
[ZIP Archive: Invoice_10482.zip]
  │  Contains: Invoice_10482.vbs  (obfuscated VBScript, ~85KB)
  │
  ▼
[Stage 1: VBScript Execution via wscript.exe]
  │  Spawns mshta.exe → fetches remote HTA/PS1 payload
  │
  ▼
[Stage 2: PowerShell Anti-Analysis + Dropper]
  │  VM/sandbox checks → AMSI bypass → downloads DarkGate loader
  │
  ▼
[Stage 3: DarkGate Loader (AutoIt compiled)]
  │  Process injection into regasm.exe or svchost.exe
  │  Establishes Registry Run Key for persistence
  │
  ▼
[Stage 4: DarkGate RAT Modules Active]
     ├── Keylogger
     ├── Credential harvester (browsers, email clients)
     ├── Remote desktop (hVNC)
     ├── Crypto miner (optional — actor-selectable)
     └── Reverse shell → further payload staging
```

---

### 4.2 Stage 1: Phishing and Initial Delivery

The phishing email is crafted to impersonate a known vendor billing system. Key observations:

- **Sender spoofing:** Display name uses a trusted vendor brand; actual SMTP origin is a compromised
  shared hosting server (no DMARC enforcement on sender domain).
- **Link redirect chain:** Phishing link → Dropbox-hosted ZIP → victim extracts and executes.
  Legitimate cloud hosting avoids URL-based email gateway blocking.
- **Lure urgency:** Subject line includes dollar amount and days overdue to drive clicks without
  scrutiny. Observed subject formats:
  - `URGENT: Invoice #[ID] – Payment 14 days overdue`
  - `ACTION REQUIRED: Your account balance $[amount]`

**No malicious attachment is used in the email itself** — the link-to-ZIP approach avoids attachment
scanning entirely.

---

### 4.3 Stage 2: VBScript Downloader

The VBScript (`Invoice_10482.vbs`) is heavily obfuscated with string concatenation and character
substitution to evade static analysis. Functionally it:

1. Invokes `wscript.exe` to execute the script silently.
2. Uses `mshta.exe` to fetch and execute a remote HTA application from actor infrastructure.
3. The HTA contains embedded PowerShell that acts as the Stage 2 dropper.

**Notable obfuscation techniques:**
- Variable names are randomized hex strings.
- Strings are split and reassembled at runtime.
- `Chr()` function used to avoid plaintext URL in static scan.

---

### 4.4 Stage 3: PowerShell Dropper and Anti-Analysis

The Stage 2 PowerShell script performs environment checks before proceeding:

**Sandbox / VM Detection Checks:**

| Check                          | Method                                              |
|--------------------------------|-----------------------------------------------------|
| CPUID hypervisor bit           | `Get-WmiObject Win32_ComputerSystem` → check Manufacturer |
| Process enumeration            | Checks for `vmtoolsd.exe`, `vboxservice.exe`, `wireshark.exe`, `procmon.exe` |
| MAC address OUI                | Checks for known VM vendor OUIs (VMware: `00:0C:29`, VirtualBox: `08:00:27`) |
| Screen resolution              | Aborts if resolution ≤ 1024×768 (common sandbox default) |
| Username / hostname patterns   | Checks for `SANDBOX`, `MALTEST`, `VIRUS`, `USER` exact matches |
| Uptime                         | Aborts if system uptime < 10 minutes                |

**If no sandbox detected:**
- AMSI bypass executed in memory (no disk write).
- DarkGate loader binary fetched from `secure-billing-portal[.]top/cdn/mscorsvw.exe`.
- Binary saved to `%AppData%\Roaming\mscorsvw.exe` (mimics legitimate .NET runtime process name).

---

### 4.5 Stage 4: DarkGate Loader and RAT

DarkGate v6.2 is an AutoIt-compiled loader/RAT sold as MaaS. Once executed:

1. **Process Injection:** DarkGate injects its code into `regasm.exe` (a legitimate .NET tool) or
   `svchost.exe` using process hollowing. This hides the malicious process under a trusted parent.

2. **Persistence:** Creates a Registry Run Key:
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsCoreUpdate`
   pointing to `%AppData%\Roaming\mscorsvw.exe`

3. **C2 Beacon:** Initiates HTTPS beacon to `185.156.74[.]12:8443` every 60 seconds.
   Traffic mimics legitimate browser HTTPS using fake browser User-Agent strings.

4. **Active Modules (observed in this campaign):**
   - **hVNC** — Hidden remote desktop session (victim unaware)
   - **Keylogger** — All keystrokes logged and exfiltrated
   - **Credential stealer** — Browser saved passwords, email client credentials
   - **File manager** — Actor browses victim filesystem for sensitive documents

**DarkGate is NOT self-propagating** — lateral movement, if observed, is actor-driven via hVNC.

---

## 5. MITRE ATT&CK Mapping

**Framework Version:** ATT&CK v15 (Enterprise)

| Phase               | Tactic              | Technique ID    | Technique Name                                       | Observed Detail                              |
|---------------------|---------------------|-----------------|------------------------------------------------------|----------------------------------------------|
| Initial Access      | Initial Access      | T1566.002       | Phishing: Malicious Link                             | "Invoice" lure → cloud-hosted ZIP            |
| Execution           | Execution           | T1059.005       | Command & Scripting Interpreter: VBScript            | Obfuscated `.vbs` dropper                    |
| Execution           | Execution           | T1059.001       | Command & Scripting Interpreter: PowerShell          | Stage 2 dropper + AMSI bypass                |
| Execution           | Execution           | T1218.005       | System Binary Proxy Execution: Mshta                 | `mshta.exe` fetches remote HTA               |
| Defense Evasion     | Defense Evasion     | T1027           | Obfuscated Files or Information                      | String obfuscation in VBScript               |
| Defense Evasion     | Defense Evasion     | T1055.012       | Process Injection: Process Hollowing                 | DarkGate hollows `regasm.exe`                |
| Defense Evasion     | Defense Evasion     | T1497.001       | Virtualization/Sandbox Evasion: System Checks        | VM/sandbox detection before payload drop     |
| Defense Evasion     | Defense Evasion     | T1562.001       | Impair Defenses: Disable or Modify Tools             | AMSI bypass in memory                        |
| Defense Evasion     | Defense Evasion     | T1036.005       | Masquerading: Match Legitimate Name                  | `mscorsvw.exe` mimics .NET runtime           |
| Persistence         | Persistence         | T1547.001       | Boot or Logon Autostart: Registry Run Keys           | `HKCU\...\Run\MsCoreUpdate`                  |
| Credential Access   | Credential Access   | T1555.003       | Credentials from Password Stores: Web Browsers      | Browser credential harvesting module         |
| Credential Access   | Credential Access   | T1056.001       | Input Capture: Keylogging                            | DarkGate keylogger module                    |
| Discovery           | Discovery           | T1057            | Process Discovery                                    | Sandbox evasion via process enumeration      |
| Discovery           | Discovery           | T1082            | System Information Discovery                         | Hardware fingerprinting (CPUID, OUI)         |
| Command & Control   | Command & Control   | T1071.001       | Application Layer Protocol: Web Protocols            | HTTPS C2 beacon on port 8443                 |
| Command & Control   | Command & Control   | T1573.001       | Encrypted Channel: Symmetric Cryptography            | DarkGate C2 encrypted comms                  |
| Collection          | Collection          | T1113            | Screen Capture                                       | hVNC module                                  |
| Exfiltration        | Exfiltration        | T1041            | Exfiltration Over C2 Channel                         | Credentials/keystrokes exfiltrated via C2    |

---

## 6. Diamond Model of Intrusion Analysis

```
                    ┌─────────────────────────────────┐
                    │           ADVERSARY             │
                    │  UNC5211 — Financial Motivated  │
                    │  MaaS operator, Eastern Europe  │
                    └────────────────┬────────────────┘
                                     │
                    Capability       │       Infrastructure
            ┌────────────────────────┼──────────────────────────┐
            │                        │                           │
  ┌─────────▼─────────┐              │             ┌────────────▼──────────┐
  │   CAPABILITY       │              │             │   INFRASTRUCTURE      │
  │                    │              │             │                       │
  │  DarkGate v6.2     │              │             │  185.156.74[.]12      │
  │  (MaaS Loader/RAT) │              │             │  secure-billing-      │
  │  Lumma Stealer     │              │             │    portal[.]top       │
  │  VBScript/PS1      │              │             │  Dropbox (staging)    │
  │  obfuscation       │              │             │  Google Drive (staging│
  └────────────────────┘              │             └───────────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │             VICTIM               │
                    │  North American SMBs             │
                    │  Finance / Legal / Healthcare    │
                    │  10–500 employees                │
                    │  Limited security tooling        │
                    └─────────────────────────────────┘
```

**Socio-Political Axis:** No political motivation assessed. Pure financial gain.
**Technology Axis:** Commodity tooling (MaaS) combined with social engineering and legitimate
cloud infrastructure abuse — low technical barrier, high operational impact on under-resourced targets.

---

## 7. Indicators of Compromise

All IOCs were cross-referenced against VirusTotal, AbuseIPDB, and URLhaus at time of publication.
Confidence levels reflect analyst assessment of attribution reliability.

### Network Indicators

| Type    | Indicator                        | Confidence | Context                            | First Seen   |
|---------|----------------------------------|------------|------------------------------------|--------------|
| IPv4    | `185.156.74[.]12`               | HIGH       | DarkGate C2 — port 8443            | 2026-02-11   |
| IPv4    | `91.243.44[.]201`               | MEDIUM     | Secondary C2 / failover            | 2026-02-13   |
| Domain  | `secure-billing-portal[.]top`   | HIGH       | Malicious payload hosting          | 2026-02-12   |
| Domain  | `cdn-invoice-services[.]com`    | MEDIUM     | Redirect / TDS infrastructure      | 2026-02-10   |
| URL     | `/cdn/mscorsvw.exe`             | HIGH       | DarkGate loader download path      | 2026-02-12   |
| URL     | `/gate.php`                     | HIGH       | DarkGate C2 check-in endpoint      | 2026-02-13   |

> **Defanging note:** All IPs and domains are defanged using bracket notation `[.]` and are safe
> to share. Re-fang only in controlled environments (e.g., firewall blocklist import).

### File Indicators

| Type      | Indicator                                                          | Confidence | Context                              |
|-----------|--------------------------------------------------------------------|------------|--------------------------------------|
| SHA-256   | `a3f1d2e4b9c7056f8e1234abcd5678ef90123456789abcdef01234567890abc` | HIGH       | DarkGate loader — `mscorsvw.exe`     |
| SHA-256   | `5c2a9b3d8e7f1045c6789012abcd3456ef789012abcdef3456789012abcdef34` | HIGH       | Obfuscated VBScript dropper          |
| SHA-1     | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`                       | MEDIUM     | ZIP archive container                |
| File Path | `%AppData%\Roaming\mscorsvw.exe`                                   | HIGH       | DarkGate persistence location        |
| File Path | `%TEMP%\Invoice_10482.vbs`                                         | HIGH       | VBScript dropper (temp staging)      |
| Registry  | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsCoreUpdate` | HIGH       | Persistence registry key             |

### Email Indicators

| Type          | Indicator                              | Confidence | Context                         |
|---------------|----------------------------------------|------------|---------------------------------|
| Subject regex | `(URGENT\|ACTION REQUIRED).*Invoice`  | HIGH       | Phishing lure subject pattern   |
| Sender domain | `@[billing/invoice]-[vendor][.]com`   | MEDIUM     | Look-alike domain pattern       |

---

## 8. Detection & Threat Hunting

### 8.1 Sigma Rules

#### Rule 1: VBScript Spawning MSHTA for Remote Execution

```yaml
title: Suspicious MSHTA Spawned by Script Interpreter
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects mshta.exe launched by a script interpreter (wscript.exe or cscript.exe),
  a technique used by DarkGate and similar loaders to execute remote HTA payloads.
  This parent-child relationship is rarely legitimate.
author: David Bigger
date: 2026/02/17
references:
  - https://attack.mitre.org/techniques/T1218/005/
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.005
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    Image|endswith: '\mshta.exe'
  filter_legit:
    CommandLine|contains: 'about:blank'  # Common false positive pattern
  condition: selection and not filter_legit
fields:
  - Image
  - ParentImage
  - CommandLine
  - ParentCommandLine
  - User
  - ComputerName
falsepositives:
  - Legacy enterprise HTA applications (extremely rare in SMB)
  - Custom IT automation using HTA (should be baselined and suppressed)
level: high
```

---

#### Rule 2: DarkGate Persistence via Registry Run Key

```yaml
title: Suspicious Registry Run Key Masquerading as .NET Runtime
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects creation of a Registry Run key pointing to an executable in the
  AppData\Roaming directory with a name mimicking legitimate .NET runtime
  binaries (e.g., mscorsvw.exe). DarkGate uses this pattern for persistence.
author: David Bigger
date: 2026/02/17
references:
  - https://attack.mitre.org/techniques/T1547/001/
tags:
  - attack.persistence
  - attack.t1547.001
  - attack.defense_evasion
  - attack.t1036.005
logsource:
  category: registry_set
  product: windows
detection:
  selection_key:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  selection_value:
    Details|contains:
      - '\AppData\Roaming\'
      - '\AppData\Local\'
    Details|endswith:
      - 'mscorsvw.exe'
      - 'svchost.exe'
      - 'regasm.exe'
  condition: selection_key and selection_value
fields:
  - TargetObject
  - Details
  - Image
  - User
falsepositives:
  - Legitimate software installing to AppData (check signing status of referenced binary)
level: high
```

---

#### Rule 3: Process Injection into regasm.exe from Unexpected Parent

```yaml
title: regasm.exe Spawned by Unexpected Parent Process
id: c3d4e5f6-a7b8-9012-cdef-012345678902
status: experimental
description: >
  Detects regasm.exe (a .NET assembly registration tool) being spawned by
  an unexpected parent process. DarkGate and other loaders inject into
  regasm.exe as a defense evasion technique. Legitimate use of regasm.exe
  is typically initiated by installers or msiexec.exe.
author: David Bigger
date: 2026/02/17
references:
  - https://attack.mitre.org/techniques/T1055/012/
tags:
  - attack.defense_evasion
  - attack.t1055.012
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regasm.exe'
  filter_legit_parents:
    ParentImage|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
      - '\devenv.exe'
      - '\MSBuild.exe'
  condition: selection and not filter_legit_parents
fields:
  - Image
  - ParentImage
  - CommandLine
  - User
falsepositives:
  - Software installers with non-standard parent chains
  - Developer environments
level: medium
```

---

### 8.2 YARA Rule — DarkGate Loader Detection

```yara
rule DarkGate_Loader_v6_Indicators
{
    meta:
        description = "Detects DarkGate v6.x loader based on string and behavioral indicators"
        author      = "David Bigger"
        date        = "2026-02-17"
        version     = "1.0"
        reference   = "CTI-2026-0412 — Operation Crimson Gate"
        hash        = "a3f1d2e4b9c7056f8e1234abcd5678ef90123456789abcdef01234567890abc"
        tlp         = "TLP:CLEAR"

    strings:
        // DarkGate C2 check-in path patterns
        $c2_gate    = "/gate.php" ascii wide
        $c2_panel   = "/panel/" ascii wide

        // Anti-analysis strings
        $vm_check1  = "vmtoolsd.exe" ascii wide nocase
        $vm_check2  = "vboxservice.exe" ascii wide nocase
        $vm_check3  = "VirtualBox" ascii wide nocase

        // AutoIt compiled binary markers
        $autoit1    = "This is a compiled AutoIt" ascii
        $autoit2    = "AU3!" ascii

        // DarkGate module identifiers (obfuscated, pattern-based)
        $dg_hvnc    = { 68 56 4E 43 }  // "hVNC" bytes
        $dg_key     = { 4B 65 79 4C 6F 67 }  // "KeyLog" bytes

        // Persistence artifact
        $persist    = "MsCoreUpdate" ascii wide

    condition:
        uint16(0) == 0x5A4D  // PE file
        and filesize < 5MB
        and (
            ($autoit1 or $autoit2)
            and 2 of ($c2_gate, $c2_panel, $persist)
            and 1 of ($vm_check1, $vm_check2, $vm_check3)
        )
}
```

---

### 8.3 KQL (Microsoft Sentinel / Defender 365)

**Hunting Query: MSHTA Network Activity**

```kql
// Detect mshta.exe making outbound network connections (DarkGate Stage 2 indicator)
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "mshta.exe"
| where RemotePort in (80, 443, 8443)
| where RemoteIPType != "Loopback"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

**Hunting Query: AppData Executable with Run Key**

```kql
// Detect executables placed in AppData that also have a corresponding Run Key
let AppDataExec = DeviceFileEvents
| where FolderPath contains @"\AppData\Roaming\"
| where FileName endswith ".exe"
| project DeviceName, FileName, FolderPath, Timestamp;
let RunKeys = DeviceRegistryEvents
| where RegistryKey contains @"CurrentVersion\Run"
| where RegistryValueData contains @"AppData"
| project DeviceName, RegistryKey, RegistryValueName, RegistryValueData, Timestamp;
AppDataExec
| join kind=inner RunKeys on DeviceName
| project DeviceName, FileName, FolderPath, RegistryKey, RegistryValueName, RegistryValueData
```

---

### 8.4 Threat Hunting Pivots

If any of the above detection rules fire, expand your investigation using these pivot points:

| Pivot                        | What to Look For                                                    |
|------------------------------|---------------------------------------------------------------------|
| Parent process of mshta.exe  | wscript.exe / cscript.exe — confirms VBScript execution             |
| Child processes of regasm.exe| Any network connections or file writes — indicates hollowing         |
| Registry Run Keys user scope | HKCU run keys pointing to AppData — persistence established          |
| DNS queries from endpoint    | Lookups for `secure-billing-portal[.]top` or similar               |
| HTTPS to port 8443           | Unusual destination — most legitimate traffic uses 443              |
| Files in %AppData%\Roaming\  | Executables with .NET-mimicking names created in last 7 days        |
| Scheduled tasks              | Any task created by wscript.exe or PowerShell in the campaign window |
| Credential vault access      | DPAPI calls from injected process (credential harvesting indicator) |

---

## 9. Mitigation & Remediation

### Immediate Actions (0–24 Hours)

- [ ] Block all IOCs from Section 7 at perimeter firewall, DNS sinkholes, and proxy.
- [ ] Search SIEM/EDR logs for the Sigma rules above — triage any hits immediately.
- [ ] Alert SOC / IT staff to watch for `mshta.exe`, `regasm.exe` anomalies.
- [ ] Submit file hashes to EDR threat intel feeds for retroactive hunting.

### Short-Term Actions (1–7 Days)

- [ ] Run KQL hunting queries across all endpoints for the campaign window (Feb 10–Feb 17, 2026).
- [ ] Conduct targeted phishing simulation — "invoice" theme — to gauge user susceptibility.
- [ ] Review email gateway logs for Dropbox / Google Drive links delivered Feb 10–17.
- [ ] Ensure `.vbs` and `.js` file extensions are mapped to Notepad via GPO (not wscript/cscript).

### Strategic Mitigations

| Control                           | Implementation                                                      | CIS Control | NIST CSF     |
|-----------------------------------|---------------------------------------------------------------------|-------------|--------------|
| Email gateway filtering           | Block ZIP/VBS/JS attachments; flag cloud storage links              | CIS 9       | PR.AC-5      |
| Script execution restrictions     | Block wscript/cscript for non-admin users via GPO / AppLocker       | CIS 4       | PR.PT-3      |
| AMSI enforcement                  | Ensure AMSI is not bypassed — verify endpoint AV integration        | CIS 10      | PR.AT-1      |
| Endpoint Detection & Response     | Deploy EDR with process injection detection                         | CIS 10      | DE.CM-4      |
| Network segmentation              | Restrict outbound HTTPS on non-standard ports (e.g., 8443)          | CIS 12      | PR.AC-5      |
| Phishing-resistant MFA            | Deploy FIDO2/hardware MFA for email and VPN                         | CIS 6       | PR.AC-7      |
| DNS filtering                     | Block newly registered / low-reputation domains at DNS layer        | CIS 9       | PR.PT-3      |
| Privilege restriction             | Run users without local admin; limit PowerShell execution policy     | CIS 5       | PR.AC-4      |
| Security awareness training       | Phishing simulation focused on invoice/payment themes               | CIS 14      | PR.AT-1      |
| Registry monitoring               | Alert on Run Key creation under HKCU pointing to AppData            | CIS 10      | DE.CM-7      |

---

## 10. Confidence Assessment

### Methodology

Confidence is assessed using a structured framework evaluating source reliability,
corroboration across independent sources, and recency of evidence.

| Dimension                    | Score  | Rationale                                                    |
|------------------------------|--------|--------------------------------------------------------------|
| IOC Reliability              | 8/10   | Network IOCs confirmed in VirusTotal + AbuseIPDB             |
| Attribution Confidence       | 5/10   | UNC5211 assessed — no definitive attribution possible        |
| TTP Consistency              | 9/10   | Infection chain matches documented DarkGate MaaS behavior    |
| Campaign Continuity          | 7/10   | Infrastructure overlap with CG-1 and CG-2 (moderate link)   |
| Victim Data                  | 4/10   | Limited victim telemetry available (demo constraint)         |
| **Overall Confidence**       | **7/10 HIGH** | Reliable for defensive action; attribution is assessed |

### Confidence Scale Reference

| Label     | Score  | Meaning                                                              |
|-----------|--------|----------------------------------------------------------------------|
| CONFIRMED | 10/10  | Directly observed, multiple independent sources, forensic evidence   |
| HIGH      | 7–9    | Strong corroboration, reliable sources, consistent TTPs              |
| MEDIUM    | 4–6    | Partial corroboration, some ambiguity, limited source diversity      |
| LOW       | 1–3    | Single source, unverified, speculative                               |
| UNKNOWN   | 0      | Insufficient data to assess                                          |

---

## 11. Conclusion

Operation Crimson Gate represents a financially motivated threat actor (UNC5211) escalating its
capabilities from credential phishing toward full persistent access via DarkGate RAT. The shift
to a Loader/RAT model with ransomware staging potential is a significant escalation from prior
campaigns and warrants elevated vigilance across the SMB sector.

**Key takeaways:**

1. **Cloud storage is being weaponized** to bypass email security controls — inspect, don't trust,
   links to Dropbox/Google Drive in unsolicited emails.

2. **DarkGate is MaaS** — this actor has low technical capability but high operational impact
   due to the quality of the purchased tooling. Expect continued use by multiple actors.

3. **SMB-sector targeting is intentional** — smaller organizations with limited security budgets
   and reduced visibility are the path of least resistance for this actor.

4. **Ransomware staging is a credible next step** — if DarkGate access is retained, the actor
   historically monetizes access through ATO (account takeover) or sells access to ransomware groups.

We recommend treating any IOC match as a **high-priority incident** requiring immediate containment,
forensic review of the affected endpoint, and credential reset for the affected user and any
accounts accessed from that machine.

---

## 12. References

| # | Source                                                                                   |
|---|------------------------------------------------------------------------------------------|
| 1 | MITRE ATT&CK Enterprise Matrix v15 — https://attack.mitre.org                           |
| 2 | DarkGate Malware Analysis — Recorded Future (public report, 2024)                        |
| 3 | DarkGate MaaS Campaign Analysis — Trellix Advanced Research Center (2023–2025)           |
| 4 | AbuseIPDB — https://www.abuseipdb.com                                                   |
| 5 | VirusTotal — https://www.virustotal.com                                                  |
| 6 | URLhaus — https://urlhaus.abuse.ch                                                       |
| 7 | Sigma Rule Repository — https://github.com/SigmaHQ/sigma                                |
| 8 | YARA Documentation — https://yara.readthedocs.io                                        |
| 9 | CIS Controls v8 — https://www.cisecurity.org/controls/v8                                |
|10 | NIST Cybersecurity Framework 2.0 — https://www.nist.gov/cyberframework                  |
|11 | Diamond Model of Intrusion Analysis — Caltagirone, Pendergast, Betz (2013)              |

---

## Appendix A: Quick-Reference IOC Block List

```
# DarkGate / Operation Crimson Gate — IOC Block List
# Format: type,indicator,description
# Generated: 2026-02-17 | CTI-2026-0412 | TLP:CLEAR

ip,185.156.74.12,DarkGate C2 primary
ip,91.243.44.201,DarkGate C2 secondary
domain,secure-billing-portal.top,Malicious payload hosting
domain,cdn-invoice-services.com,Redirect/TDS infrastructure
url,/cdn/mscorsvw.exe,DarkGate loader download path
url,/gate.php,DarkGate C2 check-in
hash_sha256,a3f1d2e4b9c7056f8e1234abcd5678ef90123456789abcdef01234567890abc,DarkGate loader binary
hash_sha256,5c2a9b3d8e7f1045c6789012abcd3456ef789012abcdef3456789012abcdef34,VBScript dropper
registry,HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsCoreUpdate,Persistence key
filepath,%AppData%\Roaming\mscorsvw.exe,DarkGate persistence location
```

---

*Report prepared for portfolio demonstration purposes.*
*All threat actor designations, IOCs, and campaign details are fictional composites.*
*TLP:CLEAR — Free for distribution.*
