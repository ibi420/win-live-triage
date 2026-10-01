# win-live-triage — Windows Live Triage & Threat Hunting Toolkit

> Advanced Windows Threat Hunting & Forensics Script  
> Requires: PowerShell 5.0+, Windows 10/11, Administrator privileges

---

## Table of Contents

- [win-live-triage — Windows Live Triage & Threat Hunting Toolkit](#win-live-triage--windows-live-triage--threat-hunting-toolkit)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Quick Start](#quick-start)
  - [Output Files](#output-files)
  - [Included Scripts](#included-scripts)
  - [Script Architecture](#script-architecture)
    - [Internal helper functions](#internal-helper-functions)
    - [PID resolution (3-tier)](#pid-resolution-3-tier)
  - [Sections Reference](#sections-reference)
    - [Section 1 — System Identity \& Hardware](#section-1--system-identity--hardware)
    - [Section 2 — User Accounts \& Privilege Audit](#section-2--user-accounts--privilege-audit)
    - [Section 3 — Detailed Process Analysis](#section-3--detailed-process-analysis)
    - [Section 4 — Network Connections \& IP Intelligence](#section-4--network-connections--ip-intelligence)
    - [Section 5 — Persistence Mechanisms](#section-5--persistence-mechanisms)
      - [5.1 Registry Autorun Keys](#51-registry-autorun-keys)
      - [5.2 Non-Microsoft Scheduled Tasks](#52-non-microsoft-scheduled-tasks)
      - [5.3 Non-Standard Running Services](#53-non-standard-running-services)
      - [5.4 WMI Event Subscriptions](#54-wmi-event-subscriptions)
      - [5.5 Browser Extensions](#55-browser-extensions)
    - [Section 6 — File System Forensics](#section-6--file-system-forensics)
      - [6.1 Recently Modified System Executables](#61-recently-modified-system-executables)
      - [6.2 Alternate Data Streams (ADS)](#62-alternate-data-streams-ads)
      - [6.3 PowerShell Command History](#63-powershell-command-history)
      - [6.4 Prefetch](#64-prefetch)
    - [Section 7 — Windows Event Log Analysis](#section-7--windows-event-log-analysis)
      - [7.1 Audit Log Tampering](#71-audit-log-tampering)
      - [7.2 Newly Installed Services](#72-newly-installed-services)
      - [7.3 Suspicious PowerShell Script Blocks](#73-suspicious-powershell-script-blocks)
      - [7.4 Remote Access Logins](#74-remote-access-logins)
    - [Section 8 — Anti-Forensics Detection](#section-8--anti-forensics-detection)
      - [8.1 Timestomping](#81-timestomping)
      - [8.2 Volume Shadow Copies](#82-volume-shadow-copies)
      - [8.3 Attacker Tool Scan](#83-attacker-tool-scan)
    - [Section 9 — Software \& Patch Status](#section-9--software--patch-status)
      - [9.1 Installed Software](#91-installed-software)
      - [9.2 Windows Update History](#92-windows-update-history)
    - [Section 10 — IOC Summary \& Threat Score](#section-10--ioc-summary--threat-score)
  - [Alert Categories](#alert-categories)
  - [Threat Score Calculation](#threat-score-calculation)
  - [False Positive Guide](#false-positive-guide)
  - [Known Limitations](#known-limitations)

---

## Overview

`win-live-triage.ps1` is a self-contained PowerShell script for investigating suspected Windows system compromise. It performs a wide sweep of forensic artefacts in a single run with no external dependencies or installed tools required, producing three output files for immediate analysis and later review.

The script is designed to be run by someone who suspects something is wrong with their machine and wants a comprehensive snapshot of its current state. It does not make changes to the system and is entirely read-only.

---

## Quick Start

Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\win-live-triage.ps1
```

> **Administrator is strongly recommended.** Without it, the Security event log, WMI subscription namespace, VSS queries, and some process owner lookups will be inaccessible, and those sections will report partial or empty results.

The script runs entirely in the foreground. On a typical machine with 100–200 processes and a full Downloads folder it takes roughly 2–4 minutes. Progress is printed to the console in real time with colour coding: red lines are alerts, yellow lines are items of interest, and green lines indicate clean results.

---

## Included Scripts

- **`win-live-triage.ps1`** — The primary 10-section deep forensic inspection and threat hunting engine.
- **`network_forensics_basic.ps1`** — A lightweight, quick 5-section network and process auditor.

---

## Output Files

Three files are written to the **current working directory** when the script completes. All filenames include a timestamp so repeated runs never overwrite each other.

| File                                      | Format     | Purpose                                                                                                                            |
| ----------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `win_live_triage_YYYYMMDD_HHmmss.txt`     | Plain text | Full console log containing everything printed to screen, saved verbatim. Use this as a raw audit trail.                            |
| `win_live_triage_YYYYMMDD_HHmmss.md`      | Markdown   | Human-readable report with tables, alert callouts, and severity badges. Open in VS Code, Obsidian, GitHub, or any Markdown viewer. |
| `win_live_triage_iocs_YYYYMMDD_HHmmss.csv`| CSV        | Structured IOC table with one row per indicator. Import into Excel, Splunk, or any SIEM for pivot analysis.                         |

The `.md` report is the primary deliverable for sharing with others or keeping as a record. The `.csv` is useful when you have many IOCs and want to sort, filter, or correlate them.

---

## Script Architecture

The script is structured around three layers that run in parallel:

**1. Console output (`Write-Log`)**  
Prints coloured output to the terminal in real time. Simultaneously appends every line to the `.txt` report file.

**2. Markdown accumulator (`Write-MD` / `Flush-MD`)**  
All Markdown content is appended to an in-memory `StringBuilder` throughout the run. The buffer is flushed to the `.md` file in a single write at the very end via `Flush-MD`. This avoids repeated file I/O and keeps the Markdown generation from interfering with the console output timing.

**3. IOC list (`Add-IOC`)**  
Every finding that warrants escalation is pushed into a typed `List[PSObject]` with fields for `Type`, `Value`, `Context`, `Severity`, and `Time`. At Section 10 this list is rendered into both the Markdown report and exported as the `.csv`.

### Internal helper functions

| Function                | Purpose                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| `Write-Log`             | Print to console + append to `.txt`                                |
| `Write-MD`              | Append a line to the Markdown buffer                               |
| `Write-MD-Table-Row`    | Append a formatted Markdown table row                              |
| `Write-MD-Table-Header` | Append a table header row + separator                              |
| `Write-MD-Badge`        | Return a coloured emoji label for an IOC severity level            |
| `Flush-MD`              | Write the complete Markdown buffer to the `.md` file               |
| `Write-Sep`             | Print a horizontal separator line                                  |
| `Write-Head`            | Print a section header to console/TXT and `##` heading to Markdown |
| `Write-Alert`           | Increment alert counter, print red warning, add Markdown callout   |
| `Add-IOC`               | Push a structured IOC object into the IOC list                     |
| `Resolve-PidName`       | Resolve a PID to a process name using a 3-tier lookup              |
| `Resolve-PidOwner`      | Resolve a PID to its owner account using a 3-tier lookup           |

### PID resolution (3-tier)

Network connections report owning PIDs, but standard `Get-Process` does not enumerate kernel and system PIDs (e.g. PID 4 = System, PID 0 = Idle). The script uses a three-tier approach to always return a name and owner:

1. **Hardcoded table** — PID 0 (`Idle`) and PID 4 (`System`) are pre-seeded.
2. **Bulk WMI pre-fetch** — `Win32_Process` is queried once at section start to build `$pidMap` and `$ownerMap` for all running processes, including kernel-mode ones `Get-Process` misses.
3. **On-demand WMI fallback** — `Resolve-PidName` and `Resolve-PidOwner` query WMI for any PID that still isn't in the map, and cache the result.

---

## Sections Reference

### Section 1 — System Identity & Hardware

**What it collects:**

- Machine model, RAM, and CPU via `Win32_ComputerSystem` and `Win32_Processor`
- All active network adapters (name, interface description, MAC address, IPv4 address) via `Get-NetAdapter` and `Get-NetIPAddress`
- Configured DNS servers per interface via `Get-DnsClientServerAddress`
- Whether DNS-over-HTTPS (DoH) is enabled (registry key `EnableAutoDoh`)
- Active (non-comment) entries in the Windows hosts file

**What it flags:**

| Condition                                 | Alert                                                          | Severity |
| ----------------------------------------- | -------------------------------------------------------------- | -------- |
| Hosts file has more than 3 active entries | Possible DNS hijack                                            | MEDIUM   |
| DoH is enabled                            | Informational note: DNS traffic not visible in plain captures  | (no IOC) |

**Why it matters:** Attackers commonly modify the hosts file to redirect traffic from legitimate sites (e.g. banking, antivirus update servers) to attacker-controlled IPs. DoH can hide DNS lookups from network monitoring tools.

---

### Section 2 — User Accounts & Privilege Audit

**What it collects:**

- All local user accounts: enabled/disabled status, last logon time, password expiry policy
- Members of the local Administrators group with their principal source (Local vs Microsoft Account vs Domain)
- Last 50 Security event log entries for Event ID 4625 (failed logon), grouped by username and sorted by count
- Running processes whose names match known credential theft and privilege escalation tools

**What it flags:**

| Condition                                                                      | Alert                       | Severity |
| ------------------------------------------------------------------------------ | --------------------------- | -------- |
| Non-built-in account enabled with password that never expires                  | Weak account configuration  | MEDIUM   |
| 10 or more failed logins for the same username                                 | Possible brute-force attack | HIGH     |
| Process name matches known tools (mimikatz, meterpreter, cobalt, psexec, etc.) | Active credential tool      | CRITICAL |

**Scanned tool names:** `mimikatz`, `meterpreter`, `cobalt`, `beacon`, `psexec`, `wce`, `fgdump`, `pwdump`, `gsecdump`, `lsadump`, `incognito`

---

### Section 3 — Detailed Process Analysis

**What it collects:**

- All running processes via `Win32_Process`, sorted by CPU time descending, with: PID, parent PID, name, CPU seconds, Authenticode signature status, and full executable path
- Unsigned executables running from outside the standard system paths (`System32`, `Program Files`, `Program Files (x86)`)
- Suspicious parent-child relationships (e.g. `winword.exe` spawning `powershell.exe`)
- DLLs loaded by running processes from writable or user-controlled directories

**Signature status values:**

| Status       | Meaning                                                    | Displayed as |
| ------------ | ---------------------------------------------------------- | ------------ |
| `Valid`      | Signed by a trusted publisher                              | ✅ Valid      |
| `NotSigned`  | No digital signature                                       | ⚠️ NotSigned  |
| `Tampered!`  | Hash mismatch: file modified after signing                 | 🔴 Tampered!  |
| `NotTrusted` | Signed but certificate is not in the trusted store         | 🔴 NotTrusted |
| `N/A`        | System process, or file format does not support signatures | -            |

**Signature resolution** uses `-LiteralPath` throughout (not positional path strings) to avoid PowerShell treating brackets in Windows driver store paths as wildcard characters, which previously caused `Error` to be reported for legitimate files like `dashost.exe`.

**Suspicious parent-child rules:**

| Child process                   | Flagged if parent is                                                         |
| ------------------------------- | ---------------------------------------------------------------------------- |
| `powershell.exe`                | winword, excel, outlook, mspaint, notepad, explorer, chrome, msedge, firefox |
| `cmd.exe`                       | winword, excel, outlook, svchost, lsass                                      |
| `wscript.exe` / `cscript.exe`   | winword, excel, outlook                                                      |
| `mshta.exe`                     | winword, excel, outlook, explorer                                            |
| `regsvr32.exe` / `rundll32.exe` | winword, excel, outlook                                                      |

**DLL hijack paths checked:** `\Temp\`, `\tmp\`, `\AppData\`, `\Downloads\`, `\Public\`, `\Desktop\`

---

### Section 4 — Network Connections & IP Intelligence

**What it collects:**

- All TCP connections via `Get-NetTCPConnection` with state, local/remote address and port, owning process name, and account owner
- All UDP listening endpoints via `Get-NetUDPEndpoint`
- For every unique external IPv4 address in an `Established` TCP connection: reverse DNS lookup and GeoIP lookup via `ip-api.com` (free, no API key required, 4-second timeout)
- ARP neighbour table via `Get-NetNeighbor` filtered to exclude multicast and broadcast entries
- Count of `SYN_SENT` connections as a port-scan/C2 beacon indicator

**What it flags:**

| Condition                                                       | Alert                              | Severity |
| --------------------------------------------------------------- | ---------------------------------- | -------- |
| External IP's rDNS or ISP name matches suspicious keyword list  | Suspicious IP                      | HIGH     |
| Duplicate MAC address for two distinct unicast IPs in ARP table | Possible ARP poisoning / MITM      | CRITICAL |
| More than 20 simultaneous `SYN_SENT` connections                | Possible port scan or C2 beaconing | HIGH     |

**Suspicious IP keyword list:**
`tor`, `onion`, `proxy`, `vpn`, `anon`, `bulletproof`, `no-log`, `offshore`, `kp`, `by`, `ru-center`, `spamhaus`, `cyberbunker`, `choopa`, `vultr-`

> **Note:** Generic hosting terms like `server`, `cloud`, `datacenter`, `node`, `vps`, and `relay` were deliberately removed from this list. They match too broadly against legitimate CDN and cloud providers (AWS, Azure, MEGA, Fastly, etc.) and caused excessive false positives.

**ARP filter:** The duplicate MAC check excludes all IPv4 multicast MACs (`01-00-5E-*`), IPv6 multicast MACs (`33-33-*`), the broadcast address (`FF-FF-FF-FF-FF-FF`), and multicast IP ranges (`224.x`, `239.x`, `ff02::`) before looking for duplicates. These are normal and appear on every Windows machine.

---

### Section 5 — Persistence Mechanisms

#### 5.1 Registry Autorun Keys

Reads the following registry locations and lists every non-PS-metadata value:

- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\SYSTEM\CurrentControlSet\Services`

**Flags values containing:** `\AppData\Local\Temp`, `\Downloads\`, `Base64`, `IEX`, `Invoke-Expression`, `FromBase64`

> Entries pointing to `AppData` (without `\Local\Temp`) are **not** flagged. Per-user applications (OneDrive, Teams, Claude, Discord, Steam, etc.) legitimately install to `AppData` and launch from there. Only the `Temp` subdirectory (a common malware drop zone) is treated as suspicious.

#### 5.2 Non-Microsoft Scheduled Tasks

Lists all scheduled tasks whose path does not contain `\Microsoft\`. Shows state, full task path/name, and action command.

**Flags tasks whose action matches:** `powershell.*-enc`, `-w hidden`, `bypass`, `FromBase64`, `IEX`, `downloadstring`, `bitsadmin`, `certutil.*-decode`, `regsvr32.*scrobj`

#### 5.3 Non-Standard Running Services

Lists running services that are not associated with a known vendor (`Microsoft`, `Windows`, `Intel`, `NVIDIA`, `AMD`, `Realtek`, `Broadcom`, `VMware`, `VirtualBox`, `Lenovo`, `Dell`, `HP`) and whose binary path is not under `System32`, `SysWOW64`, or `Program Files`.

**Flags services** whose binary runs from `\Temp\`, `\AppData\`, `\Downloads\`, or `\Public\`.

#### 5.4 WMI Event Subscriptions

Queries the `root\subscription` WMI namespace for `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` objects. WMI subscriptions are a well-known fileless persistence technique that survives reboots without writing executable files to disk.

The built-in Windows subscription `SCM Event Log Filter` / `SCM Event Log Consumer` (used by the Service Control Manager to write to the System event log) is explicitly excluded and does not trigger an alert. It is present on every Windows installation.

#### 5.5 Browser Extensions

Scans Chrome and Edge extension directories under the current user's `AppData\Local` profile. For each extension it reads `manifest.json` to extract the name and declared permissions.

**Localised extension names:** Extensions that use `__MSG_extensionName__` style localisation in their manifest are resolved by reading `_locales/en/messages.json`. If that file is absent, the script tries other locale folders. If resolution still fails, the extension folder ID is prepended to the raw key as a fallback (e.g. `[ID: abcde12345] __MSG_name__`).

**Flags extensions** requesting: `nativeMessaging`, `debugger`, `proxy`, `<all_urls>`, `webRequest`

---

### Section 6 — File System Forensics

#### 6.1 Recently Modified System Executables

Scans `System32`, `SysWOW64`, and `Windows\Temp` for `.exe` files modified within the last 72 hours. Legitimate Windows updates do modify system executables, but unexpected modifications outside an update window are worth reviewing.

#### 6.2 Alternate Data Streams (ADS)

Scans `%TEMP%` and `%USERPROFILE%\Downloads` for NTFS Alternate Data Streams using `Get-Item -Stream *`.

`Zone.Identifier` streams are **excluded** because Windows automatically attaches this stream to every file downloaded from the internet as a security feature (Mark of the Web). Flagging them would produce hundreds of false positives in any normal Downloads folder. Only other stream names are reported.

#### 6.3 PowerShell Command History

Reads the PSReadLine history file for each user profile at:
`C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

Shows the last 30 commands per user.

**Flags commands matching:** `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `-enc` / `-EncodedCommand`, `FromBase64`, `WebClient`, `Net.WebRequest`, `bitsadmin`, `certutil.*decode`, `Start-Process.*hidden`

**Excluded from flagging:** `Set-ExecutionPolicy -Scope Process Bypass` (the command used to run this script itself) and PowerShell module manifest lines (`@{`, `GUID =`, `ModuleVersion =`).

#### 6.4 Prefetch

Lists the 20 most recently executed programs from `C:\Windows\Prefetch` sorted by `LastWriteTime`.

**Flags prefetch entries** whose filename matches: `MIMIKATZ`, `METERPRETER`, `PSEXEC`, `NETCAT`, `NC.EXE`, `NMAP`, `COBALTSTRIKE`, `PWDUMP`, `WCES`

---

### Section 7 — Windows Event Log Analysis

#### 7.1 Audit Log Tampering

Checks for Event ID **1102** (Security log cleared) and Event ID **104** (System log cleared). Log clearing is a common attacker anti-forensics step. Either event triggers a CRITICAL IOC.

#### 7.2 Newly Installed Services

Queries Event ID **7045** (new service installed) from the System log for the past 7 days. New services are a common persistence mechanism, and this catches them even if the service has since been removed from the registry.

#### 7.3 Suspicious PowerShell Script Blocks

Queries Event ID **4104** (PowerShell script block logging) from the `Microsoft-Windows-PowerShell/Operational` log, limited to the most recent 200 events. Filters for blocks containing: `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64`, `WebClient`, `hidden`.

**Note:** PowerShell script block logging must be enabled in Group Policy or the registry for this section to have any data. It is not enabled by default on Windows Home editions.

PowerShell module manifests (which contain `GUID =` or `ModuleVersion =` in their content) are excluded, as these fire 4104 events on every module import and are entirely benign.

#### 7.4 Remote Access Logins

Queries Event ID **4624** (successful logon) for the past 7 days, filtering for logon types 3 (network) and 10 (remote interactive / RDP). Shows time, domain, username, source IP, and logon type for each match.

---

### Section 8 — Anti-Forensics Detection

#### 8.1 Timestomping

Scans `%TEMP%` for files where the `CreationTime` is more than 5 minutes later than the `LastWriteTime`. This is a characteristic of timestomping, where an attacker manually sets an old modification timestamp on a newly created file to make it blend in. The creation time cannot be backdated through normal file APIs, so the anomaly is detectable.

#### 8.2 Volume Shadow Copies

Queries `Win32_ShadowCopy` for the count and details of VSS snapshots. Ransomware routinely deletes shadow copies using `vssadmin delete shadows /all /quiet` before encrypting files. No shadow copies present is a HIGH severity IOC.

#### 8.3 Attacker Tool Scan

Searches for known attack tool filenames in `%TEMP%`, `%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop`, and `C:\Windows\Temp`.

**Tool names scanned:** `mimikatz*`, `meterpreter*`, `nc.exe`, `ncat.exe`, `netcat*`, `psexec*`, `pwdump*`, `wce.exe`, `fgdump*`, `gsecdump*`, `procdump*`, `cobalt*`, `beacon*`, `empire*`, `metasploit*`, `nmap*`, `masscan*`, `sqlmap*`, `hydra*`, `hashcat*`, `john*`

---

### Section 9 — Software & Patch Status

#### 9.1 Installed Software

Reads `HKLM` and `HKCU` uninstall registry keys to enumerate all installed applications with name, version, publisher, and install date. Sorted alphabetically.

#### 9.2 Windows Update History

Uses the `Microsoft.Update.Session` COM object to query the last 10 Windows Update installation events, showing result code, patch title, and date. Useful for identifying machines that are significantly behind on patches.

---

### Section 10 — IOC Summary & Threat Score

Aggregates all IOCs collected throughout the run and calculates a weighted threat score.

**Score formula:**

```
Score = (CRITICAL count × 10) + (HIGH count × 5) + (MEDIUM count × 2)
Score is capped at 100.
```

**Verdict thresholds:**

| Score  | Verdict                                       |
| ------ | --------------------------------------------- |
| 0      | 🟢 CLEAN: No indicators found                 |
| 1–10   | 🟡 LOW RISK: Minor anomalies, likely benign   |
| 11–30  | 🟠 MEDIUM RISK: Investigate flagged items     |
| 31–60  | 🔴 HIGH RISK: Strong indicators of compromise |
| 61–100 | 🔴 CRITICAL: Active threat likely present     |

The full IOC list is printed in the console/TXT output and rendered as a sortable table in the Markdown report. All IOCs are simultaneously exported to the `.csv` file.

---

## Alert Categories

| Category            | Description                                                                     | Default Severity |
| ------------------- | ------------------------------------------------------------------------------- | ---------------- |
| `HOSTS-FILE`        | More than 3 active entries in the hosts file                                    | MEDIUM           |
| `USER-ACCOUNT`      | Enabled account with non-expiring password                                      | MEDIUM           |
| `BRUTE-FORCE`       | 10+ failed logins for the same username                                         | HIGH             |
| `CREDENTIAL-TOOL`   | Known credential theft tool running                                             | CRITICAL         |
| `UNSIGNED-PROC`     | Unsigned executable outside system paths                                        | HIGH             |
| `PROCESS-INJECTION` | Shell/script spawned by an unusual parent                                       | CRITICAL         |
| `DLL-HIJACK`        | DLL loaded from a writable user directory                                       | HIGH             |
| `SUSPICIOUS-IP`     | External connection to suspicious infrastructure                                | HIGH             |
| `ARP-POISON`        | Duplicate unicast MAC in ARP table                                              | CRITICAL         |
| `PORT-SCAN`         | More than 20 simultaneous SYN_SENT connections                                  | HIGH             |
| `REGISTRY-PERSIST`  | Autorun value pointing to Temp/Downloads or containing obfuscation              | HIGH             |
| `TASK-PERSIST`      | Scheduled task with obfuscated or dangerous action                              | HIGH             |
| `SERVICE-PERSIST`   | Service binary running from Temp/AppData/Downloads                              | HIGH             |
| `WMI-PERSIST`       | Non-system WMI event subscription present                                       | CRITICAL         |
| `BROWSER-EXTENSION` | Extension with high-risk permissions (nativeMessaging, proxy, webRequest, etc.) | MEDIUM           |
| `FILE-TAMPER`       | System executable modified in the last 72 hours                                 | HIGH             |
| `ADS-MALWARE`       | Non-Zone.Identifier Alternate Data Stream detected                              | HIGH             |
| `PS-HISTORY`        | Suspicious PowerShell command in history                                        | HIGH             |
| `TOOL-EXECUTION`    | Known attack tool found in Prefetch                                             | CRITICAL         |
| `LOG-TAMPER`        | Security or System event log was cleared                                        | CRITICAL         |
| `SERVICE-INSTALL`   | New service installed in the last 7 days                                        | MEDIUM           |
| `PS-SCRIPTBLOCK`    | Suspicious PowerShell script block in Event 4104                                | HIGH             |
| `TIMESTOMP`         | File creation time is later than modification time                              | MEDIUM           |
| `VSS-DELETED`       | No Volume Shadow Copies found                                                   | HIGH             |
| `ATTACK-TOOL`       | Known attack tool file found on disk                                            | CRITICAL         |

---

## Threat Score Calculation

The score is designed to be zero on a clean, well-configured machine. A small number of MEDIUM findings (e.g. a hosts file with a few entries, a browser extension with `webRequest`) will push the score to LOW RISK (1–10), which is expected and usually benign. Genuine indicators of active compromise will push it to HIGH or CRITICAL quickly due to the exponential weighting of CRITICAL and HIGH findings.

**Example scores:**

| Scenario                                               | IOCs                | Score            |
| ------------------------------------------------------ | ------------------- | ---------------- |
| Clean machine, no findings                             | 0                   | 0: CLEAN         |
| 2 browser extensions with webRequest                   | 2 MEDIUM            | 4: LOW RISK      |
| One unsigned process + one suspicious IP               | 2 HIGH              | 10: LOW RISK     |
| Mimikatz running + log cleared + WMI subscription      | 3 CRITICAL          | 30: MEDIUM RISK  |
| Mimikatz + WMI + ARP poisoning + encoded PS in history | 3 CRITICAL + 2 HIGH | 40: HIGH RISK    |

---

## False Positive Guide

The following are commonly misunderstood alerts that have benign explanations on normal Windows machines:

| Alert                                                               | Explanation                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ARP-POISON** on `33-33-*`, `01-00-5E-*`, `FF-FF-FF-FF-FF-FF` MACs | IPv6 multicast, IPv4 multicast, and broadcast MACs are shared by design. The script filters these out, but if you see them it means your Windows version may report them differently. They are never real MITM attacks.                                      |
| **REGISTRY-PERSIST** on OneDrive, Teams, Claude, Discord, Steam     | Per-user applications legitimately autostart from `AppData`. The script only flags `AppData\Local\Temp` (not `AppData` in general) for this reason.                                                                                                         |
| **BROWSER-EXTENSION** `__MSG_name__`                                | The script resolves localised extension names automatically. If you still see this, the extension's `_locales` directory is missing or structured unusually. The extension ID in the flag name can be looked up in your browser's extension management page. |
| **ADS HIGH** on `Zone.Identifier`                                   | This is Windows' built-in Mark of the Web tagging for downloaded files. The script filters these out entirely.                                                                                                                                               |
| **WMI-PERSIST** `SCM Event Log`                                     | This subscription ships with Windows and is used by the Service Control Manager to write service events. The script explicitly ignores it.                                                                                                                   |
| **PS-HISTORY** `Set-ExecutionPolicy -Scope Process Bypass`          | This is how you run the script itself. Excluded.                                                                                                                                                                                                             |
| **PS-SCRIPTBLOCK** `@{ GUID = ...`                                  | PowerShell module manifests fire 4104 events on import. Excluded by content pattern.                                                                                                                                                                         |
| **SUSPICIOUS-IP** for MEGA, Microsoft Azure, AWS, Fastly            | Legitimate CDN and cloud infrastructure. The keyword list was tightened to avoid these. If you still see them, check that the ISP name in the alert doesn't contain any of the listed keywords.                                                              |

---

## Known Limitations

**PowerShell script block logging (Section 7.3)** requires manual enablement via Group Policy or registry. It is not active by default on Windows Home. The section will report nothing if it is not enabled.

**Security event log access (Sections 2 and 7)** requires Administrator. Events 4625, 4624, and 1102 will not be returned without elevated privileges.

**GeoIP lookups (Section 4)** rely on a live HTTP request to `ip-api.com` with a 4-second timeout. If the machine has no internet connection, or if `ip-api.com` rate-limits the requests (their free tier allows 45 requests/minute), geo information will show as `unknown`. The lookups are non-blocking, so a timeout does not stop the script.

**Prefetch (Section 6.4)** may be disabled on SSDs via the `EnablePrefetcher` registry setting. If `C:\Windows\Prefetch` does not exist, the section is skipped.

**Browser extensions (Section 5.5)** only scan the `Default` profile for Chrome and Edge. If the user runs multiple browser profiles, extensions in non-default profiles are not checked.

**DLL hijack detection (Section 3)** requires the running process to have loaded the DLL already; it does not scan on-disk DLLs speculatively. Some injected DLLs may be loaded into processes that deny module enumeration (access denied), and those will be silently skipped.

**Signature checking (Section 3)** uses `-LiteralPath` to correctly handle driver store paths with bracket characters. However, some `.mui` resource DLLs and very low-level kernel components legitimately show `N/A` (not a supported signature format) rather than `Valid`. This is normal and does not indicate tampering.

---

*Cross-reference suspicious IPs and hashes at [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com)*
