#  Hide Your RDP: Password Spray Leads to Full Compromise (CTF)
<img width="1362" height="912" alt="image" src="https://github.com/user-attachments/assets/bb01c41d-1334-49df-9b27-379b7c511988" />


## Case Summary
A password spray attack against an internet-exposed RDP endpoint resulted in a successful remote logon On *2025-09-16*. After authenticating, the intruder executed a masqueraded binary, created a scheduled task to establish persistence, and weakened Microsoft Defender by adding a folder exclusion. The actor performed host discovery, locally archived data, and communicated with external infrastructure before attempting to exfiltrate data over HTTP to a nonstandard port. All identifiable indicators (source IPs, account names, file paths, and other IoCs) are documented separately in the **IoCs** section of this report.

## 📏 Parameters

- **Date Completed:** *2025-09-26*
- **Wingmen:** [Peter Pan](https://github.com/Panbear1983/) [Mohammed A](https://github.com/SancLogic)
- **Simulated Environment:** `LOG(N) Pacific - Cyber Range 1`  
- **Impacted Host VM:** DeviceName contains `flare`  
- **Incident Date:** 2025-09-14 (first malicious activity)*
- **Incident Window** **2025-09-16 18:40:57Z → 2025-09-17:00:40:57Z
- **Frameworks Applied:** *MITRE ATT&CK*, *NIST 800-61*

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Initial Access | 1 | Credential Access → Initial Access | **T1110.001** | Brute Force: Password Guessing |
| Initial Access | 2 | Initial Access | **T1078** | Valid Accounts |
| Execution | 3 | Execution | **T1059.003** | Command & Scripting Interpreter: Windows Command Shell |
| Execution | 4 | Execution | **T1059** | Command & Scripting Interpreter (PowerShell) |
| Persistence | 5 | Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task |
| Defense Evasion | 6 | Defense Evasion | **T1562.001** | Impair Defenses: Disable/Modify Security Tools |
| Discovery | 7 | Discovery | **T1082** | System Information Discovery |
| Collection | 8 | Collection | **T1560.001** | Archive Collected Data: Local Archiving |
| Command & Control | 9 | C2 | **T1071.001**, **T1105** | Web Protocols; Ingress Tool Transfer |
| Exfiltration | 10 | Exfiltration | **T1048.003** | Exfiltration Over Unencrypted Protocol |

## 📌 Capture The Flags — Timeline of Events (UTC)

| Timestamp (UTC) | Event | Target Device | Details |
|---|---|---:|---|
| **2025-09-13 4:39:38**   | Initial RDP password-spray observed | flare | External source noted (Flag 1) |
| **2025-09-16 19:40:57** | First successful RDP authentication | flare | Compromised account observed (Flag 2) |
| **2025-09-17 (approx.)** | Malicious/misleading binary executed after login | flare | `msupdate.exe` (Flag 3) |
| **2025-09-17 (approx.)** | Payload run with execution policy bypass | flare | `msupdate.exe` Execution Policy Bypass -File C:\Users\Public\update_check.ps1 (Flag 4) |
| **2025-09-16 20:39:45** | Scheduled Task created for persistence | flare | Task named `MicrosoftUpdateSync` created (Flag 5) |
| **2025-09-16 20:39:48** | Microsoft Defender exclusion added | flare | 'C:\Windows\Temp' (Flag 6) |
| **2025-09-16 20:40:28** | Host discovery activity performed | flare | `"cmd.exe" /c systeminfo` executed (Flag 7) |
| **2025-09-16 20:43:20** | Data staged into an archive file | flare | Archive `backup_sync.zip` (Flag 8) |
| **2025-09-16 20:39:03** | C2 connection established | flare | 185.92.220.87 (Flag 9) |
| **2025-09-16 20:43:42** | Attempted data exfiltration to external endpoint | flare | 185.92.220.87:8081 (Flag 10) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag   | Objective                                   | Value                                           |
|--------|---------------------------------------------|--------------------------------------------------|
| **1**  | Attacker IP Address                         | 159.26.106.84                                    |
| **2**  | Compromised Account                         | slflare                                          |
| **3**  | Executed Binary Name                        | msupdate.exe                                     |
| **4**  | Command Line Used to Execute the Binary     | "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1 |
| **5**  | Persistence Mechanism (Scheduled Task)      | MicrosoftUpdateSync                               |
| **6**  | Defender Setting Modified (Exclusion Path)  | C:\Windows\Temp                                   |
| **7**  | Discovery Command Run                       | "cmd.exe" /c systeminfo                           |
| **8**  | Archive File Created                        | backup_sync.zip                                   |
| **9**  | C2 Connection Destination                   | 185.92.220.87                                     |
| **10** | Exfiltration Attempt Destination (IP:Port)  | 185.92.220.87:8081                                |


## 🛠️ Remediation & Hardening Plan
### Long-Term (1–3 months)
- Mandate MFA for all RDP and remote entry points; keep RDP limited to VPN/PAW with JIT as standard practice.
- Tighten lockout thresholds; audit failed logons for spray patterns.
- Implement Privileged Access Management (PAM) and rotate/administer secrets through approved vaulting.
- Segment networks to constrain lateral movement; restrict management protocols to admin subnets.
- Expand telemetry: enhance logging for PowerShell, WMI, and process creation; ensure logs are retained and queryable centrally.
- Establish DNS/HTTP egress filtering with DLP/CASB to control data flows and detect unsanctioned exfiltration paths.
- Build a proactive threat-hunting program to regularly search for spray patterns, persistence artifacts, and execution bypasses.

### Detection Engineering (Ongoing)
- Create detections for:
  - PowerShell `ExecutionPolicy Bypass` and suspicious child processes.
  - Archive creation in `Temp`/`Public` directories indicative of staging.
  - Scheduled task creation/modification by non-administrative contexts.
  - Defender policy changes, including new or altered exclusions.
- Continuously test and tune rules against real telemetry from the environment.

## 🎓 Lessons Learned 

- Exposing RDP to the internet without MFA continues to pose a significant risk for password-spraying attacks.  
- Masqueraded binaries placed in public directories can easily appear legitimate; strong naming policies and AMSI/EDR visibility are critical.  
- Adding exclusions in Defender creates persistent blind spots; all AV policy changes should be closely monitored and controlled.  
- Task Scheduler remains a common method for persistence; registry-based telemetry (`TaskCache\Tree`) provides strong detection coverage.  

---

## Capture The Flag and Steps Taken 

Stage 1: Initial Access — *The Threat Actor is trying to get into your network.*

### Flag 1: Attacker IP Address
**Objective:** Identify the earliest external IP that successfully logged in via RDP after multiple failures.  
**What to Hunt:** First `ActionType == "LogonSuccess"` from a Public `RemoteIP` on “flare” hosts.  
**TTP:** T1110.001 (Password Guessing) → T1078 (Valid Accounts).  
**Why It Matters:** Anchors initial access and the source of compromise.

**KQL Query:**

***// Earliest public IP with RDP LogonSuccess on flare hosts***
```kql (MDE)
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc
```
**Output:** `159.26.106.84`  
**Finding:** The earliest `LogonSuccess` from a public source was **159.26.106.84**, consistent with password‑spray attempts preceding a successful login.
<img width="1252" height="722" alt="image" src="https://github.com/user-attachments/assets/633128a9-df3b-4f34-bd32-5b575cbf21b8" />

---

### Flag 2: Compromised Account
**Objective:** Determine the username used during the successful RDP login.  
**What to Hunt:** Account tied to Flag 1’s `LogonSuccess` event.  
**TTP:** T1078 (Valid Accounts).  
**Why It Matters:** Establishes attacker’s operating identity and permission scope.

**KQL Query:**
***// First successful RDP login’s account on flare hosts***
```kql (Sentinel)
DeviceProcessEvents
| where DeviceName contains "flare"
| where TimeGenerated between (datetime(2025-09-16 18:40) .. datetime(2025-09-22 20:43)) // expand + 1-6h around success
| project
    TimeGenerated,
    FileName,
    InitiatingProcessFolderPath,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    ProcessVersionInfoFileDescription,
    AccountName
| order by TimeGenerated asc
```
**Output:** `slflare`  
**Finding:** The first successful RDP authentication from an external IP used the account **slflare**.
<img width="1579" height="784" alt="image" src="https://github.com/user-attachments/assets/70942d7d-3528-4be5-bcb2-cd43a9343139" />

---

### Flag 3: Executed Binary Name
**Objective:** Identify the binary executed post‑RDP access.  
**What to Hunt:** Suspicious executions by **slflare** from `Public/Temp/Downloads` locations or with download/bypass flags.  
**TTP:** T1059.003 (Cmd) / T1204.002 (Malicious File).  
**Why It Matters:** Reveals the initial payload/tooling executed by the adversary.

**KQL Query:**
***// Suspicious binary launches under slflare***
```kql (Sentinel)
DeviceProcessEvents
| where DeviceName contains "flare"
| where TimeGenerated  between (datetime(2025-09-16 19:00) .. datetime(2025-09-22 20:43)) // expand + 1-6h around success
| project TimeGenerated, FileName, InitiatingProcessFolderPath, FolderPath, ProcessCommandLine, InitiatingProcessFileName, ProcessVersionInfoFileDescription, AccountName
| order by TimeGenerated asc
```
**Output:** `msupdate.exe`  
**Finding:** Under **slflare**, the process list shows execution of **msupdate.exe**, a legit‑sounding name commonly used to masquerade malicious payloads.
<img width="1613" height="394" alt="image" src="https://github.com/user-attachments/assets/13a41058-07aa-4cba-97eb-0162ad4ccb56" />

---
### Flag 4: Command Line Used to Execute the Binary
**Objective:** Provide the full command line used to launch the binary from Flag 3.  
**What to Hunt:** `ProcessCommandLine` containing **msupdate.exe**.  
**TTP:** T1059 (Command and Scripting Interpreter).  
**Why It Matters:** Parameters expose execution policy bypass and payload pathing.

**KQL Query:**
***// Full command line for msupdate.exe***
```kql
DeviceProcessEvents
| where DeviceName contains "flare"
| where TimeGenerated  between (datetime(2025-09-16 19:00) .. datetime(2025-09-22 20:43)) // expand + 1-6h around success
| where InitiatingProcessCommandLine contains "msupdate.exe"
| project TimeGenerated, FileName, InitiatingProcessFolderPath, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, ProcessVersionInfoFileDescription, AccountName
| order by TimeGenerated asc
```
**Output:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`  
**Finding:** The binary was invoked with **ExecutionPolicy Bypass**, executing `C:\Users\Public\update_check.ps1`, indicating script‑based follow‑on activity.  
<img width="1610" height="242" alt="image" src="https://github.com/user-attachments/assets/2d818c11-094d-435c-be47-2c7215c8fa5c" />

---

### Flag 5: Persistence Mechanism Created
**Objective:** Identify the scheduled task created by the attacker.  
**What to Hunt:** Task creation breadcrumbs (e.g., `TaskCache\Tree\*`) and recent entries tied to attacker activity window.  
**TTP:** T1053.005 (Scheduled Task).  
**Why It Matters:** Confirms persistence method that survives reboots/logoff.

**KQL Query:**
***// Suspicious TaskCache registry entries***
```kql (MDE)
let StartTime = datetime(2025-09-16T19:00:00Z);
let EndTime = datetime(2025-09-22T23:59:59Z);
DeviceRegistryEvents
| where DeviceName  contains "flare"
| where InitiatingProcessAccountName  contains "slflare"
| where isnotempty( RegistryKey)
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
| order by Timestamp asc 
```
**Output:** `MicrosoftUpdateSync`  
**Finding:** New entry under **TaskCache\Tree** reveals a scheduled task named **MicrosoftUpdateSync**, consistent with persistence created minutes after initial access.
<img width="1604" height="283" alt="image" src="https://github.com/user-attachments/assets/82ca1da8-6b7c-4d04-9693-c1814ad44a09" />






