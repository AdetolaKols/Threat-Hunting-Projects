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
- Implement MFA on remote access where not already in place and reset credentials for compromised/privileged accounts; rotate administrative secrets.
