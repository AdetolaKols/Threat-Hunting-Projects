#  Port of Entry - VM Compromise (CTF)
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/175e509e-a948-4788-8507-5e7c0d30ce74" />

## Executive Summary

This investigation confirmed that the compromise of the **AZUKI-SL** administrator workstation on *19 November 2025* was not routine activity, but a coordinated intrusion that leveraged valid credentials, trusted Windows components, and staged automation.

The threat hunt uncovered a structured, multi-phase operation that followed a clear attack lifecycle:

- **Initial foothold** gained through successful RDP authentication using a compromised account.  
- **System and network reconnaissance** conducted through native utilities disguised as normal troubleshooting.  
- **Defense evasion** via Microsoft Defender tampering, file-extension and folder exclusions, and the creation of a hidden staging directory.  
- **Persistent access** established through a scheduled task masquerading as a system update and a secondary administrator-level account.  
- **Credential access** achieved using a renamed Mimikatz binary targeting LSASS memory.  
- **Data staging and exfiltration** carried out inside a concealed ProgramData folder and uploaded over HTTPS to a Discord webhook.  
- **Anti-forensics activity** including targeted clearing of the Security event log to obscure the attacker’s trail.

This activity demonstrates a deliberate compromise aimed at harvesting credentials, staging sensitive files, and moving deeper into the network. All relevant indicators are listed in the **IoCs** section of this report.

---

## Hunt Scope

- **Lab Environment:** `LOG(N) Pacific - Cyber Range 1` 
- **Platform:** Microsoft Defender for Endpoint + Azure Sentinel (Log Analytics Workspace)  
- **Host Monitored:** `azuki-sl` (IT administrator workstation)  
- **Data Sources:**  
  - `DeviceProcessEvents`  
  - `DeviceFileEvents`  
  - `DeviceNetworkEvents`  
  - `DeviceLogonEvents`  
- **Timeframe:** 2025-11-19 to 2025-11-20
- **Frameworks Applied:** *MITRE ATT&CK*, *NIST 800-61*
- **Objective:** Identify initial access, reconnaissance activity, defense evasion, credential dumping, persistence mechanisms, lateral movement attempts, and data exfiltration.

📌 Timeline of Events (UTC)

| Time (UTC) | Flag | Category / Stage           | Key Event Details                                                                                      | MITRE Technique(s)                    |
|-----------|------|-----------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------------|
|  **Nov 19, 2025 6:36:21 PM**    | 1    | Initial Access              | RDP login to `azuki-sl` using compromised account `kenji.sato`                                          | T1021.001, T1078                       |
| **Nov 19, 2025 6:36:21 PM**  | 2    | Initial Access              | Valid account leveraged to gain interactive access                                                       | T1078                                  |
|  **Nov 19, 2025 7:04:01 PM** | 3    | Execution                   | Recon commands executed (`arp -a`, `ipconfig /all`)                                                      | T1059.003, T1016                       |
| **Nov 19, 2025 6:49:21 PM**   | 4    | Execution                   | PowerShell execution from Downloads / Temp directories                                                   | T1059.001                              |
| **Nov 19, 2025 6:49:21 PM**  | 5    | Persistence                 | Scheduled task created for long-term persistence                                                         | T1053.005                              |
|  **Nov 19, 2025 6:49:21 PM**    | 6    | Defense Evasion             | Temp folder excluded from Defender scanning: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`                   | T1562.001                              |
| **Nov 19, 2025 7:06:58 PM**   | 7    | Defense Evasion             | `certutil.exe` abused to download malicious tools                                                        | T1105                                  |
| **Nov 19, 2025 7:07:46 PM**   | 8    | Persistence                 | Scheduled task name created:  “Windows Update Check” → runs attacker payload                                                      | T1053.005                              |
| **Nov 19, 2025 7:07:46 PM**   | 9    | Persistence                 | Scheduled task executes malicious payload: `C:\ProgramData\WindowsCache\svchost.exe`                     | T1053.005                              |
| **Nov 19, 2025 7:06:58 PM**    | 10   | Command & Control           | Outbound connection to C2 server: **78.141.196.6**                                                       | T1071.001, T1105                       |
| **Nov 19, 2025 7:11:04 PM**   | 11   | Command & Control           | C2 communications over port **443**                                                                     | T1071.001                              |
| **Nov 19, 2025 7:07:22 PM**   | 12   | Credential Access           | Credential dumping tool identified: `mm.exe`                                                            | T1003.001                              |
| **Nov 19, 2025 7:08:22 PM**   | 13   | Credential Access           | Mimikatz module used: `sekurlsa::logonpasswords`                                                        | T1003.001                              |
| **Nov 19, 2025 7:08:58 PM**   | 14   | Collection                  | Data compressed into archive: `export-data.zip`                                                        | T1560.001                              |
| **Nov 19, 2025 7:09:58 PM**   | 15   | Exfiltration                | Data exfiltrated via HTTPS Discord webhook (`curl.exe`)                                                 | T1567.002                              |
| **Nov 19, 2025 7:11:39 PM**   | 16   | Anti-Forensics              | Security event log cleared via `wevtutil.exe cl Security`                                               | T1070.001                              |
| **Nov 19, 2025 7:11:39 PM**  | 17   | Persistence                 | Hidden administrator account created: `support`                                                       | T1136.001                              |
| **Nov 19, 2025 6:49:48 PM**   | 18   | Execution                   | Malicious PowerShell automation script executed: `wupdate.ps1`                                        | T1059.001                              |
| **Nov 19, 2025 7:10:39 PM**    | 19   | Lateral Movement            | Attacker targets RDP host **10.1.0.188** using stored credentials                                       | T1550.002, T1021.001                   |
| **Nov 19, 2025 7:10:39 PM**   | 20   | Lateral Movement            | Built-in RDP client (`mstsc.exe`) used for pivot attempt                                                 | T1021.001                              |

## 🔧 Remediation & Hardening Plan

### **Long-Term (1–3 Months)**

- Remove public RDP exposure; enforce MFA and protected admin access.
- Move admin activities onto Privileged Access Workstations (PAWs).
- Begin transition to password-less or FIDO2 for privileged users.
- Enable LSASS protection, Credential Guard, and strict Defender Tamper Protection.
- Apply network segmentation for admin hosts and sensitive systems.
- Deploy full EDR telemetry: PowerShell, AMSI, script block logging.
- Implement egress filtering to block Discord, Pastebin, file-sharing platforms.
- Centralize logs in a tamper-proof SIEM with long-term retention.
- Apply least-privilege access for sensitive data and restrict ZIP/archiving in ProgramData/Temp.
- Roll out security awareness for admins on script abuse, LOLBins, and suspicious RDP use.

---

### **Detection Engineering (Ongoing)**

- Detect misuse of LOLBins (certutil, curl, cmdkey, schtasks).
- Alert on Defender exclusion changes (file, folder, process).
- Monitor for PowerShell with `-ExecutionPolicy Bypass` and unsigned script execution.
- Detect creation of hidden ProgramData folders and Temp-based execution.
- Flag ZIP/archiving events in non-standard directories.
- Monitor for new local admin accounts, scheduled tasks, or privilege changes.
- Alert on outbound HTTPS uploads to non-business services.
- Watch for attempts to clear logs (e.g., `wevtutil cl Security`).
- Continuously refine detection rules based on hunting observations.
- Perform regular red/purple-team exercises to test resilience.

---

## 💡 Lessons Learned

- RDP without MFA exposes organizations to high-risk credential compromise.
- LOLBins and renamed binaries make detection harder; deep telemetry is essential.
- Defender exclusions can quietly weaken protection for months if not monitored.
- Scheduled tasks and local accounts remain high-value persistence vectors.
- Strong logging, segmentation, and privileged identity controls reduce long-term risk.

## Starting Point – Initial Access

**Objective:**
Determine the origin  and source IP address of the Remote Desktop Protocol connection

- **KQL Query Used:**
```
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-22))
| where DeviceName == "azuki-sl"
| where ActionType in ("LogonSuccess", "LogonFailed")
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1", "-")
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
| order by Timestamp asc
```
<img width="1107" height="507" alt="image" src="https://github.com/user-attachments/assets/c7a813e7-23a3-4ed1-a2ea-a2a74ebdca6c" />



