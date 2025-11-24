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

| Time (UTC)            | Activity Category       | Key Event Details                                                                                  | MITRE Technique(s)                    |
|-----------------------|--------------------------|------------------------------------------------------------------------------------------------------|----------------------------------------|
| **Nov 19, 2025 6:36:21 PM**           | Initial Access           | RDP login to `azuki-sl` using compromised account `kenji.sato`                                      | T1021.001, T1078                       |
| **Nov 19, 2025 7:04:01 PM**      | Reconnaissance           | PowerShell execution; network discovery using `arp -a`, `ipconfig /all`                             | T1059.001, T1016                       |
| **Nov 19, 2025 7:05:33 PM**    | Defense Evasion          | Defender exclusions added (`.bat`, `.ps1`, `.exe`); Temp folders excluded; hidden staging folder created | T1562.001, T1074                   |
| **Nov 19, 2025 6:49:33 PM**    | Defense Evasion          | Temporary Folder Exclusion (`.bat`, `.ps1`, `.exe`); Temp folders excluded; hidden staging folder created | T1562.001, T1074                   |
| **6:49–6:50 PM**      | Malicious Script         | Execution of attacker script `wupdate.ps1` in Temp                                                   | T1059.001                              |
| **7:03–7:06 PM**      | Tool Download            | `certutil.exe` downloads `svchost.exe` and `AdobeGC.exe` into WindowsCache                           | T1105                                  |
| **7:07–7:08 PM**      | Persistence              | Scheduled task created: “Windows Update Check” → runs attacker payload                               | T1053.005                              |
| **7:08 PM**           | Credential Access        | `mm.exe` (renamed Mimikatz) dumps LSASS using `sekurlsa::logonpasswords`                             | T1003.001                              |
| **7:09 PM**           | Exfiltration             | Data archive uploaded via Discord webhook using `curl.exe`                                           | T1567.002                              |
| **7:09–7:10 PM**      | Persistence Account      | Admin account `support` created and added to Administrators group                                     | T1136.001                              |
| **7:10 PM**           | Lateral Movement         | `cmdkey.exe` sets credentials for 10.1.0.188; RDP attempt via `mstsc.exe`                            | T1550.002, T1021.001                   |
| **7:11 PM**           | Anti-Forensics           | Security event log cleared with `wevtutil.exe cl Security`                                           | T1070.001                              |
