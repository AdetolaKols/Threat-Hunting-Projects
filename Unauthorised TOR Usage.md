# Threat Hunt Report: Unauthorized TOR Usage


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

A search for files containing the string **"tor"** revealed that the user **labuserM** had downloaded a TOR installer. This activity triggered the appearance of multiple TOR-related files on the desktop and the creation of a file named `tor-shopping-list.txt` at `2025-09-30T14:10:11.4903549Z`. The sequence of events started at `2024-11-08T22:14:48.6065231Z`.  

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "mulanwindows11p"  
| where InitiatingProcessAccountName == "labuserM"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1317" height="232" alt="image" src="https://github.com/user-attachments/assets/cea5801b-47f5-4566-b67c-dd05e661ef01" />

---
### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-09-30T14:09:50.1216761Z`, an employee on the "mulanwindows11p" device ran the file `tor-browser-windows-x86_64-portable-14.5.7 (1).exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "mulanwindows11p"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7 (1).exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1538" height="434" alt="image" src="https://github.com/user-attachments/assets/501e71af-c13a-488e-a636-57b5396a9b33" />

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that employee (user) "labuserM" actually opened the TOR browser. There was evidence that they did open it at `2025-09-30T15:25:36.0170158Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1270" height="405" alt="image" src="https://github.com/user-attachments/assets/54e740bc-2d76-4510-94bd-4a16fcf80f24" />

