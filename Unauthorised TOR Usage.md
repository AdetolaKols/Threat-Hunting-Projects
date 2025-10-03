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

A search for files containing the string **"tor"** revealed that the user **labuserM** had downloaded a TOR installer. This activity triggered the appearance of multiple TOR-related files on the desktop and the creation of a file named `tor-shopping-list.txt` at `2025-09-30T14:10:11.4903549Z`. The sequence of events started at `2025-09-30T13:57:51.1140882Z`.  

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
| where DeviceName == "mulanwindows11p"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1270" height="405" alt="image" src="https://github.com/user-attachments/assets/54e740bc-2d76-4510-94bd-4a16fcf80f24" />


### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-30T15:00:40.9399968Z`, an employee on the "labuserM" device successfully established a connection to the remote IP address `192.42.116.211` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuserM\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "mulanwindows11p"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

<img width="1231" height="195" alt="image" src="https://github.com/user-attachments/assets/a8501c23-56f8-4785-8525-5472a49b6bc7" />

<img width="1233" height="351" alt="image" src="https://github.com/user-attachments/assets/408fcb63-4ab0-46a1-a6f4-3ef2322ab7a0" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-30T14:10:11.4903549Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.7 (1).exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuserM\Downloads\tor-browser-windows-x86_64-portable-14.5.7 (1).exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-30T14:09:50.1216761Z`
- **Event:** The user "labuserM" executed the file `tor-browser-windows-x86_64-portable-14.5.7 (1).exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.7 (1).exe /S`
- **File Path:** `C:\Users\labuserM\Downloads\tor-browser-windows-x86_64-portable-14.5.7 (1).exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-30T15:25:36.0170158Z`
- **Event:** User "labuserM" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuserM\Downloads\tor-browser-windows-x86_64-portable-14.5.7 (1).exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-30T15:00:40.9399968Z`
- **Event:** A network connection to IP `192.42.116.211` on port `9001` by user "labuserM" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labuserM\Downloads\tor-browser-windows-x86_64-portable-14.5.7 (1).exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-30T15:00:37.2881391Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-09-30T15:00:40.9399968Z` - Local connection to `127.0.0.1` on port `9100`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-30T15:30:45.187595Z`
- **Event:** The user "labuserM" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuserM\Downloads\tor-browser-windows-x86_64-portable-14.5.7 (1).exe`


---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mulanwindows11p` by the user `labuserM`. The device was isolated, and the user's direct manager was notified.

---
