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


---
