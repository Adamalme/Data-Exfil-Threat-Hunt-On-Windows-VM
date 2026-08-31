# 🚨 Threat Hunt Investigation: Data Exfiltration By Disgruntled Employee 

**Author:** Adam Alme \
**Date:** Sept 27, 2026 \
**Lab Type:** Threat Hunting / Data Exfiltration / MITRE ATT&CK Mapping  \

![DATA EXFILTRATION](https://github.com/user-attachments/assets/5d63ac63-fcaa-47bb-a49d-8ea211232822)

---

## :bookmark_tabs: Overview
This lab simulates a real-world threat hunting scenario involving a disgruntled employee suspected of malicious insider behavior. After being placed on a performance improvement plan (PIP), the employee was subsequently terminated. Concerns were raised that they may have attempted to steal proprietary company data from their corporate-assigned endpoint. This investigation uses Microsoft Defender for Endpoint (MDE) telemetry, KQL queries, and MITRE ATT&CK mapping to uncover potential data exfiltration activities involving unauthorized file archiving and suspicious PowerShell execution.

---

## :world_map: Incident Summary
The VM `SQL-labuser` showed repeated ZIP file creation and manipulation activity. Further investigation revealed the use of `7z.exe` to compress data and `powershell.exe` to rename and move files into a hidden backup folder—signs of possible data staging.

**File creation event showing `top_level_portion1.zip`**

<img width="725" height="425" alt="image" src="https://github.com/user-attachments/assets/27a07d5b-290c-4e5d-9667-bf13535bcbc2" />

---

## :mag_right: Investigation Timeline & KQL Queries

### 1. Detect ZIP Archive Activity
```kql
DeviceFileEvents
| where DeviceName == "SQL-labuser"
| where FileName endswith ".zip"
| order by Timestamp desc
```
**Repeated ZIP creation logs**

<img width="725" height="425" alt="image" src="https://github.com/user-attachments/assets/27a07d5b-290c-4e5d-9667-bf13535bcbc2" />


### 2. Trace the Process Behind Archive Creation
```kql
let specificTime = datetime(2026-08-31T08:34:56.8238984Z);
DeviceProcessEvents
| where DeviceName == "sql-labuser"
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath
```
**PowerShell invoking 7z.exe**

<img width="754" height="445" alt="image" src="https://github.com/user-attachments/assets/84df75eb-c707-4515-8943-ae28ac7ab4dc" />

### 3. Check for Exfiltration Evidence
```kql
DeviceFileEvents
| where DeviceName == "sql-labuser"
| where FileName endswith ".zip"
| where RequestAccountName == "Cyberlab123"
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, PreviousFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="947" height="478" alt="image" src="https://github.com/user-attachments/assets/b4818cff-0674-4eb9-98c5-7082752de69d" />

```Kql
DeviceProcessEvents
| where DeviceName == "sql-labuser"
| where FileName == "powershell.exe" or FileName == "7z.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

<img width="941" height="477" alt="image" src="https://github.com/user-attachments/assets/e5dcb0fd-ebf5-4c90-b39c-9bd3f97c954f" />

### 4. Outbound Network Activity & Exfiltration Analysis
```kql
DeviceNetworkEvents
| where DeviceName == "sql-labuser"
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| order by Timestamp desc
```
<img width="946" height="478" alt="image" src="https://github.com/user-attachments/assets/19cb3a56-fd11-4ba1-ba34-a14b9f31b602" />

## :shield: Conclusion
The user account `Cyberlab123` installed 7-Zip via PowerShell, created a ZIP archive of what appears to be employee data, and moved it to a hidden folder. Although no direct data exfiltration was observed, the behavior is strongly consistent with data staging and insider threat patterns. No data exfiltration occurred, but there is evidence of potential data‑staging

---

## :bulb: Recommendations
- Enforce PowerShell script restrictions via AppLocker
- Block unauthorized archive utilities like 7-Zip
- Enable NSG outbound filtering on critical assets
- Implement Sentinel and Defender alerts for abnormal file handling

---

## :memo: MITRE ATT&CK Mapping
| Tactic             | Technique                                     | ID         | Description |
|--------------------|-----------------------------------------------|------------|-------------|
| Execution          | Command and Scripting Interpreter: PowerShell | T1059.001  | PowerShell used to run silent install + scripts |
| Defense Evasion    | Signed Binary Proxy Execution: PowerShell     | T1218.001  | LOLBin abuse to rename/move files |
| Collection         | Archive Collected Data                        | T1560.001  | Used 7-Zip to compress internal data |
| Collection         | Local Data Staging                            | T1074.001  | Staged archive in hidden folder |
| Discovery          | File and Directory Discovery                  | T1083      | Found target files to compress |
| Collection         | Data from Local System                        | T1005      | Archived employee-related data |
| Command & Control  | Ingress Tool Transfer                         | T1105      | Downloaded 7-Zip onto the machine |
| Discovery          | Process Discovery                             | T1057      | PowerShell queried local processes |

---

## :toolbox: Lab Process Summary
### 1. **Preparation**
- Hypothesis: A user may be staging data for exfiltration using PowerShell and compression tools.

### 2. **Data Collection**
- Collected logs from Defender tables (`DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`)

### 3. **Analysis**
- Discovered timed creation and renaming of archive files using suspicious processes

### 4. **Investigation**
- Identified the tools used, user account responsible, and mapped them to TTPs

### 5. **Response**
- Isolated VM, disabled account, deleted archives, and implemented alerts

### 6. **Documentation**
- Created detailed report with findings, screenshots, and mapped techniques

### 7. **Improvement**
- Hardened PowerShell controls, added NSG rules, and enhanced baseline detection with Sentinel

---

> **Created using Microsoft Defender for Endpoint, Azure Monitor, and KQL**  
> **Project by Adam Alme | [https://github.com/Adamalme]






