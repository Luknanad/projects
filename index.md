<!-- index.html -->

---



# Security Monitoring Lab with Microsoft Sentinel

This project deploys a Windows Server 2022 VM in Azure, forwards its Windows SecurityEvent logs into Microsoft Sentinel, applies custom KQL detection rules to spot suspicious login activity.

## Objectives

> Build a basic SIEM pipeline to detect Initial Access,Credential Access techniques and demonstrate end-to-end workflow.

1. Provision Azure infrastructure: VM, Log Analytics workspace, and Sentinel onboard.
2. Install Azure Monitor Agent and configure Data Collection Rule for Security events.
3. Create KQL rules to detect:

   * Successful local (keyboard) logins (Event 4624, LogonType 2)
   * RDP logins (Event 4624, LogonType 10)
   * Brute‑force attempts (>5 failures then one success)
   * Admin‑group membership changes (Events 4728, 4729, 4732, 4733)
4. Validate with sample alerts and screenshots.

---


## Detection Rules (KQL)

```kql
// 01-local-signin.kql: Local keyboard login (T1078.002)
SecurityEvent
| where EventID == 4624 and LogonType == 2
| where Account !contains "SYSTEM"
| project TimeGenerated, Account, Computer
```

```kql
// 02-rdp-signin.kql: RDP login (T1078.004)
SecurityEvent
| where EventID == 4624 and LogonType == 10
| where Account !contains "SYSTEM"
| project TimeGenerated, Account, Computer, IPAddress
```

```kql
// 03-bruteforce.kql: Brute‑force (>5 failures then success, T1110)
let failed = SecurityEvent
  | where EventID == 4625
  | summarize count() by Account, bin(TimeGenerated, 15m);
let success = SecurityEvent
  | where EventID == 4624 and Account !contains "SYSTEM"
  | project Account, TimeGenerated;
failed
| where count_ > 5
| join kind=inner success on Account
| where success.TimeGenerated > failed.TimeGenerated
```

```kql
// 04-admin-changes.kql: Admin group changes (T1136)
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733)
| where TargetUserName == "Administrators"
| project TimeGenerated, SubjectAccount, TargetAccount
```

---


##  Alerts Export

```csv
TimeGenerated,AlertName,Account,LogonType,Computer,IPAddress,Severity
2025-07-10T08:23:15Z,Local Sign‑In,Giorgi,2,sec-lab-vm,10.0.0.4,Medium
2025-07-10T09:01:07Z,Brute‑Force Attempt,Luka,0,sec-lab-vm,192.168.1.10,High
2025-07-10T09:01:53Z,Local Sign‑In,Luka,2,sec-lab-vm,192.168.1.10,Medium

```

---

### Screenshots

<img width="1864" height="452" alt="image" src="https://github.com/user-attachments/assets/0a09259e-6e2b-4138-9544-9c947ccc904a" />
<img width="1808" height="381" alt="image" src="https://github.com/user-attachments/assets/4a6a20bc-5c9b-45e2-a599-22cf8561c9c7" />


<h3 style="font-size: 20px; color: #34495e;">Outcome</h3>
<p>
  Successfully built a lightweight SIEM solution to detect key TTPs from MITRE ATT&CK (Initial Access and Credential Access). This project demonstrates how to leverage Azure-native tools for:
</p>
<ul>
  <li>Security log collection and aggregation</li>
  <li>Threat detection with custom KQL analytics rules</li>
  <li>Alerting and basic incident response automation</li>
  
</ul>

<!-- index.html -->

---

# Malware Analysis Project 101  
*Beginner-friendly malware analysis lab with Flare VM + REMnux*

## Overview
This project creates an isolated malware analysis environment using VirtualBox with Flare VM (Windows) and REMnux (Linux). It demonstrates static and dynamic analysis techniques to identify malware behaviors and extract IOCs.

## Objectives
> Build practical malware analysis skills in a safe environment

1. Create isolated VirtualBox network for malware analysis
2. Configure Flare VM (Windows) and REMnux (Linux) tools
3. Analyze malware samples using hybrid techniques
4. Document findings in professional reports

---

## Lab Configuration

```bash
 Create isolated network:
VBoxManage natnetwork add --netname MalwareNet --network "192.168.56.0/24"

 Assign VMs to network:
VBoxManage modifyvm "FlareVM" --nic1 natnetwork --nat-network1 MalwareNet
VBoxManage modifyvm "REMnux" --nic1 natnetwork --nat-network1 MalwareNet

 Verify connectivity:
FlareVM> ping 192.168.56.102
REMnux> ping 192.168.56.101

## Analysis Workflow

### Static Analysis
```powershell
# PeStudio examination:
pestudio.exe malware.exe

# YARA scanning:
yara -r rules.yar malware.exe

### Dynamic Analysis
```bash
# CAPEv2 sandbox submission:
python3 cape2.py submit malware.exe

# Procmon monitoring:
Procmon.exe /BackingFile log.pml

## Sample Analysis: Emotet Trojan

### Findings
```markdown
## Emotet Analysis Report

### Key Indicators
- **Persistence**: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\\UpdateCheck
- **C2 Communication**: 185.130.105[.]93:443
- **Payload Retrieval**: GET /wp-content/themes/twentyten/update.php

### IOCs
```csv
Type,Value
Domain,update.businesshost[.]top
IP,185.130.105[.]93
Registry,HKCU\Software\...\Run\\UpdateCheck

### Lab Screenshots
