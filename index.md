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
<img width="998" height="318" alt="{64708812-9106-40B1-81A2-4AAD19A5E6BC}" src="https://github.com/user-attachments/assets/10d5753f-b04a-42fd-912f-3d1e4bd1f854" />

" />


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

# Malware Analysis Project 
* malware analysis lab with Flare VM + REMnux*

## Overview
This project creates an isolated malware analysis environment using VirtualBox with Flare VM (Windows) and REMnux (Linux). It demonstrates static and dynamic analysis techniques to identify malware behaviors and extract IOCs.

## Objectives
> Build practical malware analysis skills in a safe environment

* Create isolated VirtualBox network for malware analysis
* Configure Flare VM (Windows) and REMnux (Linux) tools
* Analyze malware samples using hybrid techniques
* Document findings in professional reports

---

## Lab Configuration
```bash

 Create isolated network:
 
VBoxManage natnetwork add --netname MalwareNet --network "10.0.0.1/24"

 Assign VMs to network:
VBoxManage modifyvm "FlareVM" --nic1 natnetwork --nat-network1 MalwareNet
VBoxManage modifyvm "REMnux" --nic1 natnetwork --nat-network1 MalwareNet

 Verify connectivity:
FlareVM> ping 10.0.0.2
REMnux> ping 10.0.0.3
```
## Analysis Workflow

### Static Analysis
```powershell
# PeStudio examination:

pestudio.exe malware.exe

# YARA scanning:

yara -r rules.yar malware.exe
```

### Dynamic Analysis
```bash
# CAPEv2 sandbox submission:
python3 cape2.py submit malware.exe

# Procmon monitoring:
Procmon.exe /BackingFile log.pml

## Sample Analysis: Emotet Trojan
```
### Findings
```markdown
## Emotet Analysis Report

### Key Indicators
- **Persistence**: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\\UpdateCheck
- **C2 Communication**: 185.130.105[.]93:443
- **Payload Retrieval**: GET /wp-content/themes/twentyten/update.php
```
### IOCs
```csv

Type,Value
Domain,update.businesshost[.]top
IP,185.130.105[.]93
Registry,HKCU\Software\...\Run\\UpdateCheck
```
### Lab Screenshots
 1.Host-Only Network
<img width="1441" height="215" alt="image" src="https://github.com/user-attachments/assets/7315c2b4-9ace-4a6b-909e-140c552e4a12" />







 2.
<img width="1920" height="948" alt="image" src="https://github.com/user-attachments/assets/bf60fcb0-c583-437a-a624-da22dd97b9fb" />







---

# University Network Implementation 

This project implements a secure, segmented network for Kutaisi University using Cisco Packet Tracer, featuring VLAN segmentation, router-on-a-stick architecture, DHCP services, and RIPv2 routing.

## Objectives

* Configure VLAN segmentation for staff and students
* Set up router-on-a-stick for inter-VLAN routing
* Deploy DHCP services for automatic IP assignment
* Implement RIPv2 for dynamic routing
* Establish secure access port configurations

## Network Configurations

### core setup
```cisco
! VLAN CONFIGURATION
vlan 90
 name Staff
vlan 100
 name Students

! ACCESS PORTS
interface range fa0/1-24
 switchport mode access
 switchport access vlan 100

! TRUNK PORT
interface gig1/0/1
 switchport mode trunk
 ```
## Router configuration
```cisco
! ROUTER-ON-A-STICK
interface gig0/0.90
 encapsulation dot1Q 90
 ip address 192.168.9.1 255.255.255.0

interface gig0/0.100
 encapsulation dot1Q 100
 ip address 192.168.10.1 255.255.255.0

! DHCP SERVICES
ip dhcp pool staff-pool
 network 192.168.9.0 255.255.255.0
 default-router 192.168.9.1

ip dhcp pool student-pool
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1

! RIPv2 ROUTING
router rip
 version 2
 network 192.168.9.0
 network 192.168.10.0
```

### Screenshots
1.
<img width="1900" height="695" alt="image" src="https://github.com/user-attachments/assets/7174c625-de62-42b5-ac6b-3db6450d78b3" />



2.
<img width="1346" height="560" alt="image" src="https://github.com/user-attachments/assets/6caaca83-a5a6-4d42-a76b-4df3c851f3d4" />
