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
2025-07-10T08:23:15Z,Local Sign‑In,Giorgi,2,sec-lab-vm,10.0.8.8,Medium
2025-07-10T09:01:07Z,Brute‑Force Attempt,Luka,0,sec-lab-vm,192.168.11.12,High
2025-07-10T09:01:53Z,Local Sign‑In,Luka,2,sec-lab-vm,192.168.12.5,Medium

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

This project implements a segmented network for Kutaisi University using Cisco Packet Tracer, featuring VLAN segmentation, router-on-a-stick architecture, DHCP services, and RIPv2 routing.

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






---


# IOC Enrichment Tool (VirusTotal Bulk Checker)

This project is a **Python automation tool** that takes a list of suspicious Indicators of Compromise (IOCs) — IPs, domains, or file hashes — queries the VirusTotal API in bulk, and generates a clean, analyst-ready CSV report. 

It is one of the most practical and frequently used daily automations for SOC analysts, Threat Intelligence teams, and Incident Responders.

## Objectives
> Build a reusable IOC enrichment script that integrates with VirusTotal’s public API, handles rate limiting, processes multiple indicator types, and produces professional CSV output for reporting and ticketing systems.

1. Set up a clean Python project environment with required dependencies (`requests`, `pandas`).
2. Implement secure API key handling and error management for VirusTotal lookups.
3. Support bulk processing of IOCs from a simple `.txt` input file.
4. Generate enriched results with verdict logic (MALICIOUS / SUSPICIOUS / CLEAN) based on engine detections.
5. Export results to a structured CSV report suitable for Excel, SIEM ingestion, or ticketing tools.
6. Demonstrate proper rate-limit handling and logging for production-grade use.

---

## Project Structure
IOC-Enrichment/
├── suspicious_ips.txt          # Input file (one IOC per line)
├── vt_lookup.py                # Main automation script
├── report.csv                  # Generated enriched report
└── README.md


## Input Example (`suspicious_ips.txt`)
```txt
8.8.8.8
1.1.1.1
185.220.101.1
104.16.132.229
45.33.32.156
```
## Main Script (vt_lookup.py)

```
import os
import requests   
import pandas     
import time      



API_KEY = "****************************"   
INPUT_FILE = r"C:\Desktop\python\IOC Enrichement\suspicious_ips.csv" 
OUTPUT_FILE = "report.csv"         


BASE_DIR = os.path.dirname(__file__)
INPUT_PATH = os.path.join(BASE_DIR, INPUT_FILE)
OUTPUT_PATH = os.path.join(BASE_DIR, OUTPUT_FILE)



if INPUT_FILE.lower().endswith(".csv"):
   
    df_in = pandas.read_csv(INPUT_PATH)
    if "ip" in df_in.columns:
        ip_list = df_in["ip"].dropna().astype(str).str.strip().tolist()
    else:
        ip_list = df_in.iloc[:, 0].dropna().astype(str).str.strip().tolist()
else:
    with open(INPUT_PATH, "r") as f:
       
        ip_list = f.read().strip().splitlines()

print(f"[*] Loaded {len(ip_list)} IPs to check")


def check_ip(ip):
    """
    Sends one IP to VirusTotal's API.
    Returns a dictionary with the verdict counts.
    """

   
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    
    headers = {
        "x-apikey": API_KEY
    }

    
    response = requests.get(url, headers=headers)

 
    if response.status_code != 200:
        print(f"  [!] Error checking {ip} — status: {response.status_code}")
        return {
            "ip": ip,
            "malicious": "ERROR",
            "suspicious": "ERROR",
            "harmless": "ERROR",
            "verdict": "ERROR"
        }

    
    data = response.json()

   
    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious  = stats["malicious"]   
    suspicious = stats["suspicious"]   
    harmless   = stats["harmless"]     

   
    if malicious >= 5:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "ip":         ip,
        "malicious":  malicious,
        "suspicious": suspicious,
        "harmless":   harmless,
        "verdict":    verdict
    }


results = []  

for ip in ip_list:
    print(f"  [*] Checking {ip}...")
    result = check_ip(ip)         
    results.append(result)         
    print(f"      → Verdict: {result['verdict']}")
    time.sleep(15)  
                  



df = pandas.DataFrame(results)


df.to_csv(OUTPUT_PATH, index=False)


print(f"\n[+] Done! Report saved to {OUTPUT_FILE}")
print(f"[+] Malicious IPs found: {df[df['verdict'] == 'MALICIOUS'].shape[0]}")
```

## Sample Output (report.csv)
```
ioc,malicious,suspicious,harmless,verdict
8.8.8.8,0,0,70,CLEAN
1.1.1.1,0,0,72,CLEAN
185.220.101.1,12,5,45,MALICIOUS
104.16.132.229,1,2,60,SUSPICIOUS
45.33.32.156,0,0,55,CLEAN
```
### Screenshots

<img width="1579" height="679" alt="{CE35BDB8-C2EB-442C-B36B-037AA3B4E475}" src="https://github.com/user-attachments/assets/9c743663-a5c4-4a63-bb73-84a500f8f620" />

<img width="793" height="153" alt="{ADF57F79-BD20-4E64-8405-E6C59F8A309C}" src="https://github.com/user-attachments/assets/a9b0e57e-0cc2-42c4-afc4-76dd3d71de52" />


