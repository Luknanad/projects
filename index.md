<!-- index.html -->

---



# Security Monitoring Lab with Microsoft Sentinel

This project deploys a Windows Server 2022 VM in Azure, forwards its Windows SecurityEvent logs into Microsoft Sentinel, applies custom KQL detection rules to spot suspicious login activity, and uses an Azure Logic Apps playbook to send email alerts.

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
2025-07-10T09:01:07Z,Brute‑Force Attempt,Nino,0,sec-lab-vm,192.168.1.10,High
2025-07-10T09:01:53Z,Local Sign‑In,Nino,2,sec-lab-vm,192.168.1.10,Medium

```

---

### Screenshots

<img width="1864" height="452" alt="image" src="https://github.com/user-attachments/assets/0a09259e-6e2b-4138-9544-9c947ccc904a" />


![Incident View](screenshots/incident_view.png)
*Incident investigation pane.*

  <h3 style="font-size: 20px; color: #34495e;">Outcome</h3>
  <p>
    Successfully built a lightweight SIEM solution to detect key TTPs from MITRE ATT&CK (Initial Access and Credential Access). This project demonstrates how to leverage Azure-native tools for:
    <ul>
      <li>Security log collection and aggregation</li>
      <li>Threat detection with KQL</li>
      
    </ul>
  </p>
</section>
