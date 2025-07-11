<!-- index.html -->

---

## layout: default

# Security Monitoring Lab with Microsoft Sentinel

This project deploys a Windows Server 2022 VM in Azure, forwards its Windows SecurityEvent logs into Microsoft Sentinel, applies custom KQL detection rules to spot suspicious login activity, and uses an Azure Logic Apps playbook to send email alerts.

## Objectives

> Build a basic SIEM pipeline to detect Initial Access and Credential Access techniques, automate notifications, and demonstrate end-to-end workflow.

1. Provision Azure infrastructure: VM, Log Analytics workspace, and Sentinel onboard.
2. Install Azure Monitor Agent and configure Data Collection Rule for Security events.
3. Create KQL rules to detect:

   * Successful local (keyboard) logins (Event 4624, LogonType 2)
   * RDP logins (Event 4624, LogonType 10)
   * Brute‑force attempts (>5 failures then one success)
   * Admin‑group membership changes (Events 4728, 4729, 4732, 4733)
4. Automate email alerts with a Logic Apps playbook.
5. Validate with sample alerts and screenshots.

---

## Infrastructure (Bicep)

```bicep
// Deploy VM, workspace, and Sentinel
param location string = resourceGroup().location
param adminUsername string
@secure() param adminPassword string

resource vm 'Microsoft.Compute/virtualMachines@2021-07-01' = {
  name: 'sec-lab-vm'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    osProfile: { computerName: 'sec-lab-vm', adminUsername: adminUsername, adminPassword: adminPassword }
    storageProfile: {
      imageReference: { publisher: 'MicrosoftWindowsServer', offer: 'WindowsServer', sku: '2022-Datacenter', version: 'latest' }
      osDisk: { createOption: 'FromImage' }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id }] }
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: 'secLab-law'
  location: location
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2021-09-01' = {
  name: 'secLab-DCR'
  location: location
  properties: {
    dataSources: { windowsEvents: [{ name: 'SecurityEvents', streams: ['Security'] }] }
    dataFlows: [{ streams: ['Security'], destinations: [{ workspaceId: workspace.id }] }]
  }
}

resource sentinel 'Microsoft.SecurityInsights/sentinelOnboardingStates@2021-10-01' = {
  name: workspace.name
  properties: { state: 'Onboarded' }
}
```

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

## Automated Response Playbook

*This Logic App sends an email whenever Sentinel creates an incident.*

```json
{
  "definition": {
    "triggers": {
      "When_an_incident_is_created": { "type": "HttpRequest", "inputs": {} }
    },
    "actions": {
      "Send_an_email": {
        "type": "Office365.SendEmail",
        "inputs": {
          "To": "you@example.com",
          "Subject": "@{triggerBody()?['properties']['alertRuleName']}",
          "Body": "Alert fired at @{triggerBody()?['properties']['timeGenerated']}"
        }
      }
    }
  }
}
```

---

## Sample Alerts Export

```csv
TimeGenerated,Account,LogonType,Computer,IPAddress
2025-07-06T10:15:23Z,Alice,2,sec-lab-vm,10.0.0.4
2025-07-06T11:05:42Z,Bob,10,sec-lab-vm,52.168.1.10
```

---

### Screenshots

![Alert Triggered](screenshots/alert_triggered.png)
*Sentinel alert card for local-signin.*

![Incident View](screenshots/incident_view.png)
*Incident investigation pane.*

```
Long, single-line code blocks scroll horizontally.
```

```
End of project page.
```
