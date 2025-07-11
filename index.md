---
title: Cybersecurity Projects
description: Luka’s projects
show_downloads: true
google_analytics: UA‑XXXXX‑X   # replace with your GA code or remove line
theme: jekyll-theme-hacker
layout: default
---
---
layout: default
---

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Monitoring Lab with Microsoft Sentinel</title>
  <style>
    body { font-family: Arial, sans-serif; margin:0; padding:0; background:#f9f9f9; color:#333; }
    .container { max-width:900px; margin:0 auto; padding:20px; }
    h1, h2, h3 { color:#111; margin-top:1.5em; }
    pre { background:#272822; color:#f8f8f2; padding:15px; overflow-x:auto; border-radius:5px; }
    code { font-family: Consolas, monospace; }
    .flex-img { display:flex; gap:1%; flex-wrap:wrap; }
    .flex-img img { width:48%; border-radius:5px; border:1px solid #ddd; }
    ol { margin-left:1.2em; }
    footer { margin-top:3em; text-align:center; font-size:0.85em; color:#666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Security Monitoring Lab with Microsoft Sentinel</h1>
    <p>A zero‑to‑hero SIEM lab—all on one page—showing how to deploy a Windows Server VM in Azure, ingest security events into Sentinel, write KQL detection rules, and automate alerts with Logic Apps.</p>

    <h2>📁 Project Structure</h2>
    <pre><code>sentinel-log-alerting-project/
├── iac/
│   └── main.bicep
├── rules/
│   ├── 01-local-signin.kql
│   ├── 02-rdp-signin.kql
│   ├── 03-bruteforce.kql
│   └── 04-admin-changes.kql
├── logic-app/
│   └── send-email-playbook.json
├── screenshots/
│   ├── alert_triggered.png
│   └── incident_view.png
└── sample-alerts.csv</code></pre>

    <h2>🚀 Quick Start</h2>
    <ol>
      <li><strong>Clone the repo</strong><br>
        <code>git clone https://github.com/your-username/sentinel-log-alerting-project.git<br>cd sentinel-log-alerting-project</code>
      </li>
      <li><strong>Deploy infra (Bicep)</strong><br>
        <code>az deployment group create \\
  --resource-group MyRG \\
  --template-file iac/main.bicep \\
  --parameters adminUsername=azureuser adminPassword='P@ssw0rd!'</code>
      </li>
      <li><strong>Enable Windows Security Events via AMA</strong>  
        Azure Portal → Sentinel → Data connectors → “Windows Security Events via AMA”
      </li>
      <li><strong>Import detection rules</strong>  
        Sentinel → Analytics → Create custom rule → copy each `.kql` from `rules/`
      </li>
      <li><strong>Import playbook</strong>  
        Logic Apps → Import template → `logic-app/send-email-playbook.json`
      </li>
      <li><strong>Test</strong>  
        Perform local and failed logins on the VM → check Sentinel Incidents
      </li>
    </ol>

    <h2>🏗️ Infrastructure (iac/main.bicep)</h2>
    <pre><code>param location string = resourceGroup().location
param adminUsername string
@secure() param adminPassword string

resource vm 'Microsoft.Compute/virtualMachines@2021-07-01' = {
  name: 'sec-lab-vm'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    osProfile: {
      computerName: 'sec-lab-vm'
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-Datacenter'
        version: 'latest'
      }
      osDisk: { createOption: 'FromImage' }
    }
    networkProfile: { networkInterfaces: [ { id: nic.id } ] }
  }
}

resource law 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: 'secLab-law'
  location: location
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2021-09-01' = {
  name: 'secLab-DCR'
  location: location
  properties: {
    dataSources: { windowsEvents: [ { name: 'SecurityEvents', streams: ['Security'] } ] }
    dataFlows: [ { streams: ['Security'], destinations: [ { workspaceId: law.id } ] } ]
  }
}

resource sentinel 'Microsoft.SecurityInsights/sentinelOnboardingStates@2021-10-01' = {
  name: law.name
  properties: { state: 'Onboarded' }
}</code></pre>

    <h2>🔎 Detection Rules</h2>
    <h3>01-local-signin.kql</h3>
    <pre><code>// Local keyboard login (T1078.002 – Initial Access)
SecurityEvent
| where EventID == 4624
| where LogonType == 2
| where Account !contains "SYSTEM"
| project TimeGenerated, Account, Computer</code></pre>

    <h3>02-rdp-signin.kql</h3>
    <pre><code>// RDP login (T1078.004 – Initial Access)
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where Account !contains "SYSTEM"
| project TimeGenerated, Account, Computer, IPAddress</code></pre>

    <h3>03-bruteforce.kql</h3>
    <pre><code>// Brute-force: >5 failures then success (T1110 – Credential Access)
let failed = SecurityEvent
  | where EventID == 4625
  | summarize count() by Account, bin(TimeGenerated, 15m);
let success = SecurityEvent
  | where EventID == 4624 and Account !contains "SYSTEM"
  | project Account, TimeGenerated;
failed
| where count_ > 5
| join kind=inner success on Account
| where success.TimeGenerated > failed.TimeGenerated</code></pre>

    <h3>04-admin-changes.kql</h3>
    <pre><code>// Admin group changes (T1136 – Persistence)
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733)
| where TargetUserName == "Administrators"
| project TimeGenerated, SubjectAccount, TargetAccount</code></pre>

    <h2>⚙️ Automated Response Playbook</h2>
    <pre><code>{
  "definition": {
    "triggers": {
      "When_an_incident_is_created": {
        "type": "HttpRequest",
        "inputs": { /* Sentinel webhook trigger */ }
      }
    },
    "actions": {
      "Send_an_email": {
        "type": "Office365.SendEmail",
        "inputs": {
          "To": "you@example.com",
          "Subject": "@{triggerBody()?['properties']['alertRuleName']}",
          "Body": "An alert fired: @{triggerBody()?['properties']['description']}"
        }
      }
    }
  }
}</code></pre>
    <p><em>Import via Logic Apps → Import template → <code>logic-app/send-email-playbook.json</code></em></p>

    <h2>📄 Sample Alerts (sample-alerts.csv)</h2>
    <pre><code>TimeGenerated,Account,LogonType,Computer,IPAddress
2025-07-06T10:15:23Z,Alice,2,sec-lab-vm,10.0.0.4
2025-07-06T11:05:42Z,Bob,10,sec-lab-vm,52.168.1.10</code></pre>

    <h2>🖼️ Screenshots</h2>
    <div class="flex-img">
      <img src="screenshots/alert_triggered.png" alt="Alert Triggered">
      <img src="screenshots/incident_view.png"  alt="Incident View">
    </div>

    <footer>
      <p>© 2025 Luka</p>
    </footer>
  </div>
</body>
</html>
