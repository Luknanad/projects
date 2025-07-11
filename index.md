---
title: Cybersecurity Projects
description: Luka’s projects
show_downloads: true
google_analytics: UA‑XXXXX‑X   # replace with your GA code or remove line
theme: jekyll-theme-hacker
layout: default
---
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Monitoring Lab with Microsoft Sentinel</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f9f9f9; color: #333; }
    .container { max-width: 900px; margin: 0 auto; padding: 20px; }
    h1, h2, h3, h4 { color: #111; }
    pre { background: #272822; color: #f8f8f2; padding: 15px; overflow-x: auto; border-radius: 5px; }
    code { font-family: Consolas, monospace; }
    .file-structure, .quick-start, .screenshots { margin-bottom: 30px; }
    .screenshots img { max-width: 48%; margin: 1%; border-radius: 5px; border: 1px solid #ddd; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    table, th, td { border: 1px solid #ccc; }
    th, td { padding: 8px; text-align: left; }
    .section { margin-bottom: 40px; }
    .section h2 { border-bottom: 2px solid #ddd; padding-bottom: 5px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Security Monitoring Lab with Microsoft Sentinel</h1>
    <p>A zero-to-hero SIEM lab all on one page: deploy a Windows Server VM in Azure, ingest security events into Sentinel, write KQL detection rules, and automate alerts with Logic Apps.</p>

```
<div class="section file-structure">
  <h2>Project Structure</h2>
  <pre><code>sentinel-log-alerting-project/
```

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
│   ├── alert\_triggered.png
│   └── incident\_view\.png
└── sample-alerts.csv</code></pre> </div>

```
<div class="section quick-start">
  <h2>Quick Start</h2>
  <ol>
    <li><strong>Clone the repo</strong>
      <pre><code>git clone https://github.com/your-username/sentinel-log-alerting-project.git
```

cd sentinel-log-alerting-project</code></pre> </li> <li><strong>Deploy infrastructure (Bicep)</strong> <pre><code>az deployment group create&#x20;
\--resource-group MyRG&#x20;
\--template-file iac/main.bicep&#x20;
\--parameters adminUsername=azureuser adminPassword='P\@ssw0rd!'</code></pre> </li> <li><strong>Enable Windows Security Events via AMA</strong> in Azure Portal → Sentinel → Data connectors.</li> <li><strong>Import KQL detection rules</strong> under Sentinel → Analytics → Create custom rule, copying each file from <code>rules/</code>.</li> <li><strong>Import playbook</strong> in Logic Apps → Import template → <code>logic-app/send-email-playbook.json</code>.</li> <li><strong>Test</strong> by performing local and failed logins on the VM and watching Incidents.</li> </ol> </div>

```
<div class="section">
  <h2>Infrastructure (iac/main.bicep)</h2>
  <pre><code>param location string = resourceGroup().location
```

param adminUsername string
@secure() param adminPassword string

resource vm 'Microsoft.Compute/virtualMachines\@2021-07-01' = {
name: 'sec-lab-vm'
location: location
properties: {
hardwareProfile: { vmSize: 'Standard\_B1s' }
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
networkProfile: { networkInterfaces: \[ { id: nic.id } ] }
}
}

resource law 'Microsoft.OperationalInsights/workspaces\@2021-06-01' = {
name: 'secLab-law'
location: location
}

resource dcr 'Microsoft.Insights/dataCollectionRules\@2021-09-01' = {
name: 'secLab-DCR'
location: location
properties: {
dataSources: { windowsEvents: \[ { name: 'SecurityEvents', streams: \['Security'] } ] }
dataFlows: \[ { streams: \['Security'], destinations: \[ { workspaceId: law\.id } ] } ]
}
}

resource sentinel 'Microsoft.SecurityInsights/sentinelOnboardingStates\@2021-10-01' = {
name: law\.name
properties: { state: 'Onboarded' }
}</code></pre> </div>

```
<div class="section">
  <h2>Detection Rules</h2>

  <h3>01-local-signin.kql</h3>
  <pre><code>// Local keyboard login (T1078.002 – Initial Access)
```

SecurityEvent
\| where EventID == 4624
\| where LogonType == 2
\| where Account !contains "SYSTEM"
\| project TimeGenerated, Account, Computer</code></pre>

```
  <h3>02-rdp-signin.kql</h3>
  <pre><code>// RDP login (T1078.004 – Initial Access)
```

SecurityEvent
\| where EventID == 4624
\| where LogonType == 10
\| where Account !contains "SYSTEM"
\| project TimeGenerated, Account, Computer, IPAddress</code></pre>

```
  <h3>03-bruteforce.kql</h3>
  <pre><code>// Brute-force: >5 failures then success (T1110 – Credential Access)
```

let failed = SecurityEvent
\| where EventID == 4625
\| summarize count() by Account, bin(TimeGenerated, 15m);
let success = SecurityEvent
\| where EventID == 4624 and Account !contains "SYSTEM"
\| project Account, TimeGenerated;
failed
\| where count\_ > 5
\| join kind=inner success on Account
\| where success.TimeGenerated > failed.TimeGenerated</code></pre>

```
  <h3>04-admin-changes.kql</h3>
  <pre><code>// Admin group changes (T1136 – Persistence)
```

SecurityEvent
\| where EventID in (4728, 4729, 4732, 4733)
\| where TargetUserName == "Administrators"
\| project TimeGenerated, SubjectAccount, TargetAccount</code></pre> </div>

```
<div class="section">
  <h2>Automated Response Playbook</h2>
  <pre><code>{
```

"definition": {
"triggers": {
"When\_an\_incident\_is\_created": {
"type": "HttpRequest",
"inputs": { /\* Sentinel webhook trigger \*/ }
}
},
"actions": {
"Send\_an\_email": {
"type": "Office365.SendEmail",
"inputs": {
"To": "[you@example.com](mailto:you@example.com)",
"Subject": "@{triggerBody()?\['properties']\['alertRuleName']}",
"Body": "An alert fired: @{triggerBody()?\['properties']\['description']}"
}
}
}
}
}</code></pre> <p><em>Import via Logic Apps → Import template.</em></p> </div>

```
<div class="section">
  <h2>Sample Alerts (sample-alerts.csv)</h2>
  <pre><code>TimeGenerated,Account,LogonType,Computer,IPAddress
```

2025-07-06T10:15:23Z,Alice,2,sec-lab-vm,10.0.0.4
2025-07-06T11:05:42Z,Bob,10,sec-lab-vm,52.168.1.10</code></pre> </div>

```
<div class="section screenshots">
  <h2>Screenshots</h2>
  <img src="screenshots/alert_triggered.png" alt="Alert Triggered">
  <img src="screenshots/incident_view.png" alt="Incident View">
</div>

<footer>
  <p><small>© 2025 Luka</small></p>
</footer>
```

  </div>
</body>
</html>

├── screenshots/
│   ├── alert_triggered.png
│   └── incident_view.png
└── sample-alerts.csv


