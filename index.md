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
@description('Deployment location')
param location string = resourceGroup().location

@description('Prefix for resource names (e.g., contoso-sentinel)')
param prefix string = 'contoso-sentinel'

@description('Admin username for the VM')
param adminUsername string

@description('Key Vault name where the VM admin password is stored')
param keyVaultName string

@description('Secret name in Key Vault that contains the admin password')
param keyVaultSecretName string = 'vmAdminPassword'

@description('Tags to apply to all resources')
param tags object = {
  environment: 'dev'
  owner: 'Luka'
  project: 'SentinelLab'
}

var vmName = '${prefix}-vm'
var nicName = '${prefix}-nic'
var vnetName = '${prefix}-vnet'
var subnetName = 'default'
var ipName = '${prefix}-publicip'
var workspaceName = '${prefix}-law'
var dcrName = '${prefix}-dcr'

resource vnet 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2021-05-01' = {
  name: ipName
  location: location
  tags: tags
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2021-05-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
  name: keyVaultName
}

var adminPassword = listSecret(keyVaultName, '2022-07-01', keyVaultSecretName).value

resource vm 'Microsoft.Compute/virtualMachines@2021-07-01' = {
  name: vmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: vmName
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
      osDisk: {
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2021-09-01' = {
  name: dcrName
  location: location
  tags: tags
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'SecurityEvents'
          streams: ['Microsoft-SecurityEvent']
          eventLogName: 'Security'
          xPathQueries: ['*']
        }
      ]
      performanceCounters: [
        {
          name: 'CPUUsage'
          streams: ['Microsoft-Perf']
          samplingFrequencyInSeconds: 60
          counterSpecifiers: ['\\Processor(_Total)\\% Processor Time']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'lawDestination'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-SecurityEvent', 'Microsoft-Perf']
        destinations: ['lawDestination']
      }
    ]
  }
}

resource sentinel 'Microsoft.SecurityInsights/sentinelOnboardingStates@2021-10-01' = {
  name: workspace.name
  properties: {
    state: 'Onboarded'
  }
}

output vmPublicIp string = publicIp.properties.ipAddress
output workspaceId string = workspace.id
output vmName string = vm.name

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
TimeGenerated,AlertName,Account,LogonType,Computer,IPAddress,Severity
2025-07-10T08:23:15Z,Local Sign‑In,Giorgi,2,sec-lab-vm,10.0.0.4,Medium
2025-07-10T09:01:07Z,Brute‑Force Attempt,Nino,0,sec-lab-vm,192.168.1.10,High
2025-07-10T09:01:53Z,Local Sign‑In,Nino,2,sec-lab-vm,192.168.1.10,Medium
2025-07-10T10:45:29Z,RDP Sign‑In,Lasha,10,sec-lab-vm,203.0.113.45,Medium
2025-07-10T11:12:04Z,Admin‑Group Change,Mariam,5,sec-lab-vm,10.0.0.4,High
2025-07-10T12:30:47Z,Local Sign‑In,Giorgi,2,sec-lab-vm,10.0.0.4,Medium
2025-07-10T13:05:22Z,Brute‑Force Attempt,Tea,0,sec-lab-vm,198.51.100.23,High
2025-07-10T13:06:01Z,Local Sign‑In,Tea,2,sec-lab-vm,198.51.100.23,Medium
2025-07-10T14:17:58Z,RDP Sign‑In,Levan,10,sec-lab-vm,198.51.100.23,Medium
2025-07-10T15:42:13Z,Local Sign‑In,Ketevan,2,sec-lab-vm,10.0.0.4,Medium


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
