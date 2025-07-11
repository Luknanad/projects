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

# Security Monitoring Lab with Microsoft Sentinel

This project shows how to deploy a Windows Server VM in Azure, stream security events into Microsoft Sentinel, write KQL detection rules, and automate alerts with Logic Apps—all on one page.

## Project Overview

> A step-by-step SIEM use case, from infrastructure to alerting, focused on detecting suspicious login activity (Initial Access via MITRE ATT&CK).

Core components:

* Azure Windows Server 2022 VM  
* Azure Monitor Agent (AMA) & Data Collection Rule  
* Log Analytics workspace  
* Microsoft Sentinel analytics rules  
* Azure Logic App playbook for email alerts  

---

## File Structure

```plaintext
sentinel-log-alerting-project/
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
└── sample-alerts.csv


