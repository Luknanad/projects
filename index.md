---
title: Cybersecurity Projects
description: Luka’s projects
show_downloads: true
google_analytics: UA‑XXXXX‑X   # replace with your GA code or remove line
theme: jekyll-theme-hacker
layout: default
---

# Security Monitoring with Microsoft Sentinel

A beginner‑to‑intermediate SIEM project showing how to detect and alert on Windows login events using Microsoft Sentinel on Azure.

---

## 🚀 Live Demo & Repo

**GitHub Repo:** [sentinel-log-alerting-project](https://github.com/<your‑username>/sentinel-log-alerting-project)

---

## 🔍 Project Highlights

- **VM & Logs**: Windows Server 2022 VM → Azure Monitor Agent → Log Analytics  
- **SIEM**: Microsoft Sentinel Onboarded  
- **Detection Rules** (KQL):
  1. **Local Login** (`01-local-signin.kql`):  
     ```kql
     // Detect successful local keyboard login
     SecurityEvent
     | where EventID == 4624
     | where LogonType == 2
     | where Account !contains "SYSTEM"
     | project TimeGenerated, Account, Computer
     ```
  2. **Brute‑Force** (`03-bruteforce.kql`):  
     ```kql
     // 5+ failed logins in 15m, then success
     let failed = SecurityEvent
       | where EventID == 4625
       | summarize count() by Account, bin(TimeGenerated, 15m);
     let success = SecurityEvent
       | where EventID == 4624
       | project Account, TimeGenerated;
     failed
       | where count_ > 5
       | join kind=inner success on Account
       | where success.TimeGenerated > failed.TimeGenerated
     ```
- **Automated Response**: Logic App playbook sends an email when an alert fires.

---

## 📸 Screenshots

<div style="display:flex; gap:1rem; flex-wrap:wrap;">
  <img src="screenshots/alert_triggered.png" alt="Sentinel Alert" width="300">
  <img src="screenshots/incident.png"      alt="Incident View" width="300">
</div>

---

## 🛠️ How to Reproduce

1. **Clone**  
   ```bash
   git clone https://github.com/<your‑username>/sentinel-log-alerting-project.git
   cd sentinel-log-alerting-project
