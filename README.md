# SOC-Investigations

A hands-on cybersecurity repository focused on SOC analysis, Sysmon telemetry, Windows Event ID investigations, threat hunting, and detection engineering.

This repository documents practical investigations performed in a personal SOC lab environment using Windows VMs, Sysmon, Event Viewer, PowerShell, and security monitoring techniques.

---

# Objectives

- Practice real-world SOC investigation workflows
- Learn Windows and Sysmon telemetry analysis
- Understand attacker techniques and detection opportunities
- Build hands-on threat hunting and incident analysis skills
- Create a professional cybersecurity portfolio

---

# Lab Environment

| Component | Details |
|---|---|
| Virtualization | VMware Workstation Player |
| Operating System | Windows 10 VM |
| Monitoring Tool | Sysmon |
| Log Analysis Tool | Windows Event Viewer |
| Shells Used | CMD, PowerShell |
| Future Expansion | Wazuh SIEM, Sigma Rules |

---

# Investigation Areas

This repository will include investigations related to:

- Sysmon Event ID Analysis
- Windows Security Event Logs
- Process Creation Monitoring
- PowerShell Detection
- Parent-Child Process Analysis
- Failed Login Investigations
- Persistence Detection
- Threat Hunting
- IOC Correlation
- Detection Engineering

---

# Current Investigations

| Investigation | Status |
|---|---|
| Sysmon Event ID 1 — Process Creation Analysis | Completed |
| Encoded PowerShell Detection | In Progress |
| Failed Login Investigation (4625) | Planned |
| Network Connection Analysis | Planned |
| DNS Query Investigation | Planned |

---

# Repository Structure

```text
SOC-Investigations/
│
├── Sysmon/
│   ├── sysmon-eventid1-process-analysis.md
│   ├── encoded-powershell-analysis.md
│
├── Windows-Event-Logs/
│
├── Threat-Hunting/
│
├── IOC-Reports/
│
└── Screenshots/
