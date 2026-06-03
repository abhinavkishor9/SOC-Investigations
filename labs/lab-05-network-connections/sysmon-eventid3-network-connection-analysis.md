# Network Connection Analysis — Sysmon Event ID 3

## Objective

The objective of this investigation was to analyze network connection activity using Sysmon Event ID 3 and identify potentially suspicious outbound communications initiated by processes running on a Windows system.

This investigation focused on:
- network telemetry analysis
- outbound connection monitoring
- process-to-network correlation
- threat hunting
- command-and-control detection concepts
- detection engineering

---

# Investigation Scenario

Network connections are a critical source of telemetry for SOC analysts.

Attackers frequently establish network communications to:
- download malware
- communicate with command-and-control (C2) servers
- exfiltrate data
- perform reconnaissance
- retrieve additional payloads

This lab simulated network activity in a controlled SOC environment and analyzed the resulting Sysmon telemetry.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 VM |
| Monitoring Tool | Sysmon |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Analysis Tools | Event Viewer, PowerShell |
| Virtualization | VMware Workstation |
| Investigation Type | Network Connection Analysis |

---

# Attack Simulation

The following commands were executed to generate network telemetry:

```powershell
curl https://www.microsoft.com
```

or

```powershell
nslookup microsoft.com
```

or

```powershell
ping microsoft.com
```

These actions generated outbound network connection events.

---

# Logs Used

| Log Source | Purpose |
|---|---|
| Sysmon Operational Logs | Network connection monitoring |
| Event Viewer | Event investigation |
| Event ID 3 | Network connection telemetry |

---

# Event Viewer Investigation

## Log Location

```text
Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

---

# Event ID Investigated

```text
Event ID 3 — Network Connection
```

---

# Telemetry Generated

| Telemetry Type | Description |
|---|---|
| Network Connections | Outbound communications |
| Process Metadata | Process initiating connection |
| Destination Details | Remote IP and hostname |
| Protocol Information | TCP or UDP activity |

---

# Important Fields Identified

| Field | Purpose |
|---|---|
| Image | Process initiating connection |
| DestinationIp | Remote IP address |
| DestinationHostname | Remote host |
| DestinationPort | Communication port |
| Protocol | TCP or UDP |
| User | Executing account |

---

# Event Analysis

The investigation focused on identifying:

- which process initiated the connection
- destination IP address
- destination hostname
- communication protocol
- destination port

This information helps determine whether the activity is expected or potentially suspicious.

---

# Security Relevance

Sysmon Event ID 3 is highly valuable for:

- threat hunting
- command-and-control detection
- malware investigations
- suspicious outbound traffic analysis
- process-to-network correlation

SOC analysts frequently investigate:

- powershell.exe making external connections
- cmd.exe communicating externally
- rundll32.exe accessing remote hosts
- office applications initiating network activity
- unusual destination ports

---

# Analyst Observations

Network telemetry provides visibility into how processes interact with external systems.

While the activity generated in this lab was legitimate, similar network connections in production environments should be validated to determine whether they are authorized or potentially malicious.

---

# Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Event ID | 3 |
| Activity Type | Network Connection |
| Source Process | Process initiating connection |
| Destination IP | Remote IP address |
| Destination Host | Remote hostname |
| Destination Port | Communication port |

---

# MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic |
|---|---|---|
| T1071 | Application Layer Protocol | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

---

# Detection Logic Used

## Detection Objective

Detect:
- suspicious outbound connections
- unusual process network activity
- command-and-control communications
- abnormal destination hosts

---

# Detection Conditions

| Detection Area | Logic |
|---|---|
| Network Monitoring | Sysmon Event ID 3 |
| Process Analysis | Unusual process activity |
| Destination Analysis | Suspicious IPs or domains |
| Port Monitoring | Uncommon destination ports |

---

# Detection Logic Summary

```text
IF a process establishes an outbound network connection
AND the process or destination appears suspicious
THEN flag for analyst review
```

---

# Sigma Rule Created

```yaml
title: Suspicious Outbound Network Connection
id: suspicious-network-connection-sysmon-3
status: experimental

description: Detects network connections initiated by potentially suspicious processes.

author: Abhinav Kishor
date: 2026-05-28

logsource:
  product: windows
  category: network_connection

detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\rundll32.exe'

  condition: selection

fields:
  - Image
  - User
  - DestinationIp
  - DestinationHostname
  - DestinationPort
  - Protocol

falsepositives:
  - Administrative scripts
  - Software updates
  - Legitimate automation tools

level: medium

tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1105
```

---

# Splunk Detection Query

```spl
index=sysmon EventCode=3
| table _time Computer User Image DestinationIp DestinationHostname DestinationPort Protocol
```

---

# Escalation Severity

```text
Medium
```

Reason:

A network connection was established by a process on the system. While this may be legitimate, unusual processes communicating externally should be reviewed to determine whether malicious activity is occurring.

---

# False Positive Considerations

Potential legitimate causes:

- web browsing activity
- software updates
- cloud synchronization
- enterprise management tools
- administrative scripts

Analyst validation is required before escalation.

---

# Recommended Containment

Investigate the originating process and validate the destination IP or domain. Isolate the endpoint if suspicious external communication or command-and-control activity is identified.

---

# Investigation Outcome

The investigation successfully analyzed Sysmon Event ID 3 network connection telemetry and demonstrated process-to-network correlation techniques used by SOC analysts.

---

# Key Learnings

This investigation improved understanding of:

- Sysmon network telemetry
- outbound connection analysis
- process-to-network correlation
- command-and-control detection concepts
- threat hunting methodologies
- detection engineering

---

# Future Improvements

Planned enhancements:

- Wireshark packet analysis
- IOC enrichment
- threat intelligence correlation
- Splunk dashboards
- Wazuh alert integration
- network timeline analysis

---
