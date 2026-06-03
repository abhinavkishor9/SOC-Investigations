# Registry Run Key Persistence Detection — Sysmon Event ID 13

## Objective

The objective of this investigation was to analyze Windows Registry Run Key modifications using Sysmon Event ID 13 and identify potential persistence mechanisms used by attackers to maintain access across system reboots and user logins.

This investigation focused on:
- persistence detection
- registry monitoring
- startup execution analysis
- threat hunting
- Sysmon telemetry analysis
- detection engineering

---

# Investigation Scenario

Registry Run Keys are commonly abused by attackers and malware to achieve persistence.

When a user logs in, programs configured in Run Keys execute automatically, making them an attractive persistence mechanism.

This lab simulated a registry Run Key modification in a controlled SOC environment and analyzed the resulting telemetry.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 VM |
| Monitoring Tool | Sysmon |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Analysis Tools | Event Viewer, Registry Editor |
| Virtualization | VMware Workstation |
| Investigation Type | Persistence Analysis |

---

# Attack Simulation

The following command was executed:

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SOCLabPersistence /t REG_SZ /d "notepad.exe"
```

This created a registry Run Key that launches Notepad automatically during user logon.

---

# Logs Used

| Log Source | Purpose |
|---|---|
| Sysmon Operational Logs | Registry monitoring |
| Event Viewer | Event investigation |
| Event ID 13 | Registry value modification monitoring |

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
Event ID 13 — Registry Value Set
```

---

# Telemetry Generated

| Telemetry Type | Description |
|---|---|
| Registry Modification | Registry value change |
| Process Metadata | Process performing change |
| Registry Path | Modified registry location |
| Value Data | Configured executable |

---

# Important Fields Identified

| Field | Purpose |
|---|---|
| EventType | Type of registry modification |
| TargetObject | Modified registry path |
| Details | Registry value data |
| Image | Process making change |
| User | Account involved |

---

# Event Analysis

The investigation focused on:

- registry key modified
- executable configured for startup
- process responsible for modification
- user account performing action

Particular attention was given to Run and RunOnce registry locations due to their persistence capabilities.

---

# Security Relevance

Registry Run Keys are frequently abused by:

- malware
- ransomware
- remote access trojans
- persistence frameworks
- red team tools

SOC analysts commonly monitor:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

and

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

for suspicious changes.

---

# Analyst Observations

The registry modification created a startup entry that automatically executes an application during user logon.

Although the activity was intentionally generated in a lab environment, unauthorized Run Key creation in production environments should be investigated as potential persistence activity.

---

# Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Event ID | 13 |
| Activity Type | Registry Value Set |
| Registry Path | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| Registry Value | SOCLabPersistence |
| Executable | notepad.exe |
| MITRE Technique | T1547.001 |

---

# MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic |
|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |

---

# Detection Logic Used

## Detection Objective

Detect:
- Run Key modifications
- startup persistence
- unauthorized registry changes
- suspicious executable paths

---

# Detection Conditions

| Detection Area | Logic |
|---|---|
| Registry Monitoring | Sysmon Event ID 13 |
| Persistence Monitoring | Run Key modification |
| Executable Analysis | Startup executable configured |
| Threat Hunting | Suspicious registry changes |

---

# Detection Logic Summary

```text
IF a Run or RunOnce registry key is modified
AND the value references an executable
THEN flag as potential persistence activity
```

---

# Sigma Rule Created

```yaml
title: Registry Run Key Persistence Detection
id: registry-runkey-persistence
status: experimental

description: Detects registry Run Key modifications that may indicate persistence.

author: Abhinav Kishor
date: 2026-05-28

logsource:
  product: windows
  category: registry_set

detection:
  selection:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'

  condition: selection

fields:
  - Image
  - User
  - TargetObject
  - Details

falsepositives:
  - Legitimate software installation
  - Application updates
  - Enterprise management tools

level: high

tags:
  - attack.persistence
  - attack.t1547.001
```

---

# Splunk Detection Query

```spl
index=sysmon EventCode=13
| search TargetObject="*\\CurrentVersion\\Run*"
| table _time Computer User Image TargetObject Details
```

---

# Escalation Severity

```text
Medium
```

Reason:

A Registry Run Key was modified, creating a startup entry. While this may be legitimate software behavior, Run Keys are commonly used by attackers for persistence and require analyst review.

---

# False Positive Considerations

Potential legitimate causes:

- software installation
- software updates
- antivirus products
- endpoint management tools
- approved administrative actions

Analyst validation is required before escalation.

---

# Recommended Containment

Validate whether the registry modification was authorized. Remove unauthorized Run Keys and investigate the associated executable for malicious behavior or additional persistence mechanisms.

---

# Investigation Outcome

The investigation successfully identified and analyzed registry-based persistence using Sysmon Event ID 13.

The lab demonstrated how SOC analysts can detect startup persistence techniques through registry monitoring and threat hunting workflows.

---

# Key Learnings

This investigation improved understanding of:

- Registry Run Keys
- persistence mechanisms
- Sysmon Event ID 13
- registry threat hunting
- startup execution analysis
- detection engineering

---

# Future Improvements

Planned enhancements:

- Registry baseline creation
- Wazuh persistence alerts
- Sigma rule tuning
- IOC enrichment
- persistence hunting dashboards
- ATT&CK coverage mapping

---

