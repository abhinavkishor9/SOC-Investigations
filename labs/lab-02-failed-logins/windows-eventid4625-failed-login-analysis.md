# Encoded PowerShell Detection Investigation

## Objective

The objective of this investigation was to detect and analyze suspicious PowerShell execution involving Base64-encoded commands using Sysmon telemetry and Windows Event Logs.

This investigation focused on:
- PowerShell abuse detection
- command-line analysis
- Base64 payload decoding
- Sysmon Event ID 1 analysis
- detection engineering
- Sigma rule creation

---

# Investigation Scenario

Encoded PowerShell commands are commonly used by attackers to:
- obfuscate malicious commands
- evade detections
- execute hidden payloads
- download malware
- establish persistence

This lab simulated suspicious encoded PowerShell execution in a controlled SOC lab environment.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 VM |
| Monitoring Tool | Sysmon |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Analysis Tools | Event Viewer, PowerShell |
| Virtualization | VMware Workstation |
| Investigation Type | Process Creation Analysis |

---

# Attack Simulation

The following encoded PowerShell command was executed inside the lab VM:

```powershell
powershell -enc ZQBjAGgAbwAgAGgAZQBsAGwAbwA=
```

---

# Telemetry Generated

The activity generated the following telemetry:

| Telemetry Type | Description |
|---|---|
| Sysmon Event ID 1 | Process creation event |
| PowerShell Execution | Encoded PowerShell activity |
| Command-Line Logging | Encoded payload visibility |
| Parent-Child Process Relationship | explorer.exe → powershell.exe |

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

# Event ID Observed

```text
Event ID 1 — Process Creation
```

---

# Important Fields Identified

| Field | Value |
|---|---|
| Event ID | 1 |
| Image | powershell.exe |
| CommandLine | powershell -enc ZQBjAGgAbwAgAGgAZQBsAGwAbwA= |
| ParentImage | explorer.exe |
| User | Lab User |
| IntegrityLevel | Medium |

---

# Command-Line Analysis

Observed command:

```powershell
powershell -enc ZQBjAGgAbwAgAGgAZQBsAGwAbwA=
```

## Suspicious Indicator

The following argument was identified:

```text
-enc
```

This indicates:
```text
EncodedCommand
```

Encoded PowerShell commands are heavily abused in:
- phishing attacks
- malware delivery
- ransomware
- remote command execution
- defense evasion techniques

---

# Base64 Payload Analysis

## Encoded Payload

```text
ZQBjAGgAbwAgAGgAZQBsAGwAbwA=
```

---

# Payload Decoding

The payload was decoded using:

```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("ZQBjAGgAbwAgAGgAZQBsAGwAbwA="))
```

---

# Decoded Result

```powershell
echo hello
```

---

# Analyst Observations

The use of encoded PowerShell execution is considered suspicious because attackers frequently use Base64 encoding to:
- hide malicious commands
- bypass detections
- evade security monitoring
- execute obfuscated payloads

Although the decoded payload in this lab was benign, the execution pattern itself remains highly relevant from a SOC detection perspective.

---

# Parent-Child Process Analysis

## Process Relationship

```text
explorer.exe → powershell.exe
```

### Analysis

The parent process:
```text
explorer.exe
```

indicates user-initiated execution from the desktop session.

This behavior was expected within the controlled lab environment.

---

# Security Relevance

Encoded PowerShell execution is associated with:
- malware loaders
- PowerShell download cradles
- post-exploitation frameworks
- red team tooling
- ransomware execution chains

SOC analysts frequently monitor:
- `-enc`
- `EncodedCommand`
- `FromBase64String`
- suspicious PowerShell child processes

---

# MITRE ATT&CK Mapping

| Technique ID | Technique |
|---|---|
| T1059.001 | PowerShell |
| T1027 | Obfuscated Files or Information |

---

# Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Process | powershell.exe |
| Suspicious Argument | -enc |
| Encoded Payload | ZQBjAGgAbwAgAGgAZQBsAGwAbwA= |
| Parent Process | explorer.exe |

---

# Detection Logic

## Detection Objective

Detect PowerShell execution involving:
- encoded commands
- Base64 payloads
- obfuscated command-line arguments
- suspicious PowerShell activity

---

# Detection Conditions

| Detection Area | Logic |
|---|---|
| Process Creation | Sysmon Event ID 1 |
| PowerShell Monitoring | powershell.exe execution |
| Encoded Command Detection | `-enc` argument |
| Payload Obfuscation | Base64 command usage |

---

# Sigma Rule

```yaml
title: Encoded PowerShell Detection
id: 9f6b1d8c-encoded-powershell-detection
status: experimental
description: Detects PowerShell execution using Base64 encoded commands.
author: Abhinav Kishor
date: 2026-05-27

logsource:
  product: windows
  category: process_creation

detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'

  selection_cmd:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - 'FromBase64String'

  condition: selection_img and selection_cmd

fields:
  - Image
  - ParentImage
  - CommandLine
  - User
  - IntegrityLevel

falsepositives:
  - Administrative automation scripts
  - Legitimate encoded PowerShell usage

level: high

tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

---

# Splunk Detection Query

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*"
| table _time Computer User Image CommandLine ParentImage
```

---

# Escalation Severity

| Severity | Reason |
|---|---|
| High | Encoded PowerShell is commonly associated with malicious activity and command obfuscation |

---

# False Positive Considerations

Potential legitimate cases may include:
- administrative automation
- software deployment scripts
- enterprise management tools

Analyst validation is required before escalation.

---

# Recommended Containment Actions

If malicious activity is confirmed:

- isolate endpoint from network
- terminate suspicious PowerShell process
- preserve event logs
- investigate persistence mechanisms
- review outbound connections
- collect forensic artifacts

---

# Investigation Outcome

The investigation successfully detected encoded PowerShell execution using Sysmon Event ID 1 telemetry.

The activity demonstrated:
- command-line visibility
- Base64 payload identification
- PowerShell threat hunting workflow
- detection engineering opportunities

---

# Key Learnings

This investigation improved understanding of:
- Sysmon process creation logs
- PowerShell threat hunting
- Base64 payload decoding
- command-line analysis
- MITRE ATT&CK mapping
- detection engineering
- Sigma rule development
- SOC investigation workflow

---

# Future Improvements

Future enhancements planned for this investigation:
- Splunk dashboard integration
- Wazuh alert generation
- PowerShell logging correlation
- Event ID correlation analysis
- screenshot documentation
- IOC timeline creation

---

