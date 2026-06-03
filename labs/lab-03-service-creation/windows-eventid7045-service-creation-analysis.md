# MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic |
|---|---|---|
| T1543.003 | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation |

---

# Detection Logic Used

Detect unauthorized or suspicious service installations using:

- Windows System Event ID 7045
- newly created services
- suspicious executable paths
- uncommon service names
- services running from user-writable directories

### Detection Logic Summary

```text
IF Event ID 7045 occurs
AND service executable path is suspicious or unauthorized
THEN flag as potential persistence activity
```

---

# Event ID Investigated

```text
Event ID 7045 — A Service Was Installed In The System
```

Purpose:

- detect new service creation
- identify persistence mechanisms
- monitor unauthorized software installation
- investigate privilege escalation attempts

---

# Sigma Rule Created

```yaml
title: Suspicious Service Installation
id: suspicious-service-installation-7045
status: experimental

description: Detects creation of new Windows services that may indicate persistence or unauthorized activity.

author: Abhinav Kishor
date: 2026-05-28

logsource:
  product: windows
  service: system

detection:
  selection:
    EventID: 7045

  suspicious_paths:
    ServiceFileName|contains:
      - '\Temp\'
      - '\Users\Public\'
      - 'powershell.exe'
      - 'cmd.exe'
      - 'rundll32.exe'

  condition: selection and suspicious_paths

fields:
  - ServiceName
  - ServiceFileName
  - StartType
  - AccountName

falsepositives:
  - Legitimate software installation
  - Approved IT administration tools
  - Enterprise management software

level: high

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003
```

---

# Escalation Severity

```text
Medium
```

Reason:

A new service was installed on the system. While legitimate software installations commonly create services, attackers also use services for persistence and privilege escalation. Analyst validation is required.

---

# False Positive Considerations

Potential legitimate causes:

- software installation
- Windows updates
- antivirus updates
- endpoint management tools
- authorized administrative activity

Analyst review is required before escalation.

---

# Recommended Containment

Validate whether the service installation was authorized. Disable and remove unauthorized services and investigate associated processes, files, and persistence mechanisms.
