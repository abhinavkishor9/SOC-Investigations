# Failed Login Investigation — Windows Event ID 4625

## Objective

The objective of this investigation was to analyze failed authentication attempts using Windows Security Event ID 4625 and identify potential brute-force or unauthorized login activity.

This investigation focused on:
- failed login analysis
- authentication telemetry
- brute-force detection
- logon type investigation
- source IP analysis
- SIEM correlation logic
- SOC escalation workflow

---

# Investigation Scenario

Failed login events are critical authentication-related telemetry frequently monitored by SOC analysts.

Repeated failed login attempts may indicate:
- password guessing
- brute-force attacks
- credential stuffing
- account enumeration
- unauthorized access attempts

This lab simulated failed authentication activity in a controlled SOC lab environment.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 VM |
| Log Source | Windows Security Logs |
| Event Viewer | Windows Event Viewer |
| Investigation Type | Authentication Failure Analysis |
| Virtualization | VMware Workstation |

---

# Attack Simulation

The following actions were performed:
- workstation locked using `Windows + L`
- incorrect password entered multiple times
- repeated login failures generated

This created:
```text id="4625md2"
Windows Security Event ID 4625
```

---

# Telemetry Generated

| Telemetry Type | Description |
|---|---|
| Event ID 4625 | Failed login attempt |
| Authentication Logs | Login failure telemetry |
| Account Monitoring | Targeted user account visibility |
| Logon Type Data | Local or remote login identification |

---

# Event Viewer Investigation

## Log Location

```text id="4625md3"
Windows Logs
→ Security
```

---

# Event ID Investigated

```text id="4625md4"
Event ID 4625 — Failed Logon
```

---

# Important Fields Identified

| Field | Purpose |
|---|---|
| Account Name | Targeted username |
| Logon Type | Type of login attempt |
| Source Network Address | Source IP address |
| Failure Reason | Cause of login failure |
| Workstation Name | Originating system |
| Process Name | Authentication process |

---

# Event Analysis

## Targeted Account

The investigation identified repeated failed login attempts against the configured lab account.

---

# Logon Type Analysis

Observed Logon Type:

```text id="4625md5"
7 — Unlock Workstation
```

---

# Logon Type Reference

| Logon Type | Description |
|---|---|
| 2 | Interactive Local Login |
| 3 | Network Login |
| 7 | Unlock Workstation |
| 10 | Remote Desktop Login |

---

# Failure Reason Analysis

Observed behavior:
- incorrect password submission
- authentication rejection
- repeated login failures

Potential attacker objectives:
- password guessing
- credential brute force
- unauthorized access attempts

---

# Security Relevance

Windows Event ID 4625 is highly valuable for:
- brute-force detection
- password spray analysis
- account enumeration detection
- authentication monitoring
- SOC correlation rules

SOC analysts frequently monitor:
- repeated failures
- multiple usernames
- repeated source IPs
- administrative account targeting
- failed RDP authentication

---

# Investigation Workflow

## Step 1 — Generate Failed Login Events

The workstation was intentionally locked and incorrect passwords were entered multiple times.

---

# Step 2 — Filter Security Logs

Security logs were filtered for:

```text id="4625md6"
Event ID 4625
```

---

# Step 3 — Analyze Authentication Telemetry

The following indicators were reviewed:
- account name
- logon type
- failure reason
- source system
- authentication process

---

# Analyst Observations

The failed login activity observed in this lab was generated intentionally for defensive security analysis.

Although benign in this environment, repeated failed login attempts may indicate:
- brute-force attacks
- password spraying
- unauthorized access attempts
- compromised credentials

---

# Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Event ID | 4625 |
| Activity Type | Failed Authentication |
| Log Source | Windows Security Logs |
| Suspicious Pattern | Repeated Login Failures |

---

# Detection Logic

## Detection Objective

Detect:
- repeated failed logins
- brute-force activity
- password spray attempts
- abnormal authentication failures

---

# Detection Conditions

| Detection Area | Logic |
|---|---|
| Authentication Failures | Event ID 4625 |
| Brute Force Detection | Multiple failures from same source |
| Account Targeting | Repeated attempts against same user |
| Time Correlation | High failure frequency within short timeframe |

---

# Correlation Logic

Potential brute-force indicators:
- multiple failed logins
- repeated authentication failures
- repeated attempts from same IP
- administrative account targeting
- rapid login failure sequences

---

# Splunk Detection Query

```spl id="4625md7"
EventCode=4625
| stats count by Account_Name Source_Network_Address
| sort - count
```

---

# Brute Force Detection Query

```spl id="4625md8"
EventCode=4625
| stats count by Source_Network_Address
| where count > 5
```

---

# Sigma Rule

```yaml id="4625md9"
title: Multiple Failed Login Attempts
id: failed-login-4625-detection
status: experimental
description: Detects repeated failed login attempts that may indicate brute-force activity.
author: Abhinav Kishor
date: 2026-05-28

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625

  condition: selection

fields:
  - Account_Name
  - Source_Network_Address
  - Workstation_Name
  - Logon_Type

falsepositives:
  - User password typos
  - Expired credentials
  - Forgotten passwords

level: medium

tags:
  - attack.credential_access
  - attack.t1110
  - windows
  - authentication
  - brute_force
```

---

# MITRE ATT&CK Mapping

| Technique ID | Technique |
|---|---|
| T1110 | Brute Force |
| T1078 | Valid Accounts |

---

# Escalation Severity

| Scenario | Severity |
|---|---|
| Single Failed Login | Low |
| Multiple Failed Logins | Medium |
| Repeated Admin Account Targeting | High |
| External RDP Brute Force | Critical |

---

# False Positive Considerations

Potential legitimate causes:
- incorrect password entry
- expired passwords
- forgotten credentials
- keyboard layout issues
- account lockout behavior

Analyst validation is required before escalation.

---

# Recommended Containment Actions

If malicious activity is confirmed:

- block suspicious source IP
- disable compromised accounts
- enforce MFA
- reset affected credentials
- review authentication logs
- investigate lateral movement
- monitor for persistence activity

---

# Investigation Outcome

The investigation successfully identified and analyzed Windows Event ID 4625 failed login telemetry.

The lab demonstrated:
- authentication monitoring
- failed login analysis
- brute-force detection logic
- SIEM correlation opportunities
- SOC investigation methodology

---

# Key Learnings

This investigation improved understanding of:
- Windows authentication telemetry
- failed login investigations
- brute-force detection
- SIEM correlation logic
- Event ID 4625 analysis
- SOC escalation workflow
- authentication threat hunting

---

# Future Improvements

Planned enhancements:
- Splunk dashboard integration
- Wazuh authentication alerts
- failed login timeline analysis
- source IP correlation
- account lockout monitoring
- screenshot documentation
- brute-force threshold tuning

---
