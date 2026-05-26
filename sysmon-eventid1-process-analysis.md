# Sysmon Event ID 1 Investigation — Process Creation Analysis

## Objective
Analyze Sysmon Event ID 1 logs to understand process creation telemetry and parent-child process relationships.

---

# Environment

| Component | Details |
|---|---|
| OS | Windows 10 VM |
| Monitoring Tool | Sysmon |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Event ID | 1 |
| Investigation Type | Process Creation Analysis |

---

# Event Summary

A Sysmon Event ID 1 log captured execution of `wevtutil.exe` initiated by Microsoft Defender.

---

# Key Fields Observed

| Field | Value |
|---|---|
| Image | C:\Windows\System32\wevtutil.exe |
| ParentImage | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe |
| User | NT AUTHORITY\SYSTEM |
| IntegrityLevel | System |
| CommandLine | wevtutil.exe install-manifest ... |

---

# Analysis

## Process Executed

`wevtutil.exe`

Windows Event Utility used for:
- event log management
- manifest installation
- log operations

---

## Parent Process

`MsMpEng.exe`

This is the Microsoft Defender Antivirus engine.

The parent-child relationship suggests legitimate Defender activity.

---

## Privilege Level

The process executed under:

`NT AUTHORITY\SYSTEM`

This indicates highest system-level privileges.

---

# Security Relevance

Although this event appears legitimate, `wevtutil.exe` is important from a SOC perspective because attackers may abuse it to:

- clear event logs
- tamper logging
- remove evidence

Example malicious usage:

```cmd
wevtutil cl Security
