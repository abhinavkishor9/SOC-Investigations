# Sysmon Event ID 1 Investigation — Process Creation Analysis

## 🎯 Objective
Analyze Sysmon Event ID 1 logs to understand process creation telemetry and parent-child process relationships.

## 📝 Scenario
Lab research to baseline legitimate `wevtutil.exe` execution versus potential log tampering.

## 📊 Telemetry Observed
- **Event ID:** 1 (Process Creation)
- **Image:** `C:\Windows\System32\wevtutil.exe`
- **Parent Image:** `MsMpEng.exe` (Microsoft Defender)
- **Integrity Level:** `System`

## 🔍 Analysis Performed
1. Captured process creation events via PowerShell.
2. Verified the parent process (`MsMpEng.exe`) to establish legitimacy.
3. Examined command-line arguments for patterns matching log-clearing activity.

## 🛡️ MITRE ATT&CK Mapping
- **Tactic:** Defense Evasion
- **Technique:** Indicator Removal: Clear Windows Event Logs (T1070.001)

## 💡 Detection Opportunities
**PowerShell Detection Logic:**
```powershell
# Identify attempts to clear security logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
Where-Object {$_.Message -match "wevtutil.*cl.*Security"}




