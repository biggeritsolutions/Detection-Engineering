# Detecting Ransomware Pre-Encryption Activity via Shadow Copy Deletion

## Threat Context

Modern ransomware operators routinely delete Volume Shadow Copies prior to encryption to prevent recovery.

Common tooling observed:
- vssadmin
- wmic
- PowerShell WMI queries

This activity often occurs after initial access and privilege escalation, but before encryption deployment.

## Detection Strategy

We focus on process creation telemetry because:
- SMB environments may not have full EDR coverage
- Native Windows logs are often available
- This technique requires command-line interaction

The detection logic looks for:
- vssadmin delete shadows
- wmic shadowcopy delete
- PowerShell removal of Win32_Shadowcopy objects

## Why This Matters in SMB

SMBs rarely:
- Perform routine shadow copy deletion
- Run WMI removal commands manually

This makes the signal-to-noise ratio strong.

## Tuning Considerations

- Validate backup software behaviors
- Baseline any IT maintenance scripts
- Alert severity should remain HIGH unless business process dictates otherwise

## Hunt Expansion

If triggered, pivot to:
- Recent lateral movement activity
- Credential dumping artifacts
- Scheduled task creation
- Unusual admin logons

## MITRE ATT&CK Mapping

- T1490 – Inhibit System Recovery
- T1059 – Command and Scripting Interpreter

This detection aligns strongly with ransomware pre-encryption tradecraft.
