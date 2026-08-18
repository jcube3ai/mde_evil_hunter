# MITRE ATT&CK Coverage

| MITRE ID | Technique | Script |
|---|---|---|
| T1003.001 | LSASS Memory | VH_Credential_Hunter |
| T1003.002 | SAM/Security Hive | VH_Credential_Hunter |
| T1021.001 | Remote Desktop | VH_Lateral_Hunter |
| T1021.002 | SMB/Admin Shares | VH_Lateral_Hunter |
| T1027.010 | Encoded PowerShell | VH_LOLBin_Hunter |
| T1036 | Masquerading | VH_Defense_Evasion_Hunter |
| T1047 | WMI Execution | VH_Persistence_Hunter + VH_Lateral_Hunter |
| T1048 | Exfil via Cloud | VH_C2_Exfil_Hunter |
| T1053.002 | AT Jobs | VH_ScheduledTask_Hunter |
| T1053.005 | Scheduled Tasks | VH_Persistence_Hunter + VH_ScheduledTask_Hunter |
| T1055 | Process Injection | VH_Defense_Evasion_Hunter |
| T1070.001 | Event Log Cleared | VH_Persistence_Hunter + VH_Defense_Evasion_Hunter |
| T1070.006 | Timestomping | VH_Defense_Evasion_Hunter |
| T1071 | App Layer Protocol C2 | VH_C2_Exfil_Hunter |
| T1071.004 | DNS Beaconing | VH_C2_Exfil_Hunter |
| T1105 | Internet-Sourced Files | VH_Malvertising_RMM_Hunter |
| T1197 | BITS Jobs | VH_Persistence_Hunter + VH_C2_Exfil_Hunter |
| T1218 | LOLBin Execution | VH_LOLBin_Hunter |
| T1219 | RMM Tools | VH_Malvertising_RMM_Hunter |
| T1486 | Data Encrypted / Ransom Notes | VH_PreRansom_Hunter |
| T1490 | Inhibit System Recovery | VH_PreRansom_Hunter |
| T1543.003 | Windows Services | VH_Persistence_Hunter + VH_ServiceInstall_Hunter |
| T1546.003 | WMI Subscriptions | VH_Persistence_Hunter |
| T1546.010 | AppInit_DLLs | VH_Persistence_Hunter |
| T1546.012 | IFEO | VH_Persistence_Hunter |
| T1547.001 | Run Keys | VH_Persistence_Hunter |
| T1547.002 | LSA Auth Packages | VH_Persistence_Hunter |
| T1547.004 | Winlogon Helper | VH_Persistence_Hunter |
| T1547.009 | Startup Folders | VH_Persistence_Hunter |
| T1550.002 | Pass-the-Hash | VH_Lateral_Hunter |
| T1552.001 | Credential Files | VH_Credential_Hunter |
| T1555 | Credentials from Password Stores | VH_Credential_Hunter |
| T1558.003 | Kerberoasting | VH_Credential_Hunter |
| T1558.004 | AS-REP Roasting | VH_Credential_Hunter |
| T1562.001 | Impair Defenses | VH_Defense_Evasion_Hunter |
| T1569.002 | PSExec | VH_Lateral_Hunter |
| T1572 | Named Pipe C2 | VH_C2_Exfil_Hunter |
| T1574.001 | DLL Hijack | VH_Persistence_Hunter |

Techniques with a `(User)`-tagged finding in the console/CSV output (e.g. `Registry Run Key (User)`, `RMM Installed Software (User)`) were resolved per real user profile via `Invoke-VHUserHive` / `Get-VHUserPaths`, rather than from the running process's own context — see `Modules/VH-Common.ps1`.
