# MDE_Evil_Hunter

A library of standalone PowerShell threat-hunting scripts built specifically to run through **Microsoft Defender for Endpoint Live Response's script library** during active IR — upload once, `run` against any onboarded endpoint, `getfile` the CSV back.

This is a from-the-ground-up port of [VeilHunter](https://github.com/jcube3ai/veil_hunter), rebuilt around one constraint VeilHunter wasn't originally designed for: **Live Response executes scripts as `NT AUTHORITY\SYSTEM`.** Under SYSTEM, `$env:USERPROFILE`, `$env:APPDATA`, `$env:LOCALAPPDATA`, `$env:TEMP`, and the `HKCU:` registry drive all resolve to the SYSTEM profile — not the logged-on or compromised user. A hunter written against those variables runs clean and finds nothing, every time, on exactly the box you're investigating.

Every hunter here walks real user profiles and (where relevant) mounts offline `NTUSER.DAT` hives instead, so persistence, credential theft, and staged files planted in a user's context still show up when you run this against a machine as SYSTEM.

## Why this exists

Cortex XSIAM / your SIEM tells you *something* fired on a host. Live Response gets you a shell on that host. What's been missing is a fast, no-agent-install way to run a structured hunt across the same MITRE ATT&CK coverage you'd normally reach for in KQL/XQL — directly from that shell, headless, with results you can pull back and drop straight into a ticket.

## Library

| Script | Category | MITRE Coverage |
|---|---|---|
| `VH_Persistence_Hunter.ps1` | Persistence | Scheduled tasks, services, WMI subscriptions, BITS jobs, Run keys (HKLM + every user's HKCU), IFEO, DLL hijacks, startup folders (every user), Winlogon, LSA auth packages |
| `VH_ScheduledTask_Hunter.ps1` | Persistence | Scheduled task deep dive: event log + live enumeration, AT jobs, raw task XML LOLBin scan |
| `VH_ServiceInstall_Hunter.ps1` | Persistence | Service installs (7045), start-type changes (7040), unsigned service binaries |
| `VH_Malvertising_RMM_Hunter.ps1` | Initial Access | Internet-sourced files (Zone.Identifier ADS) across every user, RMM tool footprints (service + per-user Uninstall key), task XML LOLBin refs |
| `VH_Credential_Hunter.ps1` | Credential Access | LSASS access/dumper tools, SAM/hive dumps, DPAPI master keys, browser credential stores, Credential Manager vault, credential-pattern files — all per real user |
| `VH_Lateral_Hunter.ps1` | Lateral Movement | SMB admin shares, WMI lateral movement, RDP anomalies, Pass-the-Hash, PSExec/remote exec |
| `VH_Defense_Evasion_Hunter.ps1` | Defense Evasion | AMSI bypass, Defender tampering, event log clearing, masquerading, process injection, timestomping |
| `VH_C2_Exfil_Hunter.ps1` | C2 + Exfiltration | Suspicious connections, BITS abuse, named pipe C2, DNS beaconing, cloud exfil staging — per real user's sync folders |
| `VH_PreRansom_Hunter.ps1` | Impact | Shadow copy deletion, backup tampering, ransom note drops, ransomware extensions, inhibited recovery — per real user's Desktop/Documents/Downloads |
| `VH_LOLBin_Hunter.ps1` | Execution | 24 LOLBins with parent/child chain analysis, encoded command decoding, unsigned staged binaries |

Every hunter dot-sources `Modules/VH-Common.ps1`, which provides:

- `Get-VHUserProfiles` — enumerate real user profiles on disk
- `Get-VHUserPaths` — resolve a profile-relative path (e.g. `Downloads`, `AppData\Local\Temp`) across every real user, plus the caller's own profile as a fallback
- `Invoke-VHUserHive` — run a scriptblock against every user's registry hive, mounting offline `NTUSER.DAT` files as needed and always unloading them afterward
- `Add-Finding` / `Export-Findings` / `Write-VHResults` / `Get-SignatureStatus` — shared finding store, CSV export, and console output so every hunter produces identical output shape

See `docs/MDE_LIVE_RESPONSE.md` for the upload/run/retrieve workflow, and `docs/MITRE_COVERAGE.md` for the full technique-to-script map.

## Quick start (local / interactive)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Hunters\VH_Persistence_Hunter.ps1                          # GUI launcher
.\Hunters\VH_Persistence_Hunter.ps1 -Headless -All            # headless, console output
.\Hunters\VH_Persistence_Hunter.ps1 -Headless -All -OutputPath C:\Hunts\persistence.csv
```

## Quick start (MDE Live Response)

```
run VH_PreRansom_Hunter.ps1 -parameters "-Headless -All -OutputPath C:\Windows\Temp\vh_preransom.csv"
getfile C:\Windows\Temp\vh_preransom.csv
```

Upload each `Hunters\*.ps1` file to the MDE Live Response script library individually — **do not** upload a folder. Each script is fully standalone (no dependency on sibling files being present on the endpoint) except for its dot-source of `Modules\VH-Common.ps1`, so **`VH-Common.ps1` must be uploaded to the library too**, and the hunter scripts resolve it relative to their own folder via `$PSScriptRoot`. See `docs/MDE_LIVE_RESPONSE.md` for exactly how to lay that out in the library.

## Output

Every hunter exports the same CSV shape via `-OutputPath`:

```
Timestamp, Severity, TechniqueID, Technique, Artifact, Detail, Path, User
```

`User` is populated wherever a finding is attributable to a specific profile (credential stores, per-user Run keys, ransom notes on a Desktop, etc.) and blank for machine-wide findings.

## Recommended IR triage order

1. `VH_PreRansom_Hunter.ps1` — check for imminent/in-progress encryption indicators
2. `VH_Credential_Hunter.ps1` — determine if credentials are compromised
3. `VH_Lateral_Hunter.ps1` — assess scope of movement across the environment
4. `VH_C2_Exfil_Hunter.ps1` — identify active C2 channels
5. `VH_Persistence_Hunter.ps1` + `VH_ScheduledTask_Hunter.ps1` + `VH_ServiceInstall_Hunter.ps1` — find what's keeping the attacker in

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 10 / Windows Server 2016 or later |
| PowerShell | 5.1+ (whatever ships on the endpoint — Live Response does not let you choose) |
| Privileges | SYSTEM (automatic under Live Response) or local Administrator for interactive use |
| Execution Policy | `Set-ExecutionPolicy Bypass -Scope Process -Force` for interactive use; not needed under Live Response |

For maximum event-log-based coverage (LOLBin chains, lateral movement), enable process creation auditing with command-line logging:

```
auditpol /set /subcategory:"Process Creation" /success:enable
```
(Group Policy: Administrative Templates > System > Audit Process Creation > Include command line)

## License

Apache 2.0 — see `LICENSE`.

## Credit / lineage

This library is derived from [jcube3ai/veil_hunter](https://github.com/jcube3ai/veil_hunter) (VeilHunter). See `docs/CHANGELOG.md` for exactly what changed in the port.
