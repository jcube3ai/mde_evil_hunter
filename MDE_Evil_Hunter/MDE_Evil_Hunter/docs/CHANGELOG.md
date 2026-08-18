# Changelog

## v1.0.0 — Initial MDE_Evil_Hunter port (from VeilHunter)

Ported from [jcube3ai/veil_hunter](https://github.com/jcube3ai/veil_hunter) and restructured specifically for execution via Microsoft Defender for Endpoint Live Response's script library.

### Added
- `Modules/VH-Common.ps1` — new shared module, dot-sourced by every hunter:
  - `Get-VHUserProfiles` — enumerates real user profiles from `C:\Users`, skipping `Default`/`Public`/`All Users`.
  - `Get-VHUserPaths` — resolves a profile-relative path (e.g. `Downloads`, `AppData\Local\Temp`) across every real user profile, plus the calling process's own `$env:USERPROFILE` as a fallback so scripts behave the same interactively or under SYSTEM.
  - `Invoke-VHUserHive` — runs a scriptblock against every user's registry hive. Logged-on users' hives are read directly from `HKEY_USERS\<SID>`; logged-off users' `NTUSER.DAT` is loaded temporarily via `reg.exe load`, processed, then unloaded.
  - `Test-VHIsSystem` — quick check for `NT AUTHORITY\SYSTEM` context.
  - Consolidated `Add-Finding`, `Get-SignatureStatus`, `Export-Findings`, `Write-VHResults` (previously duplicated verbatim in every script).
- `docs/MDE_LIVE_RESPONSE.md` — upload/run/retrieve workflow specific to Live Response, including known constraints (timeouts, relative-path resolution caveats, `reg.exe load`/`unload` AV sensitivity).
- `docs/MITRE_COVERAGE.md` — full technique-to-script map, carried over from the original VeilHunter README and updated for the renamed scripts.
- `User` column added to the CSV/console finding schema (`Timestamp, Severity, TechniqueID, Technique, Artifact, Detail, Path, User`) so per-user findings are attributable to a specific profile.

### Changed — SYSTEM-context fixes (the core reason this port exists)
Live Response executes scripts as `NT AUTHORITY\SYSTEM`. Under SYSTEM, `$env:USERPROFILE`, `$env:APPDATA`, `$env:LOCALAPPDATA`, `$env:TEMP`, and `HKCU:` all resolve to the SYSTEM profile, not the logged-on or compromised user — every one of the following checks would previously run clean and silently miss the finding on any real endpoint:

- **VH_Persistence_Hunter** (`Veil_Hunter_v2.ps1`) — `Hunt-RegistryPersistence` now walks HKLM Run keys directly and every real user's HKCU-equivalent Run/RunOnce/RunServices keys via `Invoke-VHUserHive`. `Hunt-StartupFolders` now checks every real user's Startup folder via `Get-VHUserPaths`, not just `$env:APPDATA`.
- **VH_Credential_Hunter** — LSASS dumper-tool search, SAM/hive dump search, and credential-file search now scan every real user's Downloads/Desktop/Documents/Temp via `Get-VHUserPaths`. DPAPI master keys, browser credential stores (Chrome/Edge/Firefox), and the Credential Manager vault are now checked per real user profile instead of only the caller's own.
- **VH_Defense_Evasion_Hunter** — unsigned-DLL and timestomping staging-path checks now cover every real user's Downloads/Temp.
- **VH_LOLBin_Hunter** — unsigned staged-binary check now covers every real user's Downloads/Temp.
- **VH_PreRansom_Hunter** — ransom-note-drop and mass-file-extension-change checks now scan every real user's Desktop/Documents/Downloads, not just the caller's own. This is the highest-value fix in the library given how often this hunter runs first during active IR.
- **VH_C2_Exfil_Hunter** — cloud exfil staging check (OneDrive/Dropbox/Google Drive/Box/iCloud) now walks every real user's profile instead of only the caller's.
- **VH_Malvertising_RMM_Hunter** — internet-sourced-file scan now covers every real user's Downloads/Desktop/Temp. RMM-software Uninstall-key check now walks every real user's hive via `Invoke-VHUserHive` in addition to the machine-wide HKLM keys (the old single `HKCU:` check has been removed since it only ever saw the running process's own key).

### Renamed
| Original | New |
|---|---|
| `Veil_Hunter_v2.ps1` | `VH_Persistence_Hunter.ps1` |
| `Task_Hunter_v2.ps1` | `VH_ScheduledTask_Hunter.ps1` |
| `service_installs_v2.ps1` | `VH_ServiceInstall_Hunter.ps1` |
| `malvertising_payload_hunter_v2.ps1` | `VH_Malvertising_RMM_Hunter.ps1` |
| `VH_Credential_Hunter.ps1` | *(unchanged)* |
| `VH_Lateral_Hunter.ps1` | *(unchanged)* |
| `VH_Defense_Evasion_Hunter.ps1` | *(unchanged)* |
| `VH_C2_Exfil_Hunter.ps1` | *(unchanged)* |
| `VH_PreRansom_Hunter.ps1` | *(unchanged)* |
| `VH_LOLBin_Hunter.ps1` | *(unchanged)* |

### Not carried over
- `VH_Master_Launcher.ps1` was **not** ported. It scanned its own directory for sibling hunter scripts and dot-sourced them, which depends on a folder of companion files being present on the endpoint — a structure MDE's Live Response script library does not provide (scripts run in isolation, one per `run` command). Run hunters individually instead; see `docs/MDE_LIVE_RESPONSE.md`.
- v1 scripts (`Veil_Hunter.ps1`, `Task_Hunter.ps1`, `malvertising_payload_hunter.ps1`, `service_installs.ps1`) were not ported — their v2 successors superseded them in the source repo already.

### Verified, not yet changed
- `VH_Lateral_Hunter.ps1`, `VH_ScheduledTask_Hunter.ps1`, and `VH_ServiceInstall_Hunter.ps1` were audited and contain no `$env:USERPROFILE`/`HKCU:`-style SYSTEM-context issues — they operate on event logs, live process/task enumeration, and machine-wide registry only, so no functional patch was needed beyond adding the shared-module dot-source for consistency.
- The `$PSScriptRoot`-relative path used to dot-source `VH-Common.ps1` (`..\Modules\VH-Common.ps1`) has **not** been validated against how a specific MDE tenant's Live Response library actually stages uploaded files. Test on a lab endpoint before relying on this in a live IR — see the fallback in `docs/MDE_LIVE_RESPONSE.md`.
