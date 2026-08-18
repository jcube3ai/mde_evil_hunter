# Running MDE_Evil_Hunter through MDE Live Response

## 1. Upload to the script library

Live Response's script library holds individual files, not folders. Upload each of the following separately (Settings > Endpoints > Live response > Library files, or via the `PutFile` Live Response API):

```
Modules/VH-Common.ps1
Hunters/VH_Persistence_Hunter.ps1
Hunters/VH_ScheduledTask_Hunter.ps1
Hunters/VH_ServiceInstall_Hunter.ps1
Hunters/VH_Malvertising_RMM_Hunter.ps1
Hunters/VH_Credential_Hunter.ps1
Hunters/VH_Lateral_Hunter.ps1
Hunters/VH_Defense_Evasion_Hunter.ps1
Hunters/VH_C2_Exfil_Hunter.ps1
Hunters/VH_PreRansom_Hunter.ps1
Hunters/VH_LOLBin_Hunter.ps1
```

**Important — relative path resolution.** Every hunter dot-sources the shared module with:

```powershell
. (Join-Path $PSScriptRoot '..\Modules\VH-Common.ps1')
```

This assumes the same relative layout as the repo: `Modules\VH-Common.ps1` sitting one directory up from `Hunters\`. MDE Live Response's `PutFile`/library working directory does **not** guarantee that structure — files pulled into a Live Response session typically land flat in the same working directory. Before your first live-fire use, verify this on a lab endpoint:

```
run VH_Persistence_Hunter.ps1 -parameters "-Headless -All"
```

If it errors on the dot-source line (`Cannot find path ...VH-Common.ps1`), the simplest fix is to flatten the reference for your library layout — change the dot-source line in each hunter to:

```powershell
. (Join-Path $PSScriptRoot 'VH-Common.ps1')
```

and upload `VH-Common.ps1` alongside each hunter (same flat directory) instead of a subfolder. Pick whichever layout matches how your tenant's library actually stages files and keep it consistent across the library.

## 2. Run a hunt

```
run VH_PreRansom_Hunter.ps1 -parameters "-Headless -All -OutputPath C:\Windows\Temp\vh_preransom.csv"
```

- Always pass `-Headless`. Without it, the script falls through to its WinForms GUI launcher, which will hang a Live Response session (no interactive desktop).
- `-All` runs every hunt module in that script. Omit it and pass specific `-Run*` switches (see each script's `.EXAMPLE` header, or `Get-Help .\Hunters\VH_Persistence_Hunter.ps1 -Full` locally) to scope a hunt to specific modules when you already know what you're chasing.
- Console output (the same HIGH/MED/INFO breakdown you'd see interactively) streams back through the Live Response session automatically — you don't need `-OutputPath` to see results, only to retrieve them as a file afterward.

## 3. Retrieve results

```
getfile C:\Windows\Temp\vh_preransom.csv
```

Live Response downloads the file to your local machine. Delete it from the endpoint afterward if your IR playbook requires cleaning up after yourself:

```
run cmd.exe -parameters "/c del C:\Windows\Temp\vh_preransom.csv"
```

## 4. Running across multiple endpoints

For a fleet-wide sweep rather than a single-box hunt, drive Live Response through the [MDE Live Response API](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/run-live-response) (`RunScript` action) instead of the console, scripted against your device list. Each hunter's CSV output uses the same field order across the whole library, so results from multiple endpoints concatenate cleanly for SIEM ingestion or a single incident-tracking spreadsheet.

## 5. Known constraints under Live Response

- **Timeouts.** Live Response sessions have an execution timeout per command. Every hunter here caps event log queries (typically `-MaxEvents 100-500`) specifically so a single hunt module finishes well inside that window, but a full `-All` run across a box with a very large Security log may still take longer than a single-box interactive run. If you hit timeouts, scope to specific `-Run*` modules instead of `-All`.
- **No network egress required.** Nothing in this library reaches out anywhere — everything is local event log, registry, filesystem, and WMI. No allowlisting needed on the Live Response network path.
- **SYSTEM context is handled**, per the README — that was the whole point of this port. But double-check `Invoke-VHUserHive`'s `reg.exe load`/`unload` calls succeed in your environment; some EDR/AV products flag `reg.exe load` against `NTUSER.DAT` as suspicious behavior (rightly — it's also how credential-dumping tooling works). If your own Defender policy blocks it, you'll lose offline-hive coverage for logged-off users but the rest of each hunter still runs.
