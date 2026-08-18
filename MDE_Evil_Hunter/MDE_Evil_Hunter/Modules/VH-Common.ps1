<#
.SYNOPSIS
    MDE_Evil_Hunter shared helper module.

.DESCRIPTION
    Every hunter in this library dot-sources this file. It solves the one
    problem that matters most for running these scripts through Microsoft
    Defender for Endpoint Live Response: MDE Live Response executes scripts
    as SYSTEM. Under SYSTEM, $env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA,
    $env:TEMP, and the HKCU: registry drive all resolve to the SYSTEM
    profile -- NOT to any logged-on user. A hunter written against those
    variables runs clean and finds nothing on a compromised box, every time.

    This module gives every hunter three things instead:

      - Get-VHUserProfiles   enumerate real user profiles on disk
      - Get-VHUserPaths      resolve a profile-relative path (e.g.
                              "Downloads", "AppData\Local\Temp") across
                              every real user, plus the caller's own
                              profile as a fallback, so scripts behave
                              the same run interactively or via Live
                              Response
      - Invoke-VHUserHive    run a scriptblock against every user's
                              registry hive (the HKCU-equivalent),
                              mounting offline NTUSER.DAT files as needed
                              and always unloading them afterward

    It also centralizes the finding/export/console helpers so every
    hunter in the library produces identical CSV output and identical
    console formatting.

.NOTES
    Dot-source this from every hunter script, e.g.:
        . (Join-Path $PSScriptRoot '..\Modules\VH-Common.ps1')
#>

# ---------------------------------------------------------------
# SHARED FINDING STORE
# ---------------------------------------------------------------
if (-not $script:Findings) {
    $script:Findings = [System.Collections.Generic.List[pscustomobject]]::new()
}

function Add-Finding {
    param(
        [ValidateSet("HIGH","MED","INFO")]
        [string]$Severity,
        [string]$TechniqueID,
        [string]$Technique,
        [string]$Artifact,
        [string]$Detail,
        [string]$Path = "",
        [string]$User = ""
    )
    $f = [pscustomobject]@{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Severity    = $Severity
        TechniqueID = $TechniqueID
        Technique   = $Technique
        Artifact    = $Artifact
        Detail      = $Detail
        Path        = $Path
        User        = $User
    }
    $script:Findings.Add($f)
    return $f
}

function Get-SignatureStatus([string]$FilePath) {
    if (-not $FilePath -or -not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        return "FILE_NOT_FOUND"
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        return $sig.Status.ToString()
    } catch {
        return "UNKNOWN"
    }
}

function Export-Findings([string]$Path) {
    if ($script:Findings.Count -eq 0) {
        Write-Host "No findings to export." -ForegroundColor Yellow
        return
    }
    try {
        $script:Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "[+] Findings exported to: $Path ($($script:Findings.Count) records)" -ForegroundColor Green
    } catch {
        Write-Host "[X] Export failed: $_" -ForegroundColor Red
    }
}

function Write-VHResults {
    <# Standard headless console summary, grouped and colored by severity. #>
    param([string]$ScriptName = "Hunt")

    Write-Host "`n===== $ScriptName Results ($($script:Findings.Count) findings) =====" -ForegroundColor Cyan
    $grouped = $script:Findings | Group-Object Severity | Sort-Object {
        switch ($_.Name) { "HIGH" { 0 } "MED" { 1 } default { 2 } }
    }
    foreach ($grp in $grouped) {
        $color = switch ($grp.Name) { "HIGH" { "Red" } "MED" { "Yellow" } default { "Gray" } }
        Write-Host "`n-- $($grp.Name) ($($grp.Count)) --" -ForegroundColor $color
        foreach ($f in $grp.Group) {
            $sev = switch ($f.Severity) { "HIGH" { "[HIGH]" } "MED" { "[MED] " } default { "[INFO]" } }
            Write-Host "$sev [$($f.TechniqueID)] $($f.Technique)" -ForegroundColor $color
            Write-Host "       Artifact : $($f.Artifact)" -ForegroundColor $color
            if ($f.User)   { Write-Host "       User     : $($f.User)" -ForegroundColor $color }
            if ($f.Detail) {
                $f.Detail -split '\|' | ForEach-Object { Write-Host "       $($_.Trim())" -ForegroundColor $color }
            }
            if ($f.Path) { Write-Host "       Path     : $($f.Path)" -ForegroundColor DarkGray }
            Write-Host ""
        }
    }
    $high = ($script:Findings | Where-Object Severity -eq "HIGH").Count
    $med  = ($script:Findings | Where-Object Severity -eq "MED").Count
    $info = ($script:Findings | Where-Object Severity -eq "INFO").Count
    Write-Host "Hunt complete -- HIGH: $high | MED: $med | INFO: $info | Total: $($script:Findings.Count)" -ForegroundColor Cyan
}

# ---------------------------------------------------------------
# SYSTEM-CONTEXT / MULTI-USER HELPERS
# ---------------------------------------------------------------
function Get-VHUserProfiles {
    <#
    Enumerates real user profiles from C:\Users, skipping service/default
    profile folders. Works identically whether the caller is SYSTEM
    (Live Response) or an interactive admin.
    #>
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') } |
        ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                ProfilePath = $_.FullName
                NtUserDat   = Join-Path $_.FullName 'NTUSER.DAT'
            }
        }
}

function Get-VHUserPaths {
    <#
    Resolves a profile-relative path (e.g. "Downloads", "AppData\Local\Temp")
    across every real user profile on disk, and also checks the calling
    process's own $env:USERPROFILE as a fallback so the same script works
    whether it's run as SYSTEM via Live Response or interactively.
    Returns only paths that actually exist.
    #>
    param([Parameter(Mandatory)][string]$RelativePath)

    $found = [System.Collections.Generic.List[string]]::new()

    Get-VHUserProfiles | ForEach-Object {
        $p = Join-Path $_.ProfilePath $RelativePath
        if (Test-Path $p -ErrorAction SilentlyContinue) { $found.Add($p) }
    }

    if ($env:USERPROFILE) {
        $selfPath = Join-Path $env:USERPROFILE $RelativePath
        if ((Test-Path $selfPath -ErrorAction SilentlyContinue) -and ($found -notcontains $selfPath)) {
            $found.Add($selfPath)
        }
    }

    return $found
}

function Invoke-VHUserHive {
    <#
    Runs a scriptblock once per real user against that user's registry hive
    (the HKCU-equivalent for that user), regardless of whether the user is
    currently logged on.

    - If the user is logged on, their hive is already mounted at
      HKEY_USERS\<SID> -- it's used directly, nothing is loaded/unloaded.
    - If the user is NOT logged on, their NTUSER.DAT is loaded temporarily
      under HKEY_USERS\VH_<username>, the scriptblock runs, then it is
      unloaded. This is the only way to see persistence planted in an
      offline user's hive during Live Response, since Live Response often
      lands you on a box where the victim/attacker account isn't logged in.

    The scriptblock receives two arguments: the profile object (Name,
    ProfilePath) and the HKEY_USERS mount name to build paths against, e.g.:
        Invoke-VHUserHive -Action {
            param($Profile, $HiveRoot)
            $runKey = "Registry::HKEY_USERS\$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
            ...
        }
    #>
    param([Parameter(Mandatory)][scriptblock]$Action)

    # Already-mounted (logged-on) hives first -- fast path, no load/unload needed
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
        ForEach-Object {
            $prof = [pscustomobject]@{ Name = $_.PSChildName; ProfilePath = $null }
            try { & $Action $prof $_.PSChildName } catch { }
        }

    # Offline profiles -- load NTUSER.DAT temporarily, run, unload
    Get-VHUserProfiles | ForEach-Object {
        $prof = $_
        if (-not (Test-Path $prof.NtUserDat -ErrorAction SilentlyContinue)) { return }

        $mountName = "VH_$($prof.Name)"
        $alreadyMounted = Test-Path "Registry::HKEY_USERS\$mountName" -ErrorAction SilentlyContinue
        $loaded = $false

        if (-not $alreadyMounted) {
            $null = & reg.exe load "HKU\$mountName" "$($prof.NtUserDat)" 2>&1
            if ($LASTEXITCODE -eq 0) { $loaded = $true }
        }

        if ($loaded -or $alreadyMounted) {
            try {
                & $Action $prof $mountName
            } finally {
                if ($loaded) {
                    [gc]::Collect()
                    Start-Sleep -Milliseconds 100
                    $null = & reg.exe unload "HKU\$mountName" 2>&1
                }
            }
        }
    }
}

function Test-VHIsSystem {
    <# True when running as NT AUTHORITY\SYSTEM -- i.e. a Live Response session. #>
    return ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')
}
