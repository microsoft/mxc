# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# T3-Workloads.ps1 — explore what real workloads can run inside the
# Tier 3 (AppContainer + DACL) sandbox on a 25H2 host.
#
# Companion to WinProcessContainer-Tests.ps1: that script proves the T3
# *primitives* (rw / ro / denied / control matrix, crash recovery, UI
# mitigations) work; this one asks whether useful programs — pwsh 7
# and git in particular — can run on top of those primitives.
#
# Safety: refuses to run if wxc-exec reports `bfsCompiledIn=true`.
# Same compile-time gate as the harness. The script only invokes
# wxc-exec with policies that have non-empty paths, which on a
# feature-off binary land naturally at T3.

[CmdletBinding()]
param(
    # Default assumes the script lives at <repo>\tests\scripts\ and the
    # built binary is at <repo>\src\target\debug\wxc-exec.exe. Override
    # -Wxc explicitly if the layout differs.
    [string]$Wxc          = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ScratchRoot  = (Join-Path $env:TEMP 'mxc-t3-workloads'),
    # Subset of workloads to run. Default: all nineteen.
    [int[]] $Run          = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19),
    # Add a few extra "kitchen sink" RO grants (TEMP, LOCALAPPDATA, ...)
    # to each workload's policy. Useful for ruling out missing-grant
    # failures while iterating on a workload.
    [switch]$Permissive,
    # Keep scratch dir + config files after the run for post-mortem.
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------
# Result accumulator
# -----------------------------------------------------------------------
$Script:Results = [System.Collections.Generic.List[object]]::new()

function Record-Workload {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [bool]$Pass,
        [int]$ExitCode = 0,
        [string]$Detail = '',
        [string]$Stderr = ''
    )
    $entry = [pscustomobject]@{
        Id        = $Id
        Name      = $Name
        Pass      = $Pass
        ExitCode  = $ExitCode
        Detail    = $Detail
        StderrTop = ($Stderr -split "`r?`n" | Select-Object -First 3) -join ' / '
    }
    $Script:Results.Add($entry) | Out-Null
    $tag = if ($Pass) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Pass) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1} :: {2} (exit={3})" -f $tag, $Id, $Name, $ExitCode) -ForegroundColor $color
    if ($Detail) { Write-Host ("        detail: {0}" -f $Detail) }
    if (-not $Pass -and $entry.StderrTop) {
        Write-Host ("        stderr: {0}" -f $entry.StderrTop) -ForegroundColor DarkRed
    }
}

function Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

# -----------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------
function Test-Preflight {
    Section 'Pre-flight'
    if (-not (Test-Path $Wxc)) {
        throw "wxc-exec not found at $Wxc. Pass -Wxc <path> or build first."
    }
    $probe = & $Wxc --probe 2>$null | ConvertFrom-Json -ErrorAction Stop
    if (-not $probe.PSObject.Properties['probes'] -or -not $probe.probes.PSObject.Properties['bfsCompiledIn']) {
        throw "Preflight: probe output missing `bfsCompiledIn`. Rebuild from a tree that has the tier2_bfs gate."
    }
    if ($probe.probes.bfsCompiledIn) {
        throw "Preflight ABORT: $Wxc was built with --features tier2_bfs. On 25H2 this risks an OS hang. Rebuild without the feature."
    }
    Write-Host ("wxc-exec:          {0}" -f $Wxc)
    Write-Host ("bfsCompiledIn:     {0}" -f $probe.probes.bfsCompiledIn)
    Write-Host ("bcApiPresent:      {0}" -f $probe.probes.baseContainerApiPresent)
    Write-Host ("scratch:           {0}" -f $ScratchRoot)
    Write-Host ("permissive grants: {0}" -f $Permissive.IsPresent)
}

# -----------------------------------------------------------------------
# Scratch + config helpers
# -----------------------------------------------------------------------
function Assert-SafeScratchRoot {
    # Refuse to nuke arbitrary paths. `Initialize-Scratch` issues a
    # recursive `Remove-Item -Force` against `$ScratchRoot`; if a user
    # accidentally passes `-ScratchRoot C:\` (or any other important
    # directory) the harness must abort BEFORE the destructive call.
    #
    # Policy: the path must be non-empty, must resolve to somewhere
    # under `$env:TEMP`, must NOT be the TEMP root itself, must NOT be
    # a drive root, and must carry the `mxc-` prefix in its leaf name.
    if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
        throw "Refusing to operate on an empty/whitespace -ScratchRoot."
    }
    $resolved = [System.IO.Path]::GetFullPath($ScratchRoot)
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not $resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing -ScratchRoot '$resolved': must resolve under `$env:TEMP` ($tempRoot). Recursive deletion of paths outside TEMP is blocked."
    }
    if ($resolved.TrimEnd('\','/') -ieq $tempRoot.TrimEnd('\','/')) {
        throw "Refusing -ScratchRoot '$resolved': cannot equal `$env:TEMP` itself."
    }
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ($root -and ($resolved.TrimEnd('\','/') -ieq $root.TrimEnd('\','/'))) {
        throw "Refusing -ScratchRoot '$resolved': drive roots are not valid scratch directories."
    }
    $leaf = Split-Path -Path $resolved -Leaf
    if ($leaf -notlike 'mxc-*') {
        throw "Refusing -ScratchRoot '$resolved': leaf name '$leaf' must start with 'mxc-' to confirm operator intent."
    }
}

function Initialize-Scratch {
    Assert-SafeScratchRoot
    if (Test-Path $ScratchRoot) {
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot
    }
    New-Item -ItemType Directory -Path $ScratchRoot       | Out-Null
    New-Item -ItemType Directory -Path "$ScratchRoot\rw"  | Out-Null
    New-Item -ItemType Directory -Path "$ScratchRoot\cfg" | Out-Null
    New-Item -ItemType Directory -Path "$ScratchRoot\log" | Out-Null
    # Pre-stage a marker for read-back tests.
    'mxc-t3-marker' | Out-File -LiteralPath "$ScratchRoot\rw\marker.txt" -Encoding ascii -Force
}

function New-Config {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$CommandLine,
        [string[]]$ReadOnly  = @(),
        [string[]]$ReadWrite = @(),
        [string]$Cwd = $null,
        [int]$TimeoutMs = 60000
    )
    if ($Permissive) {
        # Kitchen-sink grants for debugging: TEMP, LOCALAPPDATA cache
        # dirs that most CLR-using apps touch at startup.
        $extraRo = @()
        if ($env:LOCALAPPDATA) { $extraRo += $env:LOCALAPPDATA }
        $extraRw = @($env:TEMP)
        $ReadOnly  = @($ReadOnly  + $extraRo) | Select-Object -Unique
        $ReadWrite = @($ReadWrite + $extraRw) | Select-Object -Unique
    }
    $proc = [ordered]@{
        commandLine = $CommandLine
        timeout     = $TimeoutMs
    }
    if ($Cwd) { $proc['cwd'] = $Cwd }
    $obj = [ordered]@{
        version     = '0.5.0-dev'
        containerId = "MxcT3Workload-$Name"
        containment = 'appcontainer'
        process     = $proc
        fallback    = [ordered]@{ allowDaclMutation = $true }
        ui          = [ordered]@{ disable = $false }
    }
    $fs = [ordered]@{}
    if ($ReadWrite.Count -gt 0) { $fs['readwritePaths'] = @($ReadWrite) }
    if ($ReadOnly.Count  -gt 0) { $fs['readonlyPaths']  = @($ReadOnly) }
    if ($fs.Count -gt 0)        { $obj['filesystem']    = $fs }

    $path = Join-Path "$ScratchRoot\cfg" "$Name.json"
    ($obj | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}

function Invoke-Workload {
    param(
        [Parameter(Mandatory)] [string]$ConfigPath,
        [Parameter(Mandatory)] [string]$LogPath,
        [int]$TimeoutSec = 90
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Wxc
    $psi.Arguments = "--config `"$ConfigPath`" --experimental --log-file `"$LogPath`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return [pscustomobject]@{ ExitCode = -1; Stdout = ''; Stderr = "TIMEOUT after ${TimeoutSec}s" }
    }
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        Stdout   = $p.StandardOutput.ReadToEnd()
        Stderr   = $p.StandardError.ReadToEnd()
    }
}

# -----------------------------------------------------------------------
# Well-known host paths (probed at script start)
# -----------------------------------------------------------------------
function Test-NeedsAppContainerGrant {
    # System-installed dirs under Program Files / Program Files (x86)
    # inherit `ALL APPLICATION PACKAGES` Read & Execute from their
    # parent — the AppContainer child can load executables and DLLs
    # from there without any per-run grant. Per-user installs (e.g.
    # `%LOCALAPPDATA%\Programs\Python\Python3xx\`, nvm-windows under
    # `%APPDATA%\nvm\`) do not grant AAP and need an explicit
    # ReadOnly grant from this harness for the child to function.
    param([string]$Path)
    $pf  = [Environment]::GetFolderPath('ProgramFiles')
    $pfx = [Environment]::GetFolderPath('ProgramFilesX86')
    $resolved = [System.IO.Path]::GetFullPath($Path)
    return -not ($resolved.StartsWith($pf,  [System.StringComparison]::OrdinalIgnoreCase) -or
                 $resolved.StartsWith($pfx, [System.StringComparison]::OrdinalIgnoreCase))
}

function Resolve-HostPaths {
    $script:PwshDir        = $null
    $script:GitDir         = $null
    $script:NodeDir        = $null
    $script:NodeRoNeeded   = $null
    $script:PythonExe      = $null
    $script:PythonRoNeeded = $null

    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) { $script:PwshDir = Split-Path $pwsh.Source }
    $git  = Get-Command git  -ErrorAction SilentlyContinue
    if ($git)  { $script:GitDir  = Split-Path (Split-Path $git.Source) }

    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) {
        $script:NodeDir = Split-Path $node.Source
        if (Test-NeedsAppContainerGrant $script:NodeDir) {
            $script:NodeRoNeeded = $script:NodeDir
        }
    }

    # Try `python` then `python3`. Skip the Microsoft Store
    # AppExecutionAlias stub under WindowsApps — it is a 0-byte
    # redirect that just opens the Store on launch and would fail
    # to execute under AppContainer regardless.
    foreach ($name in @('python', 'python3')) {
        $py = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $py) { continue }
        if ($py.Source -like '*\WindowsApps\*') { continue }
        $script:PythonExe = $py.Source
        $pyDir = Split-Path $py.Source -Parent
        if (Test-NeedsAppContainerGrant $pyDir) {
            $script:PythonRoNeeded = $pyDir
        }
        break
    }

    Write-Host ("pwsh dir:   {0}" -f ($script:PwshDir   ?? '<not found>'))
    Write-Host ("git  dir:   {0}" -f ($script:GitDir    ?? '<not found>'))
    Write-Host ("node dir:   {0}" -f ($script:NodeDir   ?? '<not found>'))
    Write-Host ("python exe: {0}" -f ($script:PythonExe ?? '<not found>'))
    if ($script:NodeRoNeeded)   { Write-Host ("  -> auto-grant ReadOnly: {0}" -f $script:NodeRoNeeded) }
    if ($script:PythonRoNeeded) { Write-Host ("  -> auto-grant ReadOnly: {0}" -f $script:PythonRoNeeded) }
}

# -----------------------------------------------------------------------
# Workloads
# -----------------------------------------------------------------------
function W1-CmdTypeMarker {
    Section 'W1: cmd /c type marker.txt'
    $cfg = New-Config -Name 'w1-cmd-type' `
        -CommandLine "cmd /c type `"$ScratchRoot\rw\marker.txt`"" `
        -ReadWrite @("$ScratchRoot\rw")
    $log = "$ScratchRoot\log\w1.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 15
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t3-marker')
    Record-Workload -Id 'W1' -Name 'cmd /c type marker.txt' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W2-PwshReadFile {
    Section 'W2: pwsh -NoProfile -c "Get-Content marker.txt"'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W2' -Name 'pwsh Get-Content' -Pass $false -Detail 'pwsh not found on PATH'
        return
    }
    # PowerShell's install dir already grants ReadAndExecute to
    # `ALL APPLICATION PACKAGES`, which our AppContainer SID inherits.
    # Adding the dir to ReadOnly would force the dispatcher to demand
    # WRITE_DAC on a system path (admin-only) — we don't need that.
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Get-Content -LiteralPath '$ScratchRoot\rw\marker.txt'; exit 0`""
    $cfg = New-Config -Name 'w2-pwsh-read' `
        -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw")
    $log = "$ScratchRoot\log\w2.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t3-marker')
    Record-Workload -Id 'W2' -Name 'pwsh Get-Content marker' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W3-PwshGitVersion {
    Section 'W3: pwsh -NoProfile -c "git --version"'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $false -Detail 'pwsh not found'
        return
    }
    if (-not $script:GitDir)  {
        Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $false -Detail 'git not found'
        return
    }
    # Git install dir also grants ReadAndExecute to ALL APPLICATION
    # PACKAGES; no per-run ACE needed (see W2 note). Setting cwd
    # explicitly inside the rw grant avoids the AppContainer's inability
    # to read the inherited cwd from the parent process.
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& git --version; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w3-git-version' `
        -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") `
        -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w3.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'git version')
    Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function Initialize-Repo {
    param([string]$Dir)
    # Build a tiny standalone repo via real git, then we'll exercise
    # it from inside the sandbox.
    if (Test-Path $Dir) { Remove-Item -Recurse -Force -LiteralPath $Dir }
    New-Item -ItemType Directory -Path $Dir | Out-Null
    Push-Location $Dir
    try {
        & git init -q
        & git -c user.email=t3@example.com -c user.name=t3 commit -q --allow-empty -m 'initial'
        'first' | Out-File -LiteralPath (Join-Path $Dir 'file1.txt') -Encoding ascii -Force
        & git add file1.txt
        & git -c user.email=t3@example.com -c user.name=t3 commit -q -m 'add file1'
        'second' | Out-File -LiteralPath (Join-Path $Dir 'file1.txt') -Encoding ascii -Force
        & git -c user.email=t3@example.com -c user.name=t3 commit -q -am 'update file1'
    } finally {
        Pop-Location
    }
}

function W4-PwshGitStatus {
    Section 'W4: pwsh -NoProfile -c "cd <repo>; git status"'
    if (-not $script:PwshDir -or -not $script:GitDir) {
        Record-Workload -Id 'W4' -Name 'pwsh git status' -Pass $false -Detail 'pwsh or git not found'
        return
    }
    $repo = "$ScratchRoot\rw\repo"
    Initialize-Repo -Dir $repo
    # Touch a file so `git status` has something to report.
    'dirty' | Out-File -LiteralPath (Join-Path $repo 'file1.txt') -Encoding ascii -Force
    # `git -C <dir>` lets git change to <dir> internally, avoiding
    # pwsh's `Set-Location` which walks ancestor paths and trips on
    # `C:\Users\...` metadata-access checks that the AppContainer SID
    # doesn't have grants for.
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& git -C '$repo' status --porcelain; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w4-git-status' `
        -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") `
        -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w4.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 90
    # Porcelain output for a modified file looks like " M file1.txt".
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'file1\.txt')
    Record-Workload -Id 'W4' -Name 'pwsh git status' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W5-PwshGitLog {
    Section 'W5: pwsh -NoProfile -c "cd <repo>; git log --oneline -n 10"'
    if (-not $script:PwshDir -or -not $script:GitDir) {
        Record-Workload -Id 'W5' -Name 'pwsh git log' -Pass $false -Detail 'pwsh or git not found'
        return
    }
    $repo = "$ScratchRoot\rw\repo"
    if (-not (Test-Path $repo)) {
        # W5 reuses the repo from W4. If W4 didn't run, set one up.
        Initialize-Repo -Dir $repo
    }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& git -C '$repo' log --oneline -n 10; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w5-git-log' `
        -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") `
        -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w5.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 90
    # Each commit line starts with a 7-char SHA. The repo has 3 commits.
    $pass = ($r.ExitCode -eq 0) -and (($r.Stdout -split "`r?`n" | Where-Object { $_ -match '^[0-9a-f]{7}\s' }).Count -ge 2)
    Record-Workload -Id 'W5' -Name 'pwsh git log --oneline -n 10' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# Extended pwsh-only probes (W6-W10) — bypass git's NUL constraint
# -----------------------------------------------------------------------
function W6-PwshListDir {
    Section 'W6: pwsh Get-ChildItem on rw directory'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W6' -Name 'pwsh Get-ChildItem' -Pass $false -Detail 'pwsh not found'
        return
    }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Get-ChildItem -LiteralPath '$ScratchRoot\rw' | Select-Object -ExpandProperty Name; exit 0`""
    $cfg = New-Config -Name 'w6-pwsh-ls' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w6.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'marker\.txt')
    Record-Workload -Id 'W6' -Name 'pwsh Get-ChildItem rw' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W7-PwshInProcEval {
    Section 'W7: pwsh in-process script eval (math, env, pipeline)'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W7' -Name 'pwsh in-proc eval' -Pass $false -Detail 'pwsh not found'
        return
    }
    $script = '$x = 6 * 7; Write-Output "answer=$x"; 1..3 | ForEach-Object { Write-Output "iter=$_" }; exit 0'
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$script`""
    $cfg = New-Config -Name 'w7-pwsh-eval' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w7.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W7' -Name 'pwsh in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W8-PwshSpawnCmd {
    Section 'W8: pwsh spawning cmd /c (no NUL)'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W8' -Name 'pwsh spawn cmd' -Pass $false -Detail 'pwsh not found'
        return
    }
    # No NUL redirects in the child — just a one-line echo.
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& cmd /c echo hello-from-cmd; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w8-pwsh-spawn-cmd' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w8.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'hello-from-cmd')
    Record-Workload -Id 'W8' -Name 'pwsh -> cmd /c echo' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W9-PwshWriteReadRoundTrip {
    Section 'W9: pwsh Set-Content + Get-Content round-trip'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W9' -Name 'pwsh write+read' -Pass $false -Detail 'pwsh not found'
        return
    }
    $target = "$ScratchRoot\rw\w9-out.txt"
    $script = "Set-Content -LiteralPath '$target' -Value 'mxc-w9-payload'; Get-Content -LiteralPath '$target'; exit 0"
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$script`""
    $cfg = New-Config -Name 'w9-pwsh-rt' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w9.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w9-payload')
    Record-Workload -Id 'W9' -Name 'pwsh Set-Content / Get-Content' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W10-PwshDotNetIo {
    Section 'W10: pwsh .NET [System.IO.File]::ReadAllText'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W10' -Name 'pwsh .NET IO' -Pass $false -Detail 'pwsh not found'
        return
    }
    $script = "Write-Output ([System.IO.File]::ReadAllText('$ScratchRoot\rw\marker.txt')); exit 0"
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$script`""
    $cfg = New-Config -Name 'w10-pwsh-dotnet' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w10.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t3-marker')
    Record-Workload -Id 'W10' -Name 'pwsh .NET IO.File.ReadAllText' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# Node workloads (W11-W13) — mirror W2/W7/W9 for node.exe.
#
# JS source uses forward-slash paths to avoid JS escape-sequence
# ambiguity (`\U`, `\T`, etc. inside single-quoted JS strings).
# Node's fs.* accepts both separators on Windows.
# -----------------------------------------------------------------------
function W11-NodeReadFile {
    Section 'W11: node -e fs.readFileSync(marker)'
    if (-not $script:NodeDir) {
        Record-Workload -Id 'W11' -Name 'node read file' -Pass $false -Detail 'node not found on PATH'
        return
    }
    $markerFwd = ("$ScratchRoot\rw\marker.txt") -replace '\\','/'
    $js  = "process.stdout.write(require('fs').readFileSync('$markerFwd','utf8'))"
    $cmd = "node.exe -e `"$js`""
    $ro  = @()
    if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w11-node-read' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w11.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t3-marker')
    Record-Workload -Id 'W11' -Name 'node fs.readFileSync marker' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W12-NodeEval {
    Section 'W12: node in-proc eval (math, loop)'
    if (-not $script:NodeDir) {
        Record-Workload -Id 'W12' -Name 'node eval' -Pass $false -Detail 'node not found on PATH'
        return
    }
    $js  = "let x=6*7;console.log('answer='+x);for(let i=1;i<=3;i++)console.log('iter='+i);"
    $cmd = "node.exe -e `"$js`""
    $ro  = @()
    if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w12-node-eval' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w12.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W12' -Name 'node in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W13-NodeRoundTrip {
    Section 'W13: node fs.writeFileSync + readFileSync round-trip'
    if (-not $script:NodeDir) {
        Record-Workload -Id 'W13' -Name 'node write+read' -Pass $false -Detail 'node not found on PATH'
        return
    }
    $targetFwd = ("$ScratchRoot\rw\w13-out.txt") -replace '\\','/'
    $js  = "const fs=require('fs');fs.writeFileSync('$targetFwd','mxc-w13-payload');process.stdout.write(fs.readFileSync('$targetFwd','utf8'));"
    $cmd = "node.exe -e `"$js`""
    $ro  = @()
    if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w13-node-rt' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w13.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w13-payload')
    Record-Workload -Id 'W13' -Name 'node writeFileSync / readFileSync' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# Python workloads (W14-W16) — mirror W2/W7/W9 for python.
#
# Use raw-string `r'…'` literals for paths so backslashes pass through
# unescaped. The python.exe is invoked by full path (stored at discovery
# time) so we don't depend on PATH resolution inside the AppContainer.
# -----------------------------------------------------------------------
function W14-PyReadFile {
    Section 'W14: python -c open(marker).read()'
    if (-not $script:PythonExe) {
        Record-Workload -Id 'W14' -Name 'python read file' -Pass $false -Detail 'python not found on PATH'
        return
    }
    $py  = "import sys; sys.stdout.write(open(r'$ScratchRoot\rw\marker.txt').read())"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @()
    if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w14-py-read' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w14.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t3-marker')
    Record-Workload -Id 'W14' -Name 'python open().read() marker' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W15-PyEval {
    Section 'W15: python in-proc eval (math, loop)'
    if (-not $script:PythonExe) {
        Record-Workload -Id 'W15' -Name 'python eval' -Pass $false -Detail 'python not found on PATH'
        return
    }
    # `python -c` accepts ';' between simple statements but requires
    # newlines around compound statements (e.g. `for`). To keep this
    # a single line, use a list-comprehension to drive the loop.
    $py  = "x=6*7; print('answer='+str(x)); [print('iter='+str(i)) for i in range(1,4)]"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @()
    if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w15-py-eval' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w15.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W15' -Name 'python in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# chdir diagnostic helper — shared by W17/W18/W19.
#
# Creates a fresh subdir under $rw with a marker file. The chdir tests
# below have the sandboxed child runtime chdir() into this subdir and
# list its contents. We use a freshly-created subdir (NOT the git $repo)
# so we eliminate any side-effects from `git init` as a possible cause.
# -----------------------------------------------------------------------
function Initialize-ChdirTarget {
    $target = "$ScratchRoot\rw\chdir-target"
    if (-not (Test-Path $target)) {
        New-Item -ItemType Directory -Path $target | Out-Null
        'chdir-marker' | Out-File -LiteralPath (Join-Path $target 'chdir-marker.txt') -Encoding ascii -Force
    }
    return $target
}

function W16-PyRoundTrip {
    Section 'W16: python open(w,write) + open(r,read) round-trip'
    if (-not $script:PythonExe) {
        Record-Workload -Id 'W16' -Name 'python write+read' -Pass $false -Detail 'python not found on PATH'
        return
    }
    $target = "$ScratchRoot\rw\w16-out.txt"
    $py  = "open(r'$target','w').write('mxc-w16-payload'); import sys; sys.stdout.write(open(r'$target').read())"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @()
    if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w16-py-rt' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w16.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w16-payload')
    Record-Workload -Id 'W16' -Name 'python write+read round-trip' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# Runtime chdir diagnostics (W17-W19) — does runtime SetCurrentDirectory
# / chdir into a granted subdir work inside the AppContainer?
#
# W4/W5 use `git -C <subdir>` which invokes git's own chdir before doing
# anything else. After the \Device\Null fix, those still fail with
# `cannot change to '<subdir>': Permission denied` even when <subdir>
# is granted explicitly. These three tests reproduce the same operation
# from three different runtimes to see whether it is git-specific or
# something broader.
#
# Pass criterion: stdout includes 'chdir-marker.txt' (proves the chdir
# succeeded AND the post-chdir directory listing succeeded).
# -----------------------------------------------------------------------
function W17-PwshSetLocation {
    Section 'W17: pwsh Set-Location into rw subdir'
    if (-not $script:PwshDir) {
        Record-Workload -Id 'W17' -Name 'pwsh Set-Location' -Pass $false -Detail 'pwsh not found'
        return
    }
    $target = Initialize-ChdirTarget
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Set-Location -LiteralPath '$target'; Get-ChildItem -Name; exit 0`""
    $cfg = New-Config -Name 'w17-pwsh-cd' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w17.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W17' -Name 'pwsh Set-Location' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W18-NodeChdir {
    Section 'W18: node process.chdir into rw subdir'
    if (-not $script:NodeDir) {
        Record-Workload -Id 'W18' -Name 'node chdir' -Pass $false -Detail 'node not found'
        return
    }
    $target = Initialize-ChdirTarget
    $targetFwd = $target -replace '\\','/'
    $js  = "process.chdir('$targetFwd'); console.log(require('fs').readdirSync('.').join(','));"
    $cmd = "node.exe -e `"$js`""
    $ro  = @()
    if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w18-node-cd' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w18.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W18' -Name 'node process.chdir' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W19-PyChdir {
    Section 'W19: python os.chdir into rw subdir'
    if (-not $script:PythonExe) {
        Record-Workload -Id 'W19' -Name 'python chdir' -Pass $false -Detail 'python not found'
        return
    }
    $target = Initialize-ChdirTarget
    $py  = "import os; os.chdir(r'$target'); print(','.join(os.listdir('.')))"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @()
    if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w19-py-cd' -CommandLine $cmd `
        -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $log = "$ScratchRoot\log\w19.log"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W19' -Name 'python os.chdir' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
try {
    Test-Preflight
    Resolve-HostPaths
    Initialize-Scratch

    if (1  -in $Run) { W1-CmdTypeMarker }
    if (2  -in $Run) { W2-PwshReadFile }
    if (3  -in $Run) { W3-PwshGitVersion }
    if (4  -in $Run) { W4-PwshGitStatus }
    if (5  -in $Run) { W5-PwshGitLog }
    if (6  -in $Run) { W6-PwshListDir }
    if (7  -in $Run) { W7-PwshInProcEval }
    if (8  -in $Run) { W8-PwshSpawnCmd }
    if (9  -in $Run) { W9-PwshWriteReadRoundTrip }
    if (10 -in $Run) { W10-PwshDotNetIo }
    if (11 -in $Run) { W11-NodeReadFile }
    if (12 -in $Run) { W12-NodeEval }
    if (13 -in $Run) { W13-NodeRoundTrip }
    if (14 -in $Run) { W14-PyReadFile }
    if (15 -in $Run) { W15-PyEval }
    if (16 -in $Run) { W16-PyRoundTrip }
    if (17 -in $Run) { W17-PwshSetLocation }
    if (18 -in $Run) { W18-NodeChdir }
    if (19 -in $Run) { W19-PyChdir }
}
catch {
    Write-Host ''
    Write-Host "ABORT: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 2
}
finally {
    Section 'Summary'
    $passed = @($Script:Results | Where-Object { $_.Pass })
    $failed = @($Script:Results | Where-Object { -not $_.Pass })
    Write-Host ("Total: {0}    Passed: {1}    Failed: {2}" -f $Script:Results.Count, $passed.Count, $failed.Count)
    if ($failed.Count -gt 0) {
        Write-Host ''
        Write-Host 'Failures:' -ForegroundColor Red
        foreach ($r in $failed) {
            Write-Host ("  [{0}] {1} (exit={2})" -f $r.Id, $r.Name, $r.ExitCode) -ForegroundColor Red
            if ($r.Detail)    { Write-Host ("        detail: {0}" -f $r.Detail) }
            if ($r.StderrTop) { Write-Host ("        stderr: {0}" -f $r.StderrTop) -ForegroundColor DarkRed }
        }
    }
    Write-Host ''
    Write-Host ("Scratch / logs: {0}" -f $ScratchRoot)
    if (-not $KeepArtifacts -and $failed.Count -eq 0 -and $passed.Count -gt 0 -and (Test-Path $ScratchRoot)) {
        # Re-validate before deletion — `Assert-SafeScratchRoot` ran
        # at the start of the suite, but the variable could in
        # principle be mutated mid-run by future refactors. Cheap
        # belt-and-suspenders against an accidental recursive delete.
        Assert-SafeScratchRoot
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
    }
}
