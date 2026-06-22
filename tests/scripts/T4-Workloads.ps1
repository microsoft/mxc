# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# T4-Workloads.ps1 — explore what real workloads can run inside the
# Tier 4 (RestrictedToken + Low integrity + host DACL) sandbox.
#
# Companion to T3-Workloads.ps1. T3 proves that AppContainer + DACL can
# run pwsh / git / node / python against *explicitly granted leaf paths*,
# but it cannot enumerate or traverse a workspace: walking from a deep
# cwd (e.g. C:\Users\<u>\AppData\Local\Temp\...) up to the drive root
# requires FILE_TRAVERSE on every ancestor, which the AppContainer SID
# does not hold. That is the W17/W18/W19 chdir failures in T3-Workloads.
#
# Tier 4 is the answer: the restricted primary token keeps `Users`
# (and the Restricted Code SID `S-1-5-12`) in the *restricting* SID set,
# so ancestor traversal of `C:\`, `C:\Users`, `…\Temp` "just works" with
# no per-ancestor ACE injection. MXC only stamps an `S-1-5-12` ACE on the
# leaf paths named in the policy. This harness therefore expects the
# traversal-heavy workloads (Set-Location / chdir into a subdir, git from
# a real cwd) to PASS where they FAIL under T3.
#
# --- How Tier 4 is reached -------------------------------------------
# `fallback_detector::detect` does not select RestrictedToken naturally
# (it floors at Tier 3). The shipped wxc-exec also ignores MXC_FORCE_TIER
# (the env seam is `#[cfg(test)]`-only). To run this harness you MUST
# build a wxc-exec with the opt-in `force_tier_seam` Cargo feature:
#
#     cargo build -p wxc --features force_tier_seam
#
# That compiles the MXC_FORCE_TIER env seam into the real binary. This
# script sets MXC_FORCE_TIER=t4 on every child it spawns and refuses to
# run (Test-Preflight) unless `--probe` confirms the binary honors it.
#
# --- Integrity note ---------------------------------------------------
# The Tier 4 child runs at *Low* integrity. The default mandatory policy
# is No-Write-Up, so a Low process cannot write to a Medium-integrity
# file. A host provisioning a workspace for a Tier 4 sandbox must lower
# the integrity label on the read/write area. Initialize-Scratch does
# this for the `rw` subtree via `icacls /setintegritylevel Low`, exactly
# as a real provisioning step would. Ancestors keep their Medium label —
# Low processes may still read/traverse Medium objects (only write-up is
# blocked), so traversal is unaffected.

[CmdletBinding()]
param(
    # Default assumes the script lives at <repo>\tests\scripts\ and the
    # force-tier-seam binary is at <repo>\src\target\debug\wxc-exec.exe.
    # Override -Wxc explicitly if the layout differs.
    [string]$Wxc          = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ScratchRoot  = (Join-Path $env:TEMP 'mxc-t4-workloads'),
    # Subset of workloads to run. Default: all nineteen.
    [int[]] $Run          = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19),
    # Tier to force via MXC_FORCE_TIER. Defaults to t4 (restricted-token).
    [ValidateSet('t1','t2','t3','t4')]
    [string]$ForceTier    = 't4',
    # Add a few extra RO grants (LOCALAPPDATA) to each workload's policy.
    # Useful for ruling out missing-grant failures while iterating.
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
        [string]$Stderr = '',
        [switch]$Traversal
    )
    $entry = [pscustomobject]@{
        Id        = $Id
        Name      = $Name
        Pass      = $Pass
        ExitCode  = $ExitCode
        Detail    = $Detail
        Traversal = [bool]$Traversal
        StderrTop = ($Stderr -split "`r?`n" | Select-Object -First 3) -join ' / '
    }
    $Script:Results.Add($entry) | Out-Null
    $tag = if ($Pass) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Pass) { 'Green' } else { 'Red' }
    $mark = if ($Traversal) { ' (traversal)' } else { '' }
    Write-Host ("  {0} {1} :: {2}{3} (exit={4})" -f $tag, $Id, $Name, $mark, $ExitCode) -ForegroundColor $color
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
        throw "wxc-exec not found at $Wxc. Build with: cargo build -p wxc --features force_tier_seam"
    }

    # Probe WITHOUT the force env var first — establishes the natural tier
    # and the safety probes.
    $natural = & $Wxc --probe 2>$null | ConvertFrom-Json -ErrorAction Stop
    if (-not $natural.PSObject.Properties['probes'] -or -not $natural.probes.PSObject.Properties['bfsCompiledIn']) {
        throw "Preflight: probe output missing `bfsCompiledIn`. Rebuild from a tree that has the fallback detector."
    }
    if ($natural.probes.bfsCompiledIn) {
        throw "Preflight ABORT: $Wxc was built with --features tier2_bfs. On 25H2 this risks an OS hang. Rebuild without it."
    }

    # Now probe WITH MXC_FORCE_TIER=$ForceTier. The whole harness depends
    # on the binary honoring the seam; if it doesn't, every workload would
    # silently run at the natural tier and the results would be meaningless.
    $expected = switch ($ForceTier) {
        't1' { 'base-container' }
        't2' { 'appcontainer-bfs' }
        't3' { 'appcontainer-dacl' }
        't4' { 'restricted-token' }
    }
    $env:MXC_FORCE_TIER = $ForceTier
    try {
        $forced = & $Wxc --probe 2>$null | ConvertFrom-Json -ErrorAction Stop
    } finally {
        Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue
    }
    if ($forced.tier -ne $expected) {
        throw @"
Preflight ABORT: MXC_FORCE_TIER=$ForceTier had no effect.
  expected tier: $expected
  observed tier: $($forced.tier)
This wxc-exec does not have the force-tier seam compiled in. Rebuild with:
  cargo build -p wxc --features force_tier_seam
(the env seam is #[cfg(test)]-only in a default build, so the shipped binary
ignores MXC_FORCE_TIER on purpose).
"@
    }

    Write-Host ("wxc-exec:        {0}" -f $Wxc)
    Write-Host ("natural tier:    {0}" -f $natural.tier)
    Write-Host ("forced tier:     {0}  (MXC_FORCE_TIER={1})" -f $forced.tier, $ForceTier)
    Write-Host ("bfsCompiledIn:   {0}" -f $natural.probes.bfsCompiledIn)
    Write-Host ("scratch:         {0}" -f $ScratchRoot)
    Write-Host ("permissive:      {0}" -f $Permissive.IsPresent)

    # Tier 4 spawns the child via CreateProcessAsUserW, which the kernel
    # gates on SeIncreaseQuotaPrivilege — a privilege standard interactive
    # users do NOT hold in an unelevated shell. Without it the spawn fails
    # with ERROR_PRIVILEGE_NOT_HELD. See the "Caller privilege requirements"
    # section of docs/proposals/downlevel_support/tier4-restricted-token.md.
    # We warn rather than abort so partial results (e.g. simple native
    # tools) are still observable, but a clean run wants an elevated shell.
    if ($ForceTier -eq 't4') {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        $elevColor = if ($elevated) { 'Gray' } else { 'Yellow' }
        Write-Host ("elevated:        {0}" -f $elevated) -ForegroundColor $elevColor
        if (-not $elevated) {
            Write-Host ''
            Write-Host 'WARNING: not running elevated. Tier 4 requires SeIncreaseQuotaPrivilege' -ForegroundColor Yellow
            Write-Host '         (held by Administrators / service identities). CreateProcessAsUserW'  -ForegroundColor Yellow
            Write-Host '         spawns will likely fail with ERROR_PRIVILEGE_NOT_HELD. Re-run from an' -ForegroundColor Yellow
            Write-Host '         elevated PowerShell for meaningful Tier 4 results.' -ForegroundColor Yellow
        }
    }
}

# -----------------------------------------------------------------------
# Scratch + config helpers
# -----------------------------------------------------------------------
function Assert-SafeScratchRoot {
    # Refuse to nuke arbitrary paths (see T3-Workloads for the rationale).
    # The path must be non-empty, resolve under $env:TEMP, not be the TEMP
    # root or a drive root, and carry the `mxc-` prefix in its leaf name.
    if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
        throw "Refusing to operate on an empty/whitespace -ScratchRoot."
    }
    $resolved = [System.IO.Path]::GetFullPath($ScratchRoot)
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not $resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing -ScratchRoot '$resolved': must resolve under `$env:TEMP` ($tempRoot)."
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

function Set-LowIntegrity {
    # Lower the mandatory integrity label on a directory subtree to Low
    # (with object + container inheritance) so the Low-IL Tier 4 child can
    # write into it. This is the workspace-provisioning step a real Tier 4
    # host would perform; without it No-Write-Up blocks every write.
    param([Parameter(Mandatory)][string]$Path)
    $out = & icacls $Path /setintegritylevel '(OI)(CI)Low' /T /C 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("  WARN: icacls /setintegritylevel Low on '{0}' returned {1}" -f $Path, $LASTEXITCODE) -ForegroundColor Yellow
        Write-Host ("        {0}" -f (($out | Select-Object -First 2) -join ' / ')) -ForegroundColor DarkYellow
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
    'mxc-t4-marker' | Out-File -LiteralPath "$ScratchRoot\rw\marker.txt" -Encoding ascii -Force
    # Lower the rw subtree to Low IL so the Tier 4 child can write. Files
    # created under it afterwards inherit the Low label.
    Set-LowIntegrity -Path "$ScratchRoot\rw"
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
        $extraRo = @()
        if ($env:LOCALAPPDATA) { $extraRo += $env:LOCALAPPDATA }
        $ReadOnly = @($ReadOnly + $extraRo) | Select-Object -Unique
    }
    $proc = [ordered]@{
        commandLine = $CommandLine
        timeout     = $TimeoutMs
    }
    if ($Cwd) { $proc['cwd'] = $Cwd }
    $obj = [ordered]@{
        version     = '0.5.0-dev'
        containerId = "MxcT4Workload-$Name"
        containment = 'processcontainer'
        process     = $proc
        # Tier 4 stamps S-1-5-12 ACEs on leaf rw/ro paths, so DACL
        # mutation must be permitted.
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
    # Force Tier 4 (or whatever -ForceTier requested). Honored only because
    # the binary was built with the `force_tier_seam` feature; Test-Preflight
    # already verified that.
    $psi.EnvironmentVariables["MXC_FORCE_TIER"] = $ForceTier

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        # Kill the ENTIRE tree, not just wxc-exec: the sandboxed child is a
        # grandchild (spawned via CreateProcessAsUserW) and survives a bare
        # parent kill, leaving an orphan whose cwd pins the scratch dir and
        # blocks cleanup. Kill($true) walks the child process tree.
        try { $p.Kill($true) } catch { try { $p.Kill() } catch {} }
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
function Test-NeedsRestrictedGrant {
    # System-installed dirs under Program Files / Program Files (x86)
    # grant Read & Execute to `Users`, which lives in the restricted
    # token's restricting SID set — so the Tier 4 child can load and run
    # binaries from there with no per-run grant. Per-user installs (e.g.
    # %LOCALAPPDATA%\Programs\Python\..., nvm-windows under %APPDATA%\nvm\)
    # are typically owner-only and need an explicit ReadOnly grant (which
    # the dispatcher stamps for `S-1-5-12`) for the child to execute them.
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
        if (Test-NeedsRestrictedGrant $script:NodeDir) {
            $script:NodeRoNeeded = $script:NodeDir
        }
    }

    foreach ($name in @('python', 'python3')) {
        $py = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $py) { continue }
        if ($py.Source -like '*\WindowsApps\*') { continue }
        $script:PythonExe = $py.Source
        $pyDir = Split-Path $py.Source -Parent
        if (Test-NeedsRestrictedGrant $pyDir) {
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
# Repo + chdir-target helpers
# -----------------------------------------------------------------------
function Initialize-Repo {
    param([string]$Dir)
    if (Test-Path $Dir) { Remove-Item -Recurse -Force -LiteralPath $Dir }
    New-Item -ItemType Directory -Path $Dir | Out-Null
    Push-Location $Dir
    try {
        & git init -q
        & git -c user.email=t4@example.com -c user.name=t4 commit -q --allow-empty -m 'initial'
        'first' | Out-File -LiteralPath (Join-Path $Dir 'file1.txt') -Encoding ascii -Force
        & git add file1.txt
        & git -c user.email=t4@example.com -c user.name=t4 commit -q -m 'add file1'
        'second' | Out-File -LiteralPath (Join-Path $Dir 'file1.txt') -Encoding ascii -Force
        & git -c user.email=t4@example.com -c user.name=t4 commit -q -am 'update file1'
    } finally {
        Pop-Location
    }
    # The git metadata we just wrote is Medium IL (host wrote it); relabel
    # the whole repo Low so the sandboxed child can also write to it.
    Set-LowIntegrity -Path $Dir
}

function Initialize-ChdirTarget {
    $target = "$ScratchRoot\rw\chdir-target"
    if (-not (Test-Path $target)) {
        New-Item -ItemType Directory -Path $target | Out-Null
        'chdir-marker' | Out-File -LiteralPath (Join-Path $target 'chdir-marker.txt') -Encoding ascii -Force
    }
    return $target
}

# -----------------------------------------------------------------------
# Workloads
# -----------------------------------------------------------------------
function W1-CmdTypeMarker {
    Section 'W1: cmd /c type marker.txt (read through ancestor traverse)'
    $cfg = New-Config -Name 'w1-cmd-type' `
        -CommandLine "cmd /c type `"$ScratchRoot\rw\marker.txt`"" `
        -ReadWrite @("$ScratchRoot\rw")
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w1.log" -TimeoutSec 15
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t4-marker')
    Record-Workload -Id 'W1' -Name 'cmd /c type marker.txt' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W2-PwshReadFile {
    Section 'W2: pwsh Get-Content marker.txt'
    if (-not $script:PwshDir) { Record-Workload -Id 'W2' -Name 'pwsh Get-Content' -Pass $false -Detail 'pwsh not found'; return }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Get-Content -LiteralPath '$ScratchRoot\rw\marker.txt'; exit 0`""
    $cfg = New-Config -Name 'w2-pwsh-read' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw")
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w2.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t4-marker')
    Record-Workload -Id 'W2' -Name 'pwsh Get-Content marker' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W3-PwshGitVersion {
    Section 'W3: pwsh git --version'
    if (-not $script:PwshDir) { Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $false -Detail 'pwsh not found'; return }
    if (-not $script:GitDir)  { Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $false -Detail 'git not found';  return }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& git --version; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w3-git-version' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w3.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'git version')
    Record-Workload -Id 'W3' -Name 'pwsh git --version' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W4-PwshGitStatusViaCd {
    Section 'W4: pwsh Set-Location <repo>; git status  [T4 traversal headline]'
    if (-not $script:PwshDir -or -not $script:GitDir) { Record-Workload -Id 'W4' -Name 'pwsh cd + git status' -Pass $false -Detail 'pwsh or git not found'; return }
    $repo = "$ScratchRoot\rw\repo"
    Initialize-Repo -Dir $repo
    'dirty' | Out-File -LiteralPath (Join-Path $repo 'file1.txt') -Encoding ascii -Force
    # Real cwd-relative git: Set-Location into the repo (which forces the
    # runtime to resolve the deep path, traversing every ancestor) then run
    # git with NO -C. Under T3 the ancestor traverse fails; under T4 the
    # Users SID in the restricting set carries it.
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Set-Location -LiteralPath '$repo'; & git status --porcelain; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w4-git-status' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w4.log" -TimeoutSec 90
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'file1\.txt')
    Record-Workload -Id 'W4' -Name 'pwsh Set-Location + git status' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W5-PwshGitLogViaCd {
    Section 'W5: pwsh Set-Location <repo>; git log --oneline  [T4 traversal]'
    if (-not $script:PwshDir -or -not $script:GitDir) { Record-Workload -Id 'W5' -Name 'pwsh cd + git log' -Pass $false -Detail 'pwsh or git not found'; return }
    $repo = "$ScratchRoot\rw\repo"
    if (-not (Test-Path $repo)) { Initialize-Repo -Dir $repo }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Set-Location -LiteralPath '$repo'; & git log --oneline -n 10; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w5-git-log' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w5.log" -TimeoutSec 90
    $pass = ($r.ExitCode -eq 0) -and (($r.Stdout -split "`r?`n" | Where-Object { $_ -match '^[0-9a-f]{7}\s' }).Count -ge 2)
    Record-Workload -Id 'W5' -Name 'pwsh Set-Location + git log' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W6-PwshListDir {
    Section 'W6: pwsh Get-ChildItem on rw directory'
    if (-not $script:PwshDir) { Record-Workload -Id 'W6' -Name 'pwsh Get-ChildItem' -Pass $false -Detail 'pwsh not found'; return }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Get-ChildItem -LiteralPath '$ScratchRoot\rw' | Select-Object -ExpandProperty Name; exit 0`""
    $cfg = New-Config -Name 'w6-pwsh-ls' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w6.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'marker\.txt')
    Record-Workload -Id 'W6' -Name 'pwsh Get-ChildItem rw' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W7-PwshInProcEval {
    Section 'W7: pwsh in-process script eval (math, pipeline)'
    if (-not $script:PwshDir) { Record-Workload -Id 'W7' -Name 'pwsh in-proc eval' -Pass $false -Detail 'pwsh not found'; return }
    $sc = '$x = 6 * 7; Write-Output "answer=$x"; 1..3 | ForEach-Object { Write-Output "iter=$_" }; exit 0'
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$sc`""
    $cfg = New-Config -Name 'w7-pwsh-eval' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w7.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W7' -Name 'pwsh in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W8-PwshSpawnCmd {
    Section 'W8: pwsh spawning cmd /c echo'
    if (-not $script:PwshDir) { Record-Workload -Id 'W8' -Name 'pwsh spawn cmd' -Pass $false -Detail 'pwsh not found'; return }
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"& cmd /c echo hello-from-cmd; exit `$LASTEXITCODE`""
    $cfg = New-Config -Name 'w8-pwsh-spawn-cmd' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w8.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'hello-from-cmd')
    Record-Workload -Id 'W8' -Name 'pwsh -> cmd /c echo' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W9-PwshWriteReadRoundTrip {
    Section 'W9: pwsh Set-Content + Get-Content round-trip (Low-IL write)'
    if (-not $script:PwshDir) { Record-Workload -Id 'W9' -Name 'pwsh write+read' -Pass $false -Detail 'pwsh not found'; return }
    $target = "$ScratchRoot\rw\w9-out.txt"
    $sc = "Set-Content -LiteralPath '$target' -Value 'mxc-w9-payload'; Get-Content -LiteralPath '$target'; exit 0"
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$sc`""
    $cfg = New-Config -Name 'w9-pwsh-rt' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w9.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w9-payload')
    Record-Workload -Id 'W9' -Name 'pwsh Set-Content / Get-Content' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W10-PwshDotNetIo {
    Section 'W10: pwsh .NET [System.IO.File]::ReadAllText'
    if (-not $script:PwshDir) { Record-Workload -Id 'W10' -Name 'pwsh .NET IO' -Pass $false -Detail 'pwsh not found'; return }
    $sc = "Write-Output ([System.IO.File]::ReadAllText('$ScratchRoot\rw\marker.txt')); exit 0"
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"$sc`""
    $cfg = New-Config -Name 'w10-pwsh-dotnet' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w10.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t4-marker')
    Record-Workload -Id 'W10' -Name 'pwsh .NET IO.File.ReadAllText' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W11-PwshSetLocation {
    Section 'W11: pwsh Set-Location into rw subdir + list  [T4 traversal headline]'
    if (-not $script:PwshDir) { Record-Workload -Id 'W11' -Name 'pwsh Set-Location' -Pass $false -Detail 'pwsh not found'; return }
    $target = Initialize-ChdirTarget
    $cmd = "pwsh.exe -NoProfile -NoLogo -Command `"Set-Location -LiteralPath '$target'; Get-ChildItem -Name; exit 0`""
    $cfg = New-Config -Name 'w11-pwsh-cd' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w11.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W11' -Name 'pwsh Set-Location subdir' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W12-NodeReadFile {
    Section 'W12: node -e fs.readFileSync(marker)'
    if (-not $script:NodeDir) { Record-Workload -Id 'W12' -Name 'node read file' -Pass $false -Detail 'node not found'; return }
    $markerFwd = ("$ScratchRoot\rw\marker.txt") -replace '\\','/'
    $js  = "process.stdout.write(require('fs').readFileSync('$markerFwd','utf8'))"
    $cmd = "node.exe -e `"$js`""
    $ro  = @(); if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w12-node-read' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w12.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t4-marker')
    Record-Workload -Id 'W12' -Name 'node fs.readFileSync marker' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W13-NodeEval {
    Section 'W13: node in-proc eval (math, loop)'
    if (-not $script:NodeDir) { Record-Workload -Id 'W13' -Name 'node eval' -Pass $false -Detail 'node not found'; return }
    $js  = "let x=6*7;console.log('answer='+x);for(let i=1;i<=3;i++)console.log('iter='+i);"
    $cmd = "node.exe -e `"$js`""
    $ro  = @(); if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w13-node-eval' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w13.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W13' -Name 'node in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W14-NodeRoundTrip {
    Section 'W14: node fs.writeFileSync + readFileSync round-trip'
    if (-not $script:NodeDir) { Record-Workload -Id 'W14' -Name 'node write+read' -Pass $false -Detail 'node not found'; return }
    $targetFwd = ("$ScratchRoot\rw\w14-out.txt") -replace '\\','/'
    $js  = "const fs=require('fs');fs.writeFileSync('$targetFwd','mxc-w14-payload');process.stdout.write(fs.readFileSync('$targetFwd','utf8'));"
    $cmd = "node.exe -e `"$js`""
    $ro  = @(); if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w14-node-rt' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w14.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w14-payload')
    Record-Workload -Id 'W14' -Name 'node writeFileSync / readFileSync' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W15-NodeChdir {
    Section 'W15: node process.chdir into rw subdir  [T4 traversal headline]'
    if (-not $script:NodeDir) { Record-Workload -Id 'W15' -Name 'node chdir' -Pass $false -Detail 'node not found'; return }
    $target = Initialize-ChdirTarget
    $targetFwd = $target -replace '\\','/'
    $js  = "process.chdir('$targetFwd'); console.log(require('fs').readdirSync('.').join(','));"
    $cmd = "node.exe -e `"$js`""
    $ro  = @(); if ($script:NodeRoNeeded) { $ro += $script:NodeRoNeeded }
    $cfg = New-Config -Name 'w15-node-cd' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w15.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W15' -Name 'node process.chdir' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W16-PyReadFile {
    Section 'W16: python -c open(marker).read()'
    if (-not $script:PythonExe) { Record-Workload -Id 'W16' -Name 'python read file' -Pass $false -Detail 'python not found'; return }
    $py  = "import sys; sys.stdout.write(open(r'$ScratchRoot\rw\marker.txt').read())"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @(); if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w16-py-read' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w16.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-t4-marker')
    Record-Workload -Id 'W16' -Name 'python open().read() marker' -Pass $pass -Traversal `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W17-PyEval {
    Section 'W17: python in-proc eval (math, loop)'
    if (-not $script:PythonExe) { Record-Workload -Id 'W17' -Name 'python eval' -Pass $false -Detail 'python not found'; return }
    $py  = "x=6*7; print('answer='+str(x)); [print('iter='+str(i)) for i in range(1,4)]"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @(); if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w17-py-eval' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w17.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'answer=42') -and ($r.Stdout -match 'iter=3')
    Record-Workload -Id 'W17' -Name 'python in-proc eval' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W18-PyRoundTrip {
    Section 'W18: python open(w) + open(r) round-trip'
    if (-not $script:PythonExe) { Record-Workload -Id 'W18' -Name 'python write+read' -Pass $false -Detail 'python not found'; return }
    $target = "$ScratchRoot\rw\w18-out.txt"
    $py  = "open(r'$target','w').write('mxc-w18-payload'); import sys; sys.stdout.write(open(r'$target').read())"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @(); if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w18-py-rt' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w18.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'mxc-w18-payload')
    Record-Workload -Id 'W18' -Name 'python write+read round-trip' -Pass $pass `
        -ExitCode $r.ExitCode -Detail "stdout=$($r.Stdout.Trim())" -Stderr $r.Stderr
}

function W19-PyChdir {
    Section 'W19: python os.chdir into rw subdir  [T4 traversal headline]'
    if (-not $script:PythonExe) { Record-Workload -Id 'W19' -Name 'python chdir' -Pass $false -Detail 'python not found'; return }
    $target = Initialize-ChdirTarget
    $py  = "import os; os.chdir(r'$target'); print(','.join(os.listdir('.')))"
    $cmd = "`"$script:PythonExe`" -c `"$py`""
    $ro  = @(); if ($script:PythonRoNeeded) { $ro += $script:PythonRoNeeded }
    $cfg = New-Config -Name 'w19-py-cd' -CommandLine $cmd -ReadWrite @("$ScratchRoot\rw") -ReadOnly $ro -Cwd "$ScratchRoot\rw"
    $r = Invoke-Workload -ConfigPath $cfg -LogPath "$ScratchRoot\log\w19.log" -TimeoutSec 60
    $pass = ($r.ExitCode -eq 0) -and ($r.Stdout -match 'chdir-marker\.txt')
    Record-Workload -Id 'W19' -Name 'python os.chdir' -Pass $pass -Traversal `
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
    if (4  -in $Run) { W4-PwshGitStatusViaCd }
    if (5  -in $Run) { W5-PwshGitLogViaCd }
    if (6  -in $Run) { W6-PwshListDir }
    if (7  -in $Run) { W7-PwshInProcEval }
    if (8  -in $Run) { W8-PwshSpawnCmd }
    if (9  -in $Run) { W9-PwshWriteReadRoundTrip }
    if (10 -in $Run) { W10-PwshDotNetIo }
    if (11 -in $Run) { W11-PwshSetLocation }
    if (12 -in $Run) { W12-NodeReadFile }
    if (13 -in $Run) { W13-NodeEval }
    if (14 -in $Run) { W14-NodeRoundTrip }
    if (15 -in $Run) { W15-NodeChdir }
    if (16 -in $Run) { W16-PyReadFile }
    if (17 -in $Run) { W17-PyEval }
    if (18 -in $Run) { W18-PyRoundTrip }
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
    $trav   = @($Script:Results | Where-Object { $_.Traversal })
    $travPass = @($trav | Where-Object { $_.Pass })
    Write-Host ("Total: {0}    Passed: {1}    Failed: {2}" -f $Script:Results.Count, $passed.Count, $failed.Count)
    if ($trav.Count -gt 0) {
        Write-Host ("Traversal workloads (the Tier 4 raison d'etre): {0}/{1} passed" -f $travPass.Count, $trav.Count) -ForegroundColor Cyan
    }
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
        Assert-SafeScratchRoot
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
    }
}
