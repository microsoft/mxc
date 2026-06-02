# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# CliOverride-Divergence.ps1
#
# Runs each of nine common command lines two ways and prints a side-by-side
# table of how the *rendered* commandLine differs:
#
#   Mode A - the string is baked into process.commandLine in the policy JSON.
#   Mode B - the same intent is passed as argv after `--` on wxc-exec's CLI.
#
# Both modes go through `wxc-exec --dry-run`, so no sandbox is dispatched.
# Mode B's rendered string is extracted from the
#   "Overriding policy process.commandLine with CLI command: <rendered>"
# log line, or from the
#   "invalid CLI command override: <reason>"
# rejection error.
#
# The "Divergent" column flags every row where the two modes do NOT produce
# the same effective commandLine under the CURRENT renderer (cmdline.rs at
# HEAD). The proposed reduction (single CreateProcess context for all
# backends) would render every CLI-form identical to its JSON-form; this
# script only requires the current build to demonstrate that today they
# diverge.

[CmdletBinding()]
param(
    # The script lives in test_scripts/; the cargo workspace lives at
    # ../src/ from there. Resolve relative to the script's parent so the
    # defaults work no matter where the script is invoked from.
    [string]$RepoRoot     = (Split-Path -Parent $PSScriptRoot),
    [string]$Wxc          = (Join-Path $RepoRoot 'src\target\debug\wxc-exec.exe'),
    [string]$CargoRoot    = (Join-Path $RepoRoot 'src'),
    [string]$ScratchRoot  = (Join-Path $env:TEMP 'mxc-cli-override-divergence'),
    [switch]$SkipBuild,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------
# Helpers (match style of Win25H2Safe-Tests / T3-Workloads)
# -----------------------------------------------------------------------
function Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

function Assert-SafeScratchRoot {
    if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
        throw "Refusing to operate on an empty/whitespace -ScratchRoot."
    }
    $resolved = [System.IO.Path]::GetFullPath($ScratchRoot)
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not $resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing -ScratchRoot '$resolved': must resolve under `$env:TEMP."
    }
    if ($resolved.TrimEnd('\','/') -ieq $tempRoot.TrimEnd('\','/')) {
        throw "Refusing -ScratchRoot equal to `$env:TEMP itself."
    }
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ($root -and ($resolved.TrimEnd('\','/') -ieq $root.TrimEnd('\','/'))) {
        throw "Refusing -ScratchRoot '$resolved': drive roots are not valid."
    }
    $leaf = Split-Path -Path $resolved -Leaf
    if ($leaf -notlike 'mxc-*') {
        throw "Refusing -ScratchRoot '$resolved': leaf must start with 'mxc-'."
    }
}

function Initialize-Scratch {
    Assert-SafeScratchRoot
    if (Test-Path $ScratchRoot) {
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot
    }
    New-Item -ItemType Directory -Path $ScratchRoot       | Out-Null
    New-Item -ItemType Directory -Path "$ScratchRoot\cfg" | Out-Null
}

function Test-Preflight {
    Section 'Pre-flight'
    if (-not $SkipBuild) {
        if (-not (Test-Path (Join-Path $CargoRoot 'Cargo.toml'))) {
            throw "No Cargo.toml at $CargoRoot. Pass -CargoRoot <path> or -SkipBuild."
        }
        Write-Host 'Building wxc-exec (debug)...'
        Push-Location $CargoRoot
        try {
            & cargo build -p wxc 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
        } finally {
            Pop-Location
        }
    }
    if (-not (Test-Path $Wxc)) { throw "wxc-exec.exe not found at $Wxc" }
    Write-Host ('wxc-exec: {0}' -f $Wxc)
    Write-Host ('scratch:  {0}' -f $ScratchRoot)
}

function New-Policy {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Backend,
        [string]$CommandLine
    )
    $proc = [ordered]@{}
    if ($CommandLine) { $proc['commandLine'] = $CommandLine }
    $obj = [ordered]@{
        version     = '0.5.0-dev'
        containerId = "CliDivergence-$Name"
        containment = $Backend
    }
    if ($proc.Count -gt 0) { $obj['process'] = $proc }
    $path = Join-Path "$ScratchRoot\cfg" "$Name.json"
    ($obj | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}

function Invoke-Wxc {
    # Splat the argv array so PowerShell hands each element to CreateProcess
    # as its own argv token. '|' / '&&' arrive at wxc-exec as literal string
    # tokens, not as PS pipe / chain operators.
    param([string[]]$Arguments)
    $merged = & $Wxc @Arguments 2>&1 | ForEach-Object { $_.ToString() }
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Combined = ($merged -join "`n")
    }
}

function Get-RenderedCli {
    param([string]$Combined, [int]$ExitCode)
    $m = [regex]::Match(
        $Combined,
        'Overriding policy process\.commandLine with CLI command:\s*(?<r>.+?)\s*(?:\r|\n|$)'
    )
    if ($m.Success) {
        return [pscustomobject]@{ Form = $m.Groups['r'].Value.Trim(); Status = 'accepted' }
    }
    $m = [regex]::Match(
        $Combined,
        'invalid CLI command override:\s*(?<r>.+?)\s*(?:\r|\n|$)'
    )
    if ($m.Success) {
        return [pscustomobject]@{ Form = '<rejected>'; Status = $m.Groups['r'].Value.Trim() }
    }
    if ($ExitCode -ne 0) {
        return [pscustomobject]@{ Form = '<error>'; Status = "exit=$ExitCode" }
    }
    return [pscustomobject]@{ Form = ''; Status = '<no override log emitted>' }
}

# -----------------------------------------------------------------------
# Example matrix. JsonCmd is the verbatim string written into
# process.commandLine. Argv is the equivalent argv as the user would type
# after `--` on the CLI. The two are expected to produce the same effective
# commandLine inside the sandbox; the table flags when they don't.
# -----------------------------------------------------------------------
$examples = @(
    @{ N=1; Backend='windows_sandbox'; Wrapper='cmd.exe';
       Desc='MSBuild with env-var solution path';
       JsonCmd='msbuild %SOLUTION_PATH%\foo.sln /p:Configuration=Release';
       Argv=@('msbuild','%SOLUTION_PATH%\foo.sln','/p:Configuration=Release') },
    @{ N=2; Backend='windows_sandbox'; Wrapper='cmd.exe';
       Desc='git clone with ! in credential';
       JsonCmd='git clone https://user:p!ss@github.com/org/repo.git';
       Argv=@('git','clone','https://user:p!ss@github.com/org/repo.git') },
    @{ N=3; Backend='windows_sandbox'; Wrapper='cmd.exe';
       Desc='pwsh -Command with embedded quotes';
       JsonCmd='pwsh.exe -Command "Write-Host ''hello, world''"';
       Argv=@('pwsh.exe','-Command','Write-Host "hello, world"') },
    @{ N=4; Backend='windows_sandbox'; Wrapper='cmd.exe';
       Desc='cmd pipe to filter';
       JsonCmd='dir /b | findstr .json';
       Argv=@('dir','/b','|','findstr','.json') },
    @{ N=5; Backend='windows_sandbox'; Wrapper='cmd.exe';
       Desc='cmd chained build+test';
       JsonCmd='cmake --build build && ctest --test-dir build';
       Argv=@('cmake','--build','build','&&','ctest','--test-dir','build') },
    @{ N=6; Backend='wslc'; Wrapper='sh';
       Desc='sh env var expansion';
       JsonCmd='echo $HOME';
       Argv=@('echo','$HOME') },
    @{ N=7; Backend='wslc'; Wrapper='sh';
       Desc='sh glob';
       JsonCmd='ls -la *.log';
       Argv=@('ls','-la','*.log') },
    @{ N=8; Backend='wslc'; Wrapper='sh';
       Desc='sh command substitution';
       JsonCmd='echo "build host: $(uname -srv)"';
       Argv=@('echo','build host: $(uname -srv)') },
    @{ N=9; Backend='wslc'; Wrapper='sh';
       Desc='sh chained cd+tar';
       JsonCmd='cd /tmp && tar -xzf payload.tgz';
       Argv=@('cd','/tmp','&&','tar','-xzf','payload.tgz') }
)

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
try {
    Test-Preflight
    Initialize-Scratch

    Section 'Running examples (wxc-exec --dry-run --debug)'
    $rows = foreach ($e in $examples) {
        $name = 'ex{0}' -f $e.N

        # Mode A: commandLine baked into the policy. No CLI override.
        $policyA = New-Policy -Name "$name-a" -Backend $e.Backend -CommandLine $e.JsonCmd
        $null = Invoke-Wxc -Arguments @('--dry-run', '--debug', $policyA)

        # Mode B: a placeholder commandLine so the override log line always
        # fires on success; the real intent comes from argv after `--`.
        $policyB = New-Policy -Name "$name-b" -Backend $e.Backend -CommandLine 'PLACEHOLDER_OVERRIDE_ME'
        $argsB = @('--dry-run', '--debug', $policyB, '--') + $e.Argv
        $resB = Invoke-Wxc -Arguments $argsB

        $rendered = Get-RenderedCli -Combined $resB.Combined -ExitCode $resB.ExitCode
        $divergent = ($e.JsonCmd -ne $rendered.Form)
        $tag   = if ($divergent) { 'DIVERGENT' } else { 'match' }
        $color = if ($divergent) { 'Yellow' }    else { 'Green' }
        Write-Host ('  [{0,2}] {1,-7} {2,-44}  {3}' -f $e.N, $e.Wrapper, $e.Desc, $tag) -ForegroundColor $color

        [pscustomobject]@{
            '#'         = $e.N
            Wrapper     = $e.Wrapper
            Example     = $e.Desc
            'JSON-form' = $e.JsonCmd
            'CLI-form'  = if ($rendered.Form) { $rendered.Form } else { '<' + $rendered.Status + '>' }
            Divergent   = if ($divergent) { 'YES' } else { '' }
        }
    }

    Section 'Side-by-side comparison'
    $rows | Format-Table -Wrap -AutoSize

    $divergeCount = @($rows | Where-Object { $_.Divergent -eq 'YES' }).Count
    Write-Host ''
    Write-Host ('Examples flagged divergent: {0} / {1}' -f $divergeCount, $rows.Count) `
        -ForegroundColor $(if ($divergeCount -gt 0) { 'Yellow' } else { 'Green' })
}
finally {
    if (-not $KeepArtifacts -and (Test-Path $ScratchRoot)) {
        Assert-SafeScratchRoot
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
    }
}
