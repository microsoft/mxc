# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 7.0

# Manual only: exercise real runtimes without extending the scheduled CI workload.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BinDir)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$wxc = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
$scratch = Join-Path $env:TEMP ("mxc-native-workloads-" + [guid]::NewGuid().ToString('N'))
$rw = Join-Path $scratch 'rw'
New-Item -ItemType Directory -Path $rw -Force | Out-Null
$marker = Join-Path $rw 'marker.txt'
Set-Content -LiteralPath $marker -Value 'NATIVE_WORKLOAD_MARKER' -NoNewline
$chdir = Join-Path $rw 'chdir-target'
New-Item -ItemType Directory -Path $chdir | Out-Null
Set-Content -LiteralPath (Join-Path $chdir 'chdir-marker.txt') -Value 'chdir-marker' -NoNewline
Write-Host "Manual native workload artifacts: $scratch"

$hostProbe = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
    -Name 'host-probe' -Arguments @('--probe')
if ($hostProbe.ExitCode -ne 0 -or
    ($hostProbe.Stdout | ConvertFrom-Json).tier -ne 'base-container') {
    throw 'Manual workload validation requires an enabled native PSEC contract.'
}
$tools = @{}
foreach ($name in @('pwsh', 'git', 'node', 'python')) {
    $command = Get-Command "$name.exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    $tools[$name] = if ($command -and $command.Source -notlike '*\WindowsApps\*') { $command.Source } else { $null }
}
if (-not $tools.python) {
    $python3 = Get-Command 'python3.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($python3 -and $python3.Source -notlike '*\WindowsApps\*') { $tools.python = $python3.Source }
}
$readonly = @($env:SystemRoot)
foreach ($entry in $tools.GetEnumerator()) {
    if ($entry.Value) {
        $directory = Split-Path -Parent $entry.Value
        if ($entry.Key -eq 'git') { $directory = Split-Path -Parent $directory }
        $readonly += $directory
    }
}
$readonly = @($readonly | Select-Object -Unique)

function Quote-PowerShellLiteral {
    param([string]$Value)
    "'" + $Value.Replace("'", "''") + "'"
}
function New-WorkloadCommand {
    param([string]$Tool, [string]$Body)
    if ($Tool -eq 'pwsh') {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
            "`$ErrorActionPreference='Stop'; $Body"))
        return "`"$($tools.pwsh)`" -NoProfile -NonInteractive -EncodedCommand $encoded"
    }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Body))
    if ($Tool -eq 'node') {
        return "`"$($tools.node)`" -e `"eval(Buffer.from('$encoded','base64').toString('utf8'))`""
    }
    if ($Tool -eq 'python') {
        return "`"$($tools.python)`" -c `"import base64;exec(base64.b64decode('$encoded'))`""
    }
    throw "Unknown workload interpreter: $Tool"
}

function New-WorkloadGitEnvironment {
    param([string]$Directory)
    $xdg = Join-Path $Directory 'xdg'
    $git = Join-Path $xdg 'git'
    New-Item -ItemType Directory -Path $git -Force | Out-Null
    foreach ($file in @('global.gitconfig', 'system.gitconfig', 'xdg\git\ignore', 'xdg\git\attributes')) {
        [IO.File]::WriteAllText((Join-Path $Directory $file), '')
    }
    @{
        GIT_CONFIG_GLOBAL = Join-Path $Directory 'global.gitconfig'
        GIT_CONFIG_SYSTEM = Join-Path $Directory 'system.gitconfig'
        XDG_CONFIG_HOME = $xdg
    }
}
function Invoke-WorkloadGit {
    param([string[]]$Arguments)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $tools.git
    $start.UseShellExecute = $false
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    foreach ($entry in $gitEnvironment.GetEnumerator()) { $start.Environment[$entry.Key] = $entry.Value }
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(30000)) { throw 'Git fixture preparation timed out.' }
        if ($process.ExitCode -ne 0) { throw "Git fixture preparation exited $($process.ExitCode): $($Arguments -join ' ')" }
    } finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) { throw 'Git fixture preparation did not stop during cleanup.' }
            }
        } finally { $process.Dispose() }
    }
}
$gitConfigurationDirectory = Join-Path $scratch 'git-config'
$gitEnvironment = New-WorkloadGitEnvironment -Directory $gitConfigurationDirectory
$repo = Join-Path $rw 'repo'
if ($tools.pwsh -and $tools.git) {
    New-Item -ItemType Directory -Path $repo | Out-Null
    Invoke-WorkloadGit -Arguments @('-C', $repo, 'init', '--quiet')
    foreach ($index in 1..3) {
        Set-Content -LiteralPath (Join-Path $repo 'file1.txt') -Value "revision-$index"
        Invoke-WorkloadGit -Arguments @('-C', $repo, 'add', 'file1.txt')
        Invoke-WorkloadGit -Arguments @('-C', $repo, '-c', 'user.name=MxcFixture',
            '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', "fixture revision $index")
    }
    Set-Content -LiteralPath (Join-Path $repo 'file1.txt') -Value 'dirty'
    # Elevated hosts may assign Administrators ownership; use the caller as
    # owner of this newly created fixture so Git's ownership check stays enabled.
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($item in @((Get-Item -LiteralPath $repo)) + @(Get-ChildItem -LiteralPath $repo -Force -Recurse)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The owned Git fixture unexpectedly contains a reparse point.'
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner) {
            $acl.SetOwner($owner)
            Set-Acl -LiteralPath $item.FullName -AclObject $acl
        }
    }
}
$markerPs = Quote-PowerShellLiteral $marker
$rwPs = Quote-PowerShellLiteral $rw
$repoPs = Quote-PowerShellLiteral $repo
$gitPs = Quote-PowerShellLiteral ([string]$tools.git)
$chdirPs = Quote-PowerShellLiteral $chdir
$markerJson = ConvertTo-Json -InputObject $marker -Compress
$chdirJson = ConvertTo-Json -InputObject $chdir -Compress
$roundTrip = Join-Path $rw 'round-trip.txt'
$roundTripPs = Quote-PowerShellLiteral $roundTrip
$roundTripJson = ConvertTo-Json -InputObject $roundTrip -Compress
$cases = @(
    @{ Name = 'W1-cmd-read'; Tools = @(); Pattern = 'NATIVE_WORKLOAD_MARKER'; Command = {
        "`"$env:SystemRoot\System32\cmd.exe`" /d /s /c `"type `"$marker`"`""
    } },
    @{ Name = 'W2-pwsh-read'; Tools = @('pwsh'); Pattern = 'NATIVE_WORKLOAD_MARKER'; Command = {
        New-WorkloadCommand pwsh "Get-Content -LiteralPath $markerPs"
    } },
    @{ Name = 'W3-pwsh-git-version'; Tools = @('pwsh', 'git'); Pattern = 'git version'; Command = {
        New-WorkloadCommand pwsh "& $gitPs --version; exit `$LASTEXITCODE"
    } },
    @{ Name = 'W4-pwsh-git-status'; Tools = @('pwsh', 'git'); Pattern = ' M file1\.txt'; Command = {
        New-WorkloadCommand pwsh "& $gitPs -C $repoPs status --porcelain; exit `$LASTEXITCODE"
    } },
    @{ Name = 'W5-pwsh-git-log'; Tools = @('pwsh', 'git'); Pattern = '(?m)^[0-9a-f]{7,40} fixture revision 1\r?$'; Command = {
        New-WorkloadCommand pwsh "& $gitPs -C $repoPs log --oneline -n 3; exit `$LASTEXITCODE"
    } },
    @{ Name = 'W6-pwsh-list'; Tools = @('pwsh'); Pattern = 'marker\.txt'; Command = {
        New-WorkloadCommand pwsh "Get-ChildItem -LiteralPath $rwPs -Name"
    } },
    @{ Name = 'W7-pwsh-eval'; Tools = @('pwsh'); Pattern = '(?s)answer=42.*iter=3'; Command = {
        New-WorkloadCommand pwsh '$x=6*7; Write-Output "answer=$x"; 1..3 | ForEach-Object { Write-Output "iter=$_" }'
    } },
    @{ Name = 'W8-pwsh-child'; Tools = @('pwsh'); Pattern = 'NATIVE_CHILD_OK'; Command = {
        New-WorkloadCommand pwsh "& '$env:SystemRoot\System32\cmd.exe' /d /c echo NATIVE_CHILD_OK; exit `$LASTEXITCODE"
    } },
    @{ Name = 'W9-pwsh-round-trip'; Tools = @('pwsh'); Pattern = 'NATIVE_ROUND_TRIP'; Command = {
        New-WorkloadCommand pwsh "Set-Content -LiteralPath $roundTripPs -Value NATIVE_ROUND_TRIP; Get-Content -LiteralPath $roundTripPs"
    } },
    @{ Name = 'W10-pwsh-dotnet-read'; Tools = @('pwsh'); Pattern = 'NATIVE_WORKLOAD_MARKER'; Command = {
        New-WorkloadCommand pwsh "[Console]::WriteLine([IO.File]::ReadAllText($markerPs))"
    } },
    @{ Name = 'W11-node-read'; Tools = @('node'); Pattern = 'NATIVE_WORKLOAD_MARKER'; Command = {
        New-WorkloadCommand node "process.stdout.write(require('fs').readFileSync($markerJson,'utf8'))"
    } },
    @{ Name = 'W12-node-eval'; Tools = @('node'); Pattern = '(?s)answer=42.*iter=3'; Command = {
        New-WorkloadCommand node "console.log('answer='+(6*7));for(let i=1;i<=3;i++)console.log('iter='+i)"
    } },
    @{ Name = 'W13-node-round-trip'; Tools = @('node'); Pattern = 'NATIVE_ROUND_TRIP'; Command = {
        New-WorkloadCommand node "const fs=require('fs');fs.writeFileSync($roundTripJson,'NATIVE_ROUND_TRIP');console.log(fs.readFileSync($roundTripJson,'utf8'))"
    } },
    @{ Name = 'W14-python-read'; Tools = @('python'); Pattern = 'NATIVE_WORKLOAD_MARKER'; Command = {
        New-WorkloadCommand python "print(open($markerJson).read())"
    } },
    @{ Name = 'W15-python-eval'; Tools = @('python'); Pattern = '(?s)answer=42.*iter=3'; Command = {
        New-WorkloadCommand python "print('answer='+str(6*7));[print('iter='+str(i)) for i in range(1,4)]"
    } },
    @{ Name = 'W16-python-round-trip'; Tools = @('python'); Pattern = 'NATIVE_ROUND_TRIP'; Command = {
        New-WorkloadCommand python "open($roundTripJson,'w').write('NATIVE_ROUND_TRIP');print(open($roundTripJson).read())"
    } },
    @{ Name = 'W17-pwsh-chdir'; Tools = @('pwsh'); Pattern = 'chdir-marker\.txt'; Command = {
        New-WorkloadCommand pwsh "Set-Location -LiteralPath $chdirPs; Get-ChildItem -Name"
    } },
    @{ Name = 'W18-node-chdir'; Tools = @('node'); Pattern = 'chdir-marker\.txt'; Command = {
        New-WorkloadCommand node "process.chdir($chdirJson);console.log(require('fs').readdirSync('.').join(','))"
    } },
    @{ Name = 'W19-python-chdir'; Tools = @('python'); Pattern = 'chdir-marker\.txt'; Command = {
        New-WorkloadCommand python "import os;os.chdir($chdirJson);print(','.join(os.listdir('.')))"
    } }
)
function New-WorkloadRequest {
    param([hashtable]$Case)
    $request = @{
        version = '1.0.0'
        containment = 'processcontainer'
        process = @{ commandLine = (& $Case.Command); cwd = $rw; timeout = 30000 }
        filesystem = @{ readwritePaths = @($rw); readonlyPaths = $readonly }
        ui = @{ disable = $false }
        telemetry = @{ enabled = $false }
    }
    if ($Case.Tools -contains 'git') {
        $request.process.env = @($gitEnvironment.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
        $request.process.inheritDefaultEnv = $true
        $request.filesystem.readonlyPaths += $gitConfigurationDirectory
    }
    $request
}
$passed = 0
$skipped = 0
$fixtureDirectories = @($scratch, $rw, $chdir, $gitConfigurationDirectory) +
    @(Get-ChildItem -LiteralPath $gitConfigurationDirectory -Directory -Recurse | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $rw -Directory -Force -Recurse | Select-Object -ExpandProperty FullName)
$fixtureDirectories = @($fixtureDirectories | Select-Object -Unique)
foreach ($case in $cases) {
    $missing = @($case.Tools | Where-Object { -not $tools[$_] })
    if ($missing.Count) {
        Write-Host "SKIPPED: $($case.Name) (missing interpreter: $($missing -join ', '))"
        $skipped++
        continue
    }
    $request = New-WorkloadRequest -Case $case
    $path = Join-Path $scratch "$($case.Name).json"
    $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
    $security = Get-NativeFixtureSecuritySnapshot -Paths $fixtureDirectories
    try {
        $result = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
            -Name $case.Name -Arguments @($path)
        if ($result.ExitCode -ne 0 -or $result.Stdout -notmatch $case.Pattern -or
            $result.Log -notmatch '"tier":"base-container"') {
            throw "$($case.Name) failed: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr)"
        }
    } finally {
        Assert-NativeFixtureSecurity -Name $case.Name -Snapshot $security
    }
    $passed++
    Write-Host "PASSED: $($case.Name)"
}
if ($passed -eq 0) { throw 'The manual native workload suite executed no cases.' }
Write-Host "Native workloads: $passed passed, $skipped skipped"
$global:LASTEXITCODE = 0
