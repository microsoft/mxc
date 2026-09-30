# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Creates disposable inputs for a prepared, governed ProcessContainer host.
# This does not install administrative policy or tag any process.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z]:\\[^\x00-\x1f"%!^&|<>]+$')]
    [string]$Directory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
if (Test-Path -LiteralPath $Directory) {
    throw 'Use a new, empty fixture directory; existing test inputs are not overwritten.'
}
function Write-FixtureJson($Value, [string]$Name) {
    [IO.File]::WriteAllText(
        (Join-Path $Directory $Name),
        ($Value | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}
$data = Join-Path $Directory 'data'
$allowed = Join-Path $data 'allowed'
foreach ($path in @($Directory, $data, $allowed,
    (Join-Path $data 'readonly'), (Join-Path $data 'denied'), (Join-Path $data 'denied2'))) {
    New-Item -ItemType Directory -Path $path | Out-Null
}
$acl = Get-Acl -LiteralPath $Directory
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    [Security.Principal.WindowsIdentity]::GetCurrent().User,
    [Security.AccessControl.FileSystemRights]::Modify,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow)))
Set-Acl -LiteralPath $Directory -AclObject $acl
foreach ($name in @('allowed', 'readonly', 'denied', 'denied2')) {
    Set-Content -LiteralPath (Join-Path $data "$name\seed.txt") -Value 'disposable sentinel' -Encoding ASCII
}
$probe = @'
param([Parameter(Mandatory)][string]$Data)
$ErrorActionPreference = 'Stop'
function Check-Access([string]$Path, [string]$Operation, [bool]$Allowed) {
    $stream = $null
    $succeeded = $false
    try {
        $mode = if ($Operation -eq 'Create') { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Open }
        $access = if ($Operation -eq 'Read') { [IO.FileAccess]::Read } else { [IO.FileAccess]::Write }
        $stream = [IO.File]::Open($Path, $mode, $access)
        if ($Operation -eq 'Read') { $null = $stream.ReadByte() }
        if ($Operation -eq 'Write') { $stream.WriteByte(80) }
        $succeeded = $true
    } catch [System.UnauthorizedAccessException] {
        if ($Allowed) { throw }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    if ($succeeded -ne $Allowed) { throw "$Operation at $Path did not enforce the expected access." }
    if ($Operation -eq 'Create' -and $succeeded) { [IO.File]::Delete($Path) }
}
foreach ($name in @('allowed', 'readonly', 'denied', 'denied2')) {
    $directory = [IO.Path]::Combine($Data, $name)
    $seed = [IO.Path]::Combine($directory, 'seed.txt')
    Check-Access $seed Read ($name -in @('allowed', 'readonly'))
    Check-Access $seed Write ($name -eq 'allowed')
    Check-Access ([IO.Path]::Combine($directory, [Guid]::NewGuid().ToString('N') + '.txt')) Create ($name -eq 'allowed')
}
[Console]::Out.WriteLine('MXC_POLICY_FIXTURE_OK')
'@
Set-Content -LiteralPath (Join-Path $Directory 'probe.ps1') -Value $probe -Encoding ASCII
$probeCommand = "& {`n$probe`n} -Data '" + $data.Replace("'", "''") + "'"
$encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeCommand))
$cwdProbe = @'
@echo off
if /I not "%CD%"=="%~1" exit /b 41
echo MXC_POLICY_CWD_OK
exit /b 0
'@
Set-Content -LiteralPath (Join-Path $Directory 'cwd-probe.cmd') -Value $cwdProbe -Encoding ASCII
$policy = @{
    version = 1
    agents = @()
    default_process_sandbox_policy = @{
        default_action = @{
            effect = 'allow'
            ceiling = @{
                read_write_paths = @($allowed)
                read_only_paths = @($env:SystemRoot, $Directory)
                deny_paths = @((Join-Path $data 'denied'), (Join-Path $data 'denied2'))
                block_network_access = $false
                block_permissive_mode = $false
            }
        }
    }
}
Write-FixtureJson $policy 'agent-policy.json'
$cases = foreach ($mode in @('pass-through', 'mutate')) {
    $config = @{
        version = '0.10.0-alpha'
        containment = 'processcontainer'
        process = @{
            commandLine = ('"{0}\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand {1}' -f $env:SystemRoot, $encodedProbe)
            cwd = $allowed
            timeout = 15000
        }
        filesystem = @{
            readwritePaths = @($data, $allowed)
            readonlyPaths = @($env:SystemRoot, $Directory)
        }
        network = @{ egress = @{ default = 'deny' }; ingress = @{ default = 'deny'; hostLoopback = 'deny' } }
        # PowerShell initialization needs Win32k; the workload remains noninteractive.
        ui = @{ disable = $false }
        processContainer = @{ policyEnforcement = @{ mode = $mode; maxAttempts = 8 } }
    }
    Write-FixtureJson $config "$mode.json"
    $mutate = $mode -eq 'mutate'
    [ordered]@{
        name = "$mode filesystem ceiling"
        config = "$mode.json"
        experimental = $mutate
        expectedExitCode = if ($mutate) { 0 } else { -1 }
        expectedTermination = if ($mutate) { 'created' } else { 'rejected' }
        expectedOutcomeCode = if ($mutate) { 2 } else { 3 }
        minAttempts = if ($mutate) { 2 } else { 1 }
        maxAttempts = if ($mutate) { 2 } else { 1 }
        expectedDetailCounts = if ($mutate) { @(3,0) } else { @(3) }
        stdoutPattern = '(?m)^MXC_POLICY_FIXTURE_OK\r?$'
        stdoutMatchCount = if ($mutate) { 1 } else { 0 }
        expectedProcessCreations = if ($mutate) { 1 } else { 0 }
    }
}
$implicitCwd = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$implicitCwd.process.PSObject.Properties.Remove('cwd')
$implicitCwd.process.commandLine = ('"{0}\System32\cmd.exe" /d /c call "{1}\cwd-probe.cmd" "{2}"' -f $env:SystemRoot, $Directory, $data)
Write-FixtureJson $implicitCwd 'implicit-cwd.json'
$cases += [ordered]@{
    name = 'Mutation preserves the original implicit working directory'
    config = 'implicit-cwd.json'
    experimental = $true
    expectedExitCode = 0
    expectedTermination = 'created'
    expectedOutcomeCode = 2
    minAttempts = 2
    maxAttempts = 2
    expectedDetailCounts = @(3,0)
    stdoutPattern = '(?m)^MXC_POLICY_CWD_OK\r?$'
    stdoutMatchCount = 1
    expectedProcessCreations = 1
}
$readonlyRoot = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$readonlyRoot.filesystem.readwritePaths = @($allowed)
$readonlyRoot.filesystem.readonlyPaths = @([IO.Path]::GetPathRoot($Directory), $env:SystemRoot, $Directory)
Write-FixtureJson $readonlyRoot 'readonly-root.json'
$cases += [ordered]@{
    name = 'Root deny repair preserves explicit child grants'
    config = 'readonly-root.json'
    experimental = $true
    expectedExitCode = 0
    expectedTermination = 'created'
    expectedOutcomeCode = 2
    minAttempts = 2
    maxAttempts = 2
    expectedDetailCounts = @(3,0)
    stdoutPattern = '(?m)^MXC_POLICY_FIXTURE_OK\r?$'
    stdoutMatchCount = 1
    expectedProcessCreations = 1
}
$compatibility = @{
    version = '0.10.0-alpha'
    containment = 'processcontainer'
    process = @{ commandLine = 'cmd.exe /d /c echo MXC_POLICY_COMPAT'; cwd = $env:SystemRoot; timeout = 15000 }
    filesystem = @{ readonlyPaths = @($env:SystemRoot) }
    network = @{ egress = @{ default = 'deny' }; ingress = @{ default = 'deny'; hostLoopback = 'deny' } }
    processContainer = @{ leastPrivilege = $true; policyEnforcement = @{ mode = 'mutate' } }
}
Write-FixtureJson $compatibility 'lpac-compatibility.json'
$cases += [ordered]@{
    name = 'LPAC ignores mutation without experimental authorization'
    config = 'lpac-compatibility.json'
    experimental = $false
    expectedExitCode = 0
    expectedTermination = 'ignored'
    expectedOutcomeCode = -1
    expectedAvailability = 'notApplicable'
    expectedTier = 'appcontainer-dacl'
    minAttempts = 0
    maxAttempts = 0
    stdoutPattern = '(?m)^MXC_POLICY_COMPAT\r?$'
    stdoutMatchCount = 1
    expectedProcessCreations = 1
}
$explicitEmpty = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$explicitEmpty.processContainer.policyEnforcement = [pscustomobject]@{}
Write-FixtureJson $explicitEmpty 'explicit-empty.json'
$cases += [ordered]@{
    name = 'Empty controls explicitly request pass-through reporting'
    config = 'explicit-empty.json'
    experimental = $false
    expectedExitCode = -1
    expectedTermination = 'rejected'
    expectedOutcomeCode = 3
    minAttempts = 1
    maxAttempts = 1
    expectedDetailCounts = @(3)
    stdoutPattern = '(?m)^MXC_POLICY_FIXTURE_OK\r?$'
    stdoutMatchCount = 0
    expectedProcessCreations = 0
}
$legacy = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$legacy.version = '0.9.0-alpha'
$legacy.processContainer.PSObject.Properties.Remove('policyEnforcement')
Write-FixtureJson $legacy 'legacy-refusal.json'
$cases += [ordered]@{
    name = 'Published legacy request is refused without new diagnostics'
    config = 'legacy-refusal.json'
    experimental = $false
    expectReport = $false
    expectedExitCode = -1
    stderrPattern = 'failed to create the process security environment:'
    expectedPolicyDeniedGuidance = $true
    stdoutPattern = '(?m)^MXC_POLICY_FIXTURE_OK\r?$'
    stdoutMatchCount = 0
    expectedProcessCreations = 0
}
$legacy.filesystem.readwritePaths = @($allowed)
$legacy.filesystem.readonlyPaths = @($data, $env:SystemRoot, $Directory)
$legacy.filesystem | Add-Member -NotePropertyName deniedPaths `
    -NotePropertyValue @((Join-Path $data 'denied'), (Join-Path $data 'denied2'))
foreach ($capture in @($false, $true)) {
    $name = if ($capture) { 'legacy-capture' } else { 'legacy-allowed' }
    if ($capture) {
        $legacy.processContainer | Add-Member -NotePropertyName captureDenials `
            -NotePropertyValue ([pscustomobject]@{ mode = 'block' })
    }
    Write-FixtureJson $legacy "$name.json"
    $cases += [ordered]@{
        name = "$name preserves caller-authored restrictions without new reports"
        config = "$name.json"
        experimental = $false
        expectReport = $false
        expectedExitCode = 0
        stdoutPattern = '(?m)^MXC_POLICY_FIXTURE_OK\r?$'
        stdoutMatchCount = 1
        expectedProcessCreations = 1
    }
}
Write-FixtureJson $cases 'cases.json'
Write-Output "Policy authoring input: $Directory\agent-policy.json"
Write-Output "Prepared-host case manifest: $Directory\cases.json"
Write-Output 'No policy was deployed. Use an isolated VM, capture its existing policy state, and restore it afterward.'
