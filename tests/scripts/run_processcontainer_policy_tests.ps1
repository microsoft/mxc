# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinDir,
    [string]$FinalPathProbe
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$WxcExec = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
$UiProbe = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-ui-probe.exe'
if (-not (Test-Path -LiteralPath $UiProbe -PathType Leaf)) {
    throw "Native HANDLES validation requires the published artifact: $UiProbe"
}
$ScratchRoot = Join-Path $env:TEMP ("mxc-native-policy-" + [guid]::NewGuid().ToString('N'))
$FixtureDirectories = @(
    '', 'rw', 'rw\blocked', 'rw\child', 'rw\conflict', 'rw\denied-long-directory',
    'rw\granted-long-directory', 'ro', 'unlisted', 'rw\denied-parent',
    'rw\denied-parent\child', 'rw\denied-parent\sibling', 'launcher'
)
foreach ($directory in $FixtureDirectories) {
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot $directory) -Force | Out-Null
}
foreach ($directory in @('rw\blocked', 'rw\conflict', 'rw\denied-long-directory', 'rw\granted-long-directory', 'ro', 'unlisted', 'rw\denied-parent\sibling')) {
    Set-Content -LiteralPath (Join-Path $ScratchRoot "$directory\seed.txt") -Value 'seed' -NoNewline
}
$WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $WindowsPowerShell -PathType Leaf)) {
    throw 'Native policy validation requires Windows PowerShell 5.1.'
}
$ProbeScript = Join-Path $PSScriptRoot 'lib\processcontainer_policy_probe.ps1'
$Passed = 0
Write-Host "Native policy artifacts: $ScratchRoot"
$probeResult = Invoke-NativeProcessContainer -WxcExec $WxcExec -ScratchRoot $ScratchRoot `
    -Name 'host-probe' -Arguments @('--probe')
if ($probeResult.ExitCode -ne 0) { throw "Native host probe failed: $($probeResult.Stderr)" }
$facts = ($probeResult.Stdout | ConvertFrom-Json).probes
if (-not $facts.baseContainerApiPresent) { throw 'Native policy validation requires PSEC.' }

function New-PolicyRequest {
    param([string]$Mode, [string[]]$ProbeArguments = @())
    $command = @($WindowsPowerShell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $ProbeScript, $Mode, $ScratchRoot) + $ProbeArguments
    @{
        version = '1.0.0'
        containment = 'processcontainer'
        process = @{
            commandLine = (($command | ForEach-Object { '"' + $_ + '"' }) -join ' ')
            cwd = (Join-Path $ScratchRoot 'rw')
            timeout = 30000
        }
        filesystem = @{
            readwritePaths = @((Join-Path $ScratchRoot 'rw'))
            readonlyPaths = @($env:SystemRoot, (Split-Path $ProbeScript -Parent))
        }
        ui = @{ disable = $false }
        processContainer = @{ ui = @{ isolation = 'container' } }
    }
}

function Invoke-PolicyCase {
    param(
        [string]$Name,
        [hashtable]$Request,
        [scriptblock]$Observe,
        [switch]$Reject,
        [string]$RejectionMessage,
        [string]$ExpectedOutput = 'NATIVE_POLICY_OK',
        [string]$ExpectedOutputPattern,
        [int]$ExpectedExitCode = 0,
        [hashtable]$Environment = @{},
        [string]$WorkingDirectory,
        [switch]$Timeout,
        [switch]$ObserveSecurity,
        [scriptblock]$ValidateResult,
        [switch]$PassThru
    )
    if ($ObserveSecurity) {
        if ($Reject -or $Observe) { throw 'Live SDDL observation requires its own coordinated workload.' }
        $securityReady = Join-Path $ScratchRoot "rw\$Name.security-ready"
        $securityRelease = Join-Path $ScratchRoot "rw\$Name.security-release"
        $Request.process.commandLine += ' -SecurityReady "' + $securityReady + '" -SecurityRelease "' + $securityRelease + '"'
    }
    if ($Reject) {
        if ([string]::IsNullOrWhiteSpace($RejectionMessage)) {
            throw "$Name requires the specific native rejection message."
        }
        $sentinel = Join-Path $ScratchRoot "rw\$Name.executed"
        $Request.process.commandLine = 'cmd.exe /d /s /c "echo executed > "' + $sentinel + '""'
    }
    $path = Join-Path $ScratchRoot "$Name.json"
    $Request | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path
    $security = Get-NativeFixtureSecuritySnapshot -Paths @(
        $FixtureDirectories | ForEach-Object { Join-Path $ScratchRoot $_ })
    if ($ObserveSecurity) {
        $Observe = {
            param($Process)
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $securityReady)) {
                if ($Process.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw "$Name did not become ready for live SDDL observation." }
                Start-Sleep -Milliseconds 20
            }
            try {
                if ($Process.HasExited) { throw "$Name exited before live SDDL observation." }
                foreach ($entry in $security.GetEnumerator()) {
                    if ((Get-Acl -LiteralPath $entry.Key).Sddl -cne $entry.Value.Sddl) {
                        throw "$Name changed fixture security while the workload was alive: $($entry.Key)"
                    }
                }
                Write-Host "OBSERVED: $Name SDDL unchanged while workload is alive"
            } finally { Set-Content -LiteralPath $securityRelease -Value 'release' }
        }
    }
    $verified = $true
    try {
        $elapsed = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-NativeProcessContainer -WxcExec $WxcExec -ScratchRoot $ScratchRoot `
            -Name $Name -Arguments @($path) -Observe $Observe -Environment $Environment -WorkingDirectory $WorkingDirectory
        $elapsed.Stop()
        if (-not $Reject -and $result.Log -notmatch '"tier":"base-container"') {
            throw "$Name did not report native ProcessContainer execution."
        }
        if ($Reject) {
            if ($result.ExitCode -eq 0 -or -not $result.Stderr.Contains($RejectionMessage) -or
                $result.Log -match '"event":"mxc.ProcessExited"' -or
                (Test-Path -LiteralPath $sentinel)) {
                throw "$Name was not rejected before execution: $($result.Stderr)"
            }
        } elseif ($Timeout) {
            if ($result.ExitCode -eq 0 -or $elapsed.ElapsedMilliseconds -lt $Request.process.timeout -or
                $elapsed.Elapsed.TotalSeconds -ge 30 -or
                $result.Stdout -notmatch 'NATIVE_TIMEOUT_PARENT_STARTED' -or
                "$($result.Stdout)`n$($result.Stderr)" -notmatch '(?i)timed out|execution.*timeout') {
                throw "$Name did not demonstrate bounded timeout teardown: exit=$($result.ExitCode); elapsed=$($elapsed.Elapsed); stderr=$($result.Stderr)"
            }
        } else {
            $outputMatches = if ($ExpectedOutputPattern) {
                $result.Stdout.Trim() -match $ExpectedOutputPattern
            } else { $result.Stdout.Trim() -ceq $ExpectedOutput }
            if ($result.ExitCode -ne $ExpectedExitCode -or -not $outputMatches) {
                throw "$Name failed: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr). See $ScratchRoot."
            }
        }
        if ($ValidateResult) {
            $verified = & $ValidateResult $result
            if ($verified -isnot [bool]) { throw "$Name result validator must return a Boolean." }
        }
    } finally {
        Assert-NativeFixtureSecurity -Name $Name -Snapshot $security
    }
    if ($verified) {
        $script:Passed++
        Write-Host "PASSED: $Name"
    } else {
        Write-Host "SKIPPED: $Name"
    }
    if ($PassThru) { return $result }
}

$filesystemArguments = @("$([int]$facts.baseContainerSupportsDenyPaths)")
Add-Type @'
using System.Runtime.InteropServices;
using System.Text;
public static class MxcPolicyShortPath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint GetShortPathNameW(string path, StringBuilder output, uint length);
}
'@
$longPath = Join-Path $ScratchRoot 'unlisted\seed.txt'
$shortPath = [Text.StringBuilder]::new(1024)
if (-not [MxcPolicyShortPath]::GetShortPathNameW($longPath, $shortPath, $shortPath.Capacity)) {
    throw 'Could not query the host short-path alias.'
}
if ($shortPath.ToString() -ine $longPath) {
    if ((Get-Content -LiteralPath $shortPath.ToString() -Raw) -cne 'seed') { throw 'Host short-path control failed.' }
    $filesystemArguments += $shortPath.ToString()
} else {
    Write-Host 'SKIPPED (volume has no short alias): 8.3 filesystem alias'
}
$grantedLong = Join-Path $ScratchRoot 'rw\granted-long-directory\seed.txt'
$shortGranted = [Text.StringBuilder]::new(1024)
if (-not [MxcPolicyShortPath]::GetShortPathNameW($grantedLong, $shortGranted, $shortGranted.Capacity)) { throw 'Granted short-path query failed.' }
$grantedShortDirectory = Split-Path (Split-Path $shortGranted.ToString() -Parent) -Leaf
$hasGrantedAlias = $grantedShortDirectory -ine 'granted-long-directory'
if ($hasGrantedAlias) {
    if ((Get-Content -LiteralPath $shortGranted.ToString() -Raw) -cne 'seed') { throw 'Host granted-short-path control failed.' }
    $filesystemArguments += @('-GrantedShortAlias', $shortGranted.ToString())
} else {
    Write-Host 'SKIPPED (volume has no granted-directory short alias): contained 8.3 grant/deny differential'
}
if ($facts.baseContainerSupportsDenyPaths) {
    $deniedLong = Join-Path $ScratchRoot 'rw\denied-long-directory\seed.txt'
    $shortDenied = [Text.StringBuilder]::new(1024)
    if (-not [MxcPolicyShortPath]::GetShortPathNameW($deniedLong, $shortDenied, $shortDenied.Capacity)) { throw 'Denied short-path query failed.' }
    $deniedShortDirectory = Split-Path (Split-Path $shortDenied.ToString() -Parent) -Leaf
    if ($deniedShortDirectory -ine 'denied-long-directory' -and $hasGrantedAlias) {
        if ((Get-Content -LiteralPath $shortDenied.ToString() -Raw) -cne 'seed') { throw 'Host denied-short-path control failed.' }
        $filesystemArguments += $shortDenied.ToString()
    } else {
        Write-Host 'SKIPPED (paired directory aliases unavailable): 8.3 explicit-deny alias'
    }
} else {
    $unsupported = New-PolicyRequest -Mode 'denial'
    $unsupported.filesystem.deniedPaths = @((Join-Path $ScratchRoot 'rw\blocked'))
    Invoke-PolicyCase -Name 'unsupported-denied-paths-rejected-before-execution' -Request $unsupported -Reject `
        -RejectionMessage 'Windows ProcessContainer requires native PSEC denied-path support for this request'
}
function New-FilesystemPolicyRequest {
    $request = New-PolicyRequest -Mode 'filesystem' -ProbeArguments $filesystemArguments
    $request.filesystem.readonlyPaths += Join-Path $ScratchRoot 'ro'
    $request.filesystem.readwritePaths += Join-Path $ScratchRoot 'rw\conflict'
    if ($facts.baseContainerSupportsDenyPaths) {
        $request.filesystem.deniedPaths = @('rw\blocked', 'rw\conflict', 'rw\denied-long-directory') |
            ForEach-Object { Join-Path $ScratchRoot $_ }
    }
    return $request
}
$filesystem = New-FilesystemPolicyRequest
Invoke-PolicyCase -Name 'filesystem-grants-denials-and-aliases' -Request $filesystem -ObserveSecurity
if ((Get-Content -LiteralPath (Join-Path $ScratchRoot 'ro\seed.txt') -Raw) -cne 'seed') {
    throw 'The read-only host seed changed.'
}
$fallback = New-FilesystemPolicyRequest
$fallback.fallback = @{ allowDaclMutation = $true }
Invoke-PolicyCase -Name 'fallback-consent-does-not-mutate-host-sddl' -Request $fallback -ObserveSecurity
$learning = New-FilesystemPolicyRequest
$learning.processContainer.learningMode = $true
Invoke-PolicyCase -Name 'native-learning-mode-preserves-enforcement' -Request $learning
if ($facts.baseContainerSupportsDenyPaths) {
    $precedenceControl = New-PolicyRequest -Mode 'precedence' -ProbeArguments @('0')
    $precedenceControl.filesystem.readwritePaths += Join-Path $ScratchRoot 'rw\denied-parent\child'
    Invoke-PolicyCase -Name 'parent-without-deny-allows-sibling' -Request $precedenceControl
    $precedence = New-PolicyRequest -Mode 'precedence' -ProbeArguments @('1')
    $precedence.filesystem.readwritePaths += Join-Path $ScratchRoot 'rw\denied-parent\child'
    $precedence.filesystem.deniedPaths = @((Join-Path $ScratchRoot 'rw\denied-parent'))
    Invoke-PolicyCase -Name 'denied-parent-preserves-explicit-child-grant' -Request $precedence
}

foreach ($code in @(0, 1, 42)) {
    Invoke-PolicyCase -Name "exit-code-$code" -Request (New-PolicyRequest -Mode 'exit' -ProbeArguments @("$code")) -ExpectedExitCode $code
}
function ConvertTo-ProbeArgument {
    param([hashtable]$Value)
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress)))
}
$launcherVariable = "MXC_LAUNCHER_ONLY_$([guid]::NewGuid().ToString('N'))"
$customValues = @{ MXC_SPACES = 'one two'; MXC_EQUALS = 'one=two'; MXC_EMPTY = '' }
$environmentSpec = @{
    environment = $customValues + @{ SYSTEMROOT = $env:SystemRoot }
    redirected = @{ LOCALAPPDATA = $env:LOCALAPPDATA }
    absent = @($launcherVariable, 'PATH')
    cwd = (Join-Path $ScratchRoot 'rw')
}
$explicit = New-PolicyRequest -Mode 'plumbing' -ProbeArguments @((ConvertTo-ProbeArgument $environmentSpec))
$explicit.process.env = @("SYSTEMROOT=$env:SystemRoot", "LOCALAPPDATA=$env:LOCALAPPDATA") +
    @($customValues.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
Invoke-PolicyCase -Name 'explicit-environment-values-and-native-profile' -Request $explicit `
    -Environment @{ $launcherVariable = 'must-not-leak' } -WorkingDirectory (Join-Path $ScratchRoot 'launcher')
$inheritedSpec = @{
    environment = @{ MXC_SPACES = 'one two'; PATH = 'native-policy-custom-path' }
    present = @('SYSTEMROOT', 'LOCALAPPDATA')
    cwd = (Join-Path $ScratchRoot 'rw')
}
$inherited = New-PolicyRequest -Mode 'plumbing' -ProbeArguments @((ConvertTo-ProbeArgument $inheritedSpec))
$inherited.process.env = @('MXC_SPACES=one two', 'PATH=native-policy-custom-path')
$inherited.process.inheritDefaultEnv = $true
Invoke-PolicyCase -Name 'inherited-environment-layers-defaults' -Request $inherited
foreach ($explicitCwd in @($true, $false)) {
    $expectedCwd = Join-Path $ScratchRoot $(if ($explicitCwd) { 'rw\child' } else { 'rw' })
    $cwdSpec = @{ cwd = $expectedCwd }
    $cwdRequest = New-PolicyRequest -Mode 'plumbing' -ProbeArguments @((ConvertTo-ProbeArgument $cwdSpec))
    if ($explicitCwd) { $cwdRequest.process.cwd = $expectedCwd } else { $cwdRequest.process.Remove('cwd') }
    Invoke-PolicyCase -Name "cwd-explicit-$explicitCwd-not-launcher" -Request $cwdRequest `
        -WorkingDirectory (Join-Path $ScratchRoot 'launcher')
}
$intent = New-PolicyRequest -Mode 'allowed'
$intent.containment = 'process'
Invoke-PolicyCase -Name 'process-intent-resolves-native-base-container' -Request $intent
$childName = "mxc-grandchild-$([guid]::NewGuid().ToString('N'))"
$childImage = Join-Path $ScratchRoot "rw\$childName.exe"
Copy-Item -LiteralPath $WindowsPowerShell -Destination $childImage
Copy-Item -LiteralPath "$WindowsPowerShell.config" -Destination "$childImage.config"
$readyFile = Join-Path $ScratchRoot 'rw\grandchild-ready'
$timeoutSpec = @{ powershell = $childImage; ready = $readyFile }
$timeoutRequest = New-PolicyRequest -Mode 'timeout-parent' -ProbeArguments @((ConvertTo-ProbeArgument $timeoutSpec))
# Two Windows PowerShell cold starts take over 5 seconds on some arm64 hosts.
# The grandchild must be ready before the timeout fires.
$timeoutRequest.process.timeout = 20000
$observeTree = {
    param($Process)
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $readyFile)) {
        if ($Process.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'Grandchild did not demonstrate readiness before timeout.' }
        Start-Sleep -Milliseconds 20
    }
    $childPid = [int](Get-Content -LiteralPath $readyFile -Raw)
    $child = Get-Process -Id $childPid -ErrorAction Stop
    try { if ($child.ProcessName -ne $childName) { throw 'Ready PID did not name the controlled grandchild.' } }
    finally { $child.Dispose() }
}
try {
    Invoke-PolicyCase -Name 'timeout-kills-ready-grandchild-tree' -Request $timeoutRequest -Timeout -Observe $observeTree
    $deadline = [DateTime]::UtcNow.AddSeconds(2)
    while (@(Get-Process -Name $childName -ErrorAction SilentlyContinue).Count -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 20
    }
    if (@(Get-Process -Name $childName -ErrorAction SilentlyContinue).Count) { throw 'Grandchild survived native timeout teardown.' }
} finally {
    foreach ($survivor in @(Get-Process -Name $childName -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $survivor.Id -Force
        $survivor.Dispose()
    }
}

$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot 'run_processcontainer_filesystem_enumerate_test.ps1') -BinDir $BinDir
if ($LASTEXITCODE -ne 0) { throw "Focused enumeration suite exited $LASTEXITCODE." }

$rejected = New-PolicyRequest -Mode 'filesystem' -ProbeArguments @('0')
$rejected.processContainer.leastPrivilege = $true
Invoke-PolicyCase -Name 'unsupported-lpac-rejected-before-execution' -Request $rejected -Reject `
    -RejectionMessage 'Windows ProcessContainer cannot enforce the requested LPAC or legacy network.proxy policy'

$hostPrivilegeJson = & $WindowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ProbeScript 'privileges-host' $ScratchRoot
if ($LASTEXITCODE -ne 0) { throw 'Host token privilege control failed.' }
$hostPrivileges = @($hostPrivilegeJson | ConvertFrom-Json)
if ($hostPrivileges.Count) {
    Write-Host "Host token control contains: $($hostPrivileges -join ', ')"
    Invoke-PolicyCase -Name 'restricted-token-privileges' -Request (New-PolicyRequest -Mode 'privileges')
} else {
    Write-Host 'SKIPPED (host token has none of the tested privileges): privileged-token removal'
}
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class MxcPolicyAtoms {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern ushort GlobalAddAtomW(string value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern ushort GlobalFindAtomW(string value);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern ushort GlobalDeleteAtom(ushort value);
    [DllImport("kernel32.dll")] public static extern void SetLastError(uint value);
}
public static class MxcPolicyWindow {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateWindowExW(
        uint extendedStyle, string className, string title, uint style,
        int x, int y, int width, int height, IntPtr parent,
        IntPtr menu, IntPtr instance, IntPtr parameter);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyWindow(IntPtr window);
}
public static class MxcPolicyClipboardFormats {
    [DllImport("user32.dll", SetLastError = true)] private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseClipboard();
    [DllImport("user32.dll", SetLastError = true)] private static extern uint EnumClipboardFormats(uint format);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool EmptyClipboard();
    [DllImport("kernel32.dll")] private static extern void SetLastError(uint error);
    private static void Open() {
        for (int i = 0; i < 100; i++) {
            if (OpenClipboard(IntPtr.Zero)) return;
            System.Threading.Thread.Sleep(20);
        }
        throw new Win32Exception(Marshal.GetLastWin32Error(), "Clipboard unavailable");
    }
    private static void Close() {
        if (!CloseClipboard()) throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseClipboard failed");
    }
    public static bool HasNonTextFormats() {
        Open();
        try {
            uint format = 0;
            while (true) {
                SetLastError(0);
                format = EnumClipboardFormats(format);
                if (format == 0) {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 0) throw new Win32Exception(error);
                    return false;
                }
                if (format != 1 && format != 7 && format != 13 && format != 16) return true;
            }
        } finally { Close(); }
    }
    public static void Clear() {
        Open();
        try { if (!EmptyClipboard()) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        finally { Close(); }
    }
}
public static class MxcPolicySettings {
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", SetLastError = true)]
    private static extern bool GetSetting(uint action, uint parameter, ref int value, uint flags);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", SetLastError = true)]
    private static extern bool SetSetting(uint action, uint parameter, IntPtr value, uint flags);
    public static int GetMouseSpeed() {
        int value = 0;
        if (!GetSetting(0x70, 0, ref value, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return value;
    }
    public static void SetMouseSpeed(int value) {
        if (!SetSetting(0x71, 0, (IntPtr)value, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
function Remove-PolicyHostAtom {
    param([ushort]$Atom, [string]$Name)
    # Shared-namespace PSEC can retain one additional reference to our fixture.
    for ($reference = 0; $reference -lt 2; $reference++) {
        $current = [MxcPolicyAtoms]::GlobalFindAtomW($Name)
        if (-not $current) { return }
        if ($current -ne $Atom) { throw 'Owned fixture atom identity changed before cleanup.' }
        [MxcPolicyAtoms]::SetLastError(0)
        [void][MxcPolicyAtoms]::GlobalDeleteAtom($current)
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($errorCode) { throw "Owned fixture atom cleanup failed: $errorCode" }
    }
    if ([MxcPolicyAtoms]::GlobalFindAtomW($Name)) { throw 'Owned fixture atom remained after guest teardown and cleanup.' }
}
function New-UiPolicyRequest {
    param([string[]]$Arguments)
    $request = New-PolicyRequest -Mode 'denial'
    $request.process.commandLine = (@($UiProbe) + $Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $request.filesystem.readonlyPaths += Split-Path $UiProbe -Parent
    return $request
}
function Invoke-HostUiControl {
    param([string]$Name, [string[]]$Arguments)
    $output = (& $UiProbe @Arguments 2> (Join-Path $ScratchRoot "$Name.stderr.txt") | Out-String).Trim()
    $code = $LASTEXITCODE
    Set-Content -LiteralPath (Join-Path $ScratchRoot "$Name.stdout.txt") -Value $output
    return @{ ExitCode = $code; Stdout = $output }
}
$script:UiGrantable = @{}
function Invoke-UiPolicyMatrixCase {
    param(
        [string]$Name,
        [string]$Tag,
        [hashtable]$Ui = @{},
        [hashtable]$ProcessContainerUi = @{},
        [string[]]$ProbeArguments = @(),
        [bool]$Allowed = $false,
        [switch]$Baseline,
        [switch]$RequireClipboardRoundTrip
    )
    if (-not $Baseline -and $Allowed -and -not $script:UiGrantable[$Tag]) {
        Write-Host "SKIPPED: $Name (the fully permissive contained control could not perform $Tag)"
        return
    }
    $request = New-UiPolicyRequest -Arguments (@($Tag) + $ProbeArguments)
    $request.ui = @{ disable = $false; clipboard = 'all'; injection = $true }
    $request.processContainer.ui = @{
        isolation = 'desktop'; desktopSystemControl = $true; systemSettings = 'all'; ime = $true
    }
    foreach ($key in $Ui.Keys) { $request.ui[$key] = $Ui[$key] }
    foreach ($key in $ProcessContainerUi.Keys) { $request.processContainer.ui[$key] = $ProcessContainerUi[$key] }
    $validate = {
        param($Result)
        $match = [regex]::Matches($Result.Stdout, "(?m)^$Tag=(PASS|FAIL|INCONCLUSIVE)\r?$")
        if ($match.Count -ne 1) { throw "$Name did not report exactly one $Tag verdict." }
        $verdict = $match[0].Groups[1].Value
        if ($verdict -eq 'INCONCLUSIVE') {
            if (-not $Baseline -and $Tag -ne 'INJECTION' -and $script:UiGrantable[$Tag]) {
                throw "$Name could not exercise a capability its contained control demonstrated: $($Result.Stdout)"
            }
            if ($Baseline) { $script:UiGrantable[$Tag] = $false }
            Write-Host "$Name could not exercise its UI operation: $($Result.Stdout.Trim())"
            return $false
        }
        if ($Baseline) {
            $script:UiGrantable[$Tag] = $verdict -eq 'FAIL'
            if (-not $script:UiGrantable[$Tag]) {
                Write-Host "$Name was denied even with a fully permissive contained policy."
                return $false
            }
        } else {
            $expected = if ($Allowed) { 'FAIL' } else { 'PASS' }
            if ($verdict -cne $expected) { throw "$Name expected $Tag=$expected, got: $($Result.Stdout)" }
        }
        if ($RequireClipboardRoundTrip -and $Result.Stdout -notmatch 'returned the seeded text') {
            if ($Result.Stdout -match 'in-process seed failed') {
                if ($Baseline) { $script:UiGrantable[$Tag] = $false }
                Write-Host "$Name could not seed the contained clipboard: $($Result.Stdout.Trim())"
                return $false
            }
            throw "$Name did not read back the text seeded in the contained clipboard: $($Result.Stdout)"
        }
        return $true
    }
    Invoke-PolicyCase -Name $Name -Request $request `
        -ExpectedOutputPattern "(?m)^$Tag=(PASS|FAIL|INCONCLUSIVE)\r?$" -ValidateResult $validate
}
foreach ($disabled in @($false, $true)) {
    $request = New-UiPolicyRequest -Arguments @('WIN32K', '--win32k-query=true')
    $request.ui.disable = $disabled
    $expected = if ($disabled) { 'WIN32K=PASS' } else { 'WIN32K=FAIL' }
    Invoke-PolicyCase -Name "win32k-mitigation-$disabled" -Request $request -ExpectedOutput $expected
}
$window = [MxcPolicyWindow]::CreateWindowExW(
    0, 'STATIC', ("MxcHandles_" + [guid]::NewGuid().ToString('N')), 0,
    0, 0, 0, 0, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
if ($window -eq [IntPtr]::Zero) { throw 'Could not create the host HANDLES control window.' }
try {
    $handleArguments = @('HANDLES', "--handle-hwnd=$($window.ToInt64())", "--handle-pid=$PID")
    $hostControl = (& $UiProbe @handleArguments `
        2> (Join-Path $ScratchRoot 'handles-host-control.stderr.txt') | Out-String).Trim()
    $hostExit = $LASTEXITCODE
    Set-Content -LiteralPath (Join-Path $ScratchRoot 'handles-host-control.stdout.txt') -Value $hostControl
    if ($hostExit -ne 0 -or $hostControl -cne 'HANDLES=FAIL') {
        throw "Uncontained HANDLES control could not resolve its host window: exit=$hostExit; output=$hostControl"
    }
    $Passed++
    Write-Host 'PASSED: handles-host-positive-control (window owner resolved)'
    $desktopHandles = New-UiPolicyRequest -Arguments $handleArguments
    $desktopHandles.processContainer.ui.isolation = 'desktop'
    $observation = Invoke-PolicyCase -Name 'handles-desktop-observation' -Request $desktopHandles `
        -ExpectedOutputPattern '^HANDLES=(PASS|FAIL)$' -PassThru
    $desktopResolvesOwner = $observation.Stdout.Trim() -ceq 'HANDLES=FAIL'
    Write-Host "OBSERVED: isolation=desktop resolves host HWND owner=$desktopResolvesOwner"
    if (-not $desktopResolvesOwner) {
        Write-Host 'SKIPPED (PSEC blocks host handles even with desktop isolation): HANDLES allowed-direction differential'
    }
    foreach ($isolation in @('container', 'handles', 'atoms', 'desktop')) {
        $handles = New-UiPolicyRequest -Arguments $handleArguments
        $handles.processContainer.ui.isolation = $isolation
        $blocked = $isolation -in @('container', 'handles') -or -not $desktopResolvesOwner
        $expected = if ($blocked) { 'HANDLES=PASS' } else { 'HANDLES=FAIL' }
        Invoke-PolicyCase -Name "native-handles-$isolation" -Request $handles -ExpectedOutput $expected
    }

    $clipboardUsable = $false
    try {
        if ([MxcPolicyClipboardFormats]::HasNonTextFormats()) {
            Write-Host 'SKIPPED (clipboard contains non-text formats; left unchanged): READCLIPBOARD and WRITECLIPBOARD'
        } else {
            $clipboardText = [string](Get-Clipboard -Raw -ErrorAction Stop)
            $clipboardUsable = $true
        }
    } catch [ComponentModel.Win32Exception] {
        Write-Host "SKIPPED (cannot safely save/restore clipboard): READCLIPBOARD and WRITECLIPBOARD; $($_.Exception.Message)"
    }
    if ($clipboardUsable) {
        try {
            $tokenA, $tokenB = "MxcClipboardHost_$([guid]::NewGuid().ToString('N'))", "MxcClipboardGuest_$([guid]::NewGuid().ToString('N'))"
            $writeControl = Invoke-HostUiControl -Name 'writeclipboard-host-control' -Arguments @('WRITECLIPBOARD', "--clipboard-token=$tokenA")
            if ($writeControl.ExitCode -eq 0 -and $writeControl.Stdout -ceq 'WRITECLIPBOARD=FAIL' -and
                [string](Get-Clipboard -Raw) -ceq $tokenA) {
                $Passed++
                Write-Host 'PASSED: writeclipboard-host-positive-control'
                $write = New-UiPolicyRequest -Arguments @('WRITECLIPBOARD', "--clipboard-token=$tokenB")
                $write.ui.clipboard = 'read'
                Invoke-PolicyCase -Name 'writeclipboard-does-not-change-host' -Request $write `
                    -ExpectedOutputPattern '^WRITECLIPBOARD=(PASS|FAIL)$'
                if ([string](Get-Clipboard -Raw) -ceq $tokenB) { throw 'Contained clipboard write reached the host clipboard.' }
            } else {
                Write-Host 'SKIPPED (host clipboard write/read control unavailable): WRITECLIPBOARD'
            }
            Set-Clipboard -Value $tokenA
            $readControl = Invoke-HostUiControl -Name 'readclipboard-host-control' -Arguments @('READCLIPBOARD', "--clipboard-token=$tokenA")
            if ($readControl.ExitCode -eq 0 -and $readControl.Stdout -ceq 'READCLIPBOARD=FAIL' -and
                [string](Get-Clipboard -Raw) -ceq $tokenA) {
                $Passed++
                Write-Host 'PASSED: readclipboard-host-positive-control'
                $read = New-UiPolicyRequest -Arguments @('READCLIPBOARD', "--clipboard-token=$tokenA")
                $read.ui.clipboard = 'write'
                Invoke-PolicyCase -Name 'readclipboard-cannot-read-host-token' -Request $read -ExpectedOutput 'READCLIPBOARD=PASS'
            } else {
                Write-Host 'SKIPPED (host clipboard token cannot be read): READCLIPBOARD'
            }
            Invoke-UiPolicyMatrixCase -Name 'clipboard-read-permissive-control' -Tag 'READCLIPBOARD' `
                -Baseline -RequireClipboardRoundTrip
            Invoke-UiPolicyMatrixCase -Name 'clipboard-write-permissive-control' -Tag 'WRITECLIPBOARD' -Baseline
            foreach ($clipboard in @('all', 'read', 'write', 'none')) {
                Invoke-UiPolicyMatrixCase -Name "clipboard-$clipboard-read" -Tag 'READCLIPBOARD' `
                    -Ui @{ clipboard = $clipboard } -Allowed:($clipboard -in @('all', 'read')) `
                    -RequireClipboardRoundTrip:($clipboard -eq 'all')
                Invoke-UiPolicyMatrixCase -Name "clipboard-$clipboard-write" -Tag 'WRITECLIPBOARD' `
                    -Ui @{ clipboard = $clipboard } -Allowed:($clipboard -in @('all', 'write'))
            }
        } finally {
            if ($clipboardText.Length) { Set-Clipboard -Value $clipboardText }
            else { [MxcPolicyClipboardFormats]::Clear() }
            if ([string](Get-Clipboard -Raw) -cne $clipboardText) { throw 'Original clipboard text was not restored.' }
        }
    }
} finally {
    if (-not [MxcPolicyWindow]::DestroyWindow($window)) {
        throw 'Could not destroy the host HANDLES control window.'
    }
}

foreach ($tag in @('DESKTOP', 'SYSTEMPARAMETERS')) {
    $arguments = @($tag)
    if ($tag -eq 'SYSTEMPARAMETERS') {
        $mouseSpeed = [MxcPolicySettings]::GetMouseSpeed()
        $arguments += "--mouse-speed=$mouseSpeed"
    }
    try {
        $control = Invoke-HostUiControl -Name "$tag-host-control" -Arguments $arguments
        if ($control.ExitCode -eq 0 -and $control.Stdout -ceq "$tag=FAIL") {
            $Passed++
            Write-Host "PASSED: $tag-host-positive-control"
            Invoke-PolicyCase -Name "$tag-native-blocked" -Request (New-UiPolicyRequest -Arguments $arguments) -ExpectedOutput "$tag=PASS"
        } else {
            Write-Host "SKIPPED (uncontained $tag control did not succeed): native blocked direction"
        }
    } finally {
        if ($tag -eq 'SYSTEMPARAMETERS' -and [MxcPolicySettings]::GetMouseSpeed() -ne $mouseSpeed) {
            [MxcPolicySettings]::SetMouseSpeed($mouseSpeed)
            throw 'SYSTEMPARAMETERS probe changed host mouse speed; original value restored.'
        }
    }
}

foreach ($tag in @('SYSTEMPARAMETERS', 'DISPLAYSETTINGS')) {
    $arguments = if ($tag -eq 'SYSTEMPARAMETERS') { @("--mouse-speed=$mouseSpeed") } else { @() }
    try {
        Invoke-UiPolicyMatrixCase -Name "$tag-permissive-control" -Tag $tag -ProbeArguments $arguments -Baseline
        foreach ($settings in @('all', 'parameters', 'display', 'none', 'not-a-settings-level')) {
            $allowed = $settings -eq 'all' -or
                ($tag -eq 'SYSTEMPARAMETERS' -and $settings -eq 'parameters') -or
                ($tag -eq 'DISPLAYSETTINGS' -and $settings -eq 'display')
            Invoke-UiPolicyMatrixCase -Name "$tag-settings-$settings" -Tag $tag -ProbeArguments $arguments `
                -ProcessContainerUi @{ systemSettings = $settings } -Allowed:$allowed
        }
    } finally {
        if ($tag -eq 'SYSTEMPARAMETERS' -and [MxcPolicySettings]::GetMouseSpeed() -ne $mouseSpeed) {
            [MxcPolicySettings]::SetMouseSpeed($mouseSpeed)
            throw 'The UI settings matrix changed host mouse speed; original value restored.'
        }
    }
}
Invoke-UiPolicyMatrixCase -Name 'desktop-permissive-control' -Tag 'DESKTOP' -Baseline
Invoke-UiPolicyMatrixCase -Name 'injection-permissive-control' -Tag 'INJECTION' -Baseline
foreach ($allowed in @($false, $true)) {
    Invoke-UiPolicyMatrixCase -Name "desktop-control-$allowed" -Tag 'DESKTOP' `
        -ProcessContainerUi @{ desktopSystemControl = $allowed } -Allowed:$allowed
    Invoke-UiPolicyMatrixCase -Name "input-injection-$allowed" -Tag 'INJECTION' `
        -Ui @{ injection = $allowed } -Allowed:$allowed
}
$invalidIsolation = New-UiPolicyRequest -Arguments @('HANDLES')
$invalidIsolation.processContainer.ui.isolation = 'not-an-isolation-level'
Invoke-PolicyCase -Name 'unknown-ui-isolation-rejected-before-execution' -Request $invalidIsolation -Reject `
    -RejectionMessage 'isolation'
$disabledPermissive = New-UiPolicyRequest -Arguments @('WIN32K', '--win32k-query=true')
$disabledPermissive.ui = @{ disable = $true; clipboard = 'all'; injection = $true }
$disabledPermissive.processContainer.ui = @{
    isolation = 'desktop'; desktopSystemControl = $true; systemSettings = 'all'; ime = $true
}
Invoke-PolicyCase -Name 'disabled-ui-overrides-permissive-matrix' -Request $disabledPermissive `
    -ExpectedOutput 'WIN32K=PASS'
Write-Host 'SKIPPED: logoff execution and IME mutation have no safe functional probe in this matrix.'

foreach ($atomCase in @(
    @{ Isolation = 'container'; Disabled = $false },
    @{ Isolation = 'desktop'; Disabled = $false },
    @{ Isolation = 'handles'; Disabled = $false },
    @{ Isolation = 'atoms'; Disabled = $false },
    @{ Isolation = 'desktop'; Disabled = $true }
)) {
    $isolation = $atomCase.Isolation
    $suffix = [guid]::NewGuid().ToString('N')
    $hostName, $guestName = "MxcPolicyHost_$suffix", "MxcPolicyGuest_$suffix"
    $ready, $release = (Join-Path $ScratchRoot "rw\ready-$suffix"), (Join-Path $ScratchRoot "rw\release-$suffix")
    $hostAtom = [MxcPolicyAtoms]::GlobalAddAtomW($hostName)
    if (-not $hostAtom) { throw 'Host atom creation failed.' }
    try {
        if (-not [MxcPolicyAtoms]::GlobalFindAtomW($hostName)) { throw 'Host atom lookup control failed.' }
        $shared = -not $atomCase.Disabled -and $isolation -in @('desktop', 'handles')
        if ($atomCase.Disabled) {
            $request = New-UiPolicyRequest -Arguments @(
                'GLOBALATOMS', "--atom-host-name=$hostName", "--atom-guest-name=$guestName",
                "--atom-ready-file=$ready", "--atom-release-file=$release"
            )
            $request.ui.disable = $true
            $name, $expected = 'disabled-ui-overrides-desktop-atom-sharing', 'GLOBALATOMS_HOST_TO_GUEST=PASS'
        } else {
            $request = New-PolicyRequest -Mode 'atoms' -ProbeArguments @($hostName, $guestName, "$([int]$shared)", $ready, $release)
            $request.process.commandLine += ' -UiProbe "' + $UiProbe + '"'
            $request.filesystem.readonlyPaths += Split-Path $UiProbe -Parent
            $name, $expected = "bidirectional-global-atoms-$isolation", 'NATIVE_POLICY_OK'
        }
        $request.processContainer.ui.isolation = $isolation
        $observe = {
            param($Process)
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $ready)) {
                if ($Process.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'Guest atom probe did not become ready.' }
                Start-Sleep -Milliseconds 20
            }
            try {
                if ([bool][MxcPolicyAtoms]::GlobalFindAtomW($guestName) -ne $shared) {
                    throw 'Guest-to-host atom isolation mismatch.'
                }
            } finally {
                Set-Content -LiteralPath $release -Value 'release'
            }
        }
        Invoke-PolicyCase -Name $name -Request $request -Observe $observe -ExpectedOutput $expected
    } finally {
        Remove-PolicyHostAtom -Atom $hostAtom -Name $hostName
    }
}

if ($facts.nativeCaptureAvailable) {
    $capture = New-PolicyRequest -Mode 'denial'
    $capture.processContainer.captureDenials = @{ outputPath = (Join-Path $ScratchRoot 'capture.json') }
    $captureResult = Invoke-PolicyCase -Name 'native-denial-capture' -Request $capture -PassThru
    $documents = @(Get-ChildItem -LiteralPath $ScratchRoot -Filter 'capture.*.json' |
        Where-Object Name -NotLike '*.verbose.json')
    if ($documents.Count -ne 1) { throw 'Expected one native capture document.' }
    $document = Get-Content -LiteralPath $documents[0].FullName -Raw | ConvertFrom-Json
    if (-not @($document.denials | Where-Object resource -Like '*unlisted*').Count) {
        throw 'Native capture did not record the denied workload access.'
    }
    $pointer = @($captureResult.Stderr -split "`r?`n" | Where-Object { $_ -match '^\{"type":"captureDenials"' } |
        ForEach-Object { $_ | ConvertFrom-Json })
    if ($pointer.Count -ne 1 -or $pointer[0].outputPath -cne $documents[0].FullName) {
        throw 'Capture stderr did not name the stamped output found on disk.'
    }
    $second = Invoke-PolicyCase -Name 'same-explicit-capture-path-is-unique' -Request $capture -PassThru
    $secondPointer = @($second.Stderr -split "`r?`n" | Where-Object { $_ -match '^\{"type":"captureDenials"' } |
        ForEach-Object { $_ | ConvertFrom-Json })
    if ($secondPointer.Count -ne 1 -or $secondPointer[0].outputPath -ceq $pointer[0].outputPath -or
        (Split-Path $secondPointer[0].outputPath -Parent) -cne $ScratchRoot -or
        -not (Test-Path -LiteralPath $secondPointer[0].outputPath -PathType Leaf)) { throw 'Explicit capture path did not produce distinct stamped siblings.' }
    $learningCapture = New-FilesystemPolicyRequest
    $learningCapture.processContainer.learningMode = $true
    $learningCapture.processContainer.captureDenials = @{ outputPath = (Join-Path $ScratchRoot 'learning-capture.json') }
    Invoke-PolicyCase -Name 'learning-mode-with-native-capture-enforces-policy' -Request $learningCapture
    $allowCapture = New-PolicyRequest -Mode 'allowed'
    $allowCapture.processContainer.captureDenials = @{ mode = 'allow'; outputPath = (Join-Path $ScratchRoot 'allow-capture.json') }
    $allowResult = Invoke-PolicyCase -Name 'permissive-capture-emits-security-warning' -Request $allowCapture -PassThru
    if ("$($allowResult.Stderr)`n$($allowResult.Log)" -notmatch 'SECURITY WARNING.*permissiveLearningMode') {
        throw 'Permissive capture did not emit the security warning end to end.'
    }
} else {
    $capture = New-PolicyRequest -Mode 'denial'
    $capture.processContainer.captureDenials = @{ outputPath = (Join-Path $ScratchRoot 'capture.json') }
    Invoke-PolicyCase -Name 'unsupported-native-capture-rejected-before-execution' -Request $capture -Reject `
        -RejectionMessage 'Windows ProcessContainer requires native Learning Mode capture support for this request'
}
$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot 'run_processcontainer_contract_tests.ps1') -BinDir $BinDir
if ($LASTEXITCODE -ne 0) { throw "Native CLI contract suite exited $LASTEXITCODE." }
$regression = Join-Path (Split-Path -Parent $PSScriptRoot) 'regression_tests\test_cases\Invoke-Issue694-GetFinalPathNameByHandle.ps1'
$global:LASTEXITCODE = 0
& $regression -WxcExec $WxcExec -WorkDirectory (Join-Path $ScratchRoot 'issue-694') -ProbeExe $FinalPathProbe
if ($LASTEXITCODE -ne 0) { throw "Native final-path regression exited $LASTEXITCODE." }
Write-Host "PASSED: all $Passed native ProcessContainer policy cases"
