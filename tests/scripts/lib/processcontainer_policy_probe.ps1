# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 5.1

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory, Position = 0)][string]$Mode,
    [Parameter(Mandatory, Position = 1)][string]$Root,
    [Parameter(Position = 2, ValueFromRemainingArguments = $true)][string[]]$ProbeArguments,
    [string]$SecurityReady,
    [string]$SecurityRelease,
    [string]$GrantedShortAlias,
    [string]$UiProbe
)

$ErrorActionPreference = 'Stop'
function Assert-Probe {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Blocked {
    param([scriptblock]$Operation)
    try { & $Operation }
    catch {
        $failure = $_.Exception
        while ($failure) {
            if ($failure -is [UnauthorizedAccessException] -or
                ($failure -is [IO.IOException] -and $failure.HResult -eq -2147024891)) { return }
            $failure = $failure.InnerException
        }
        throw
    }
    throw 'Forbidden filesystem access succeeded'
}
function Read-Spec {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ProbeArguments[0])) | ConvertFrom-Json
}
Assert-Probe ([bool]$SecurityReady -eq [bool]$SecurityRelease) 'Security handshake requires ready and release paths'

switch ($Mode) {
    'filesystem' {
        $allowed = Join-Path $Root 'rw\allowed.txt'
        [IO.File]::WriteAllText($allowed, 'allowed')
        Assert-Probe ([IO.File]::ReadAllText($allowed) -ceq 'allowed') 'Allowed read/write failed'
        Assert-Probe ([IO.File]::ReadAllText((Join-Path $Root 'ro\seed.txt')) -ceq 'seed') 'Read-only read failed'
        if ($GrantedShortAlias) {
            Assert-Probe ([IO.File]::ReadAllText($GrantedShortAlias) -ceq 'seed') 'Granted short-name read failed'
        }
        Assert-Blocked { [IO.File]::WriteAllText((Join-Path $Root 'ro\forbidden.txt'), 'forbidden') }
        $deniedDirectories = @('unlisted')
        $nativeDeny = [bool][int]$ProbeArguments[0]
        if ($nativeDeny) { $deniedDirectories += @('rw\blocked', 'rw\conflict', 'rw\denied-long-directory') }
        foreach ($relative in $deniedDirectories) {
            $directory = Join-Path $Root $relative
            Assert-Blocked { [IO.File]::ReadAllText((Join-Path $directory 'seed.txt')) }
            Assert-Blocked { [IO.File]::WriteAllText((Join-Path $directory 'forbidden.txt'), 'forbidden') }
        }
        $aliases = @("$Root\rw\..\unlisted\seed.txt", "\\?\$Root\unlisted\seed.txt")
        if ($ProbeArguments.Count -gt 1) { $aliases += $ProbeArguments[1..($ProbeArguments.Count - 1)] }
        if ($nativeDeny) { $aliases += @("$Root\rw\child\..\blocked\seed.txt", "\\?\$Root\rw\blocked\seed.txt") }
        foreach ($alias in $aliases) { Assert-Blocked { [IO.File]::ReadAllText($alias) } }
    }
    'enumerate' {
        $directory = Join-Path $Root 'enumerate'
        Assert-Probe ([IO.Directory]::GetFiles($directory) -contains (Join-Path $directory 'seed.txt')) 'Enumerate-only grant failed'
        Assert-Blocked { [IO.File]::ReadAllText((Join-Path $directory 'seed.txt')) }
        Assert-Blocked { [IO.File]::WriteAllText((Join-Path $directory 'forbidden.txt'), 'forbidden') }
        Assert-Blocked { [IO.Directory]::GetFileSystemEntries((Join-Path $Root 'unlisted')) }
    }
    'precedence' {
        $sibling = Join-Path $Root 'rw\denied-parent\sibling'
        if ([int]$ProbeArguments[0]) {
            Assert-Blocked { [IO.File]::ReadAllText((Join-Path $sibling 'seed.txt')) }
            Assert-Blocked { [IO.File]::WriteAllText((Join-Path $sibling 'written.txt'), 'forbidden') }
        } else {
            Assert-Probe ([IO.File]::ReadAllText((Join-Path $sibling 'seed.txt')) -ceq 'seed') 'Sibling read control failed'
            [IO.File]::WriteAllText((Join-Path $sibling 'written.txt'), 'allowed')
            Assert-Probe ([IO.File]::ReadAllText((Join-Path $sibling 'written.txt')) -ceq 'allowed') 'Sibling write control failed'
        }
        $child = Join-Path $Root 'rw\denied-parent\child\written.txt'
        [IO.File]::WriteAllText($child, 'child')
        Assert-Probe ([IO.File]::ReadAllText($child) -ceq 'child') 'Regranted child read failed'
    }
    'allowed' {
        $file = Join-Path $Root 'rw\allowed.txt'
        [IO.File]::WriteAllText($file, 'allowed')
        Assert-Probe ([IO.File]::ReadAllText($file) -ceq 'allowed') 'Allowed operation failed'
    }
    'denial' {
        Assert-Blocked { [IO.File]::ReadAllText((Join-Path $Root 'unlisted\seed.txt')) }
    }
    'plumbing' {
        $spec = Read-Spec
        $environment = @{}
        foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
            $environment[$entry.Key] = $entry.Value
        }
        foreach ($entry in $spec.environment.PSObject.Properties) {
            Assert-Probe ($environment.Contains($entry.Name) -and $environment[$entry.Name] -ceq $entry.Value) "Environment entry changed: $($entry.Name)"
        }
        foreach ($entry in $spec.redirected.PSObject.Properties) {
            $actual = [string]$environment[$entry.Name]
            Assert-Probe ([IO.Path]::IsPathRooted($actual) -and
                [IO.Path]::GetFullPath($actual) -ine [IO.Path]::GetFullPath($entry.Value)) "Native profile redirection missing: $($entry.Name)"
        }
        foreach ($key in $spec.absent) { Assert-Probe (-not $environment.Contains($key)) "Launcher-only environment leaked: $key" }
        foreach ($key in $spec.present) { Assert-Probe (-not [string]::IsNullOrEmpty($environment[$key])) "Default environment entry missing: $key" }
        if ($spec.cwd) { Assert-Probe ([Environment]::CurrentDirectory -ieq $spec.cwd) 'cwd mismatch' }
    }
    'exit' {
        Write-Output 'NATIVE_POLICY_OK'
        exit ([int]$ProbeArguments[0])
    }
    'timeout-parent' {
        $spec = Read-Spec
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $spec.powershell
        $start.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath +
            '" -Mode timeout-child -Root "' + $Root + '" "' + $spec.ready + '"'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $child = [Diagnostics.Process]::Start($start)
        $child.Dispose()
        Write-Output 'NATIVE_TIMEOUT_PARENT_STARTED'
        Start-Sleep -Seconds 120
        throw 'Configured timeout did not terminate the workload'
    }
    'timeout-child' {
        [IO.File]::WriteAllText($ProbeArguments[0], [string]$PID)
        Start-Sleep -Seconds 120
        throw 'Configured timeout did not terminate the grandchild'
    }
    { $_ -in @('privileges', 'privileges-host') } {
        $output = (& "$env:SystemRoot\System32\whoami.exe" /priv 2>&1 | Out-String)
        Assert-Probe ($LASTEXITCODE -eq 0) 'Token privilege query failed'
        $present = @(@('SeDebugPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege') |
            Where-Object { $output -match "(?m)^\s*$([regex]::Escape($_))\s" })
        if ($Mode -eq 'privileges-host') { ConvertTo-Json -InputObject $present -Compress; exit 0 }
        Assert-Probe ($present.Count -eq 0) "Forbidden privileges remain in the child token: $($present -join ', ')"
    }
    'atoms' {
        Assert-Probe (-not [string]::IsNullOrWhiteSpace($UiProbe)) 'Atoms require the published native UI probe'
        $atomArguments = @(
            'GLOBALATOMS', "--atom-host-name=$($ProbeArguments[0])", "--atom-guest-name=$($ProbeArguments[1])",
            "--atom-ready-file=$($ProbeArguments[3])", "--atom-release-file=$($ProbeArguments[4])"
        )
        $output = (& $UiProbe @atomArguments | Out-String).Trim()
        $expected = if ([int]$ProbeArguments[2]) { 'GLOBALATOMS_HOST_TO_GUEST=FAIL' } else { 'GLOBALATOMS_HOST_TO_GUEST=PASS' }
        Assert-Probe ($LASTEXITCODE -eq 0 -and $output -ceq $expected) "Host atom isolation mismatch: $output"
    }
    'dns' {
        $resolver, $hostname, $expected = $ProbeArguments
        $id = [Guid]::NewGuid().ToByteArray()
        $packet = [Collections.Generic.List[byte]]::new()
        $packet.AddRange([byte[]]@($id[0], $id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        foreach ($label in $hostname.Split('.')) {
            $bytes = [Text.Encoding]::ASCII.GetBytes($label)
            $packet.Add([byte]$bytes.Length)
            $packet.AddRange($bytes)
        }
        $packet.AddRange([byte[]]@(0, 0, 1, 0, 1))
        $answered = $false
        $client = $null
        try {
            $client = [Net.Sockets.UdpClient]::new()
            $client.Client.ReceiveTimeout = 2000
            [void]$client.Send($packet.ToArray(), $packet.Count, $resolver, 53)
            $peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $response = $client.Receive([ref]$peer)
            Assert-Probe ($peer.Address.ToString() -eq $resolver -and $peer.Port -eq 53) 'DNS response came from an unexpected peer'
            Assert-Probe ($response.Length -ge 12) 'DNS response was truncated'
            Assert-Probe ($response[0] -eq $id[0] -and $response[1] -eq $id[1] -and
                ($response[2] -band 128) -ne 0 -and ($response[3] -band 15) -eq 0 -and
                ([int]$response[6] * 256 + $response[7]) -gt 0) 'DNS positive response was invalid'
            $answered = $true
        } catch {
            $failure = $_.Exception
            while ($failure.InnerException) { $failure = $failure.InnerException }
            if ($failure -isnot [Net.Sockets.SocketException] -or
                $failure.SocketErrorCode -notin @([Net.Sockets.SocketError]::AccessDenied, [Net.Sockets.SocketError]::TimedOut)) { throw }
        } finally { if ($client) { $client.Dispose() } }
        Assert-Probe ($answered -eq [bool][int]$expected) 'Direct UDP/53 enforcement mismatch'
    }
    default { throw "Unknown probe mode: $Mode" }
}

if ($SecurityReady) {
    [IO.File]::WriteAllText($SecurityReady, 'ready')
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (-not [IO.File]::Exists($SecurityRelease)) {
        Assert-Probe ([DateTime]::UtcNow -lt $deadline) 'Live SDDL observation did not release the workload'
        Start-Sleep -Milliseconds 20
    }
}
Write-Output 'NATIVE_POLICY_OK'
