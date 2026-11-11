# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Assert-W365Guid([string] $Value, [string] $Name) {
    $parsed = [guid]::Empty
    if ($Value -cnotmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or
        -not [guid]::TryParse($Value, [ref] $parsed) -or $parsed -eq [guid]::Empty) {
        throw "$Name must be a nonempty hyphenated GUID."
    }
    return $parsed.ToString('D')
}

function Assert-W365Host([string] $Value, [string] $Name) {
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 253) {
        throw "$Name must be a bare ASCII DNS hostname/suffix, not a URL."
    }
    foreach ($label in $Value.Split('.')) {
        if ($label.Length -gt 63 -or $label -cnotmatch '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$') {
            throw "$Name must be a bare ASCII DNS hostname/suffix, not a URL."
        }
    }
}

function Get-W365Executor([string] $ExplicitPath, [string] $RepoRoot) {
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) { throw 'WxcExePath does not exist.' }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    $target = if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') {
        'aarch64-pc-windows-msvc'
    } else { 'x86_64-pc-windows-msvc' }
    foreach ($relative in @("src\target\$target\release", 'src\target\release',
            "src\target\$target\debug", 'src\target\debug')) {
        $candidate = Join-Path $RepoRoot "$relative\wxc-exec.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'wxc-exec.exe not found. Build from src with cargo build -p wxc, or pass -WxcExePath.'
}

function New-W365Child([string] $Exe) {
    $start = [Diagnostics.ProcessStartInfo]::new($Exe)
    foreach ($key in @($start.Environment.Keys)) {
        if ($key -like 'W365A_*' -or $key -like 'MXC_W365_TEST_*') {
            $null = $start.Environment.Remove($key)
        }
    }
    return $start
}

function Get-W365Token([string] $Tenant, [string] $Client, [string] $Hint,
        [string] $ExpectedOwner, [switch] $Force, [switch] $SilentOnly) {
    $start = New-W365Child (Get-Command python -CommandType Application -ErrorAction Stop).Source
    foreach ($arg in @((Join-Path $PSScriptRoot 'w365_auth.py'), '--tenant-id', $Tenant, '--client-id', $Client)) {
        $start.ArgumentList.Add($arg)
    }
    if ($Hint) { $start.ArgumentList.Add('--login-hint'); $start.ArgumentList.Add($Hint) }
    if ($ExpectedOwner) { $start.ArgumentList.Add('--expected-user-object-id'); $start.ArgumentList.Add($ExpectedOwner) }
    if ($Force) { $start.ArgumentList.Add('--force-sign-in') }
    if ($SilentOnly) { $start.ArgumentList.Add('--silent-only') }
    $result = [Mxc.W365Manual.ChildProcess]::Run($start, 300000, $false)
    if ($result.Failure -or $result.ExitCode -ne 0) {
        $safe = 'helper_failed'
        if ($result.Stderr -match '(?m)^W365_AUTH_ERROR:([A-Za-z0-9_-]{1,120})\r?$') { $safe = $Matches[1] }
        throw "Browser/cache authentication failed: $safe. No token or response body printed."
    }
    try {
        $auth = ConvertFrom-Json -InputObject $result.Stdout -AsHashtable
        if ($auth -isnot [System.Collections.IDictionary] -or
            $auth.accessToken -cnotmatch '^[A-Za-z0-9_.-]+$' -or
            $auth.expiresOn -isnot [long] -and $auth.expiresOn -isnot [int]) {
            throw 'Invalid private auth response.'
        }
        $owner = Assert-W365Guid $auth.userObjectId 'Authenticated userObjectId'
        if ($ExpectedOwner -and $owner -ne $ExpectedOwner) { throw 'Authenticated identity mismatch.' }
        if ($auth.expiresOn -lt [DateTimeOffset]::UtcNow.AddMinutes(5).ToUnixTimeSeconds()) {
            throw 'Insufficient token lifetime.'
        }
        return @{ Token = $auth.accessToken; UserObjectId = $owner; ExpiresOn = $auth.expiresOn }
    } catch { throw 'Invalid private auth response or identity. Response suppressed.' }
    finally { $result.Stdout = $null; $result.Stderr = $null }
}

function Get-W365CleanupAuth([hashtable] $Auth, [string] $Tenant, [string] $Client, [string] $Hint) {
    if ($Auth.ExpiresOn -lt [DateTimeOffset]::UtcNow.AddSeconds(90).ToUnixTimeSeconds()) {
        return Get-W365Token $Tenant $Client $Hint $Auth.UserObjectId -SilentOnly
    }
    return $Auth
}

function Invoke-W365Native([string] $Exe, [string] $Operation, [hashtable] $Request,
        [string] $Id, [string] $CpHost, [string] $DpSuffix, [string] $Token,
        [int] $BudgetMs, [switch] $DryRun, [switch] $Stream) {
    $start = New-W365Child $Exe
    $start.Environment['W365A_CONTROLPLANE_URL'] = $CpHost
    $start.Environment['W365A_DP_SUFFIX'] = $DpSuffix
    $start.Environment['W365A_CP_TOKEN'] = $Token
    $start.Environment['W365A_DP_TOKEN'] = $Token
    foreach ($arg in @('--experimental', '--operation', $Operation, '--config-base64',
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $Request -Depth 10 -Compress))))) {
        $start.ArgumentList.Add($arg)
    }
    if ($Id) { $start.ArgumentList.Add('--container-id'); $start.ArgumentList.Add($Id) }
    if ($DryRun) { $start.ArgumentList.Add('--dry-run') }
    try { return [Mxc.W365Manual.ChildProcess]::Run($start, $BudgetMs, $Stream.IsPresent) }
    finally {
        $null = $start.Environment.Remove('W365A_CP_TOKEN')
        $null = $start.Environment.Remove('W365A_DP_TOKEN')
    }
}

function ConvertFrom-W365Envelope($Native) {
    if ($Native.Failure) { throw "Native $($Native.Failure); remote outcome is unknown." }
    try { $value = ConvertFrom-Json -InputObject $Native.Stdout -AsHashtable }
    catch { throw 'Invalid native lifecycle envelope; raw output suppressed, outcome unknown.' }
    if ($value -isnot [System.Collections.IDictionary] -or
        ($value.Contains('result') -eq $value.Contains('error')) -or
        ($value.Contains('result') -and $value.result -isnot [System.Collections.IDictionary]) -or
        ($value.Contains('error') -and $value.error -isnot [System.Collections.IDictionary])) {
        throw 'Invalid native lifecycle envelope; raw output suppressed, outcome unknown.'
    }
    return $value
}

function Get-W365SafeError([System.Collections.IDictionary] $ErrorInfo) {
    $safe = @{ category = 'unknown'; code = 'unknown' }
    if ($ErrorInfo['code'] -cmatch '^[a-z_]{1,80}$') { $safe.category = $ErrorInfo['code'] }
    $details = $ErrorInfo['details']
    if ($details -is [System.Collections.IDictionary]) {
        if ($details['code'] -cmatch '^[a-z_]{1,80}$') { $safe.code = $details['code'] }
        foreach ($key in @('requestId', 'clientRequestId')) {
            if ($details[$key] -is [string] -and $details[$key] -cmatch '^[A-Za-z0-9_.:-]{1,128}$') {
                $safe[$key] = $details[$key]
            }
        }
        if (($details['httpStatus'] -is [long] -or $details['httpStatus'] -is [int]) -and
            $details['httpStatus'] -ge 100 -and $details['httpStatus'] -le 599) { $safe.httpStatus = $details['httpStatus'] }
        if ($details['possiblySucceeded'] -is [bool]) { $safe.possiblySucceeded = $details['possiblySucceeded'] }
    }
    return $safe
}

function Get-W365SandboxId([string] $Value, [string] $Pool) {
    $parts = $Value.Split(':')
    if ($parts.Length -ne 3 -or $parts[0] -cne 'w365' -or $parts[1] -ine $Pool) {
        throw 'Invalid native cleanup identity; reconcile with the service operator.'
    }
    $null = Assert-W365Guid $parts[1] 'Native poolId'
    $null = Assert-W365Guid $parts[2] 'Native sessionId'
    return $Value
}

function Save-W365Journal([string] $Path, [hashtable] $Journal, [switch] $Create) {
    $Journal.updatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Journal -Depth 12))
            $file.Write($bytes, 0, $bytes.Length)
            $file.Flush($true)
        } finally { $file.Dispose() }
        if ($Create) { [IO.File]::Move($temporary, $Path, $false) }
        else { [IO.File]::Move($temporary, $Path, $true) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}
