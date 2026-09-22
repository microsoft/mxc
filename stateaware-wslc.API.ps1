[CmdletBinding()]
param(
    [string]$MxcRepoPath = "S:\repo_other\mxc_rust",
    [string]$Image = "alpine:latest",
    [switch]$SkipImageSetup
)

$ErrorActionPreference = "Stop"

$resolvedRepoPath = Resolve-Path -LiteralPath $MxcRepoPath -ErrorAction Stop
$wxc = Join-Path $resolvedRepoPath "src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe"
if (-not (Test-Path $wxc -PathType Leaf)) {
    throw "wxc-exec.exe was not found under the MXC repository: $wxc"
}

$binaryDirectory = Split-Path -Parent $wxc
$buildCommand = "& `"$(Join-Path $resolvedRepoPath 'build.bat')`" --with-wslc"
foreach ($requiredFile in @("wxc-wslc-daemon.exe", "wslcsdk.dll")) {
    $requiredPath = Join-Path $binaryDirectory $requiredFile
    if (-not (Test-Path $requiredPath -PathType Leaf)) {
        throw "$requiredFile was not found next to wxc-exec.exe: $requiredPath. Rebuild MXC with WSLC support: $buildCommand"
    }
}

$configRoot = Join-Path $env:TEMP "mxc-manual-test\wslc-state-aware-api"
New-Item -ItemType Directory -Force $configRoot | Out-Null
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

if (-not $SkipImageSetup) {
    $daemonPath = Join-Path $binaryDirectory "wxc-wslc-daemon.exe"
    $activeDaemon = Get-CimInstance Win32_Process -Filter "Name = 'wxc-wslc-daemon.exe'" |
        Where-Object { $_.ExecutablePath -eq $daemonPath } |
        Select-Object -First 1
    if ($activeDaemon) {
        Write-Host "WSLC daemon $($activeDaemon.ProcessId) is active; using its existing image cache."
    }
    else {
        & $wxc --setup-wslc --image $Image
        if ($LASTEXITCODE -ne 0) {
            throw "WSLC image setup for '$Image' failed with exit code $LASTEXITCODE."
        }
    }
}

function Invoke-Request {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("provision", "start", "exec", "stop", "deprovision")]
        [string]$Operation,

        [Parameter(Mandatory)]
        [hashtable]$Request,

        [string]$SandboxId,

        [switch]$ParseJson
    )

    $configPath = Join-Path $configRoot "$Operation.json"
    $json = $Request | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($configPath, $json, $utf8NoBom)

    $arguments = @("--experimental", "--operation", $Operation)
    if ($SandboxId) {
        $arguments += @("--sandbox-id", $SandboxId)
    }
    $arguments += $configPath

    if ($ParseJson) {
        $output = & $wxc @arguments
        if ($LASTEXITCODE -ne 0) {
            $outputText = $output -join [Environment]::NewLine
            throw "WSLC $Operation failed with exit code $LASTEXITCODE.`n$outputText"
        }
        return $output | ConvertFrom-Json
    }

    & $wxc @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSLC $Operation failed with exit code $LASTEXITCODE."
    }
}

$sandboxId = $null
$started = $false
try {
    $result = Invoke-Request -Operation "provision" -ParseJson -Request @{
        version = "0.9.0-alpha"
        containment = "wslc"
        network = @{
            egress = @{ default = "deny" }
            ingress = @{
                default = "deny"
                hostLoopback = "deny"
            }
        }
        experimental = @{
            wslc = @{
                image = $Image
            }
        }
    }
    $sandboxId = $result.result.sandboxId
    if (-not $sandboxId) {
        throw "WSLC provision did not return a sandboxId."
    }
    $result
    Write-Host "Sandbox ID: $sandboxId"

    Invoke-Request -Operation "start" -SandboxId $sandboxId -Request @{
        version = "0.9.0-alpha"
    }
    $started = $true

    Invoke-Request -Operation "exec" -SandboxId $sandboxId -Request @{
        version = "0.9.0-alpha"
        process = @{
            commandLine = "sh -c 'echo `"hello from wslc bash`"; sleep 3; echo `"hello again from wslc bash`"'"
            timeout = 30000
        }
    }
}
finally {
    if ($sandboxId) {
        try {
            if ($started) {
                Invoke-Request -Operation "stop" -SandboxId $sandboxId -Request @{
                    version = "0.9.0-alpha"
                }
            }
        }
        finally {
            Invoke-Request -Operation "deprovision" -SandboxId $sandboxId -Request @{
                version = "0.9.0-alpha"
            }
        }
    }
}
