<#
.SYNOPSIS
Copies the SDK integration-test artifacts onto a remote test VM via PowerShell Remoting.

.DESCRIPTION
Stages a flat payload of the integration-test artifacts (built tests, runner,
package.json, node_modules) plus the SDK's published shape (bin, dist,
package.json, LICENSE.md, node_modules) into a temp directory on the host,
zips it, copies the single zip onto the VM via PSSession, and expands it
in place.

The integration-test `node_modules\@microsoft\mxc-sdk` is a symlink to the
SDK root, which itself contains `tests\integration\node_modules` — directly
copying the tree would recurse indefinitely. The staging step skips the
symlink and copies the SDK's published shape directly instead.

.PARAMETER ComputerName
DNS name or IP of the remote VM. Mutually exclusive with -VMName.

.PARAMETER VMName
Hyper-V VM name. Mutually exclusive with -ComputerName.

.PARAMETER Credential
PSCredential for the remote session.

.PARAMETER DestinationPath
Path on the VM where artifacts are deployed. Defaults to C:\sdk-integration-tests.

.EXAMPLE
.\push_sdk_integration_tests_to_vm.ps1 -ComputerName myvm -Credential (Get-Credential)

.EXAMPLE
.\push_sdk_integration_tests_to_vm.ps1 -VMName HYPERV-VM -Credential (Get-Credential)
#>

[CmdletBinding(DefaultParameterSetName = 'ComputerName')]
param(
    [Parameter(ParameterSetName = 'ComputerName', Mandatory)]
    [string]$ComputerName,

    [Parameter(ParameterSetName = 'VMName', Mandatory)]
    [string]$VMName,

    [Parameter(Mandatory)]
    [System.Management.Automation.PSCredential]$Credential,

    [string]$DestinationPath = 'C:\sdk-integration-tests'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$sdkRoot = Join-Path $repoRoot 'sdk'
$integrationDir = Join-Path $sdkRoot 'tests\integration'

if (-not (Test-Path (Join-Path $integrationDir 'dist'))) {
    throw "Integration tests not built. Run: cd sdk\tests\integration; npm install; npm run build"
}
if (-not (Test-Path (Join-Path $sdkRoot 'bin'))) {
    throw "SDK binaries not built. Run: build.bat --x64 --with-isolation-session"
}

$stagingRoot = Join-Path $env:TEMP "mxc-sdk-integration-deploy-$([Guid]::NewGuid())"
$zipPath = "$stagingRoot.zip"

try {
    Write-Host "Staging payload at $stagingRoot..."
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

    Copy-Item -Recurse (Join-Path $integrationDir 'dist') (Join-Path $stagingRoot 'dist')
    Copy-Item (Join-Path $integrationDir 'package.json') (Join-Path $stagingRoot 'package.json')
    Copy-Item (Join-Path $integrationDir 'run-tests.js') (Join-Path $stagingRoot 'run-tests.js')

    # Walk the integration node_modules, skipping the @microsoft symlink (we'll
    # copy the SDK's published shape directly below).
    $integrationNodeModules = Join-Path $integrationDir 'node_modules'
    $stagingNodeModules = Join-Path $stagingRoot 'node_modules'
    New-Item -ItemType Directory -Path $stagingNodeModules -Force | Out-Null
    foreach ($entry in Get-ChildItem -Path $integrationNodeModules -Force) {
        if ($entry.Name -eq '@microsoft') { continue }
        Copy-Item -Recurse -Force $entry.FullName (Join-Path $stagingNodeModules $entry.Name)
    }

    # Copy the SDK's published shape directly — no recursion into the symlink.
    $sdkStaged = Join-Path $stagingNodeModules '@microsoft\mxc-sdk'
    New-Item -ItemType Directory -Path $sdkStaged -Force | Out-Null
    Copy-Item -Recurse (Join-Path $sdkRoot 'bin') (Join-Path $sdkStaged 'bin')
    Copy-Item -Recurse (Join-Path $sdkRoot 'dist') (Join-Path $sdkStaged 'dist')
    Copy-Item (Join-Path $sdkRoot 'package.json') (Join-Path $sdkStaged 'package.json')
    $licensePath = Join-Path $sdkRoot 'LICENSE.md'
    if (Test-Path $licensePath) {
        Copy-Item $licensePath (Join-Path $sdkStaged 'LICENSE.md')
    }
    Copy-Item -Recurse (Join-Path $sdkRoot 'node_modules') (Join-Path $sdkStaged 'node_modules')

    Write-Host "Compressing payload to $zipPath..."
    Compress-Archive -Path "$stagingRoot\*" -DestinationPath $zipPath -CompressionLevel Fastest -Force

    $sessionParams = if ($PSCmdlet.ParameterSetName -eq 'VMName') {
        @{ VMName = $VMName; Credential = $Credential }
    } else {
        @{ ComputerName = $ComputerName; Credential = $Credential }
    }

    Write-Host "Opening PSSession..."
    $session = New-PSSession @sessionParams
    try {
        Write-Host "Preparing destination $DestinationPath on the VM..."
        Invoke-Command -Session $session -ScriptBlock {
            param($Dest)
            if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
            New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        } -ArgumentList $DestinationPath

        $remoteZip = Join-Path $DestinationPath 'integration-deploy.zip'
        Write-Host "Copying zip to $remoteZip..."
        Copy-Item -ToSession $session -Path $zipPath -Destination $remoteZip -Force

        Write-Host "Expanding zip on the VM..."
        Invoke-Command -Session $session -ScriptBlock {
            param($Dest, $Zip)
            Expand-Archive -Path $Zip -DestinationPath $Dest -Force
            Remove-Item -Force $Zip
        } -ArgumentList $DestinationPath, $remoteZip

        Write-Host "Deployed to $DestinationPath."
    } finally {
        Remove-PSSession $session
    }
}
finally {
    if (Test-Path $stagingRoot) { Remove-Item -Recurse -Force $stagingRoot }
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
}
