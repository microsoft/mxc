# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$WxcExec,
    [string]$SecondaryDriveWorkDirectory,
    [string]$HostPrepExe,
    [string]$DisposableVolumeRoot,
    [switch]$IncludeDestructive,
    [switch]$InstallMissingDependencies,
    [switch]$RunWithMissingDependencies,
    [switch]$PassThru
)

$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "inc\Run-RegressionTests.Lib.ps1")

# Load the test catalog.
$shell = (Get-Process -Id $PID).Path
$manifest = Import-PowerShellDataFile (Join-Path $PSScriptRoot "TestCases.psd1")

# Find and report missing dependencies.
$missingDependencies = @(Get-MissingTestDependencies $manifest)
if ($missingDependencies) {
    Write-MissingDependencyWarning $missingDependencies -InstallRequested:$InstallMissingDependencies
}

# Install dependencies when requested.
if ($missingDependencies -and $InstallMissingDependencies) {
    foreach ($missingDependency in $missingDependencies) {
        [void](Install-Dependency $missingDependency.Dependency)
    }
    $missingDependencies = @(Get-MissingTestDependencies $manifest)
}

# Stop before execution unless missing dependencies were explicitly allowed.
if ($missingDependencies -and -not $RunWithMissingDependencies) {
    Write-Error "Dependency preflight failed. Install the listed dependencies or pass -RunWithMissingDependencies to attempt the tests anyway."
    exit 1
}

# Run every cataloged test in issue order.
$results = foreach ($entry in $manifest.GetEnumerator() | Sort-Object { [int]$_.Key }) {
    Invoke-RegressionTestCase -Issue $entry.Key -Metadata $entry.Value -RegressionRoot $PSScriptRoot -Shell $shell `
        -WxcExec $WxcExec -SecondaryDriveWorkDirectory $SecondaryDriveWorkDirectory -HostPrepExe $HostPrepExe `
        -DisposableVolumeRoot $DisposableVolumeRoot -IncludeDestructive:$IncludeDestructive `
        -RunWithMissingDependencies:$RunWithMissingDependencies
}

# Emit pipeline objects or the colored console report.
if ($PassThru) {
    $results
} else {
    Write-RegressionTestResults $results
}

# Return failure when any test failed.
$failed = $results.Where({ $_.Status -eq "Failed" }).Count
if ($failed) { exit 1 }
