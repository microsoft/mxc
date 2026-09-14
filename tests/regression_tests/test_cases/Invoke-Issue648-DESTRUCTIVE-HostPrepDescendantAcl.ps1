# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$HostPrepExe,
    [Parameter(Mandatory)]
    [ValidatePattern("^[A-Za-z]:\\$")]
    [string]$DisposableVolumeRoot,
    [switch]$AllowDestructive,
    [switch]$AcknowledgeDisposableVolume
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
$HostPrepExe = Resolve-RegressionExecutable $HostPrepExe "wxc-host-prep.exe"
if (-not $AllowDestructive) {
    throw "Refusing to run this destructive test without -AllowDestructive."
}
if (-not $AcknowledgeDisposableVolume) {
    throw "Refusing to run without -AcknowledgeDisposableVolume. Use only a dedicated disposable NTFS test volume."
}
if ($DisposableVolumeRoot -eq [IO.Path]::GetPathRoot($env:SystemRoot)) {
    throw "Refusing to run this repro against the system volume."
}

function Get-AclSnapshot {
    param([string]$Root)
    Get-ChildItem -LiteralPath $Root -Force -Recurse | ForEach-Object {
        try {
            "$($_.FullName)`t$((Get-Acl -LiteralPath $_.FullName).Sddl)"
        } catch {
            "$($_.FullName)`t<ACL-READ-FAILED>"
        }
    } | Sort-Object
}

Write-Host "Issue #648: snapshotting descendant ACLs on disposable volume $DisposableVolumeRoot." -ForegroundColor Cyan
$before = Get-AclSnapshot $DisposableVolumeRoot
& $HostPrepExe prepare-system-drive --target $DisposableVolumeRoot
$hostPrepExit = $LASTEXITCODE
if ($hostPrepExit -ne 0) {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "Host preparation exited with code $hostPrepExit." -FailureExitCode $hostPrepExit
}
$after = Get-AclSnapshot $DisposableVolumeRoot
$differences = Compare-Object $before $after
$differences
Write-Host "Issue reproduces when descendant ACL differences are listed." -ForegroundColor Yellow
Write-Host "Do not use unprepare as cleanup for this repro; restore the disposable volume from its baseline." -ForegroundColor Yellow
Complete-RegressionTest -Passed ([bool]$differences) -SuccessMessage "Descendant ACL differences reproduced." -FailureMessage "No descendant ACL differences were detected."
