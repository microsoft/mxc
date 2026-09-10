# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Find-DependencyExecutable {
    param([hashtable]$Dependency)

    foreach ($path in @($Dependency.Paths)) {
        $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
        if (Test-Path -LiteralPath $expandedPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $expandedPath).Path
        }
    }

    if ($Dependency.Executable) {
        $localPath = Join-Path (Get-Location) $Dependency.Executable
        if (Test-Path -LiteralPath $localPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $localPath).Path
        }

        $command = Get-Command $Dependency.Executable -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command) {
            return $command.Source
        }
    }

    return $null
}

function Install-Dependency {
    param([hashtable]$Dependency)

    if (-not $Dependency.WingetId) {
        return $false
    }

    $winget = Get-Command "winget.exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $winget) {
        return $false
    }

    Write-Host "Installing $($Dependency.Name) with winget..." -ForegroundColor Yellow
    & $winget.Source install --id $Dependency.WingetId --exact --accept-source-agreements --accept-package-agreements | Out-Host
    return $LASTEXITCODE -eq 0
}

function Get-TestDependencies {
    param([hashtable]$Metadata)

    if (-not $Metadata.ContainsKey("Dependencies")) {
        return
    }

    $dependencyMetadata = $Metadata["Dependencies"]
    if ($dependencyMetadata -is [System.Collections.IDictionary]) {
        Write-Output -NoEnumerate $dependencyMetadata
    } else {
        $dependencyMetadata
    }
}

function Get-MissingTestDependencies {
    param([hashtable]$Manifest)

    foreach ($entry in $Manifest.GetEnumerator() | Sort-Object { [int]$_.Key }) {
        foreach ($dependency in @(Get-TestDependencies $entry.Value)) {
            if (-not (Find-DependencyExecutable $dependency)) {
                [pscustomobject]@{
                    Issue = "#$($entry.Key)"
                    Name = $dependency.Name
                    InstallCommand = if ($dependency.WingetId) {
                        "winget install --id $($dependency.WingetId) --exact"
                    } else {
                        "No automatic installer configured"
                    }
                    Dependency = $dependency
                }
            }
        }
    }
}

function Write-MissingDependencyWarning {
    param(
        [object[]]$MissingDependencies,
        [switch]$InstallRequested
    )

    $warningLines = $MissingDependencies | ForEach-Object {
        "$($_.Issue): $($_.Name) - $($_.InstallCommand)"
    }
    $installNote = if ($InstallRequested) {
        "`nAutomatic installation was requested and will be attempted before tests start."
    } else {
        "`nUse -InstallMissingDependencies to install dependencies with configured winget packages."
    }
    Write-Warning ("Missing test dependencies:`n  " + ($warningLines -join "`n  ") + $installNote)
}

function New-RegressionTestResult {
    param(
        [string]$Issue,
        [hashtable]$Metadata,
        [ValidateSet("Passed", "Failed", "Skipped")]
        [string]$Status,
        [string]$Detail = "",
        [AllowNull()]
        [object]$ExitCode
    )

    [pscustomobject]@{
        Issue = "#$Issue"
        FriendlyName = $Metadata.FriendlyName
        ExpectedTierSupport = $Metadata.ExpectedTierSupport -join ", "
        Status = $Status
        Detail = $Detail
        ExitCode = $ExitCode
    }
}

function Invoke-RegressionTestCase {
    param(
        [string]$Issue,
        [hashtable]$Metadata,
        [string]$RegressionRoot,
        [string]$Shell,
        [string]$WxcExec,
        [string]$SecondaryDriveWorkDirectory,
        [string]$HostPrepExe,
        [string]$DisposableVolumeRoot,
        [switch]$IncludeDestructive,
        [switch]$RunWithMissingDependencies
    )

    if ($Metadata.Destructive -and -not $IncludeDestructive) {
        return New-RegressionTestResult $Issue $Metadata "Skipped" "Destructive test; use -IncludeDestructive" $null
    }

    $test = Join-Path $RegressionRoot $Metadata.Script
    if (-not (Test-Path -LiteralPath $test -PathType Leaf)) {
        return New-RegressionTestResult $Issue $Metadata "Failed" "Script not found: $test" 1
    }

    $arguments = @("-NoProfile", "-File", $test)
    foreach ($dependency in @(Get-TestDependencies $Metadata)) {
        $dependencyPath = Find-DependencyExecutable $dependency
        if (-not $dependencyPath) {
            if ($RunWithMissingDependencies) {
                continue
            }
            $installHint = if ($dependency.WingetId) {
                " Install with: winget install --id $($dependency.WingetId) --exact"
            } else {
                ""
            }
            return New-RegressionTestResult $Issue $Metadata "Failed" "Missing dependency: $($dependency.Name).$installHint" 1
        }

        if ($dependency.ArgumentName) {
            $arguments += @("-$($dependency.ArgumentName)", $dependencyPath)
        }
    }

    if ($Metadata.HarnessArguments -eq "HostPrep") {
        if (-not $DisposableVolumeRoot) {
            return New-RegressionTestResult $Issue $Metadata "Failed" "-DisposableVolumeRoot is required" 1
        }
        $arguments += @("-DisposableVolumeRoot", $DisposableVolumeRoot, "-AllowDestructive", "-AcknowledgeDisposableVolume")
        if ($HostPrepExe) {
            $arguments += @("-HostPrepExe", $HostPrepExe)
        }
    } elseif ($Metadata.HarnessArguments -eq "SecondaryDrive") {
        if (-not $SecondaryDriveWorkDirectory) {
            $systemDrive = [IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd("\")
            $secondaryDrive = Get-PSDrive -PSProvider FileSystem |
                Where-Object { $_.Root.TrimEnd("\") -ne $systemDrive } |
                Select-Object -First 1
            if (-not $secondaryDrive) {
                return New-RegressionTestResult $Issue $Metadata "Failed" "No secondary filesystem drive exists" 1
            }
            $SecondaryDriveWorkDirectory = Join-Path $secondaryDrive.Root "mxc-regression-825"
        }
        $arguments += @("-WxcExec", $WxcExec, "-WorkDirectory", $SecondaryDriveWorkDirectory)
    } elseif ($WxcExec) {
        $arguments += @("-WxcExec", $WxcExec)
    }

    Write-Host "`n=== Issue #${Issue}: $($Metadata.ExpectedTierSupport -join ', ') ===" -ForegroundColor Cyan
    & $Shell @arguments | Out-Host
    $exitCode = $LASTEXITCODE
    $status = if ($exitCode -eq 0) { "Passed" } else { "Failed" }
    if ($exitCode -eq 0) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
    }
    New-RegressionTestResult $Issue $Metadata $status "" $exitCode
}

function Write-RegressionTestResults {
    param([object[]]$Results)

    $issueWidth = [Math]::Max(5, ($Results.Issue | Measure-Object -Property Length -Maximum).Maximum)
    $nameWidth = [Math]::Max(4, ($Results.FriendlyName | Measure-Object -Property Length -Maximum).Maximum)
    $tiersWidth = [Math]::Max(21, ($Results.ExpectedTierSupport | Measure-Object -Property Length -Maximum).Maximum)
    $statusWidth = 7

    Write-Host ""
    Write-Host (("{0,-$issueWidth}  {1,-$nameWidth}  {2,-$tiersWidth}  {3,-$statusWidth}  {4}" -f "Issue", "Name", "Expected Tier Support", "Status", "Detail"))
    Write-Host (("-" * $issueWidth) + "  " + ("-" * $nameWidth) + "  " + ("-" * $tiersWidth) + "  " + ("-" * $statusWidth) + "  " + ("-" * 6))
    foreach ($result in $Results) {
        Write-Host (("{0,-$issueWidth}  {1,-$nameWidth}  {2,-$tiersWidth}  " -f $result.Issue, $result.FriendlyName, $result.ExpectedTierSupport)) -NoNewline
        $statusColor = switch ($result.Status) {
            "Passed" { "Green" }
            "Failed" { "Red" }
            "Skipped" { "Yellow" }
            default { "White" }
        }
        Write-Host (("{0,-$statusWidth}" -f $result.Status)) -ForegroundColor $statusColor -NoNewline
        Write-Host "  $($result.Detail)"
    }

    $passed = $Results.Where({ $_.Status -eq "Passed" }).Count
    $failed = $Results.Where({ $_.Status -eq "Failed" }).Count
    $skipped = $Results.Where({ $_.Status -eq "Skipped" }).Count
    Write-Host "`nTotal: $($Results.Count), Passed: $passed, Failed: $failed, Skipped: $skipped"
}
