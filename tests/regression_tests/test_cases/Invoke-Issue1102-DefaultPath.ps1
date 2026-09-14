# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1102")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
$cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
$testVariable = "MXC_ISSUE_1102_VAR"
$testValue = "a value"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

function Get-CurrentProcessEnvironment {
    $environment = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $name = [string]$entry.Key
        if ([string]::IsNullOrEmpty($name) -or $name.StartsWith("=") -or $name -ieq $testVariable) {
            continue
        }
        [void]$environment.Add("$name=$($entry.Value)")
    }
    return $environment.ToArray()
}

function Invoke-PathCase {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [bool]$InheritDefaultEnv,
        [Parameter(Mandatory)]
        [bool]$EnvironmentSpecified,
        [AllowEmptyCollection()]
        [string[]]$Environment,
        [Parameter(Mandatory)]
        [bool]$ExpectSuccess,
        [Parameter(Mandatory)]
        [bool]$ExpectVariable
    )

    $process = [ordered]@{
        cwd = $WorkDirectory
        inheritDefaultEnv = $InheritDefaultEnv
        timeout = 30000
    }
    if ($EnvironmentSpecified) {
        $process["env"] = @($Environment)
    }

    $config = [ordered]@{
        version = "0.9.0-alpha"
        containment = "processcontainer"
        process = $process
        filesystem = [ordered]@{
            readonlyPaths = @($env:SystemRoot)
            readwritePaths = @($WorkDirectory)
        }
        fallback = [ordered]@{
            allowDaclMutation = $true
        }
        ui = [ordered]@{
            disable = $false
        }
    }

    $variableCheck = if ($ExpectVariable) {
        "if `"%$testVariable%`"==`"$testValue`" (exit /b 0) else (exit /b 42)"
    } else {
        "if not defined $testVariable (exit /b 0) else (exit /b 43)"
    }
    $commandBody = "if not defined PATH exit /b 41 & $variableCheck"
    $commandLine = "`"$cmdExe`" /d /c `"$commandBody`""
    $configJson = $config | ConvertTo-Json -Depth 10
    $json = Add-RegressionCommandLine $configJson $commandLine
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

    Write-Host "`n$Name" -ForegroundColor Cyan
    Write-Host "inheritDefaultEnv=$($InheritDefaultEnv.ToString().ToLowerInvariant()), env=$(
        if (-not $EnvironmentSpecified) { "null (omitted)" }
        elseif ($Environment.Count -eq 0) { "[]" }
        else { "[$($Environment.Count) entries]" }
    )"

    & $WxcExec --config-base64 $base64
    $exitCode = $LASTEXITCODE
    $passed = if ($ExpectSuccess) { $exitCode -eq 0 } else { $exitCode -ne 0 }

    [pscustomobject]@{
        Case = $Name
        Expected = if ($ExpectSuccess) { "success" } else { "failure" }
        ExitCode = $exitCode
        Passed = $passed
    }
}

$variableEntry = "$testVariable=$testValue"
$processEnvironment = @(Get-CurrentProcessEnvironment)
$processEnvironmentWithVariable = @($processEnvironment) + $variableEntry

$results = @(
    Invoke-PathCase -InheritDefaultEnv $false -EnvironmentSpecified $false -ExpectSuccess $true -ExpectVariable $false -Name "Default user cleanroom environment"
    Invoke-PathCase -InheritDefaultEnv $true -EnvironmentSpecified $false -ExpectSuccess $true -ExpectVariable $false -Name "User cleanroom environment"
    Invoke-PathCase -InheritDefaultEnv $true -EnvironmentSpecified $true -Environment @($variableEntry) -ExpectSuccess $true -ExpectVariable $true -Name "User cleanroom environment + variable"
    Invoke-PathCase -InheritDefaultEnv $false -EnvironmentSpecified $true -Environment @($variableEntry) -ExpectSuccess $false -ExpectVariable $true -Name "Empty environment + variable"
    Invoke-PathCase -InheritDefaultEnv $false -EnvironmentSpecified $true -Environment @() -ExpectSuccess $false -ExpectVariable $false -Name "Empty environment"
    Invoke-PathCase -InheritDefaultEnv $false -EnvironmentSpecified $true -Environment $processEnvironmentWithVariable -ExpectSuccess $true -ExpectVariable $true -Name "Process environment + variable"
)

$results | Format-Table -AutoSize | Out-Host
$failed = @($results | Where-Object { -not $_.Passed })
$failureMessage = if ($failed.Count -eq 0) {
    "One or more environment cases did not behave as expected."
} else {
    "Unexpected result: " + (($failed | ForEach-Object { "$($_.Case) exited $($_.ExitCode), expected $($_.Expected)" }) -join "; ")
}
Complete-RegressionTest -Passed ($failed.Count -eq 0) -SuccessMessage "All six default, inherited, empty, and process environment cases behaved as expected." -FailureMessage $failureMessage
