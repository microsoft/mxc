# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Generates the experimental MXC Diplomat C and .NET binding layers.

.DESCRIPTION
Uses the repository-local mxc_diplomat_codegen wrapper, which pins
diplomat-tool 0.16.1 in src/Cargo.lock. No globally installed Diplomat CLI is
used. The generated C headers land under src/target (a build artifact); the
generated C# source is compiled by Microsoft.Mxc.Diplomat.Generated. The
public convenience facade is generated from that API into
Microsoft.Mxc.Diplomat.Prototype.

.EXAMPLE
.\scripts\generate-diplomat-bindings.ps1 -Build
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Smoke,
    [switch]$ExerciseProcess
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$rustRoot = Join-Path $repositoryRoot 'src'
$cOutput = Join-Path $rustRoot 'target\diplomat-bindings\c'
$dotnetProject = Join-Path $repositoryRoot 'sdk\dotnet\Microsoft.Mxc.Diplomat.Generated\Microsoft.Mxc.Diplomat.Generated.csproj'
$dotnetOutput = Join-Path $repositoryRoot 'sdk\dotnet\Microsoft.Mxc.Diplomat.Generated\Generated'
$prototypeProject = Join-Path $repositoryRoot 'sdk\dotnet\Microsoft.Mxc.Diplomat.Prototype\Microsoft.Mxc.Diplomat.Prototype.csproj'
$prototypeOutput = Join-Path $repositoryRoot 'sdk\dotnet\Microsoft.Mxc.Diplomat.Prototype\Generated'
$smokeProject = Join-Path $repositoryRoot 'sdk\dotnet\Microsoft.Mxc.Diplomat.Smoke\Microsoft.Mxc.Diplomat.Smoke.csproj'

function Reset-GeneratedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

Reset-GeneratedDirectory -Path $cOutput
Reset-GeneratedDirectory -Path $dotnetOutput
Reset-GeneratedDirectory -Path $prototypeOutput

Push-Location $rustRoot
try {
    Invoke-Checked -FilePath 'cargo' -Arguments @(
        'run', '-p', 'mxc_diplomat_codegen', '--', 'c', $cOutput
    )
    Invoke-Checked -FilePath 'cargo' -Arguments @(
        'run', '-p', 'mxc_diplomat_codegen', '--', 'dotnet', $dotnetOutput, $prototypeOutput
    )
    if ($Build -or $Smoke -or $ExerciseProcess) {
        Invoke-Checked -FilePath 'cargo' -Arguments @('build', '-p', 'mxc_ffi')
        Invoke-Checked -FilePath 'dotnet' -Arguments @('build', $dotnetProject)
        Invoke-Checked -FilePath 'dotnet' -Arguments @('build', $prototypeProject)
    }
    if ($Smoke -or $ExerciseProcess) {
        $smokeArguments = @('run', '--project', $smokeProject)
        if ($ExerciseProcess) {
            $smokeArguments += @('--', '--exercise-process')
        }
        Invoke-Checked -FilePath 'dotnet' -Arguments $smokeArguments
    }
}
finally {
    Pop-Location
}
