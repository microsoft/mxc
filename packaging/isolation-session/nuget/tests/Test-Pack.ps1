#Requires -Version 5.1
<#
.SYNOPSIS
    Focused tests for packaging\isolation-session\nuget\pack.ps1, exercised
    against synthetic (non-Microsoft-internal) base nupkgs built by
    New-SyntheticBaseNupkg.ps1.

.DESCRIPTION
    Copyright (c) Microsoft Corporation. All rights reserved.

    Covers:
      1. Happy path for ArchTag x64 -> RID win-x64, with an architecture-
         suffixed package id, injected runtime entries, an updated nuspec,
         and preserved metadata bytes.
      2. Happy path for ArchTag arm64 -> RID win-arm64 (distinct RID + id
         from the x64 case, run against the same base nupkg).
      3. Strict failure when the base nupkg <version> does not match -MonthId.
      4. Strict failure when GENERATION_INFO.toml `instance` does not match
         -MonthId (even though the nuspec version matches).
      5. Metadata byte-preservation: the repackaged nupkg's metadata/*.winmd
         and metadata/GENERATION_INFO.toml bytes are byte-for-byte identical
         to the base package's.

    No Microsoft-internal WinMD or real IsoSessionApp.dll is used or
    required; the "binary" injected is a synthetic placeholder file.

    Run directly with pwsh/powershell; no Pester dependency required.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$nugetDir = Split-Path -Parent $PSScriptRoot
$packScript = Join-Path $nugetDir "pack.ps1"
$syntheticBuilder = Join-Path $PSScriptRoot "New-SyntheticBaseNupkg.ps1"

if (-not (Test-Path -LiteralPath $packScript)) {
    throw "pack.ps1 not found at '$packScript'."
}
if (-not (Test-Path -LiteralPath $syntheticBuilder)) {
    throw "New-SyntheticBaseNupkg.ps1 not found at '$syntheticBuilder'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mxc-isosession-pack-test-{0}" -f ([guid]::NewGuid()))
$failures = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Get-ZipEntryNames {
    param([string]$NupkgPath)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        return @($zip.Entries | ForEach-Object { $_.FullName })
    }
    finally { $zip.Dispose() }
}

function Get-ZipEntryTextFromPath {
    param([string]$NupkgPath, [string]$EntryName)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        $entry = $zip.GetEntry($EntryName)
        if (-not $entry) { return $null }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $zip.Dispose() }
}

function Get-ZipEntryBytesFromPath {
    param([string]$NupkgPath, [string]$EntryName)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        $entry = $zip.GetEntry($EntryName)
        if (-not $entry) { return $null }
        $stream = $entry.Open()
        try {
            $ms = New-Object System.IO.MemoryStream
            try {
                $stream.CopyTo($ms)
                return $ms.ToArray()
            }
            finally { $ms.Dispose() }
        }
        finally { $stream.Dispose() }
    }
    finally { $zip.Dispose() }
}

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    Write-Host "==> $Name"
    try {
        & $Body
        Write-Host "    PASS" -ForegroundColor Green
    }
    catch {
        Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red
        $script:failures += "$Name : $($_.Exception.Message)"
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

    $monthId = "2026.06"
    $baseNupkg = Join-Path $testRoot "Microsoft.Windows.AI.IsolationSession.SDK.0.202606.0.nupkg"
    & $syntheticBuilder -OutFile $baseNupkg -Version "0.202606.0" -Instance $monthId | Out-Null

    $binDir = Join-Path $testRoot "bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    $appDllBytes = [System.Text.Encoding]::ASCII.GetBytes("synthetic-IsoSessionApp-dll-bytes")
    [System.IO.File]::WriteAllBytes((Join-Path $binDir "IsoSessionApp.dll"), $appDllBytes)

    # ------------------------------------------------------------------
    Test-Case "x64: ArchTag maps to win-x64 RID, arch-suffixed id, injected entries" {
        $outDir = Join-Path $testRoot "out-x64"
        & $packScript -BinDir $binDir -BaseNupkg $baseNupkg -OutDir $outDir -ArchTag x64 -MonthId $monthId | Out-Null

        $expectedNupkg = Join-Path $outDir "Microsoft.Windows.AI.IsolationSession.SDK.x64.0.202606.0.nupkg"
        Assert-True (Test-Path -LiteralPath $expectedNupkg) "expected output nupkg '$expectedNupkg' to exist"

        $entries = Get-ZipEntryNames -NupkgPath $expectedNupkg
        Assert-True ($entries -contains "runtimes/win-x64/native/IsoSessionApp.dll") "runtimes/win-x64/native/IsoSessionApp.dll entry present"
        Assert-True ($entries -contains "runtimes/win-x64/native/IsoSession.manifest") "runtimes/win-x64/native/IsoSession.manifest entry present"
        Assert-True ($entries -contains "metadata/GENERATION_INFO.toml") "metadata/GENERATION_INFO.toml entry present"
        Assert-True ($entries -contains "metadata/windows.ai.isolationsession.winmd") "metadata winmd entry present"

        $nuspecName = @($entries | Where-Object { $_ -like "*.nuspec" })[0]
        $nuspecText = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName $nuspecName
        Assert-True ($nuspecText -match '<id>Microsoft\.Windows\.AI\.IsolationSession\.SDK\.x64</id>') "nuspec id is arch-suffixed with .x64"
        Assert-True ($nuspecText -match 'runtimes\\win-x64\\native\\IsoSessionApp\.dll') "nuspec references win-x64 runtime dll"
        Assert-True ($nuspecText -match '<summary>[^<]*x64[^<]*</summary>') "nuspec summary mentions x64"

        $manifestText = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName "runtimes/win-x64/native/IsoSession.manifest"
        Assert-True ($manifestText -match [regex]::Escape("name=`"$monthId`"")) "manifest stamped with MonthId"
    }

    # ------------------------------------------------------------------
    Test-Case "arm64: ArchTag maps to win-arm64 RID, distinct arch-suffixed id" {
        $outDir = Join-Path $testRoot "out-arm64"
        & $packScript -BinDir $binDir -BaseNupkg $baseNupkg -OutDir $outDir -ArchTag arm64 -MonthId $monthId | Out-Null

        $expectedNupkg = Join-Path $outDir "Microsoft.Windows.AI.IsolationSession.SDK.arm64.0.202606.0.nupkg"
        Assert-True (Test-Path -LiteralPath $expectedNupkg) "expected output nupkg '$expectedNupkg' to exist"

        $entries = Get-ZipEntryNames -NupkgPath $expectedNupkg
        Assert-True ($entries -contains "runtimes/win-arm64/native/IsoSessionApp.dll") "runtimes/win-arm64/native/IsoSessionApp.dll entry present"
        Assert-True ($entries -contains "runtimes/win-arm64/native/IsoSession.manifest") "runtimes/win-arm64/native/IsoSession.manifest entry present"
        Assert-True (-not ($entries -contains "runtimes/win-x64/native/IsoSessionApp.dll")) "arm64 package must not carry win-x64 runtime entries"

        $nuspecName = @($entries | Where-Object { $_ -like "*.nuspec" })[0]
        $nuspecText = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName $nuspecName
        Assert-True ($nuspecText -match '<id>Microsoft\.Windows\.AI\.IsolationSession\.SDK\.arm64</id>') "nuspec id is arch-suffixed with .arm64"
        Assert-True ($nuspecText -match 'runtimes\\win-arm64\\native\\IsoSessionApp\.dll') "nuspec references win-arm64 runtime dll"
    }

    # ------------------------------------------------------------------
    Test-Case "Metadata bytes (winmd + GENERATION_INFO.toml) preserved unchanged" {
        $outDir = Join-Path $testRoot "out-preserve"
        & $packScript -BinDir $binDir -BaseNupkg $baseNupkg -OutDir $outDir -ArchTag x64 -MonthId $monthId | Out-Null
        $outNupkg = Join-Path $outDir "Microsoft.Windows.AI.IsolationSession.SDK.x64.0.202606.0.nupkg"

        foreach ($entryName in @(
                "metadata/windows.ai.isolationsession.winmd",
                "metadata/windows.ai.isolationsession.preview.winmd",
                "metadata/GENERATION_INFO.toml")) {
            $before = Get-ZipEntryBytesFromPath -NupkgPath $baseNupkg -EntryName $entryName
            $after = Get-ZipEntryBytesFromPath -NupkgPath $outNupkg -EntryName $entryName
            Assert-True ($null -ne $before -and $null -ne $after) "entry '$entryName' present in both base and output"
            Assert-True (
                $before.Length -eq $after.Length -and
                -not (Compare-Object $before $after -SyncWindow 0)
            ) "entry '$entryName' bytes are unchanged"
        }
    }

    # ------------------------------------------------------------------
    Test-Case "Strict failure: base nupkg version mismatches MonthId" {
        $mismatchNupkg = Join-Path $testRoot "Microsoft.Windows.AI.IsolationSession.SDK.0.202607.0.nupkg"
        & $syntheticBuilder -OutFile $mismatchNupkg -Version "0.202607.0" -Instance "2026.06" | Out-Null

        $outDir = Join-Path $testRoot "out-version-mismatch"
        $threw = $false
        try {
            & $packScript -BinDir $binDir -BaseNupkg $mismatchNupkg -OutDir $outDir -ArchTag x64 -MonthId "2026.06" | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw "pack.ps1 must throw (not warn) when nupkg version disagrees with -MonthId"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $outDir "Microsoft.Windows.AI.IsolationSession.SDK.x64.0.202607.0.nupkg"))) "no output package should be produced on validation failure"
    }

    # ------------------------------------------------------------------
    Test-Case "Strict failure: GENERATION_INFO instance mismatches MonthId" {
        $mismatchNupkg = Join-Path $testRoot "Microsoft.Windows.AI.IsolationSession.SDK.0.202606.0-badinstance.nupkg"
        & $syntheticBuilder -OutFile $mismatchNupkg -Version "0.202606.0" -Instance "2026.07" | Out-Null

        $outDir = Join-Path $testRoot "out-instance-mismatch"
        $threw = $false
        try {
            & $packScript -BinDir $binDir -BaseNupkg $mismatchNupkg -OutDir $outDir -ArchTag x64 -MonthId "2026.06" | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw "pack.ps1 must throw (not warn) when GENERATION_INFO instance disagrees with -MonthId"
    }

    # ------------------------------------------------------------------
    Test-Case "Rejects unsupported ArchTag values" {
        $outDir = Join-Path $testRoot "out-bad-arch"
        $threw = $false
        try {
            & $packScript -BinDir $binDir -BaseNupkg $baseNupkg -OutDir $outDir -ArchTag "x86" -MonthId $monthId 2>$null | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw "pack.ps1 must reject an ArchTag outside the x64/arm64 ValidateSet"
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n$($failures.Count) test(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "`nAll IsoSession nuget pack.ps1 tests passed." -ForegroundColor Green
exit 0
