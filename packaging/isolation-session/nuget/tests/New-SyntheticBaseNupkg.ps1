<#
.SYNOPSIS
    Test helper: build a synthetic metadata-only IsoSession SDK base nupkg
    for exercising pack.ps1 without any real/internal Windows OS WinMD.

.DESCRIPTION
    Copyright (c) Microsoft Corporation. All rights reserved.

    Produces a minimal but structurally faithful nupkg containing:
      metadata/windows.ai.isolationsession.winmd
      metadata/windows.ai.isolationsession.preview.winmd
      metadata/GENERATION_INFO.toml   (with the requested `instance`)
      README.md
      _rels/.rels
      [Content_Types].xml
      Microsoft.Windows.AI.IsolationSession.SDK.nuspec  (<id>/<version> only,
        no runtimes/ entries -- a genuine "metadata-only" base package)

    This intentionally omits the runtimes/win-x64/native/* entries that a
    real POC base package might already carry from a prior pack, so tests
    exercise pack.ps1's additive injection path against a true base package.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutFile,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$Instance,

    [string]$PackageId = "Microsoft.Windows.AI.IsolationSession.SDK"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
if (Test-Path -LiteralPath $OutFile) {
    Remove-Item -LiteralPath $OutFile -Force
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Add-TextEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [string]$Text
    )
    $entry = $Archive.CreateEntry($EntryName)
    $stream = $entry.Open()
    try {
        $bytes = $utf8NoBom.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
}

function Add-BytesEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [byte[]]$Bytes
    )
    $entry = $Archive.CreateEntry($EntryName)
    $stream = $entry.Open()
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

$generationInfo = @"
# Synthetic GENERATION_INFO.toml for pack.ps1 tests. Not a real WinMD provenance record.
winmd = "windows.ai.isolationsession.winmd"
winmd_preview = "windows.ai.isolationsession.preview.winmd"
target_windows_crate = "0.62"
windows_bindgen = "0.62.1"
instance = "$Instance"
runtime_dir = "%ProgramFiles%\\Microsoft\\Agentic Runtime\\$Instance"
os_build = "test"
winmd_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
generated_utc = "2026-01-01T00:00:00.0000000Z"
"@

$nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$PackageId</id>
    <version>$Version</version>
    <title>Windows AI Isolation Session SDK (build-time metadata)</title>
    <authors>Microsoft</authors>
    <owners>Microsoft</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>Synthetic test package.</description>
    <summary>SDK for the Windows.AI.IsolationSession API: build-time metadata only.</summary>
    <tags>Windows IsolationSession WinRT WinMD MXC AgenticRuntime metadata sdk test</tags>
    <readme>README.md</readme>
  </metadata>
  <files>
    <file src="payload\windows.ai.isolationsession.winmd" target="metadata" />
    <file src="payload\windows.ai.isolationsession.preview.winmd" target="metadata" />
    <file src="payload\GENERATION_INFO.toml" target="metadata" />
    <file src="README.md" target="" />
  </files>
</package>
"@

$contentTypes = @"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="winmd" ContentType="application/octet" />
  <Default Extension="toml" ContentType="application/octet" />
  <Default Extension="md" ContentType="application/octet" />
</Types>
"@

$rels = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$PackageId.nuspec" Id="R0" />
</Relationships>
"@

$zip = [System.IO.Compression.ZipFile]::Open($OutFile, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Add-TextEntry -Archive $zip -EntryName "README.md" -Text "# Synthetic IsoSession SDK test package`n"
    Add-BytesEntry -Archive $zip -EntryName "metadata/windows.ai.isolationsession.winmd" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("synthetic-winmd-bytes"))
    Add-BytesEntry -Archive $zip -EntryName "metadata/windows.ai.isolationsession.preview.winmd" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("synthetic-preview-winmd-bytes"))
    Add-TextEntry -Archive $zip -EntryName "metadata/GENERATION_INFO.toml" -Text $generationInfo
    Add-TextEntry -Archive $zip -EntryName "_rels/.rels" -Text $rels
    Add-TextEntry -Archive $zip -EntryName "[Content_Types].xml" -Text $contentTypes
    Add-TextEntry -Archive $zip -EntryName "$PackageId.nuspec" -Text $nuspec
}
finally {
    $zip.Dispose()
}

Write-Output $OutFile
