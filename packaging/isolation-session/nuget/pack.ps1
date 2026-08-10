<#
.SYNOPSIS
    Repackage the IsoSession SDK NuGet to additively carry the runtime shim
    (IsoSessionApp.dll) and its side-by-side manifest (IsoSession.manifest),
    on top of the existing metadata-only package, producing an
    architecture-suffixed package for the requested ArchTag.

.DESCRIPTION
    Copyright (c) Microsoft Corporation. All rights reserved.

    This is the MXC-side packaging step for the IsoSession artifact plan. It
    takes an existing metadata-only SDK nupkg as the base and injects two
    entries under runtimes/<rid>/native/, where <rid> is the NuGet runtime
    identifier for the requested -ArchTag (x64 -> win-x64, arm64 -> win-arm64):

        IsoSessionApp.dll   -- the in-proc WinRT activation shim (from BinDir)
        IsoSession.manifest -- SxS manifest with the <iso:instance> MonthId
                               marker (stamped from IsoSession.manifest.template)

    The output package ID is architecture-suffixed (e.g.
    "Microsoft.Windows.AI.IsolationSession.SDK.x64" or ".arm64") so that x64
    and arm64 runtime payloads can be published and restored side by side
    without colliding.

    The base package's metadata/ entries (both .winmd files and
    GENERATION_INFO.toml) are copied byte-for-byte, so MXC bindings build.rs
    invariants stay green: the winmd_sha256, the {id}.{version}.nupkg
    filename, and the instance <-> version-minor coupling are all preserved.
    Extra runtimes/ entries are ignored by build.rs's gate.

    Design rationale for the additive approach: the .winmd files are build
    artifacts that are never committed to the OS repo, so we cannot re-run a
    clean `nuget pack` from source here.  Starting from the already-published
    metadata-only nupkg guarantees the hash-gated metadata is untouched.

    Validation is strict: the base package's <version> (nuspec) and its
    embedded GENERATION_INFO.toml `instance` value must both match -MonthId
    exactly, or this script throws. A silent mismatch here would ship a
    runtime shim under the wrong month's identity, which downstream MXC/
    IsoSessionApp instance matching would fail on in a much more confusing way
    at execution time -- so we fail fast at pack time instead.

.PARAMETER BinDir
    Build output directory containing IsoSessionApp.dll (e.g. _NTTREE).

.PARAMETER BaseNupkg
    Path to the existing metadata-only SDK nupkg to extend. Never modified
    in place; a copy is made before any mutation.

.PARAMETER OutDir
    Directory to write the repackaged nupkg into.

.PARAMETER ArchTag
    Target architecture for the runtime payload. Must be 'x64' or 'arm64'.
    Selects both the NuGet runtime identifier (RID) the shim/manifest are
    injected under and the architecture suffix appended to the output
    package ID.

.PARAMETER MonthId
    Runtime instance / MonthId to stamp into the manifest (default 2026.06).
    Must match the base package's nuspec <version> (0.<MonthId minus dots>.0)
    and the base package's embedded GENERATION_INFO.toml `instance` value --
    this script throws if either disagrees.

.PARAMETER ManifestTemplate
    Path to IsoSession.manifest.template (default: alongside this script).

.EXAMPLE
    .\pack.ps1 -BinDir $env:_NTTREE `
               -BaseNupkg C:\mxc\external\windows-sdk\isolation-session\Microsoft.Windows.AI.IsolationSession.SDK.0.202606.0.nupkg `
               -OutDir .\out `
               -ArchTag x64 `
               -MonthId 2026.06

.EXAMPLE
    .\pack.ps1 -BinDir $env:_NTTREE `
               -BaseNupkg .\Microsoft.Windows.AI.IsolationSession.SDK.0.202606.0.nupkg `
               -OutDir .\out `
               -ArchTag arm64 `
               -MonthId 2026.06
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinDir,

    [Parameter(Mandatory = $true)]
    [string]$BaseNupkg,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$ArchTag,

    [string]$MonthId = "2026.06",

    [string]$ManifestTemplate = (Join-Path $PSScriptRoot "IsoSession.manifest.template")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# --- Explicit ArchTag -> NuGet RID mapping ---------------------------------
# Single source of truth for the architecture <-> runtime-identifier
# coupling used throughout this script. Add new architectures here only.
$archRidMap = @{
    "x64"   = "win-x64"
    "arm64" = "win-arm64"
}
$rid = $archRidMap[$ArchTag]
if (-not $rid) {
    # Unreachable given [ValidateSet], but keeps the mapping self-defending
    # if the set and the map ever drift apart.
    throw "No RID mapping registered for ArchTag '$ArchTag'."
}

# --- Validate inputs -------------------------------------------------------

if ($MonthId -notmatch '^\d{4}\.\d{2}$') {
    throw "MonthId '$MonthId' is not in YYYY.MM format (e.g. 2026.06)."
}

$appDll = Join-Path $BinDir "IsoSessionApp.dll"
if (-not (Test-Path -LiteralPath $appDll)) {
    throw "IsoSessionApp.dll not found in BinDir: $appDll"
}

if (-not (Test-Path -LiteralPath $BaseNupkg)) {
    throw "Base nupkg not found: $BaseNupkg"
}

if (-not (Test-Path -LiteralPath $ManifestTemplate)) {
    throw "Manifest template not found: $ManifestTemplate"
}

$strippedInstance = $MonthId.Replace('.', '')
$expectedVersion = "0.$strippedInstance.0"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "ArchTag:    $ArchTag"
Write-Host "RID:        $rid"
Write-Host "MonthId:    $MonthId"
Write-Host "App shim:   $appDll"
Write-Host "Base nupkg: $BaseNupkg"

# --- Stamp the manifest ----------------------------------------------------

# Read as text, substitute the placeholder, and re-encode as UTF-8 (no BOM)
# via .NET so the exact bytes are controlled (Set-Content/Out-File can inject a
# BOM or rewrite line endings -- both consumers use naive byte parsers).
$manifestText = [System.IO.File]::ReadAllText($ManifestTemplate)
$manifestText = $manifestText.Replace('$(MonthId)', $MonthId)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$manifestBytes = $utf8NoBom.GetBytes($manifestText)

# --- Helpers ----------------------------------------------------------------

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# (Re)write a zip entry from a byte[]. Deletes an existing entry first so
# Update mode replaces rather than duplicates.
function Set-ZipEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [byte[]]$Bytes
    )
    $existing = $Archive.GetEntry($EntryName)
    if ($existing) { $existing.Delete() }
    $entry = $Archive.CreateEntry($EntryName)
    $stream = $entry.Open()
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

# Read a zip entry to a string.
function Get-ZipEntryText {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName
    )
    $entry = $Archive.GetEntry($EntryName)
    if (-not $entry) { return $null }
    $reader = New-Object System.IO.StreamReader($entry.Open())
    try { return $reader.ReadToEnd() }
    finally { $reader.Dispose() }
}

# Read a zip entry to a byte[] (used for tamper-evidence hashing of the
# preserved metadata entries).
function Get-ZipEntryBytes {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName
    )
    $entry = $Archive.GetEntry($EntryName)
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

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

# --- Strict pre-flight validation against the base nupkg -------------------
# Read (but do not yet mutate) the base nupkg to validate the version and
# GENERATION_INFO instance agree with -MonthId. Any mismatch here is a hard
# failure: packing a mismatched instance would silently ship a runtime shim
# under the wrong month identity.

$baseZip = [System.IO.Compression.ZipFile]::OpenRead($BaseNupkg)
$baseNuspecEntryName = $null
$baseNuspecText = $null
$baseWinmdHashes = @{}
$baseGenerationInfoHash = $null
$basePackageId = $null
try {
    $baseNuspecEntry = $baseZip.Entries | Where-Object { $_.FullName -like "*.nuspec" } | Select-Object -First 1
    if (-not $baseNuspecEntry) {
        throw "Base nupkg '$BaseNupkg' does not contain a .nuspec entry."
    }
    $baseNuspecEntryName = $baseNuspecEntry.FullName
    $baseNuspecText = Get-ZipEntryText -Archive $baseZip -EntryName $baseNuspecEntryName

    $idMatch = [regex]::Match($baseNuspecText, '<id>([^<]+)</id>')
    if (-not $idMatch.Success) {
        throw "Base nuspec '$baseNuspecEntryName' has no <id> element."
    }
    $basePackageId = $idMatch.Groups[1].Value.Trim()

    $versionMatch = [regex]::Match($baseNuspecText, '<version>([^<]+)</version>')
    if (-not $versionMatch.Success) {
        throw "Base nuspec '$baseNuspecEntryName' has no <version> element."
    }
    $baseVersion = $versionMatch.Groups[1].Value.Trim()
    if ($baseVersion -ne $expectedVersion) {
        throw ("Base nupkg version '$baseVersion' does not match MonthId '$MonthId' " +
               "(expected '$expectedVersion'). Refusing to pack a mismatched instance.")
    }

    $genInfoEntry = $baseZip.Entries | Where-Object { $_.FullName -eq "metadata/GENERATION_INFO.toml" } | Select-Object -First 1
    if (-not $genInfoEntry) {
        throw "Base nupkg '$BaseNupkg' is missing 'metadata/GENERATION_INFO.toml'."
    }
    $genInfoText = Get-ZipEntryText -Archive $baseZip -EntryName $genInfoEntry.FullName
    $instanceMatch = [regex]::Match($genInfoText, '(?m)^\s*instance\s*=\s*"([^"]+)"')
    if (-not $instanceMatch.Success) {
        throw "metadata/GENERATION_INFO.toml in '$BaseNupkg' has no `instance` field."
    }
    $genInfoInstance = $instanceMatch.Groups[1].Value.Trim()
    if ($genInfoInstance -ne $MonthId) {
        throw ("Base nupkg GENERATION_INFO.toml instance '$genInfoInstance' does not match " +
               "MonthId '$MonthId'. Refusing to pack a mismatched instance.")
    }
    $baseGenerationInfoHash = Get-Sha256Hex -Bytes (Get-ZipEntryBytes -Archive $baseZip -EntryName $genInfoEntry.FullName)

    # Record byte hashes of every metadata/*.winmd entry so we can assert
    # after repackaging that they were preserved byte-for-byte.
    $baseZip.Entries |
        Where-Object { $_.FullName -like "metadata/*.winmd" } |
        ForEach-Object {
            $baseWinmdHashes[$_.FullName] = Get-Sha256Hex -Bytes (Get-ZipEntryBytes -Archive $baseZip -EntryName $_.FullName)
        }
    if ($baseWinmdHashes.Count -eq 0) {
        throw "Base nupkg '$BaseNupkg' contains no metadata/*.winmd entries."
    }
}
finally {
    $baseZip.Dispose()
}

Write-Host "Base package id:   $basePackageId"
Write-Host "Base package ver:  $expectedVersion (validated against MonthId)"
Write-Host "GENERATION_INFO instance validated: $MonthId"
Write-Host ("Preserved metadata/*.winmd entries: {0}" -f ($baseWinmdHashes.Keys -join ', '))

# --- Assemble the architecture-suffixed package -----------------------------

$archPackageId = "$basePackageId.$ArchTag"
$outNupkgName = "$archPackageId.$expectedVersion.nupkg"
$outNupkg = Join-Path $OutDir $outNupkgName
Write-Host "Out nupkg:  $outNupkg"

Copy-Item -LiteralPath $BaseNupkg -Destination $outNupkg -Force

$zip = [System.IO.Compression.ZipFile]::Open($outNupkg, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    Set-ZipEntry -Archive $zip -EntryName "runtimes/$rid/native/IsoSessionApp.dll" `
        -Bytes ([System.IO.File]::ReadAllBytes($appDll))
    Set-ZipEntry -Archive $zip -EntryName "runtimes/$rid/native/IsoSession.manifest" `
        -Bytes $manifestBytes

    # --- Patch [Content_Types].xml so the package stays a valid OPC part set.
    $ctName = "[Content_Types].xml"
    $ct = Get-ZipEntryText -Archive $zip -EntryName $ctName
    if ($ct) {
        foreach ($ext in @("dll", "manifest")) {
            if ($ct -notmatch "Extension=`"$ext`"") {
                $ct = $ct -replace '(</Types>)', ("  <Default Extension=`"$ext`" ContentType=`"application/octet`" />`r`n`$1")
            }
        }
        Set-ZipEntry -Archive $zip -EntryName $ctName -Bytes $utf8NoBom.GetBytes($ct)
    }

    # --- Patch the .nuspec: architecture-suffixed id, registered runtime
    #     files under the selected RID, and refreshed summary prose.
    $nuspec = $baseNuspecText

    $nuspec = $nuspec -replace '<id>[^<]+</id>', "<id>$archPackageId</id>"

    $runtimeDllEntry = "runtimes\$rid\native\IsoSessionApp.dll"
    $runtimeManifestEntry = "runtimes\$rid\native\IsoSession.manifest"
    if ($nuspec -notmatch [regex]::Escape($runtimeDllEntry)) {
        $runtimeFiles = @"
    <file src="payload\$runtimeDllEntry" target="runtimes\$rid\native" />
    <file src="payload\$runtimeManifestEntry" target="runtimes\$rid\native" />
"@
        $nuspec = $nuspec -replace '(\s*</files>)', ("`r`n$runtimeFiles`$1")
    }

    $nuspec = $nuspec -replace '<summary>[^<]*</summary>',
        ("<summary>SDK for the Windows.AI.IsolationSession API ($ArchTag): build-time metadata " +
         "(winmd + provenance) plus the in-proc runtime shim (IsoSessionApp.dll) and its SxS " +
         "manifest for the $rid runtime.</summary>")

    Set-ZipEntry -Archive $zip -EntryName $baseNuspecEntryName -Bytes $utf8NoBom.GetBytes($nuspec)
}
finally {
    $zip.Dispose()
}

# --- Post-build verification -------------------------------------------------
# Re-open the produced package read-only and assert:
#   1. Every expected entry (metadata + the new runtime entries + nuspec) is
#      present.
#   2. The metadata/*.winmd and metadata/GENERATION_INFO.toml bytes are
#      unchanged from the base package (tamper-evidence for the hash-gated
#      MXC build.rs invariants).

$verify = [System.IO.Compression.ZipFile]::OpenRead($outNupkg)
try {
    $expectedEntries = @(
        "metadata/GENERATION_INFO.toml",
        "runtimes/$rid/native/IsoSessionApp.dll",
        "runtimes/$rid/native/IsoSession.manifest",
        $baseNuspecEntryName
    ) + @($baseWinmdHashes.Keys)

    $missingEntries = @($expectedEntries | Where-Object { -not $verify.GetEntry($_) })
    if ($missingEntries.Count -gt 0) {
        throw "Repackaged nupkg '$outNupkg' is missing expected entries: $($missingEntries -join ', ')"
    }

    $genInfoBytesAfter = Get-ZipEntryBytes -Archive $verify -EntryName "metadata/GENERATION_INFO.toml"
    $genInfoHashAfter = Get-Sha256Hex -Bytes $genInfoBytesAfter
    if ($genInfoHashAfter -ne $baseGenerationInfoHash) {
        throw "metadata/GENERATION_INFO.toml bytes changed during repackaging (sha256 mismatch)."
    }

    foreach ($winmdName in $baseWinmdHashes.Keys) {
        $hashAfter = Get-Sha256Hex -Bytes (Get-ZipEntryBytes -Archive $verify -EntryName $winmdName)
        if ($hashAfter -ne $baseWinmdHashes[$winmdName]) {
            throw "$winmdName bytes changed during repackaging (sha256 mismatch)."
        }
    }

    Write-Host "`nRepackaged nupkg: $outNupkg" -ForegroundColor Cyan
    Write-Host "Package id:  $archPackageId" -ForegroundColor Cyan
    Write-Host "Version:     $expectedVersion" -ForegroundColor Cyan
    Write-Host "RID:         $rid" -ForegroundColor Cyan
    Write-Host "Verified metadata bytes unchanged (winmd + GENERATION_INFO.toml)." -ForegroundColor Cyan
    Write-Host "Entries:" -ForegroundColor Cyan
    $verify.Entries | Select-Object FullName, Length | Format-Table -AutoSize | Out-String | Write-Host
}
finally {
    $verify.Dispose()
}

Write-Output $outNupkg
