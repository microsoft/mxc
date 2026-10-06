param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [switch]$RequireWslc
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $PackagePath))
try {
    $entries = @{}
    foreach ($entry in $archive.Entries) {
        $entries[$entry.FullName.Replace('\', '/')] = $true
    }

    $required = @(
        'lib/net8.0/Microsoft.Mxc.Sdk.dll',
        'lib/net8.0/Microsoft.Mxc.Sdk.pdb',
        'runtimes/win-x64/native/mxc_ffi.dll',
        'runtimes/win-x64/native/plm.exe',
        'runtimes/win-arm64/native/mxc_ffi.dll',
        'runtimes/win-arm64/native/plm.exe',
        'runtimes/linux-x64/native/libmxc_ffi.so',
        'runtimes/linux-arm64/native/libmxc_ffi.so',
        'runtimes/osx-arm64/native/libmxc_ffi.dylib',
        'README.md',
        'LICENSE.md'
    )

    if ($RequireWslc) {
        $required += @(
            'runtimes/win-x64/native/wxc-wslc-daemon.exe',
            'runtimes/win-x64/native/wslcsdk.dll',
            'runtimes/win-arm64/native/wxc-wslc-daemon.exe',
            'runtimes/win-arm64/native/wslcsdk.dll'
        )
    }

    $missing = @($required | Where-Object { -not $entries.ContainsKey($_) })
    if ($missing.Count -ne 0) {
        throw "NuGet package is missing required files:`n  $($missing -join "`n  ")"
    }

    $nuspecEntries = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
    if ($nuspecEntries.Count -ne 1) {
        throw "Expected exactly one .nuspec file in the NuGet package, found $($nuspecEntries.Count)"
    }

    $reader = [System.IO.StreamReader]::new($nuspecEntries[0].Open())
    try {
        [xml]$nuspec = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }

    $expectedCopyright = "$([char]0x00A9) Microsoft Corporation. All rights reserved."
    $actualCopyright = [string]$nuspec.package.metadata.copyright
    if ($actualCopyright -cne $expectedCopyright) {
        throw "NuGet package copyright metadata must be '$expectedCopyright', found '$actualCopyright'"
    }

    Write-Host "Verified $($required.Count) required files in $PackagePath"
}
finally {
    $archive.Dispose()
}
