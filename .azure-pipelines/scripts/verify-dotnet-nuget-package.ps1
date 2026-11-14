param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [switch]$RequireWslc,

    [switch]$VerifyNvxRuntime
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $PackagePath))
try {
    $entries = @{}
    foreach ($entry in $archive.Entries) {
        $entries[$entry.FullName.Replace('\', '/')] = $true
    }
    if (@($entries.Keys | Where-Object { $_ -eq 'plm.exe' -or $_ -like '*/plm.exe' }).Count) {
        throw 'NuGet package contains the retired PLM executable.'
    }

    if ($VerifyNvxRuntime) {
        . (Join-Path $PSScriptRoot 'get-nvx-bundle-inventory.ps1')
        $prefix = 'runtimes/win-x64/aci-edge-sandboxes/'
        $required = @(
            'build/Microsoft.Mxc.Sdk.Nvx.Runtime.targets',
            'buildTransitive/Microsoft.Mxc.Sdk.Nvx.Runtime.targets',
            'README.md',
            'LICENSE.md'
        )
        $required += @(Get-NvxBundleInventory | ForEach-Object { "$prefix$_" })
        $missing = @($required | Where-Object { -not $entries.ContainsKey($_) })
        if ($missing.Count) { throw "NVX runtime package is missing required files:`n  $($missing -join "`n  ")" }
        $stray = @($entries.Keys | Where-Object { $_ -match '(?i)(^|/)(mxc_ffi|Microsoft\.Mxc\.Sdk)\.dll$' })
        if ($stray.Count) { throw "NVX runtime package contains base SDK binaries: $($stray -join ', ')" }
        $nuspecs = @($archive.Entries | Where-Object { $_.FullName -match '^[^/]+\.nuspec$' })
        if ($nuspecs.Count -ne 1) { throw 'Expected exactly one root nuspec in the NVX runtime package.' }
        $reader = [System.IO.StreamReader]::new($nuspecs[0].Open())
        try { [xml]$nuspec = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $metadata = $nuspec.SelectSingleNode("/*[local-name()='package']/*[local-name()='metadata']")
        $id = $metadata.SelectSingleNode("*[local-name()='id']").InnerText
        $version = $metadata.SelectSingleNode("*[local-name()='version']").InnerText
        if ($id -ne 'Microsoft.Mxc.Sdk.Nvx.Runtime') { throw "Unexpected package ID: $id" }
        foreach ($framework in @('net8.0', 'net10.0')) {
            $groups = @($metadata.SelectNodes("*[local-name()='dependencies']/*[local-name()='group']") | Where-Object { $_.targetFramework -eq $framework -or $_.targetFramework -eq ".NETCoreApp,Version=v$($framework.Substring(3))" })
            if ($groups.Count -ne 1) { throw "Expected one $framework dependency group." }
            $dependencies = @($groups[0].SelectNodes("*[local-name()='dependency']") | Where-Object { $_.id -eq 'Microsoft.Mxc.Sdk' })
            if ($dependencies.Count -ne 1 -or $dependencies[0].version -ne "[$version]") { throw "Expected exact Microsoft.Mxc.Sdk [$version] dependency for $framework." }
        }
        Write-Host "Verified NVX runtime package $version in $PackagePath"
        return
    }

    $required = @(
        'lib/net8.0/Microsoft.Mxc.Sdk.dll',
        'lib/net8.0/Microsoft.Mxc.Sdk.pdb',
        'lib/net10.0/Microsoft.Mxc.Sdk.dll',
        'lib/net10.0/Microsoft.Mxc.Sdk.pdb',
        'runtimes/win-x64/native/mxc_ffi.dll',
        'runtimes/win-arm64/native/mxc_ffi.dll',
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
            'runtimes/win-x64/native/mxc-wslc-gateway.tar',
            'runtimes/win-arm64/native/wxc-wslc-daemon.exe',
            'runtimes/win-arm64/native/wslcsdk.dll',
            'runtimes/win-arm64/native/mxc-wslc-gateway.tar'
        )
    }

    $missing = @($required | Where-Object { -not $entries.ContainsKey($_) })
    if ($missing.Count -ne 0) {
        throw "NuGet package is missing required files:`n  $($missing -join "`n  ")"
    }

    Write-Host "Verified $($required.Count) required files in $PackagePath"
}
finally {
    $archive.Dispose()
}
