<#
.SYNOPSIS
    Builds the WSLC egress gateway images committed under
    `src/mxc-sdk/assets/`.

.DESCRIPTION
    Cross-compiles `mxc-wslc-gateway` for x86_64 and aarch64 Linux musl and
    writes each binary into a single-layer `docker save` tar with no base
    image. Timestamps, owners and JSON formatting are fixed, so the same source
    and toolchain always give the same image ID. `mxc-sdk`'s build script reads
    the image ID from the committed tar and stages the tar beside the binary.

    Run this after changing the gateway (`src/tools/wslc_gateway/`,
    `src/mxc-sdk/src/backends/wslc/gateway_policy.rs`), its dependencies or
    `$gatewayToolchain`, and commit the updated tars.

    Run it on Windows: panic locations embed source paths, and Windows paths
    differ from Linux paths, so a Linux build gives different image IDs. The
    script always uses the x64 Windows host toolchain, because Cargo hashes
    the host into build script units and so into dependent crates' symbols.
    ARM64 Windows runs it under emulation.

.PREREQUISITES
    rustup. The script installs the x64 Windows host toolchain for
    `$gatewayToolchain` with the musl targets and `rust-src`, and links with
    the bundled `rust-lld`.
#>
[CmdletBinding()]
param(
    # Build into a temporary directory and fail if the committed tars differ.
    [switch] $Check
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$srcDir = Join-Path $repoRoot 'src'
$assetsDir = Join-Path $srcDir 'mxc-sdk\assets'
$profileName = 'wslc-gateway'
# Exact compiler for the committed images, so a new patch release of the
# workspace channel can't change their bytes.
$gatewayToolchain = '1.93.1'
$channelMatch = Select-String -Path (Join-Path $srcDir 'rust-toolchain.toml') -Pattern '^channel\s*=\s*"([^"]+)"'
if (-not $channelMatch) { throw 'No channel in src/rust-toolchain.toml.' }
$channel = $channelMatch.Matches[0].Groups[1].Value
if ($gatewayToolchain -notlike "$channel.*") {
    throw "`$gatewayToolchain '$gatewayToolchain' isn't on the workspace channel '$channel'. Update it in $PSCommandPath and regenerate the images."
}
$targets = [ordered]@{
    'x86_64'  = @{ Triple = 'x86_64-unknown-linux-musl'; ImageArch = 'amd64' }
    'aarch64' = @{ Triple = 'aarch64-unknown-linux-musl'; ImageArch = 'arm64' }
}

function Get-Sha256Hex([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Write-Field([byte[]] $Header, [int] $Offset, [string] $Value) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

# USTAR archive of regular files with uid/gid 0, empty owner names and mtime 0,
# padded to a 10240-byte record like tar and Python's tarfile.
function New-Tar([object[]] $Entries) {
    $out = New-Object IO.MemoryStream
    foreach ($entry in $Entries) {
        $header = New-Object byte[] 512
        Write-Field $header 0 $entry.Name
        Write-Field $header 100 ('{0}{1}' -f [Convert]::ToString($entry.Mode, 8).PadLeft(7, '0'), "`0")
        Write-Field $header 108 "0000000`0"
        Write-Field $header 116 "0000000`0"
        Write-Field $header 124 ('{0}{1}' -f [Convert]::ToString([long]$entry.Data.Length, 8).PadLeft(11, '0'), "`0")
        Write-Field $header 136 "00000000000`0"
        Write-Field $header 148 '        '
        Write-Field $header 156 '0'
        Write-Field $header 257 "ustar`0"
        Write-Field $header 263 '00'
        $sum = 0
        foreach ($b in $header) { $sum += $b }
        Write-Field $header 148 ('{0}{1} ' -f [Convert]::ToString($sum, 8).PadLeft(6, '0'), "`0")
        $out.Write($header, 0, 512)
        $out.Write($entry.Data, 0, $entry.Data.Length)
        $pad = (512 - ($entry.Data.Length % 512)) % 512
        $out.Write((New-Object byte[] $pad), 0, $pad)
    }
    $out.Write((New-Object byte[] 1024), 0, 1024)
    $pad = (10240 - ($out.Length % 10240)) % 10240
    $out.Write((New-Object byte[] $pad), 0, $pad)
    , $out.ToArray()
}

function New-GatewayImage([byte[]] $Binary, [string] $ImageArch) {
    $layer = New-Tar @(@{ Name = 'gateway'; Mode = 0x1ED; Data = $Binary })
    $diffId = Get-Sha256Hex $layer
    # Keys are sorted and unspaced so the config bytes, and so the ID, are stable.
    $config = [Text.Encoding]::UTF8.GetBytes(
        '{"architecture":"' + $ImageArch + '","config":{"Cmd":["/gateway"],"User":"0:0"},' +
        '"created":"1970-01-01T00:00:00Z","os":"linux",' +
        '"rootfs":{"diff_ids":["sha256:' + $diffId + '"],"type":"layers"}}')
    $imageId = Get-Sha256Hex $config
    $manifest = [Text.Encoding]::UTF8.GetBytes(
        '[{"Config":"' + $imageId + '.json","Layers":["' + $diffId + '/layer.tar"],' +
        '"RepoTags":["mxc-wslc-gateway:' + $imageId.Substring(0, 12) + '"]}]')
    $tar = New-Tar @(
        @{ Name = "$diffId/layer.tar"; Mode = 0x1A4; Data = $layer },
        @{ Name = "$imageId.json"; Mode = 0x1A4; Data = $config },
        @{ Name = 'manifest.json'; Mode = 0x1A4; Data = $manifest }
    )
    @{ Id = "sha256:$imageId"; Tar = $tar }
}

$targetDir = Join-Path $srcDir 'target'
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
$outDir = if ($Check) { Join-Path ([IO.Path]::GetTempPath()) "mxc-wslc-gateway-$PID" } else { $assetsDir }
New-Item -ItemType Directory -Force $outDir | Out-Null
$savedEnv = @{}
foreach ($name in 'RUSTUP_TOOLCHAIN', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER',
    'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER') {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name)
}

Push-Location $srcDir
try {
    $env:RUSTUP_TOOLCHAIN = "$gatewayToolchain-x86_64-pc-windows-msvc"
    $triples = @($targets.Values | ForEach-Object { $_.Triple })
    # With rust-src installed, rustc records std paths under the local
    # toolchain instead of /rustc/<commit>; require it and map it back.
    rustup toolchain install $env:RUSTUP_TOOLCHAIN --no-self-update --force-non-host --profile minimal `
        --component rust-src `
        @($triples | ForEach-Object { '--target', $_ })
    if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install failed ($LASTEXITCODE)" }
    Write-Host (rustc -V)
    $rustSrc = Join-Path (rustc --print sysroot) 'lib\rustlib\src\rust'
    $commit = (rustc -Vv | Select-String '^commit-hash: (\w+)').Matches[0].Groups[1].Value

    $env:RUSTFLAGS = $null
    cargo fetch --locked @($triples | ForEach-Object { '--target', $_ })
    if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed ($LASTEXITCODE)" }
    # Machine-specific paths would otherwise end up in panic locations. The
    # registry directory is named after the configured source (crates.io or a
    # mirror), so every one maps to the same path. rustc applies the last
    # matching prefix. With --target, these flags apply only to the
    # gateway, not build scripts.
    $remaps = @(
        "$cargoHome=/cargo",
        "$srcDir=/mxc",
        "$rustSrc=/rustc/$commit"
    ) + @(Get-ChildItem (Join-Path $cargoHome 'registry\src') -Directory |
        ForEach-Object { "$($_.FullName)=/cargo/registry/src/crates" })
    $env:CARGO_ENCODED_RUSTFLAGS = @($remaps | ForEach-Object { "--remap-path-prefix=$_" }) -join [char]0x1F
    $failed = @()
    foreach ($arch in $targets.Keys) {
        $triple = $targets[$arch].Triple
        $envTriple = $triple.ToUpperInvariant().Replace('-', '_')
        Set-Item "env:CARGO_TARGET_${envTriple}_LINKER" 'rust-lld'
        cargo build --locked --profile $profileName --target $triple --target-dir $targetDir `
            -p mxc-wslc-gateway
        if ($LASTEXITCODE -ne 0) { throw "cargo build for $triple failed ($LASTEXITCODE)" }

        $binaryPath = Join-Path $targetDir "$triple\$profileName\mxc-wslc-gateway"
        $image = New-GatewayImage ([IO.File]::ReadAllBytes($binaryPath)) $targets[$arch].ImageArch
        $name = "mxc-wslc-gateway-$arch.tar"
        [IO.File]::WriteAllBytes((Join-Path $outDir $name), $image.Tar)
        Write-Host ('{0,-34} {1,9:N0} bytes  {2}' -f $name, $image.Tar.Length, $image.Id)

        if ($Check) {
            $committed = Join-Path $assetsDir $name
            $committedHash = if (Test-Path $committed) { Get-Sha256Hex ([IO.File]::ReadAllBytes($committed)) }
            if ($committedHash -ne (Get-Sha256Hex $image.Tar)) { $failed += $name }
        }
    }
} finally {
    Pop-Location
    foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) }
    if ($Check) { Remove-Item -Recurse -Force $outDir -ErrorAction SilentlyContinue }
}

if ($failed) {
    throw ("These committed gateway images don't match the source: $($failed -join ', '). " +
        'Run scripts/build-wslc-gateway-image.ps1 on Windows and commit the updated tars.')
}
