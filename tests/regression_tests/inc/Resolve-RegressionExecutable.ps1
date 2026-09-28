function Resolve-RegressionExecutable {
    param(
        [string]$Value,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Value) {
        if (Test-Path -LiteralPath $Value -PathType Leaf) {
            return (Resolve-Path -LiteralPath $Value).Path
        }
        $command = Get-Command $Value -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) {
            return $command.Source
        }
        throw "Executable '$Value' was not found."
    }

    $local = Join-Path (Get-Location) $Name
    if (Test-Path -LiteralPath $local -PathType Leaf) {
        return (Resolve-Path -LiteralPath $local).Path
    }

    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
    if (Test-Path -LiteralPath (Join-Path $repoRoot "src\Cargo.toml") -PathType Leaf) {
        $targetArchitecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            "aarch64-pc-windows-msvc"
        } else {
            "x86_64-pc-windows-msvc"
        }
        $sdkArchitecture = if ($targetArchitecture -eq "aarch64-pc-windows-msvc") { "arm64" } else { "x64" }
        $repoCandidates = @(
            (Join-Path $repoRoot "src\target\$targetArchitecture\debug\$Name"),
            (Join-Path $repoRoot "src\target\debug\$Name"),
            (Join-Path $repoRoot "src\target\$targetArchitecture\release\$Name"),
            (Join-Path $repoRoot "src\target\release\$Name"),
            (Join-Path $repoRoot "sdk\node\bin\$sdkArchitecture\$Name")
        )
        $repoExecutable = $repoCandidates |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            ForEach-Object { Get-Item -LiteralPath $_ } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($repoExecutable) {
            return $repoExecutable.FullName
        }
    }

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    if ($Name -eq "wxc-exec.exe" -and (Test-Path -LiteralPath (Join-Path $repoRoot "src\Cargo.toml") -PathType Leaf)) {
        throw "Executable '$Name' was not found in the current directory, repository build outputs, or PATH. Build it with '.\build.bat --debug' or 'cargo build --manifest-path src\Cargo.toml -p wxc'."
    }
    throw "Executable '$Name' was not found in the current directory, repository build outputs, or PATH."
}
