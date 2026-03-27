# Tests that BFS paths with spaces (e.g. "C:\Users\Public\wxc bfs test") are
# quoted correctly when passed to bfscfg.exe.

param(
    [ValidateSet(
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu")
    ]
    [System.String]
    $Target = "x86_64-pc-windows-msvc",

    [ValidateSet('debug', 'release')]
    [System.String]
    $Config = "release"
)

$ErrorActionPreference = 'Stop'
$wxcExe = Join-Path $PSScriptRoot "..\src\target\$Target\$Config\wxc-exec.exe"
$testConfig = Join-Path $PSScriptRoot "..\test_configs\filesystem_bfs_spaces_test.json"
$testDir = "C:\Users\Public\wxc bfs test"

if (-not (Test-Path $wxcExe)) {
    Write-Host "ERROR: wxc-exec.exe not found at $wxcExe" -ForegroundColor Red
    Write-Host "Run 'build.bat --debug' from the repo root first." -ForegroundColor Yellow
    exit 1
}

try {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null

    Write-Host "Running BFS spaces-in-path test..."
    & $wxcExe --debug $testConfig
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: BFS path with spaces handled correctly" -ForegroundColor Green
} finally {
    if (Test-Path $testDir) {
        Remove-Item -Recurse -Force $testDir
    }
}
