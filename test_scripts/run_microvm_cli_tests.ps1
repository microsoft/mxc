# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs MicroVM E2E tests through the MXC CLI (run-sdk --no-pty --containment microvm).

.DESCRIPTION
    - Locates the CLI entry point (cli/dist/cli.js)
    - Runs each test case via: node cli.js run-sdk --script <python> --policy ... --containment microvm --no-pty --experimental --debug
    - Validates exit codes and stdout content
    - Reports pass/fail summary with per-test performance timing
    - Writes microvm-cli-perf-results.json for CI artifact consumption

.PARAMETER CliPath
    Path to cli.js entry point. Defaults to ..\cli\dist\cli.js

.EXAMPLE
    .\run_microvm_cli_tests.ps1
    .\run_microvm_cli_tests.ps1 -CliPath C:\build\cli\dist\cli.js
#>

param(
    [string]$CliPath = "..\cli\dist\cli.js"
)

$ErrorActionPreference = "Stop"

# -- WHP check (local runs only) ---------------------------------------------
if (-not $env:CI) {
    function Test-WhpAvailable {
        if (-not (Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")) {
            return $false
        }
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            return ($cs -and $cs.HypervisorPresent)
        } catch {
            return $false
        }
    }

    if (-not (Test-WhpAvailable)) {
        Write-Host "SKIP: Windows Hypervisor Platform (WHP) is not available." -ForegroundColor Yellow
        Write-Host "      Enable it with: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform"
        exit 0
    }
}

Write-Host "`n=== MicroVM CLI E2E Tests ===" -ForegroundColor Cyan

# -- Locate CLI ---------------------------------------------------------------
if (-not (Test-Path $CliPath)) {
    Write-Host "ERROR: CLI not found at: $CliPath" -ForegroundColor Red
    Write-Host "       Build with: cd sdk && npm run build && cd ../cli && npm install && npm run build"
    exit 1
}

$cliJs = Resolve-Path $CliPath
Write-Host "CLI: $cliJs"

# -- Minimal SandboxPolicy file -----------------------------------------------
$policyFile = [System.IO.Path]::GetTempFileName()
@{ version = "0.4.0-alpha" } | ConvertTo-Json | Set-Content $policyFile -Encoding UTF8

# -- Test definitions ---------------------------------------------------------
$tests = @(
    @{
        Script       = "x = 42`ny = 58`nprint('Hello from MicroVM! sum=%d' % (x + y))"
        ExpectedExit = 0
        Description  = "Hello world"
        OutputContains = "sum=100"
    },
    @{
        Script       = "import sys; sys.exit(42)"
        ExpectedExit = 42
        Description  = "Exit code propagation"
    },
    @{
        Script       = "def fib(n):`n    a, b = 0, 1`n    for _ in range(n):`n        a, b = b, a + b`n    return a`n`nfor i in range(10):`n    print(f'fib({i}) = {fib(i)}')"
        ExpectedExit = 0
        Description  = "Multi-line script (fibonacci)"
        OutputContains = "fib("
    },
    @{
        Script       = "import json, math, hashlib`ndata = {'pi': math.pi, 'e': math.e, 'hash': hashlib.sha256(b'nanvix').hexdigest()[:16]}`nprint(json.dumps(data))"
        ExpectedExit = 0
        Description  = "Stdlib (json, math, hashlib)"
        OutputContains = "pi"
    },
    @{
        Script       = "for i in range(1000):`n    print(f'line {i}: ' + 'x' * 80)"
        ExpectedExit = 0
        Description  = "Large stdout (1000 lines)"
        OutputContains = "line 999"
    },
    @{
        Script       = "raise ValueError('intentional test error')"
        ExpectedExit = 1
        Description  = "Python exception"
        OutputContains = "ValueError"
    }
    # Note: timeout test is omitted — SandboxPolicy doesn't expose process.timeout.
    # Timeout behavior is covered by the wxc-exec direct tests (run_microvm_tests.ps1).
)

# -- Run tests ----------------------------------------------------------------
$passed = 0
$failed = 0
$results = @()

foreach ($test in $tests) {
    Write-Host "`n--- $($test.Description) ---" -ForegroundColor White

    # Write script to temp file to avoid Start-Process argument quoting issues
    $scriptFile = [System.IO.Path]::GetTempFileName()
    Set-Content $scriptFile -Value $test.Script -Encoding UTF8 -NoNewline

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    $process = Start-Process -FilePath "node" `
        -ArgumentList @(
            $cliJs,
            "run-sdk",
            "--script-file", $scriptFile,
            "--policy-file", $policyFile,
            "--containment", "microvm",
            "--no-pty",
            "--experimental",
            "--debug"
        ) `
        -PassThru -Wait `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile
    $sw.Stop()

    $actualExit = $process.ExitCode
    $expectedExit = $test.ExpectedExit
    $elapsedMs = $sw.ElapsedMilliseconds
    $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
    Remove-Item $stdoutFile, $stderrFile, $scriptFile -ErrorAction SilentlyContinue

    $pass = ($actualExit -eq $expectedExit)
    $reason = ""

    if (-not $pass) {
        $reason = "expected exit=$expectedExit, got exit=$actualExit"
    }

    # Check stdout content if OutputContains is specified
    if ($pass -and $test.OutputContains) {
        $combined = "$stdout`n$stderr"
        if ($combined -notmatch [regex]::Escape($test.OutputContains)) {
            $pass = $false
            $reason = "output missing '$($test.OutputContains)'"
        }
    }

    if ($pass) {
        Write-Host "  PASS (exit=$actualExit, ${elapsedMs}ms)" -ForegroundColor Green
        $passed++
        $results += @{ Test = $test.Description; Status = "PASS"; Exit = $actualExit; WallTimeMs = $elapsedMs }
    } else {
        Write-Host "  FAIL ($reason, ${elapsedMs}ms)" -ForegroundColor Red
        $combined = "$stdout`n$stderr"
        $combined -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 5 | ForEach-Object {
            Write-Host "    > $($_.TrimEnd())" -ForegroundColor Gray
        }
        $failed++
        $results += @{ Test = $test.Description; Status = "FAIL"; Exit = $actualExit; WallTimeMs = $elapsedMs }
    }
}

# -- Performance summary ------------------------------------------------------
Write-Host "`n=== Performance ===" -ForegroundColor Cyan
Write-Host ("  {0,-35} {1,10} {2,8}" -f "Test", "Time (ms)", "Status")
Write-Host ("  {0,-35} {1,10} {2,8}" -f "----", "---------", "------")
foreach ($r in $results) {
    $color = if ($r.Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("  {0,-35} {1,10} {2,8}" -f $r.Test, $r.WallTimeMs, $r.Status) -ForegroundColor $color
}

# Write JSON results for CI artifact consumption
$perfOutput = @{
    commit    = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    timestamp = (Get-Date -Format "o")
    via       = "cli"
    results   = $results | ForEach-Object {
        @{
            test         = $_.Test
            wall_time_ms = $_.WallTimeMs
            exit_code    = $_.Exit
            status       = $_.Status
        }
    }
}
$perfJsonPath = Join-Path (Split-Path $PSScriptRoot) "microvm-cli-perf-results.json"
$perfOutput | ConvertTo-Json -Depth 3 | Set-Content $perfJsonPath -Encoding UTF8
Write-Host "`n  Performance results written to: $perfJsonPath"

# -- Summary ------------------------------------------------------------------
$total = $passed + $failed
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Remove-Item $policyFile -ErrorAction SilentlyContinue
if ($total -eq 0) {
    Write-Host "  ERROR: No tests were executed." -ForegroundColor Red
    exit 1
}
Write-Host "  Passed: $passed / $total"
if ($failed -gt 0) {
    Write-Host "  Failed: $failed / $total" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "    - $($_.Test) (exit=$($_.Exit))" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "  All MicroVM CLI E2E tests passed!" -ForegroundColor Green
    exit 0
}
