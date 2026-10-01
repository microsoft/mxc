# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1245"),
    [switch]$CheckPrerequisites
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

$probeSourcePath = Join-Path $WorkDirectory "issue-1245-desktop-system-control.cs"
$probeExe = Join-Path $WorkDirectory "issue-1245-desktop-system-control.exe"
if (Test-Path -LiteralPath $probeExe) {
    Remove-Item -LiteralPath $probeExe -Force
}

$probeSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static class Program
{
    private const uint DesktopCreateWindow = 0x0002;
    private const int ErrorAccessDenied = 5;
    private const uint EwxForceIfHung = 0x0010;
    private const uint EwxLogoff = 0x0000;
    private const uint GenericAll = 0x10000000;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateDesktopW(
        string desktop,
        IntPtr device,
        IntPtr devMode,
        uint flags,
        uint desiredAccess,
        IntPtr securityAttributes);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ExitWindowsEx(uint flags, uint reason);

    public static int Main()
    {
        string name = "mxc_issue_1245_" + Process.GetCurrentProcess().Id;
        IntPtr desktop = CreateDesktopW(
            name,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            DesktopCreateWindow | GenericAll,
            IntPtr.Zero);

        if (desktop == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            Console.WriteLine("CREATE_DESKTOP=blocked win32Error=" + error + " message=" + new Win32Exception(error).Message);
            if (error != ErrorAccessDenied)
            {
                return 1;
            }
        }
        else
        {
            CloseDesktop(desktop);
            Console.WriteLine("CREATE_DESKTOP=allowed");
            Console.WriteLine("EXIT_WINDOWS=not-attempted safety=CreateDesktopW-was-allowed");
            return 2;
        }

        // Only attempt logoff after CreateDesktopW has already demonstrated
        // that this environment is denying desktop-system-control operations.
        bool logoffAccepted = ExitWindowsEx(EwxLogoff | EwxForceIfHung, 0);
        int logoffError = Marshal.GetLastWin32Error();
        if (logoffAccepted)
        {
            Console.WriteLine("EXIT_WINDOWS=allowed");
            return 1;
        }

        Console.WriteLine("EXIT_WINDOWS=blocked win32Error=" + logoffError + " message=" + new Win32Exception(logoffError).Message);
        return logoffError == ErrorAccessDenied ? 0 : 1;
    }
}
'@

Set-Content -LiteralPath $probeSourcePath -Value $probeSource -Encoding UTF8
$powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$compilerScript = "Add-Type -Path '$($probeSourcePath.Replace("'", "''"))' -OutputAssembly '$($probeExe.Replace("'", "''"))' -OutputType ConsoleApplication"
$encodedCompilerScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($compilerScript))
$compilerOutput = @(& $powerShellExe -NoProfile -NonInteractive -EncodedCommand $encodedCompilerScript 2>&1)
$compilerExitCode = $LASTEXITCODE
if ($compilerExitCode -ne 0 -or -not (Test-Path -LiteralPath $probeExe -PathType Leaf)) {
    $compilerOutput | Out-Host
    throw "Failed to compile the issue #1245 CreateDesktopW probe; compiler exit code was $compilerExitCode."
}

$controlOutput = @(& $probeExe 2>&1)
$controlText = $controlOutput | Out-String
$controlText | Write-Host
if (-not $controlText.Contains("CREATE_DESKTOP=allowed")) {
    if ($CheckPrerequisites) {
        Write-Host "SKIPPED: The uncontained CreateDesktopW control is blocked in this session." -ForegroundColor Yellow
        exit 77
    }
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "The uncontained CreateDesktopW control failed, so Tier 1 behavior cannot be isolated: $($controlText.Trim())"
}

$configJson = @"
{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
    },
    "ui": {
        "disable": false,
        "clipboard": "all",
        "injection": true
    },
    "processContainer": {
        "ui": {
            "isolation": "desktop",
            "desktopSystemControl": true,
            "systemSettings": "all",
            "ime": true
        }
    }
}
"@

$json = Add-RegressionCommandLine $configJson "`"$probeExe`""
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #1245: desktopSystemControl=true on the Tier 1 BaseContainer path." -ForegroundColor Cyan
$probeOutput = @(& $WxcExec --probe --config-base64 $base64 2>&1)
$probeExitCode = $LASTEXITCODE
$probeText = $probeOutput | Out-String
$probeText | Write-Host

try {
    $probe = $probeText | ConvertFrom-Json
} catch {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "The tier probe did not return valid JSON; exit code was $probeExitCode."
}

if ($probe.tier -ne "base-container") {
    if ($CheckPrerequisites) {
        Write-Host "SKIPPED: Tier 1 BaseContainer was not selected; selected tier was '$($probe.tier)'." -ForegroundColor Yellow
        exit 77
    }
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "Issue #1245 requires Tier 1 BaseContainer, but the selected tier was '$($probe.tier)'."
}

if ($probeExitCode -ne 0) {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "The Tier 1 request probe failed with exit code $probeExitCode." -FailureExitCode $probeExitCode
}

if ($CheckPrerequisites) {
    exit 0
}

$output = @(& $WxcExec --config-base64 $base64 2>&1)
$exitCode = $LASTEXITCODE
$outputText = $output | Out-String
$outputText | Write-Host

$desktopBlocked = $outputText -match "CREATE_DESKTOP=blocked win32Error=5\b"
$exitWindowsBlocked = $outputText -match "EXIT_WINDOWS=blocked win32Error=5\b"
$passed = $exitCode -eq 0 -and $desktopBlocked -and $exitWindowsBlocked

Complete-RegressionTest -Passed $passed `
    -SuccessMessage "Tier 1 left CreateDesktopW and ExitWindowsEx(EWX_LOGOFF) denied when desktopSystemControl=true." `
    -FailureMessage "Expected both operations to remain denied with ERROR_ACCESS_DENIED; CreateDesktopW blocked was $desktopBlocked, ExitWindowsEx blocked was $exitWindowsBlocked, executor exit code was $exitCode." `
    -FailureExitCode $exitCode
