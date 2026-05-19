@echo off
:: Thin wrapper around Invoke-MxcIsolationSessionTests.ps1. Sets the cmd
:: console codepage to UTF-8 (so Node's test reporter Unicode and any
:: child Write-Host output render correctly) and invokes PowerShell with
:: -ExecutionPolicy Bypass so an unsigned .ps1 runs without the default
:: Restricted policy blocking.
::
:: When run with no arguments, the .ps1 auto-discovers the
:: mxc-iso-test-package*.zip in this folder. Args are forwarded verbatim,
:: e.g.:
::    Run-Tests.cmd
::    Run-Tests.cmd -PackagePath C:\artifacts\mxc.zip
::    Run-Tests.cmd -ExtractPath D:\big-drive -ResultsPath D:\results

setlocal

for /f "tokens=2 delims=:" %%i in ('chcp') do set "ORIG_CP_RAW=%%i"
for /f "tokens=1" %%j in ("%ORIG_CP_RAW%") do set "ORIG_CP=%%j"
if "%ORIG_CP%"=="" set "ORIG_CP=437"

chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-MxcIsolationSessionTests.ps1" %*
set "EXITCODE=%ERRORLEVEL%"

chcp %ORIG_CP% >nul

endlocal & exit /b %EXITCODE%
