@echo off
rem Copyright (c) Microsoft Corporation. All rights reserved.
rem
rem Bundle terminate step for the IsoSession UI installer.
rem
rem Stops the versioned IsolationSession service and kills any IsolationProxy.exe
rem worker processes so the MSI can replace in-use files (e.g., during an in-month
rem repair or patch). Mirrors PowerToys' terminate_powertoys.cmd.
rem
rem   %1 = versioned service name (e.g., IsolationSession_2026_07_x64), supplied
rem        by the bundle via ExePackage InstallArguments.
rem
rem Always exits 0 (Vital="no") so a not-running service never blocks install.

if not "%~1"=="" (
    sc stop "%~1" >nul 2>&1
)

taskkill /IM IsolationProxy.exe /F >nul 2>&1

exit /b 0
