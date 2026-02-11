@echo off
rem Create temp directories for test
mkdir c:\temp\wxc_sandbox
mkdir c:\temp\wxc_combined_test
..\x64\debug\wxc_test_driver.exe ..\examples
rmdir /s /q c:\temp\wxc_sandbox
rmdir /s /q c:\temp\wxc_combined_test