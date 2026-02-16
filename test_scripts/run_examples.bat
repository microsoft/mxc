@echo off
rem Create temp directories for test
mkdir c:\temp\wxc_sandbox
mkdir c:\temp\wxc_combined_test
..\outputs\wxc\x64\Debug\wxc_test_driver.exe ..\examples
rmdir /s /q c:\temp\wxc_sandbox
rmdir /s /q c:\temp\wxc_combined_test