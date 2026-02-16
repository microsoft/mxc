@echo off
rem Create temp directories for test
mkdir c:\temp\wxc_test_allowed
mkdir c:\temp\wxc_test_allowedreadonly
mkdir c:\temp\wxc_test_denied
echo "Test Input" >> c:\temp\wxc_test_allowedreadonly\test_input.txt
..\outputs\wxc\x64\Debug\wxc_test_driver.exe ..\test_configs
rmdir /s /q c:\temp\wxc_test_allowed
rmdir /s /q c:\temp\wxc_test_allowedreadonly
rmdir /s /q c:\temp\wxc_test_denied