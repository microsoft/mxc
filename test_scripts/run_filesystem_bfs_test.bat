@echo off
mkdir c:\temp\wxc_test_allowed
mkdir c:\temp\wxc_test_denied
..\outputs\wxc\x64\Debug\wxc-exec.exe --debug ..\test_configs\filesystem_bfs_test.json
rmdir /s /q c:\temp\wxc_test_allowed
rmdir /s /q c:\temp\wxc_test_denied