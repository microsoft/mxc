@echo off
mkdir c:\temp\wxc_test_allowedreadonly
echo 'Test Input' > c:\temp\wxc_test_allowedreadonly\test_input.txt
..\outputs\wxc\x64\Debug\wxc-exec.exe --debug ..\test_configs\filesystem_bfs_readonly_test.json
rmdir /s /q c:\temp\wxc_test_allowedreadonly