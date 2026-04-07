@echo off
:: Quick MicroVM smoke test — run from test_scripts\ directory
..\src\target\debug\wxc-exec.exe --debug --experimental ..\test_configs\microvm_hello.json
