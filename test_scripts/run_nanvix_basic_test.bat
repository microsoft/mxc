@echo off
:: Quick NanVix smoke test — run from test_scripts\ directory
..\src\target\debug\wxc-exec.exe --debug --experimental ..\test_configs\nanvix_hello.json
