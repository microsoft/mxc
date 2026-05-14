#TODO replace with xperf

$AcpPath = "c:\users\adminuser\desktop\acp"
import-module "$AcpPath\Microsoft.Windows.Win32Isolation.ApplicationCapabilityProfiler.dll"
start-profiling -force