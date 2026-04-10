Write-Host "=== Hypervisor Diagnostics ==="
Write-Host "OS: $([System.Environment]::OSVersion)"
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
Write-Host "HypervisorPresent: $($cs.HypervisorPresent)"
Write-Host "WinHvPlatform.dll exists: $(Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")"
$feature = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
Write-Host "HypervisorPlatform feature state: $($feature.State)"
