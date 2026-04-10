$feature = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
if ($null -eq $feature -or $feature.State -ne "Enabled") {
  Write-Host "::error::Windows Hypervisor Platform is not enabled. E2E tests require WHP on windows-latest."
  exit 1
}

$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($null -eq $cs -or -not $cs.HypervisorPresent) {
  Write-Host "::error::HypervisorPresent is false — WHP feature is enabled but hypervisor is not running."
  exit 1
}

Write-Host "WHP is enabled and hypervisor is present."
if ($env:GITHUB_OUTPUT) {
  Add-Content -Path $env:GITHUB_OUTPUT -Value "whp_available=true"
}
