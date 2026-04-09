param(
  [Parameter(Mandatory = $true)]
  [string]$JsonPath
)

if (Test-Path $JsonPath) {
  $data = Get-Content $JsonPath -Raw | ConvertFrom-Json
  Write-Host "`n=== MicroVM Performance Summary ==="
  Write-Host "Commit: $($data.commit)"
  Write-Host "Timestamp: $($data.timestamp)"
  Write-Host ""
  Write-Host ("{0,-35} {1,10} {2,8}" -f "Test", "Time (ms)", "Status")
  Write-Host ("{0,-35} {1,10} {2,8}" -f "----", "---------", "------")
  foreach ($r in $data.results) {
    Write-Host ("{0,-35} {1,10} {2,8}" -f $r.description, $r.wall_time_ms, $r.status)
  }
} else {
  Write-Host "::warning::No performance results found — perf JSON was not generated."
}
