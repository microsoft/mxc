# capture_bfs_deadlock.ps1
# Alternative to kernel debugging: captures WPR (Windows Performance Recorder)
# trace inside the VM to catch the BFS pushlock contention.
#
# Run this INSIDE the VM (elevated) BEFORE reproducing the issue.
# Uses ETW kernel lock tracing to capture the deadlock.

param(
    [int]$DurationSeconds = 300,
    [string]$OutputPath = "C:\bfs_trace.etl"
)

$ErrorActionPreference = "Stop"

Write-Host "=== BFS Deadlock WPR Capture ===" -ForegroundColor Cyan
Write-Host "This will record a $DurationSeconds-second kernel trace."
Write-Host "Reproduce the BFS scenario during recording."
Write-Host ""

# Start a kernel trace with SyncObject (lock) and FileIO providers
Write-Host "Starting ETW trace..." -ForegroundColor Yellow
$profileXml = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0">
  <Profiles>
    <SystemCollector Id="SC" Name="NT Kernel Logger">
      <BufferSize Value="1024"/>
      <Buffers Value="256"/>
    </SystemCollector>
    <SystemProvider Id="SP">
      <Keywords>
        <Keyword Value="CpuConfig"/>
        <Keyword Value="Loader"/>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="SynchronizationObjects"/>
        <Keyword Value="FileIO"/>
        <Keyword Value="FileIOInit"/>
        <Keyword Value="DiskIO"/>
      </Keywords>
      <Stacks>
        <Stack Value="ThreadCreate"/>
        <Stack Value="ReadyThread"/>
        <Stack Value="SynchronizationObjectWait"/>
        <Stack Value="FileCreate"/>
      </Stacks>
    </SystemProvider>
    <Profile Id="BfsLockTrace.Verbose.File" Name="BfsLockTrace" Description="BFS Lock Contention Trace" LoggingMode="File" DetailLevel="Verbose">
      <Collectors>
        <SystemCollectorId Value="SC">
          <SystemProviderId Value="SP"/>
        </SystemCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@

$wprProfile = "$env:TEMP\bfs_trace_profile.wprp"
$profileXml | Set-Content $wprProfile -Force

try {
    wpr -start $wprProfile -filemode 2>&1
    Write-Host "Trace started. Reproduce the issue now!" -ForegroundColor Green
    Write-Host "Waiting $DurationSeconds seconds (or press Ctrl+C to stop early)..."
    
    Start-Sleep $DurationSeconds
} finally {
    Write-Host "Stopping trace..." -ForegroundColor Yellow
    wpr -stop $OutputPath 2>&1
    Write-Host "Trace saved to: $OutputPath" -ForegroundColor Green
    Write-Host "Analyze with: WPA.exe $OutputPath" -ForegroundColor Cyan
}
