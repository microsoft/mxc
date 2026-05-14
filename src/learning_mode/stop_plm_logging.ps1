#Param for file locations
param(
    [string]$LogDir = (Join-Path (Get-Location) "logs" (Get-Date -Format "yyyy-MM-dd_HHmmss")),
    [string]$FilePath,
    [string]$OutputConfigPath,
    [bool]$InPlaceEdit,
    [string]$AcpPath
)


#TODO replace with xperf
$AcpPath = "c:\users\adminuser\desktop\acp"
import-module "$AcpPath\Microsoft.Windows.Win32Isolation.ApplicationCapabilityProfiler.dll"

$traceFileName = "trace.etl"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
# Set-Location $logDir

stop-profiling -TracePath $logDir\$traceFileName
Get-ProfilingResults -EtlFilePaths $logDir\$traceFileName -RecordsOutputPath $logDir\results.csv -SummaryOutputPath $logDir\summary.txt -ManifestPath $logDir\manifest.xml

$summaryPath = Join-Path $logDir "summary.txt"
$filePaths = @()
if (Test-Path $summaryPath) {
    $inFileSection = $false
    foreach ($line in Get-Content $summaryPath) {
        if ($line -match '^\s*Type:\s*File\s*$') {
            $inFileSection = $true
            continue
        }
        if ($inFileSection -and -not ($line.Trim() -eq '')) {
            $trimmed = $line.Trim()

            #Stripping away leading \\??\\
            $trimmed = $trimmed.substring(4)

            $filePaths += $trimmed
            # Write-Host $trimmed
        }
    }
    Write-Host #newline
}

if ($FilePath) {
    $destConfig = Join-Path $logDir (Split-Path $FilePath -Leaf)
    Copy-Item -Path $FilePath -Destination $destConfig -Force
    $config = Get-Content $destConfig -Raw | ConvertFrom-Json
    write-host $config

    if (-not $config.PSObject.Properties['filesystem']) {
        $config | Add-Member -NotePropertyName filesystem -NotePropertyValue ([pscustomobject]@{})
    }
    if (-not $config.filesystem.PSObject.Properties['readwritePaths']) {
        $config.filesystem | Add-Member -NotePropertyName readwritePaths -NotePropertyValue @()
    }

    $ReadWrite = @($config.filesystem.readwritePaths)
    $merged = $ReadWrite + ($filePaths | Where-Object { $ReadWrite -notcontains $_ })
    $config.filesystem.readwritePaths = [string[]]$merged

    # if (-not $config.filesystem.PSObject.Properties['readonlyPaths']) {
    #     $config.filesystem | Add-Member -NotePropertyName readonlyPaths -NotePropertyValue @()
    # }
    
    # Only files have their parent directories added as readonly. 
    # I couldn't get this to work with just read @Salah does shouldn't it only require read desktop if it has explicit write permission for a file?

    $readonly = @($config.filesystem.readwritePaths)
    foreach ($p in  $readonly) {
        if (-not (Test-Path -Path $p -PathType Leaf)) { continue }
        $parent = Split-Path $p -Parent
        if ($parent -and ($readonly -notcontains $parent) -and ($readonly -notcontains $parent)) {
            $readonly += $parent
        }
    }
    $config.filesystem.readwritePaths = [string[]]$readonly

    $adjustedPath = Join-Path (Split-Path $destConfig -Parent) ("Adjusted_" + (Split-Path $destConfig -Leaf))
    $config | ConvertTo-Json -Depth 32 | Set-Content -Path $adjustedPath -Encoding UTF8

    Copy-Item -Path $adjustedPath  -Destination (Split-Path $FilePath -Parent)
}

