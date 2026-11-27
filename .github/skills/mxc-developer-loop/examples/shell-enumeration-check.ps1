param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Desktop', 'Documents')]
    [string]$Folder,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedFolder,
    [Parameter(Mandatory = $true)]
    [string]$FixtureName
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$checkIds = if ($Folder -eq 'Desktop') { @('desktop-file-found') } else { @('documents-path', 'documents-file-found') }
$results = @()
$exitCode = 0

function New-CheckResult {
    param([string]$Id, [bool]$Passed, [string]$Evidence)
    [ordered]@{ id = $Id; passed = $Passed; evidence = $Evidence }
}

try {
    if ($ExpectedFolder -notmatch '^[A-Za-z]:\\') {
        throw 'ExpectedFolder must be an independently supplied absolute drive path.'
    }
    if ([string]::IsNullOrWhiteSpace($FixtureName) -or $FixtureName -in @('.', '..') -or
        $FixtureName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw 'FixtureName must be a single nonempty file name, not a path.'
    }
    $expected = [System.IO.Path]::GetFullPath($ExpectedFolder)
    $fixture = [System.IO.Path]::Combine($expected, $FixtureName)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    if ($Folder -eq 'Desktop') {
        $shell = New-Object -ComObject Shell.Application
        $desktop = $shell.NameSpace('shell:Desktop')
        if ($null -eq $desktop) { throw 'Shell Desktop namespace was unavailable.' }
        $items = $desktop.Items()
        $found = $false
        for ($index = 0; $index -lt $items.Count; $index++) {
            $item = $items.Item($index)
            if ($item.IsFileSystem -and -not $item.IsFolder -and
                [string]::Equals([string]$item.Path, $fixture, $comparison)) {
                $found = $true
            }
        }
        $results += New-CheckResult 'desktop-file-found' $found (
            "Shell Desktop returned $($items.Count) items; exact filesystem file '$fixture' found=$found")
    } else {
        $resolved = [Environment]::GetFolderPath('Personal')
        $correctPath = -not [string]::IsNullOrWhiteSpace($resolved) -and
            [string]::Equals([System.IO.Path]::GetFullPath($resolved).TrimEnd('\'), $expected.TrimEnd('\'), $comparison)
        $found = $false
        $count = 0
        if ($correctPath) {
            $items = @(Get-ChildItem -LiteralPath $resolved -Force -ErrorAction Stop)
            $count = $items.Count
            $found = @($items | Where-Object {
                -not $_.PSIsContainer -and [string]::Equals($_.FullName, $fixture, $comparison)
            }).Count -gt 0
        }
        $results += New-CheckResult 'documents-path' $correctPath (
            "Resolved='$resolved'; expected='$expected'")
        $results += New-CheckResult 'documents-file-found' $found (
            "Correct folder=$correctPath; enumerated items=$count; exact file '$fixture' found=$found")
    }
} catch {
    $exitCode = 1
    $results = @()
    foreach ($id in $checkIds) {
        $results += New-CheckResult $id $false ("Check execution failed: " + $_.Exception.Message)
    }
    [Console]::Error.WriteLine($_.Exception.Message)
}

foreach ($result in $results) {
    [Console]::WriteLine('MXC_FUNCTIONAL_CHECK ' + ($result | ConvertTo-Json -Compress))
}
exit $exitCode
