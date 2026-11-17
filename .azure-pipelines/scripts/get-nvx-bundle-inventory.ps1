function Get-NvxBundleInventory {
    $source = Join-Path $PSScriptRoot '..\..\src\mxc-sdk\src\backends\nvx\crate_runtime.rs'
    $text = Get-Content -LiteralPath $source -Raw -ErrorAction Stop
    $match = [regex]::Match($text, '(?s)const REQUIRED_BUNDLE_FILES:\s*&\[&str\]\s*=\s*&\[(.*?)\];')
    if (-not $match.Success) { throw 'NVX resolver bundle inventory not found.' }

    $files = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($match.Groups[1].Value -split '\r?\n')) {
        $entry = $line.Trim()
        if (-not $entry) { continue }
        if ($entry -cnotmatch '^r"([^"]+)",$') { throw "Invalid NVX resolver inventory entry: $entry" }
        $path = $Matches[1].Replace('\', '/')
        if ($path -match '(^/|//|(^|/)\.\.?(/|$)|:)' -or -not $files.Add($path)) {
            throw "Invalid or duplicate NVX resolver inventory path: $path"
        }
    }
    if (-not $files.Contains('SHA256SUMS') -or -not $files.Contains('bin/aci_edge_agent.dll')) {
        throw 'NVX resolver inventory is incomplete.'
    }
    return @($files)
}
