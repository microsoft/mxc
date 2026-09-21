function Resolve-RegressionExecutable {
    param(
        [string]$Value,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Value) {
        if (Test-Path -LiteralPath $Value -PathType Leaf) {
            return (Resolve-Path -LiteralPath $Value).Path
        }
        $command = Get-Command $Value -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) {
            return $command.Source
        }
        throw "Executable '$Value' was not found."
    }

    $local = Join-Path (Get-Location) $Name
    if (Test-Path -LiteralPath $local -PathType Leaf) {
        return (Resolve-Path -LiteralPath $local).Path
    }

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }
    throw "Executable '$Name' was not found in the current directory or PATH."
}
