# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-RegressionCommandLine {
    param(
        [Parameter(Mandatory)]
        [string]$ConfigJson,
        [Parameter(Mandatory)]
        [string]$CommandLine
    )

    $config = $ConfigJson | ConvertFrom-Json
    if ($null -eq $config.process) {
        throw "Regression configuration is missing the process object."
    }

    $config.process | Add-Member -NotePropertyName "commandLine" -NotePropertyValue $CommandLine
    $config | ConvertTo-Json -Depth 10 -Compress
}
