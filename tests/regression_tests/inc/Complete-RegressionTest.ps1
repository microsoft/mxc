function Complete-RegressionTest {
    param(
        [Parameter(Mandatory)]
        [bool]$Passed,
        [Parameter(Mandatory)]
        [string]$SuccessMessage,
        [Parameter(Mandatory)]
        [string]$FailureMessage,
        [int]$FailureExitCode = 1
    )

    if ($Passed) {
        Write-Host "PASSED: $SuccessMessage" -ForegroundColor Green
        exit 0
    }

    if ($FailureExitCode -eq 0) {
        $FailureExitCode = 1
    }
    Write-Host "FAILED: $FailureMessage" -ForegroundColor Red
    exit $FailureExitCode
}
