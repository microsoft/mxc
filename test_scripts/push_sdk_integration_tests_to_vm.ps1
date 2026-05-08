# Copies the SDK integration-test artifacts onto the connected TShell device.
#
# Prerequisites:
#   - Active TShell session connected via Open-Device.
#   - SDK binaries built locally:
#       build.bat --x64 --with-isolation-session
#   - SDK integration tests built locally:
#       cd sdk\tests\integration; npm install; npm run build
#
# Usage:
#   . .\push_sdk_integration_tests_to_vm.ps1
#
# Paths are anchored to this script's directory ($PSScriptRoot) so the
# script works regardless of the active TShell session's current location.

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$integrationDir = Join-Path $repoRoot 'sdk\tests\integration'
$binDir = Join-Path $repoRoot 'sdk\bin\x64'

putd $binDir WXC\sdk-integration-tests\bin\x64\
putd (Join-Path $integrationDir 'dist') WXC\sdk-integration-tests\dist\
putd (Join-Path $integrationDir 'node_modules') WXC\sdk-integration-tests\node_modules\
putd (Join-Path $integrationDir 'package.json') WXC\sdk-integration-tests\
putd (Join-Path $integrationDir 'run-tests.js') WXC\sdk-integration-tests\
