# Windows OS-version support

This is the reference for **Windows OS support of the `processcontainer` and `isolation_session` backends**.

## Releases

| Windows 11 release | Process Isolation | Session Isolation |
|--------------------|-------------------|------------------|
| 24H2 | [26100.9278](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update) | [26100.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 25H2 | [26200.9278](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update) | [26200.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 26H2 | [26300.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) | [26300.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 26H1 | [28000.2804](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120996-windows-11-26h1-update) | [28000.3086](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124006-windows-11-26h1-update) |

## Creation-policy diagnostics

On the selected BaseContainer path, CPSE is the creation entrypoint on every
host. After its policy-denied HRESULT, MXC retrieves the calling thread's cached
refusal through the optional `GetLastProcessSecurityEnvironmentPolicyResult`
export. `PSE_SUPPORT_POLICY_RESULT` advertises that getter, not whether policy
governs the caller. This adds no release-floor requirement or tier-selection
change; unavailable diagnostics never replace the original creation result.
See [detailed policy errors](../../development/guides/process-container-adding-os-features.md#detailed-policy-errors)
for the diagnostic contract and retrieval-failure handling.
