# Windows OS-version support

This is the reference for **Windows OS support of the `processcontainer` and `isolation_session` backends**.

## Releases

| Windows 11 release | Process Isolation | Session Isolation |
|--------------------|-------------------|------------------|
| 24H2 | [26100.9278](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update) | [26100.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 25H2 | [26200.9278](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update) | [26200.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 26H2 | [26300.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) | [26300.9550](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124010-windows-11-24h2-25h2-update) |
| 26H1 | [28000.2804](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120996-windows-11-26h1-update) | [28000.3086](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/kb5124006-windows-11-26h1-update) |

## Learning Mode capture compatibility

`processContainer.captureDenials` selects its capture provider by runtime
capability probing rather than by the release table above. Native
ProcessContainer capture requires the PSEC create/query/close exports plus one
compatible Learning Mode start export and both lifecycle exports:

- `StartLearningModeTraceWithOptions` (preferred) or `StartLearningModeTrace`
- `StopLearningModeTrace`
- `CloseLearningModeTrace`

The option-aware start collects access and network events. The legacy start
collects access events only, so its trace cannot contain WFP network decisions.
If the selected option-aware call fails, MXC reports that failure and does not
retry through the legacy export. When native capture is unavailable, MXC uses
the guarded WPR provider only when the selected AppContainer tier and helper can
fully honor the request.

Internal validation found no native capture support on build `26657.1002` and
the complete option-aware contract on build `26663.1000`. These are validation
points, not public support boundaries; runtime probing remains authoritative.
