# Node V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public subpath: `@microsoft/mxc-sdk/v1/dev`. Operations accept complete MXC
request JSON with a caller-declared contract version and return Promises.
MXC validates the unchanged document against its declared contract and
checks policy and backend availability.

`JsonOptions` contains optional `experimental?: boolean` authorization,
independent of the authored JSON version. `PtyJsonOptions` additionally
contains optional `size?: MxcPtySize` (24 rows by 80 columns by default).
`SpawnExtendedJsonOptions` additionally contains optional
`stdio?: SpawnStdio` (`'pipes'` by default).
Execution returns the existing V1 result or process types. Lifecycle and
validation return the complete native response JSON string. Phase-specific
methods reject a different phase before native dispatch.

```typescript
export function runJson(json: string, options?: JsonOptions): Promise<ExecutionResult>;
export function spawnJson(json: string, options?: JsonOptions): Promise<MxcProcess>;
export function spawnWithPtyJson(json: string, options?: PtyJsonOptions): Promise<MxcPtyProcess>;
export function spawnWithExtendedOptionsJson(
  json: string, options?: SpawnExtendedJsonOptions
): Promise<MxcProcess>;

export function runInContainerJson(json: string, options?: JsonOptions): Promise<ExecutionResult>;
export function spawnInContainerJson(json: string, options?: JsonOptions): Promise<MxcProcess>;
export function spawnInContainerWithPtyJson(
  json: string, options?: PtyJsonOptions
): Promise<MxcPtyProcess>;

export function provisionContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function startContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function stopContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function deprovisionContainerJson(json: string, options?: JsonOptions): Promise<string>;
export function validateProvisionJson(json: string, options?: JsonOptions): Promise<string>;
export function validateStartJson(json: string, options?: JsonOptions): Promise<string>;
export function validateStopJson(json: string, options?: JsonOptions): Promise<string>;
export function validateDeprovisionJson(json: string, options?: JsonOptions): Promise<string>;
export function validateProcessJson(json: string, options?: JsonOptions): Promise<string>;
```

Captured stdout and stderr are lossy UTF-8 text. Callers own pipe and PTY
handles. `spawnWithExtendedOptionsJson` with `stdio: 'inherit'` attaches the
workload to this process's standard streams and supports ProcessContainer,
Bubblewrap, and Seatbelt.
Existing-container execution leaves the container caller-owned.
On timeout, in-container capture returns partial text without waiting for
output streams to close. Read failures reject promptly, and cleanup
preserves the original read or wait error.

On Windows, ProcessContainer `spawnWithPtyJson` uses `wxc-exec`;
`0.9.0-alpha` requests support the `appcontainer` alias. Its Promise resolves
at executor startup, before policy validation. Later failures appear in
combined terminal output and the exit code. Structured warnings and output
metadata are unavailable on this route. The executor enforces
`process.timeout`, but `wait().timedOut` is `false`: the terminal channel
reports only an exit code.

For MicroVM output and recovery limitations, see the
[NVX backend guide](../../../backends/nvx/nvx.md#output-timeout-and-cleanup).
