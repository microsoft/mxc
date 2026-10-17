# Node V1.Dev exact-JSON API

Public subpath: `@microsoft/mxc-sdk/v1/dev`. All operations accept one
complete caller-authored exact-version JSON string and return Promises.
The SDK never stamps a version or reserializes the document through the V1
stable mapper. Native exact parsing remains authoritative for unknown fields,
unsupported versions, policy, and backend availability. There is no
package-root alias.

`JsonOptions` contains optional `experimental?: boolean` authorization,
independent of the authored JSON version. `PtyJsonOptions` additionally
contains optional `size?: MxcPtySize` (24 rows by 80 columns by default).
Execution returns the existing V1 result or process types. Lifecycle and
validation return the complete native response JSON string. Phase-specific
methods reject a different phase before native dispatch.

```typescript
export function runJson(json: string, options?: JsonOptions): Promise<ExecutionResult>;
export function spawnJson(json: string, options?: JsonOptions): Promise<MxcProcess>;
export function spawnWithPtyJson(json: string, options?: PtyJsonOptions): Promise<MxcPtyProcess>;

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

Captured stdout and stderr are returned as lossy UTF-8 text. Pipe and PTY
operations resolve with owning V1 handles after startup. Existing-container
execution does not deprovision its caller-owned container. On timeout,
in-container capture closes its output streams and returns the text collected
so far. If capture fails, disposal cannot replace the
original read or wait error; read failures reject without waiting for the
workload to exit. The Node ProcessContainer one-shot PTY route
passes the original UTF-8 JSON through `wxc-exec --config-base64`, including
the historical `0.9.0-alpha` `appcontainer` alias, rather than the stable
typed mapper. Its Promise resolves when the executor starts, before the executor
finishes policy validation; subsequent failures appear in combined terminal
output and its exit code. This route cannot expose structured native warnings
or output metadata through its current terminal channel. It forwards
`process.timeout` to `wxc-exec`, but `wait().timedOut` remains `false` on an
executor exit even if the executor enforced that timeout; the terminal
channel supplies no distinct timeout outcome.
