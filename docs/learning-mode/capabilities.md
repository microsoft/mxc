# Learning-mode capabilities

MXC sandboxes are **deny-by-default**: when a workload touches a file, registry
key, or other resource the policy does not grant, the access is blocked and the
OS returns the usual "Access is denied" error. For non-trivial workloads this is
operationally fragile — the author must enumerate every path the workload will
ever touch up front, or hand the operator a stack trace and ask them to guess.

**Learning mode** turns those denied accesses into observable events. It is
enabled per-run through two Windows-specific policy capabilities. These
capabilities are the *inputs* to learning mode; the machinery that collects and
surfaces the resulting denial events is layered on top in later work.

> **Platform support.** Learning-mode capabilities are **Windows-only** and
> apply to the AppContainer-based backends (classic AppContainer and
> BaseContainer, which share `backends/appcontainer/common`). On other platforms
> the capability strings are ignored.

## The two capabilities

The two capabilities are **semantically distinct and must not be conflated**:

| Capability              | Behavior                                              | Enforcement                          |
| ----------------------- | ----------------------------------------------------- | ------------------------------------ |
| `learningModeLogging`   | Logs every **failed** access check (deny-and-record). | **Unchanged** — accesses stay denied. |
| `permissiveLearningMode`| Logs **every** access check and **allows** it (audit / allow-all). | **Weakened** — the container no longer enforces deny-by-default. |

### `learningModeLogging` — deny-and-record

The OS records each access check that *would have been denied*, but the access
is **still denied**. Containment is unchanged, so this is safe to use as a
diagnostic aid: the workload behaves exactly as it would without learning mode,
while producing a record of what it tried and failed to reach.

### `permissiveLearningMode` — audit / allow-all

The OS records **every** access check and **allows** it. This is an audit mode:
it answers "what would this workload touch if nothing were blocked?" but it does
so by **not enforcing deny-by-default** for the duration of the run.

Because it relaxes containment, `permissiveLearningMode` is **security-sensitive**:
whenever it is present, both the AppContainer and BaseContainer runners record a
**security warning**. The library does not write it to the host's stderr — it
must not write to an embedding process's terminal behind its back — so each
surface delivers it explicitly:

| Surface | How the warning is delivered |
|---------|------------------------------|
| Rust | `Sandbox::warnings()` / `Output::warnings` |
| C# | `RunResult.Warnings` |
| C ABI (`mxc_ffi`) | `MxcRunResult::warnings_json_utf8` (JSON array of strings) |
| `wxc-exec` | printed to stderr after the run — the CLI owns its terminal |

It is a reserved internal capability enabled by the dedicated audit/capture
entry points.

The parser rejects both learning-mode capability names in
`processContainer.capabilities`, case-insensitively. This prevents a policy from
selecting contradictory modes or bypassing the security-sensitive entry points.

## How to enable them

Enable deny-and-record through the dedicated `learningMode` setting:

```jsonc
{
  "processContainer": {
    "learningMode": true
  }
}
```

Enable permissive audit mode through the CLI:

```text
wxc-exec --audit --config <config>
```

These entry points inject the reserved capability strings internally; users
must not add them directly to `processContainer.capabilities`.
When either learning-mode capability is in effect the runner emits a diagnostic
describing the mode (informational logging for `learningModeLogging`, a retained
security warning for `permissiveLearningMode`, readable via `warnings()`).

## Three learning-mode flows

Learning-mode telemetry is consumed through three distinct flows. They differ in
*who* runs them, *how* the capability is supplied, and *whether* deny-by-default
stays enforced:

| Flow | Audience | Entry point | Enforcement |
| ---- | -------- | ----------- | ----------- |
| **Developer inner-loop** | The author bringing a workload up | `--audit` CLI flag | Relaxed (allow-all) |
| **App / user-configurable** | Apps that let end users tune their own config | `captureDenials` (`mode: "block"`) / `learningModeLogging` | Enforced (deny-and-record) |
| **Fleet auditing** | IT admins | `captureDenials` (`mode: "allow"`) / `permissiveLearningMode` | Relaxed (allow-all) |

1. **Developer inner-loop (`--audit`).** A developer runs `wxc-exec --audit`
   with ProcessContainer containment to discover the capabilities and paths
   their process needs. `--audit` is rejected for every other Windows backend.
   It is also mutually exclusive with `captureDenials`; use
   `captureDenials.mode: "allow"` for permissive application-driven capture.
   It is a compatibility wrapper over `captureDenials.mode: "allow"` with ETL
   retention forced on, and injects `permissiveLearningMode`. The selected
   ProcessContainer capture backend owns the trace lifecycle: complete PSEC/V2
   hosts use native capture without PLM or UAC, while legacy or incompatible
   tiers use the session-scoped guarded-WPR fallback and elevate only its
   fixed-operation guardian. The CLI consumes the returned JSON and ETL paths,
   relocates the policy output, its verbose logging sibling, and the trace to
   `denials.json`, `denials.verbose.json`, and `trace.etl`, and generates the
   source snapshot and `Adjusted_*.json` from the policy denials without decoding
   ETL again. Truncated analysis skips the adjusted config.

   ```
   wxc-exec --audit --config <config>
   ```

2. **App / user-configurable (`captureDenials` block / `learningModeLogging`).**
   An app wants to let its users "configure" their own sandbox. Each user
   workflow differs, so the app records what was blocked, presents it through its
   own UX, and re-generates the config with the new paths/capabilities.
   Deny-by-default stays enforced — the workload behaves exactly as it would in
   production while the denials are recorded.

3. **Fleet auditing (`captureDenials` allow / `permissiveLearningMode`).**
   IT admins audit access checks across a fleet by running MXC instances in
   permissive learning mode. This flow does **not** trigger UAC: the capability
   is supplied through config and takes effect directly, allowing and recording
   every access check.

## Relationship to denial capture

Injecting these capabilities makes the OS *emit* learning-mode events. The
Windows-only `captureDenials` config switch drives collecting those events and
surfacing the resulting denials to the caller. Its `mode` selects how each
ungranted access is handled while it is recorded:

> **Host selection.** MXC prefers native capture on a feature-enabled Windows
> build exposing the complete official V2 API set:
> `StartLearningModeTrace`, `StopLearningModeTrace`,
> `CloseLearningModeTrace`, `CreateProcessSecurityEnvironment`,
> `QueryProcessSecurityEnvironmentSupport`, and
> `CloseProcessSecurityEnvironment`. When that set is unavailable or cannot
> fully honor the requested policy, MXC retains the highest compatible legacy
> containment tier (SBOX, AppContainer+BFS, or AppContainer+DACL) and pairs it
> with the guarded WPR capture provider. Unsupported hosts return
> `backend_unavailable` only when neither path can preserve the full policy.
>
> Internal validation confirmed that build `26657.1002` exposes only the
> incompatible earlier contract and is rejected, while build `26663.1000`
> exposes the complete V2 contract. These are validation points, not a public
> Windows release-floor commitment; callers should rely on the runtime probe.
>
> Native PSEC capture cannot represent `processContainer.leastPrivilege`
> because the process security-environment API does not expose an LPAC token
> option. MXC therefore retains a compatible legacy containment tier and uses
> guarded WPR instead of weakening or rejecting the requested policy.
>
> Native PSEC capture also cannot currently represent `network.proxy` without a
> separate proxy AppContainer peer identity. Compatible requests use guarded
> WPR with the legacy tier that can enforce the proxy contract.
>
> Native capture uses `filesystem.deniedPaths` only when
> `QueryProcessSecurityEnvironmentSupport` advertises `PSE_SUPPORT_FS_DENY`.
> Otherwise MXC selects a compatible legacy SBOX, AppContainer+BFS, or
> AppContainer+DACL tier and uses guarded WPR.

- `mode: "block"` (default) maps onto `learningModeLogging`
  (deny-and-record) — the app / user-configurable flow.
- `mode: "allow"` maps onto `permissiveLearningMode` (allow-and-record)
  — the fleet-auditing flow.

### Output file the caller consumes

After the sandboxed workload exits, MXC decodes the captured denials and writes
the policy JSON deliverable a host application reads to regenerate its
sandbox policy:

```json
{
  "denials": [
    {
      "resource": "C:\\Users\\test\\secret.txt",
      "resourceType": "file",
      "accessType": "read",
      "pid": 1234,
      "filetime": "132847890123456789"
    },
    {
      "resource": "internetClient",
      "resourceType": "capability",
      "accessType": "unknown",
      "pid": 1234,
      "filetime": "132847890123512345"
    }
  ],
  "summary": {
    "exitCode": 0,
    "totalDenials": 2,
    "deniedResourcesTruncated": false
  }
}
```

- `denials` is already de-duplicated per `(resource, accessType)`, so
  `summary.totalDenials` equals `denials.length`.
- Analysis retains at most 10,000 unique denials and processes at most
  1,000,000 ETW events. Reaching the unique-denial bound stops adding policy
  entries but continues bounded diagnostic accounting; reaching either bound
  sets `summary.deniedResourcesTruncated` to `true`.
- `resource` is the user-visible identifier for the denied resource,
  interpreted by `resourceType`: an absolute `C:\…` path for `file`, the
  AppContainer **capability name** (e.g. `internetClient`) for `capability`,
  and the raw resource identifier otherwise. Named Section, SymbolicLink, and
  Timer access checks are emitted as `other`. Well-known capability SIDs are
  resolved to their policy name; custom (hashed) capability SIDs that can't be
  reversed fall back to the `S-1-15-3-…` SID string. Event 28 is
  schema-discriminated: UI-shaped `Category`/`Detail` payloads emit `ui`
  resources instead of treating the package SID as a capability.
- `resourceType` is one of `file`, `ui`, `network`, `capability`, `other`;
  `accessType` is one of `read`, `write`, `execute`, `unknown`. Capability
  denials are recorded under `block`; current `allow` traces expose capability
  checks as empty-`ObjectType` access events that are omitted because they do
  not carry a stable capability identifier.
- `filetime` is a decimal string containing the Windows `FILETIME` value, so
  JavaScript consumers retain all 64 bits without numeric precision loss.

### Network denial sources

Feature-enabled Windows builds can add WFP decisions to the managed Learning
Mode ETL through the manifested
`Microsoft-Windows-LearningMode-NetworkDecision` provider
(`{71237669-21C3-4101-BD2F-FF38945D725A}`). MXC accepts event ID `1`,
`NetworkDecisionV1`, with schema version `1`. The OS Learning Mode broker owns
the WFP subscription, runtime-filter lookup, subject scoping, event
normalization, queue draining, and ETW flush before the trace is sealed.

MXC currently recognizes two normalized source domains:

- App Isolation missing-capability decisions map capability IDs `0`, `1`, and
  `2` to `internetClient`, `internetClientServer`, and
  `privateNetworkClientServer`.
- Tessera direct-network default-deny decisions carrying the version-1
  ProcessModel filter tag map a complete remote endpoint to a `network`
  resource such as `tcp://203.0.113.10:443` or
  `udp://[2001:db8::1]:53`.

Tessera explicit denies, allow exclusions, and proxy-containment decisions are
intentional authored policy rather than missing grants. They are retained in
the verbose logging artifact but are not emitted as policy recommendations;
recommending a direct allow for proxy containment could bypass the proxy.
Malformed events, unknown reasons, identity mismatches, and incomplete
endpoints are also verbose-only.
Legacy, malformed, and future Tessera filter tags are normalized as the
unknown reason and remain verbose-only until their policy meaning is proven.

Actionable network records include an additive `details` object with
`kind: "network"` and the normalized source, reason, direction, protocol,
endpoint, application ID, and runtime filter ID. The WFP event does not provide
a reliable workload PID, so these records use `pid: 0`; the broker-provided
package, user, and application identities remain available to the decoder for
validation and diagnostics. `filetime` is the original WFP event timestamp
carried in the normalized payload, not the later ETW emission time.

This source is available only through native managed broker capture. The
guarded-WPR fallback filters ETW by exact workload process generations, while
the normalized network event's ETW header identifies the broker process, so
guarded-WPR analysis intentionally excludes it.

### Verbose logging event signatures

Every successful decode also writes a deterministic sibling file:
`denials.<run-id>.json` produces `denials.<run-id>.verbose.json`. This verbose
logging artifact is a bounded, sensitive-value-redacted superset containing
policy denial occurrences plus diagnostic outcomes omitted from the policy file:

```json
{
  "version": 1,
  "signatures": [
    {
      "signature": {
        "provider": "kernelGeneral",
        "providerGuid": "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}",
        "eventId": 14,
        "reason": "canonicalDenial",
        "pid": 4321,
        "accessType": "read",
        "resourceType": "file",
        "properties": [
          ["PackageSid", "S-1-15-3-1"],
          ["resource", "<REDACTED>"]
        ]
      },
      "count": 37
    }
  ],
  "summary": {
    "totalOccurrences": 37,
    "overflowOccurrences": 0,
    "canonicalOverflowOccurrences": 0,
    "aggregateGroupsTruncated": false,
    "processedEventsTruncated": false,
    "canonicalDenialLimitReached": false
  }
}
```

Signatures are keyed by symbolic provider category, provider GUID,
provider-scoped event ID, closed exclusion reason, PID, and sorted sanitized
properties. SIDs, capability names, GUIDs, PIDs/process identifiers, and
non-file resource values are retained. Complete file paths are replaced with
`<REDACTED>`; standalone user/account names remain replaced with
`<redacted-user>`.
Exact header timestamps and timestamp-like properties are omitted so otherwise
identical events deduplicate, and free-form decoder errors are never serialized.

Every valid denial candidate is classified as `canonicalDenial` in the verbose
file, including its first occurrence, later duplicates, and candidates observed
after the policy file's unique-denial bound. Those occurrences deduplicate under the
same signature and increment its count. `accessType` and `resourceType` are
included when denial extraction determined them; diagnostic outcomes without
those classifications omit the fields.

Candidates excluded from the policy output retain a closed diagnostic
reason and their sanitized event properties:

- `unusableResourcePath` means a File access-check resource could not be
  converted to a safe absolute DOS or UNC path. For example,
  `\Device\MountPointManager` is useful Devices-namespace evidence, but it is
  not a directly authorable filesystem grant.
- `unsupportedObjectType` means the event names a resource outside the
  supported policy model. Observed Section, SymbolicLink, and Timer checks are
  retained as `other` resources; remaining examples include
  `\BaseNamedObjects` as a Directory, ALPC Ports such as
  `ubpmtaskhostchannel`, and RPC Interface GUIDs.

Property values longer than 256 characters retain bounded prefix and suffix
context plus a SHA-256 digest of the complete sanitized value. This keeps long
named-object resources individually identifiable when they share a prefix
without exceeding the per-property bound. Redaction occurs before the digest is computed, so neither retained context nor
a digest is derived from a sensitive value.

Unknown event IDs from known Learning Mode providers are classified as
`unsupportedEventSchema`; the real ETL path retains their provider GUID and
PID without attempting an unsupported TDH payload decode.

Per-event TDH failures use closed diagnostic reasons:
`eventPayloadMalformed` means the payload conflicts with its declared schema,
`decoderLimitReached` means a nesting/element/work safety bound stopped
decoding, and `unsupportedPropertyEncoding` means the decoder cannot consume
that property shape. When TDH exposes it, the schema-declared name is retained
as the bounded `EventName` signature property. Free-form decoder errors are
never serialized. Failure to obtain the event schema remains a fatal analysis
error rather than being represented as a verbose logging signature.

To keep diagnostics bounded, verbose logging retains at most 4,096 distinct
signatures, 24 sorted properties per signature, and 256 characters per property
value. `overflowOccurrences` and `aggregateGroupsTruncated` indicate that
additional diagnostic groups were omitted. `canonicalOverflowOccurrences`
counts omitted policy-denial occurrences, while `processedEventsTruncated`
indicates that the 1,000,000-event limit prevented complete accounting. The
policy file itself is never reduced to make room for verbose logging.

The policy and verbose logging files fail together: MXC stages both and reports
capture failure unless both final artifacts are committed. The verbose logging path
is intentionally absent from stderr pointers and Rust, Node, C#, and FFI output
metadata; callers derive it from the policy output path using the naming rule
above.

**Locating the file.** Set `captureDenials.outputPath` to name the file
explicitly (its parent directory must already exist). MXC inserts a unique
per-run identifier (process id plus random suffix) into the file stem
(`denials.json` → `denials.<run-id>.json`) so concurrent and sequential
captures using the same configured path do not collide. If `outputPath` is
omitted, MXC writes a managed per-run temp file. `wxc-exec` prints **one
structured pointer line** to its own **stderr** — carrying the *actual* path —
so CLI callers can locate the deliverable without scanning the filesystem:

```json
{"type":"captureDenials","outputPath":"C:\\logs\\denials.4321_0123456789abcdef0123456789abcdef.json","exitCode":0,"totalDenials":2,"deniedResourcesTruncated":false}
```

The pointer echoes the policy file's `summary`; that file is the authoritative
record of denials. In-process Rust callers receive the same summary information through
`Output::output_metadata` or `Sandbox::output_metadata()` after waiting. The
C# SDK exposes it through `RunResult.OutputMetadata` and
`MxcSandboxProcess.OutputMetadata`.

By default, the intermediate ETW `.etl` trace is an internal, runner-managed
file in a protected per-run temporary directory that MXC deletes after
analysis. Set `captureDenials.retainEtl` to `true` to preserve the sealed trace
for diagnostics after a terminal wait. Both native PSEC/V2 capture and the
guarded-WPR fallback honor retention. Native retention begins under
`%LOCALAPPDATA%\Microsoft\MXC\capture-denials\working` and moves to a protected
per-run directory under `capture-denials\retained` only after sealing
succeeds.

WPR's source ETL is host-wide, so the elevated guarded-WPR helper never
transfers that file across the privilege boundary for `captureDenials` or
`--audit`. After the sandbox process tree terminates, the helper uses the
retained, job-attested process handles and their exact PID/creation/exit
`FILETIME` ranges to relog a second ETL. The
retained ETL contains only supported Learning Mode events whose event header
falls inside one of those attested process generations. Guarded analysis and
retention both consume that same filtered ETL; filtering failure transfers no
trace. The host-wide source remains in protected elevated scratch and is
deleted with that scratch. The unelevated caller writes the filtered retained
ETL beside its unique denials JSON output. Both paths contain the same run
identifier and remain distinct even when the configured output path has no
extension or already ends in `.etl`.

Abandoning or disposing a process without a terminal wait deletes or discards
the internal trace because no caller can observe its structured path. When
retention succeeds, the structured pointer and in-process metadata include its
absolute `etlPath`:

```json
{"type":"captureDenials","outputPath":"C:\\logs\\denials.4321_0123456789abcdef0123456789abcdef.json","exitCode":0,"totalDenials":2,"deniedResourcesTruncated":false,"etlPath":"C:\\Users\\runneradmin\\AppData\\Local\\Microsoft\\MXC\\capture-denials\\retained\\4321_0123456789abcdef0123456789abcdef\\capture.etl"}
```

If native post-seal analysis fails while retention is enabled, MXC preserves
the ETL and exposes its path through `captureDenialsError`. Guarded WPR
transfers the filtered ETL only after process-scoped analysis succeeds; if a
later JSON output step fails, the same error metadata identifies the
transferred trace.
ETL traces can contain sensitive resource paths and identifiers; callers that
retain them are responsible for deleting the ETL and, for native managed
retention, its now-empty per-run parent directory when no longer needed.
