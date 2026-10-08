# Learning-mode capabilities

> **Audience:** MXC consumers

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
> BaseContainer, which share `backends/process_container/common`). On other platforms
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
| C# | `ExecutionResult.Warnings` / `MxcProcess.Warnings` |
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
   ProcessContainer capture backend owns the trace lifecycle: compatible PSEC
   hosts use native capture without PLM or UAC, while incompatible tiers use
   the session-scoped guarded-WPR fallback and elevate only its fixed-operation
   guardian. The CLI consumes the returned JSON and ETL paths,
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

> **Host selection.** MXC uses native capture when Windows exposes the PSEC
> lifecycle plus a compatible Learning Mode lifecycle. It prefers
> `StartLearningModeTraceWithOptions`, which requests `ACCESS | NETWORK`, and
> falls back to access-only `StartLearningModeTrace` when the option-aware
> export is absent. Both paths require `StopLearningModeTrace`,
> `CloseLearningModeTrace`, `CreateProcessSecurityEnvironment`,
> `QueryProcessSecurityEnvironmentSupport`, and
> `CloseProcessSecurityEnvironment`. If the option-aware export exists but its
> call fails, MXC reports the failure rather than silently downgrading. When
> native capture is unavailable or cannot fully honor the requested policy,
> MXC retains the highest compatible legacy
> AppContainer containment tier (AppContainer+BFS or AppContainer+DACL) and pairs it
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
> option. MXC therefore uses a compatible AppContainer tier with guarded WPR
> instead of weakening or rejecting the requested policy.
>
> Native PSEC capture represents `runtimeConfig.networkProxy` with the PSEC
> proxy endpoint and either the requested proxy AppContainer peer identity or
> MXC's reserved unrestricted-loopback sentinel. Other proxy policies remain
> on a compatible AppContainer tier with guarded WPR capture.
>
> Native capture uses `filesystem.deniedPaths` only when
> `QueryProcessSecurityEnvironmentSupport` advertises `PSE_SUPPORT_FS_DENY`.
> Otherwise MXC selects a compatible AppContainer+BFS or AppContainer+DACL tier
> and uses guarded WPR.

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
  entries but continues bounded diagnostic accounting; reaching either bound, or
  failing to read a non-network event's schema, sets
  `summary.deniedResourcesTruncated` to `true`.
- `resource` is the user-visible identifier for the denied resource,
  interpreted by `resourceType`: an absolute `C:\…` path for `file`, the
  AppContainer **capability name** (e.g. `internetClient`) for `capability`,
  and the raw resource identifier otherwise. Well-known capability SIDs are
  resolved to their policy name; custom (hashed) capability SIDs that can't be
  reversed fall back to the `S-1-15-3-…` SID string. Named Section,
  SymbolicLink, and Timer checks are verbose-only because the config has no
  corresponding policy grants. Event 28 is
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
When option-aware native capture is selected, MXC requests both `ACCESS` and
`NETWORK` sources. A failed combined start fails the trace rather than retrying
with partial access-only collection. Legacy native capture remains access-only.
MXC does not coordinate with WFP directly.

Native PSEC capture has one capture-specific capability exception. When the
caller explicitly supplies a direct `network.egress` section and enables
`captureDenials`, MXC adds `internetClient` so the outbound attempt reaches
Tessera's WFP policy and can be recorded there. The authored egress table still
makes the allow-or-deny decision. This exception is not applied when
`network.egress` is absent, when the request supplies ingress only, when
capture is disabled, or when proxy mode is selected.

MXC currently recognizes two normalized source domains:

- App Isolation missing-capability decisions map capability IDs `0`, `1`, and
  `2` to `internetClient`, `internetClientServer`, and
  `privateNetworkClientServer`. These decisions remain actionable capability
  denials and carry the `addCapability` configuration recommendation in the
  version-5 verbose artifact.
- Tessera direct-network default-deny decisions map a complete remote endpoint
  to a `network` resource such as `tcp://203.0.113.10:443` or
  `udp://[2001:db8::1]:53`. These decisions remain actionable network denials.

`NetworkDecisionV1` retains its original 24-property event ID/version `1`
schema. Tessera attribution is carried only in the existing `Reason` field:

| Source/reason | Meaning | Version-5 recommendation |
|---|---|---|
| App Isolation `1` | Missing capability | `addCapability`: add the exact capability named by the actionable record. |
| Tessera `100` | Direct default deny | `addEgressAllow`: author an exact egress allow only when the numeric endpoint and protocol are representable. |
| Tessera `101` | Authored explicit deny | `reviewEgressDeny`: remove or narrow the matching deny if that authored restriction is unintended. Adding an allow does not override a deny. |
| Tessera `102` | Exclusion from an allow rule | `reviewAllowExclusion`: review or narrow the matching `to[].except` entry rather than broadening the existing allow. |
| Tessera `103` | Proxy-containment baseline | `useConfiguredProxy`: route the workload through `runtimeConfig.networkProxy` rather than enabling direct egress. |

The internal WFP provider-data format used to produce the reason is not part of
the ETW contract. MXC does not parse provider data or require additional policy
model, rule-kind, or rule-ordinal fields.

Tessera explicit denies, allow exclusions, and proxy-containment decisions are
intentional authored policy rather than missing grants. They do not appear as
actionable `DeniedResource` grant candidates. The version-5 artifact retains
their typed decision reason and the reason-specific review or proxy guidance
shown above. It never recommends a direct allow for these decisions.
Malformed events, unknown reasons, identity mismatches, and incomplete
endpoints are diagnostic-only and receive no success-shaped recommendation.
Reason `65535` remains `unknownNetworkReason`.

For reason `100`, the structured endpoint recommendation is emitted only when
MXC can preserve the observed numeric address and a supported protocol without
widening it to `any`. IPv4 addresses map to `/32`, IPv6 addresses map to
`/128`, TCP and UDP retain the observed port when present, and ICMP omits
ports. Unknown protocol encodings do not produce `addEgressAllow`.

Actionable network records use the existing `DeniedResource` shape. The
normalized protocol, remote address, and optional remote port are encoded in
`resource`; no network-specific field is added to the public Rust type or JSON
record. The WFP event does not provide a reliable workload PID, so these
records use `pid: 0`. `filetime` is the original WFP event timestamp carried
in the normalized payload, not the later ETW emission time.

The caller-facing network record is:

```json
{
  "resource": "tcp://203.0.113.10:443",
  "resourceType": "network",
  "accessType": "unknown",
  "pid": 0,
  "filetime": "132847890123512345"
}
```

The existing `(resource, accessType)` deduplication contract still applies.
When repeated events describe the same endpoint, the actionable record retains
the first observation's `pid` and `filetime`. Per-event source properties such
as direction, filter ID, local endpoint, package identity, and application ID
remain available only in the bounded verbose logging signature. Complete
application paths are redacted there as `<REDACTED>`; timestamps are omitted
from the signature so repeated observations can aggregate.

This source is available only through option-aware native managed broker
capture. The guarded-WPR fallback filters ETW by exact workload process
generations, while the normalized network event's ETW header identifies the
broker process, so guarded-WPR analysis intentionally excludes it.

The public Rust `DenialAnalyzer` contract remains source-compatible with MXC
1.x. It returns actionable WFP capability and reason-`100` network records
through the existing `DeniedResource` fields, but its existing exhaustive
provider and reason enums cannot truthfully represent the new WFP diagnostic
groups. The compatibility projection therefore does not fabricate a legacy
provider or reason: it omits those groups from the public verbose signature
array and includes their occurrence counts in the existing overflow counters.
MXC's native product capture path retains the complete groups in version 5.

### Verbose logging event signatures

Every successful decode also writes a deterministic sibling file:
`denials.<run-id>.json` produces `denials.<run-id>.verbose.json`. This verbose
logging artifact is a bounded, sensitive-value-redacted superset containing
policy denial occurrences plus diagnostic outcomes omitted from the policy file:

```json
{
  "version": 5,
  "signatures": [
    {
      "signature": {
        "provider": "learningModeNetworkDecision",
        "providerGuid": "{71237669-21C3-4101-BD2F-FF38945D725A}",
        "eventId": 1,
        "eventName": "NetworkDecisionV1",
        "reason": "actionable",
        "pid": 0,
        "accessType": "unknown",
        "resourceType": "network",
        "networkDecisionReason": "directDefaultDeny",
        "configurationRecommendation": "addEgressAllow",
        "networkEndpoint": {
          "protocol": "tcp",
          "remoteAddress": "203.0.113.10",
          "remotePort": 443
        },
        "properties": [
          ["ApplicationId", "<REDACTED>"],
          ["FilterId", "12345"]
        ]
      },
      "count": 3
    }
  ],
  "summary": {
    "totalOccurrences": 3,
    "overflowOccurrences": 0,
    "actionableOverflowOccurrences": 0,
    "aggregateGroupsTruncated": false,
    "processedEventsTruncated": false,
    "actionableLimitReached": false
  }
}
```

Version `3` is the legacy contract preceding scoped verbose diagnostics.
Version `4` adds the schema `eventName` field, the `other` provider category,
and `schemaUnavailable` outcome used by scoped verbose diagnostics. Version
`5` adds MXC's internal WFP provider, WFP-specific outcome reasons, typed
network decision reason, reason-specific configuration recommendation, and
exact endpoint components. Option-aware native
`captureDenials` writes version 5 even when a particular trace contains no WFP
occurrences. Legacy and guarded capture paths may still produce their
corresponding legacy document version. MXC readers that consume captured
artifacts accept versions 3, 4, and 5 and reject every other version rather
than interpreting an unknown provider or reason with an older vocabulary.

Signatures are keyed by symbolic provider category, provider GUID,
provider-scoped event ID, schema name, outcome reason from a fixed list, PID, and
sorted sanitized properties. SIDs, capability names, GUIDs, PIDs/process identifiers, and
non-file resource values are retained. Complete file paths are replaced with
`<REDACTED>`; standalone user/account names remain replaced with
`<redacted-user>`.
Exact header timestamps and timestamp-like properties are omitted so otherwise
identical events deduplicate, and free-form decoder errors are never serialized.

Every valid actionable denial is classified as `actionable` in the verbose
file, including its first occurrence, later duplicates, and candidates observed
after the actionable file's unique-denial bound. Those occurrences deduplicate
under the same signature and increment its count. `accessType` and
`resourceType` are included when denial extraction determined them; diagnostic
outcomes without those classifications omit the fields.

Version-5 WFP signatures may also include `networkDecisionReason`,
`configurationRecommendation`, and `networkEndpoint`. The decision reason can
remain present when endpoint decoding is incomplete, but an exact endpoint and
automatic allow recommendation are omitted when the decoder cannot represent
the policy change without broadening it. `FilterId` is diagnostic correlation
only and is never presented as a policy selector.

Candidates excluded from the actionable output retain a diagnostic reason
from a fixed list and their sanitized event properties:

- `notActionable` includes registry writes, registry checks whose access mask
  cannot be classified as a read, and recognized Section, SymbolicLink, and
  Timer checks. MXC has no corresponding policy grants, so reporting them in
  the actionable `captureDenials` file would not give the caller an action it
  could take. They remain available in verbose logging with their classified
  access type and sanitized resource.
- `unusableResourcePath` means a File access-check resource could not be
  converted to a safe absolute DOS or UNC path. For example,
  `\Device\MountPointManager` is useful Devices-namespace evidence, but it is
  not a directly authorable filesystem grant.
- `comActivation` and `comInterfaceCall` mark observed classic COM class
  activation and interface-call access checks: denied under `block`, recorded
  and allowed under `allow`. The CLSID or IID is retained. A missing identifier
  is `missingObjectName`; an invalid one is `eventPayloadMalformed`.
- `unsupportedObjectType` means the event names a resource outside the
  supported diagnostic model. Examples include `\BaseNamedObjects` as a
  Directory, ALPC Ports such as
  `ubpmtaskhostchannel`, and RPC Interface GUIDs.

Property values longer than 256 characters retain bounded prefix and suffix
context plus a SHA-256 digest of the complete sanitized value. This keeps long
named-object resources individually identifiable when they share a prefix
without exceeding the per-property bound. Redaction occurs before the digest is computed, so neither retained context nor
a digest is derived from a sensitive value.

Only Learning Mode events are decoded: Kernel-General events 14, 27, and 28,
PermissiveLearningMode events 14, 27, and 4907, and NetworkDecision event 1.
Other provider and event ID pairs are ignored. `unsupportedEventSchema` means
the event has no actionable extractor. NetworkDecision records are kept only by
unscoped analysis, with PID 0 and that reason; the local file keeps their
sanitized properties, including remote endpoints, while telemetry drops them.

Per-event TDH failures use these predefined diagnostic reasons:
`eventPayloadMalformed` means the payload is malformed or conflicts with its declared schema,
`decoderLimitReached` means a nesting/element/work safety bound stopped
decoding, and `unsupportedPropertyEncoding` means the decoder cannot consume
that property shape. When TDH exposes it, the schema-declared name is retained
as the bounded `eventName` signature field. Free-form decoder errors are
never serialized. `schemaUnavailable` means the event schema could not be
obtained. Analysis continues but sets `deniedResourcesTruncated` because the
unreadable event may have been a denial; network decisions are not denials, so
they do not. Schema failures
remain fatal for raw decoding and for scoping brokered capability events in
guarded traces.

To keep diagnostics bounded, verbose logging retains at most 4,096 distinct
signatures, 24 sorted properties per signature, and 256 characters per property
value. `overflowOccurrences` and `aggregateGroupsTruncated` indicate that
additional diagnostic groups were omitted. `actionableOverflowOccurrences`
counts omitted actionable-denial occurrences, while `processedEventsTruncated`
indicates that the 1,000,000-event limit prevented complete accounting. The
actionable file itself is never reduced to make room for verbose logging.

The actionable and verbose logging files fail together: MXC stages both and reports
capture failure unless both final artifacts are committed. The verbose logging path
is intentionally absent from stderr pointers and Rust, Node, C#, and FFI output
metadata; callers derive it from the actionable output path using the naming rule
above.

When stable telemetry is enabled and authorized, MXC may validate, compact, and
send this redacted verbose document through `Microsoft.MXC/MXC.VerboseDenials`. Each
event contains a valid JSON array of complete signatures and document
reconstruction metadata. Before emission, MXC derives provider GUIDs from the
predefined provider enum and drops every verbose property name and value. MXC does
not send the actionable denials file, workload-derived properties, or raw ETL
through telemetry. See [MXC telemetry](development/architecture/telemetry.md).

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
record of denials. In-process Rust callers receive the same summary information
through `Output::output_metadata` or `Sandbox::output_metadata()` after
waiting. The C# SDK exposes it through `ExecutionResult.OutputMetadata` and
`MxcProcess.OutputMetadata`.

By default, the intermediate ETW `.etl` trace is an internal, runner-managed
file in a protected per-run temporary directory that MXC deletes after
analysis. Set `captureDenials.retainEtl` to `true` to preserve the sealed trace
for diagnostics after a terminal wait. Both native PSEC capture and the
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
