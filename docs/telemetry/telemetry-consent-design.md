# Telemetry consent design

MXC telemetry is Windows-only and fails closed. Collection requires all four
conditions at the time each event is written:

```text
per-run telemetry requested
&& current-version user consent is Granted
&& administrative policy does not block
&& the platform/provider is available
```

No prompt, no response, No, dismissal, withdrawal, malformed state, an unknown
prompt version, or any read/write failure means no telemetry. Administrative
policy is a deny-only ceiling: it may block collection but can never opt a user
in.

## Canonical consent resource

Rust owns one immutable, versioned resource in
`wxc_common::telemetry::consent_prompt`. Every EXE and SDK presenter must show
every supplied field verbatim. Hosts control layout, accessibility, and native
UI, but may not substitute wording.

Current resource:

- Resource version: `1`
- Locale: `en-US`
- Mandatory fallback: `en-US`
- Privacy link: <https://privacy.microsoft.com/privacystatement>

### Title

> Help improve Microsoft eXecution Container (MXC)

### Body

> Would you like to send optional diagnostic data to Microsoft to help us
> understand how MXC is used, diagnose problems, and improve the product?
>
> If you choose Yes, MXC will send the MXC version and channel, containment
> backend, run outcome and exit code, run duration, bounded failure category,
> lifecycle phase, and random identifiers used to correlate events from the
> same app session or sandbox lifecycle.
>
> MXC does not send your command text, file paths, environment variables,
> standard input or output, usernames, credentials, or free-form error
> messages.
>
> Choosing No, closing this prompt, or not responding will keep telemetry off.
> If this consent request is never shown, telemetry also remains off. You can
> change or withdraw your choice later using MXC telemetry consent controls.

### Actions

- Affirmative: **Yes, send optional diagnostic data**
- Negative: **No, do not send**
- Learn more: **Microsoft Privacy Statement**

Each field has a stable message ID. Locale lookup normalizes BCP 47 tags and
falls back to `en-US`; complete messages are translated as units rather than
assembled from fragments. Adding a translation does not change the public API.
A material wording or data-inventory change requires a new resource version and
explicit re-consent.

## State and persistence

MXC stores consent per user at:

```text
%LOCALAPPDATA%\mxc\telemetry-consent.json
```

Schema version 2 records:

- `consent`: `granted` or `denied`
- `promptResourceVersion`
- `promptLocale`
- MXC version, source, and update timestamp for local audit/support provenance

Stored and effective state are reported separately. A legacy grant without the
current prompt version remains visible as `storedState: "granted"` but is
`effectiveState: "undetermined"` with reason `prompt-version-missing` or
`prompt-version-unsupported`. It never authorizes collection. Legacy denial
remains denied.

Only two operations mutate the store:

1. A presenter invoked by MXC returns an explicit `yes` or `no` for the prompt
   supplied in that same invocation.
2. The explicit withdrawal operation persists `denied`.

Dismissal, EOF, presenter failure, localization fallback failure, or never
requesting consent does not fabricate or rewrite a decision.

## Administrative ceiling

Policy is read from:

```text
HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry (REG_DWORD)
```

Only value `3` permits MXC optional diagnostic data. Other values, wrong value
types, unreadable state, and ambiguity fail closed to `blocked`. An absent key
is `unrestricted`. `allowed` and `unrestricted` merely leave the user's choice
in control; neither creates consent.

A consent request made while policy is blocked does not invoke the presenter or
persist dormant consent. Withdrawal remains available while blocked.

## Per-run enablement

Consent is not an execution switch. Each run must also request telemetry:

- JSON execution config: top-level `telemetry.enabled: true`
- Rust SDK: `SandboxRequest::set_telemetry_enabled(true)`
- C# and Node policies serialize the same top-level execution field

`telemetry.enabled: true` never prompts. Runs continue normally when telemetry
is disabled or unauthorized.

## EXE maintenance JSON

State-changing consent flags do not exist. The old grant/revoke/source
spellings are non-mutating migration tombstones that return an actionable
error.

Consent administration uses the ordinary JSON input loader with a separate
closed maintenance contract:

```json
{
  "$schema": "https://raw.githubusercontent.com/microsoft/mxc/main/schemas/dev/mxc-telemetry-consent.schema.1.json",
  "command": "telemetryConsent",
  "action": "request",
  "locale": "en-US"
}
```

Actions:

- `request`: invoke a presenter when needed
- `withdraw`: idempotently persist `denied`
- `status`: read only

`--telemetry-consent-status` remains a read-only convenience and emits the same
typed JSON response as `action: "status"`.

Responses include:

```json
{
  "action": "status",
  "result": "status",
  "storedState": "undetermined",
  "effectiveState": "undetermined",
  "reason": "no-record",
  "policy": "unrestricted",
  "needsPrompt": true
}
```

The maintenance schema is generated separately from Rust at
`schemas/dev/mxc-telemetry-consent.schema.1.json`. The execution schema remains
execution-only.

### Interactive EXE

For a terminal request, `wxc-exec` renders the canonical resource and accepts
only an explicit affirmative or negative choice. Noninteractive input, EOF, or
unavailable presentation returns a typed non-grant result without launching a
sandbox.

### Node presenter protocol

Node uses a private same-process stdio handshake:

1. The child emits the canonical prompt and a random 32-byte challenge.
2. Node invokes the host presenter.
3. Node returns one typed decision with that challenge and prompt version.
4. The same child verifies both values before persisting.

Replay, cross-process responses, and prompt-version mismatches are rejected.
This protocol is internal and does not expose a detached begin/complete API.

## Public SDK surfaces

### Rust

```rust,no_run
use mxc_sdk::telemetry::{self, ConsentDecision};

let outcome = telemetry::request_consent(Some("en-US"), |prompt| {
    // Render every field verbatim.
    Ok(ConsentDecision::Yes)
})?;

let status = telemetry::get_consent_status();
let withdrawal = telemetry::withdraw_consent()?;
# let _ = (outcome, status, withdrawal);
# Ok::<(), telemetry::ConsentError>(())
```

`request_consent_async` provides the asynchronous presenter variant.

### C#

```csharp
var outcome = MxcTelemetry.RequestConsent(prompt =>
{
    // Render every field verbatim.
    return TelemetryConsentDecision.Yes;
});

TelemetryConsentStatus status = MxcTelemetry.GetConsentStatus();
MxcTelemetry.WithdrawConsent();
```

`RequestConsentAsync` accepts an asynchronous presenter.

### Node.js

```typescript
const outcome = await requestTelemetryConsent(async (prompt) => {
  // Render every field verbatim.
  return 'yes';
}, 'en-US');

const status = queryTelemetryConsent();
withdrawTelemetryConsent();
```

The presenter may return a decision directly or a promise. Node never writes
the consent store itself.

## Live enforcement and event compatibility

Consent and policy are checked immediately before every `Execution` and
`Error` event write. A withdrawal or newly blocking policy therefore stops
later writes from an already-running process even if the provider was
registered earlier.

The public ETW event identities remain:

- `MXC.Execution`
- `MXC.Error`

Collectors may continue filtering those names; consent stabilization does not
rename the provider or events.

## Validation and release gate

CI enforces:

- telemetry policy strings across Rust, C#, and generated TypeScript
- maintenance schema/TypeScript codegen
- C ABI/C# binding codegen and error-code parity
- named release-mode consent and policy tests
- isolated debug consent and ETW smoke tests

The versioned wording and data/control inventory require Microsoft
privacy/legal approval before release. See
[`telemetry-consent-privacy-review.md`](telemetry-consent-privacy-review.md).
