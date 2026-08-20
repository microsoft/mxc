# Telemetry consent design

This document defines the Windows telemetry-consent contract.

MXC telemetry is Windows-only and fails closed. Collection requires all four
conditions at the time each event is written:

```text
per-run telemetry requested
&& current-version user consent is Granted
&& administrative policy does not block
&& the platform/provider is available
```

No prompt, no response, the literal string "No", dismissal, withdrawal,
malformed state, an unknown prompt version, or any read/write failure means no
telemetry. Administrative policy is a deny-only ceiling: it may block
collection but can never opt a user in.

## Canonical consent resource

MXC owns one immutable, versioned consent resource. Every EXE and SDK presenter
must show every supplied field verbatim. Hosts control layout, accessibility,
and native UI, but may not substitute wording.

Current resource:

- Resource version: `1`
- Locale: `en-US`
- Mandatory fallback: `en-US`
- Privacy link: <https://go.microsoft.com/fwlink/?linkid=521839>

### Title

> Help improve Microsoft eXecution Container (MXC)

### Body

> Help improve MXC by sharing optional diagnostic data with Microsoft.
> If enabled, MXC sends diagnostic information about product usage,
> performance, and reliability. MXC does not send your commands, file paths,
> credentials, or other customer content.
> You can change your choice at any time.

### Actions

- Affirmative: **Yes**
- Negative: **No**
- Learn more: **Privacy Statement**

Each field has a stable message ID. Locale lookup normalizes BCP 47 tags and
falls back to `en-US`; complete messages are translated as units rather than
assembled from fragments. Adding a translation does not change the public API.
A material wording or data-inventory change requires a new resource version and
explicit re-consent.

## SDK presenter requirements

An SDK host owns the native presentation experience, while MXC owns the
resource, decision validation, and persistence. Implementers must follow this
contract:

1. Route consent through the MXC-owned request flow. Do not write the consent
   store directly or create a separate grant path.
2. Render every supplied field verbatim: title, body, affirmative label,
   negative label, learn-more label, and learn-more URL. Hosts may control
   layout, accessibility, and platform-native styling, but must not hardcode,
   shorten, reorder within a message, or replace the supplied wording.
3. Map the affirmative control to `Yes` and the negative control to `No`.
4. Map window close, cancel, timeout, or no response to `Dismissed`. If the UI
   cannot be presented or otherwise fails, return a presenter error instead.
   Never infer `Yes` from a default button, policy, prior application
   preference, or absence of a response.
5. Make the learn-more control open the supplied URL, normally in the user's
   default browser. Do not substitute a different privacy destination.
6. Return only the typed decision to MXC. MXC persists the decision together
   with the resource version and locale that were actually presented.
7. Use the typed status API to explain the current stored/effective state and
   administrative ceiling. Provide an explicit withdrawal control in the
   host's settings or other appropriate telemetry-controls surface.

MXC does not invoke the presenter when the result is already determined:

- `AlreadyGranted`: the current resource version is already granted.
- `PolicyBlocked`: administrative policy prevents collection.
- `NotApplicable`: telemetry is unavailable on this platform.

If the host never calls the request API, telemetry remains off. A presenter
failure must be surfaced as an error to the host and must not create or alter a
grant.

## State and persistence

MXC stores consent per user at:

```text
%LOCALAPPDATA%\mxc\telemetry-consent.json
```

The persisted consent record is a versioned JSON document. The current schema
version is 2 and records:

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

### Atomicity, locking, and recovery

Every consent-store mutation must be atomic across processes. Synchronization
must use a separate primitive keyed by the consent-store path, such as a named
mutex or a sibling lock file. It must never keep the live JSON file open
because that can prevent atomic replacement on Windows.

1. Acquire the cross-process writer lock before reading, validating, or
   replacing the file.
2. Write the full replacement document to a sibling temporary file in the same
   directory.
3. Flush the temporary file, then replace the live file with a single
   same-volume atomic rename/replace operation.
4. Release the lock only after the replacement is durable.

Readers must coordinate through the same separate primitive or use an
equivalent close-and-retry strategy; they must not hold the live JSON handle
while a writer replaces it. They must never observe or accept a
partially-written document. Any malformed file, missing required field,
version mismatch, unreadable path, or lock/replace failure is treated as
`undetermined`/`denied` as appropriate and must not authorize collection.
Recovery is fail-closed: MXC may surface a typed error or status reason to the
host, but it must not silently recreate a grant from a corrupted file.

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

Consent is not an execution switch. Each run must also request telemetry with
the stable top-level `telemetry.enabled: true` setting. The switch never
prompts, never persists consent, and never bypasses consent or administrative
policy.

Consent-management surfaces should still support the three behavior classes
defined here:

- request consent through a presenter when a decision is needed
- withdraw consent by persisting `denied`
- report stored consent, effective consent, blocking policy, and whether a
  prompt is still required

## Live enforcement and event compatibility

Consent and policy are checked immediately before each logical telemetry
emission. A terminal failure may emit paired `MXC.Error` and `MXC.Execution`
events under the same authorization decision so collectors never receive half
of the pair. A withdrawal or newly blocking policy stops the next logical
emission from an already-running process even if the provider was registered
earlier.

The public ETW event identities remain:

- `MXC.Execution`
- `MXC.Error`

Collectors may continue filtering those names; consent stabilization does not
rename the provider or events.

## Validation and release gate

Implementations should include deterministic coverage for policy evaluation,
prompt gating, withdrawal, corruption recovery, and concurrent consent-store
mutation. The checked-in ETW smoke test only validates event emission; it is
not a substitute for consent-flow coverage.

The versioned wording and data/control inventory still require Microsoft
privacy/legal approval before release.
