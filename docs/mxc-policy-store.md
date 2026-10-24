# Feature Spec: Known-tool Policy Floors

**Status:** Under review. Pending API sign-off from the designated MXC SDK
reviewers before merge and implementation. Not part of MXC 1.0; no later release
is committed.

**IMPORTANT NOTE:** The Policy Store provides best-effort baseline requirements
believed necessary for representative tool workflows. Floors may broaden file
access to unblock tools, but guarantee neither success nor safety. Users and
clients must review that access; their settings and enterprise policies can
further constrain or override the recommendation.

---

## 1. Problem Statement

When users first enable sandboxing without known-good configurations, tools
can break and users spend time debugging or disable containment. The catalog
supplies a suggested starting policy intended to make requested tools work
out of the box when the user has not configured the sandbox and no enterprise
policy overrides it.

Clients can configure the sandbox and override these defaults; user and
enterprise policy can further restrict them, including later changes. The
catalog is a best-effort suggestion, not authorization or a guarantee of
success or safety.

For caller-facing review, start with the [API spec](mxc-policy-store-api.md).

This document does not restate general MXC sandboxing concepts already covered
by the [v1 SDK reference](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/docs/reference/node/v1/README.md) or
[versioning design](development/architecture/versioning.md). It covers only what a policy store adds.

### Non-goals

- This does not change backend enforcement or the MXC 1.x request contract.
  Catalog data uses a supported subset of `ContainerRequest`; it does not
  define a parallel policy vocabulary or supply commands.
- This is not a trust or attestation mechanism, and it does not authorize
  anything. See [§8](#8-trust-model).
- This is not a guarantee that a complete tool workflow will succeed under
  process containment.
- This does not define how any specific consumer stores, displays, or lets a
  user approve requirements. See [§2](#2-ownership-boundary).
- This does not define Learning Mode's candidate-generation or review UX. See
  [§7](#7-relationship-to-learning-mode).

### MXC feature impact and defaults

**SDK type reuse:** Lookup is command-free.
`ContainerRequirements` reuses the filesystem, network, UI, and timeout types
from the [v1 request](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/sdk/node/src/v1/types.ts#L549-L597);
the caller supplies the command and final execution settings later. The SDK owns
wire version selection.

This is an MXC SDK API, not a command-line utility. Following the feature-impact
checklist in
[authoring a new feature](development/guides/authoring-a-new-feature.md):

- **Policy changes:** None. Entries use the existing v1 request access fields.
- **ContainerConfig changes:** None. The catalog does not add configuration
  fields or change omission behavior in an existing contract.
- **OS and backend changes:** None. Backends continue to validate whether they
  can enforce the resolved policy.
- **MXC SDK changes:** Add one resolver operation to the existing
  TypeScript/JavaScript, Rust and C#/.NET SDKs, returning a summary with optional
  `ContainerRequirements` and required original-input `unresolvedInputs`.
- **Delivery:** V1 policy data is embedded in the MXC native library at build
  time and ships in the existing MXC SDK packages. See
  [§5](#5-intended-repository-and-packaging-boundary).

Caller defaults and omission behavior are defined in the
[API spec](mxc-policy-store-api.md#context-defaults-and-symbol-resolution).
Lookup is command-free and opt-in; unresolved requirements never authorize a
less restrictive execution fallback.

## 2. Ownership boundary

MXC owns the reviewed, versioned, read-only catalog, its resolver API and its
SDK publication lifecycle in `microsoft/mxc`.
The requirements type and its underlying request field types remain MXC-owned as well.

The catalog states a best-effort baseline for a tool. It does not grant
access, modify caller state, create a sandbox, or guarantee workflow success.
Filesystem and network composition combine lower-bound requirements using the
least restrictive access needed by the selected tools. This is distinct from
the consumer's restrictive composition with its own security ceilings.

Everything else is a consumer decision:

- Whether automatic catalog lookup is enabled at all.
- Access-profile mapping, elevation preference, and per-tool authorization.
- Persistence of input/context, accepted requirements and the client's own
  acceptance record. The result does not expose per-entry resolution provenance.
- Composition with the consumer's own user, learned, and invocation-specific
  policy layers, and with non-overridable OS/enterprise/device ceilings.
- Approval UX, audit, and the final call to the v1 `run` / `spawn` operations
  (or their language equivalents).

`resolveToolRequirements` returns available requirements and original input
indexes not completely included. The consumer decides whether and how to act
on that partial result. A resolved entry asserts baseline need, never access
the host is required to grant.

## 3. Data model

### 3.1 Versions

| Field | Meaning |
|---|---|
| `catalogSchemaVersion` | Version of the catalog JSON shape itself. |
| `catalogRevision` | Immutable identifier for one published, fully reviewed catalog. |
| `entryRevision` | Monotonic revision of a single entry, for cache invalidation and audit comparison. |
| `sdkContractVersion` | Catalog-revision metadata recording its published validation target (`1.0.0` initially), not a caller-selected wire version. |

These identifiers serve separate purposes and do not advance in lockstep.
Registering a new exact request contract does not change existing catalog
data. A semantic entry change increments its `entryRevision` and the containing
`catalogRevision`; changing only catalog metadata, including its published
validation target, increments only `catalogRevision`. Revalidating unchanged
data does not rewrite its published metadata or either revision.
Tool versions and `versionRange` values are distinct from catalog revisions.

Entries use MXC's v1 request access fields; breaking changes require a new
major surface. No entry or caller chooses a wire version. At SDK build time,
every bundled revision is revalidated against that SDK's exact
`SDK_CONTRACT_VERSION` and its matching schema, not automatically accepted by
semver range. Data with an older published validation target can remain bundled when
it is an exact registered stable target in the same major and the current
build has revalidated its data successfully. Other revisions are not bundled.
Lookup uses the bundled manifest's default catalog, not a caller-selected
revision. Never dispatch a catalog's historical SDK target or silently substitute
another catalog when the default is unavailable. The SDK owns wire version
selection as described in the [versioning design](development/architecture/versioning.md).

### 3.2 Entry shape

```json
{
  "entryId": "tool:git",
  "entryRevision": 3,
  "displayName": "Git",
  "versionScheme": "intdot",
  "identity": [
    { "kind": "purl", "value": "pkg:generic/git" },
    { "kind": "invocation-name", "names": ["git", "git.exe"] }
  ],
  "default": {
    "requirements": {
      "filesystem": {
        "readonlyPaths": ["${git_prefix}"],
        "readwritePaths": ["${project_root}"]
      }
    },
    "intents": {
      "local": {
        "exampleSubcommands": ["status", "diff"],
        "policyAdditions": {}
      },
      "fetch": {
        "exampleSubcommands": ["fetch", "pull"],
        "policyAdditions": {
          "network": {
            "egress": {
              "allow": [
                { "to": [{ "cidr": "192.0.2.10/32" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
              ]
            }
          }
        }
      },
      "push": {
        "exampleSubcommands": ["push"],
        "policyAdditions": {
          "network": {
            "egress": {
              "allow": [
                { "to": [{ "cidr": "192.0.2.10/32" }], "ports": [{ "protocol": "tcp", "port": 22 }] }
              ]
            }
          }
        }
      }
    }
  },
  "platformVariants": [
    {
      "when": { "platform": "windows" },
      "policyAdditions": {
        "filesystem": { "readonlyPaths": ["${programData}/Git"] }
      }
    }
  ],
  "versionVariants": [
    {
      "versionRange": "vers:intdot/>=2.40|<2.50",
      "intentAdditions": {
        "push": { "dependencies": [{ "entryId": "tool:ssh" }] }
      }
    },
    {
      "versionRange": "vers:intdot/>=2.50|<3",
      "newIntents": {
        "bundle-fetch": {
          "exampleSubcommands": ["clone --bundle-uri=<uri>"],
          "policyAdditions": {
            "filesystem": { "readwritePaths": ["${temp_dir}/git-bundles"] },
            "network": {
              "egress": {
                "allow": [
                  { "to": [{ "cidr": "198.51.100.20/32" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
                ]
              }
            }
          }
        }
      }
    }
  ],
  "provenance": { "method": "reviewed-observation", "sourceRevision": "opaque-review-reference" }
}
```

Each entry has exactly one unversioned `default`, containing the conservative
subset common to all tool versions and platforms, not the newest version's
behavior. It contains base access fields and an optional timeout suggestion in
`requirements`, plus intent additions. The timeout is advisory, not an access
grant; the caller supplies the command and final execution settings when
constructing a `ContainerRequest`.
Unversioned means no tool-version selector, not a caller-selectable wire version.

`versionVariants` is an optional list of non-overlapping VERS ranges using the
entry's `versionScheme`. Effective policy data is `default` plus the selected
platform/architecture overlay and at most one selected version overlay.
Neither dimension cascades across multiple variants. In either overlay,
`policyAdditions` and `dependencies` add to the base, `intentAdditions` adds to
intents the default declares, and `newIntents` defines intents the default
does not declare. Additions use only fields
with defined monotone composition: no replacements, deletions, narrowing,
negative operations, or removal/renaming of inherited intents.
In v1, access additions are read-only/read-write paths and outbound allow
rules. Overlay deny rules, scalar replacements, and delete/rename operations
are invalid.

To narrow requirements for newer versions, remove the access from the default
and add it only to the older version ranges that need it. Each effective
variant must retain all default access and intents. Intent bodies themselves
remain additions to their effective base, not full policy copies.

The Git example illustrates the structure, not a verified Git compatibility
matrix. `local` adds nothing; default fetch and push add their network needs.
The first range adds an SSH dependency to push through `intentAdditions`. The
second defines `bundle-fetch` through `newIntents`, without inheriting the
first range's SSH dependency. The endpoints are
documentation addresses. The Windows overlay adds `${programData}/Git`;
`programData` is the Windows common application-data directory and is resolved
only when that overlay is selected.

Intent names are exact identifiers scoped to the tool: Git's `local`, `fetch`,
and `push` are supplied as `intent: "local"`, `"fetch"`, or `"push"`.
`exampleSubcommands` contains non-normative hints for callers. The caller maps
command lines to intents; the catalog does not parse or execute command lines.

Invariants:

- `entryId` is stable, unique, namespaced, and is the only key `dependencies`
  edges may reference.
- `entryRevision` increases on every semantic change to the entry.
- Exactly one `default` is required, including when no version variants exist.
  Entries with only versioned variants, multiple defaults, or a variant tagged
  as default are invalid.
- Each entry declares a supported `versionScheme`. Version ranges are valid,
  non-overlapping, and use that scheme. Overlap is a catalog error, not a
  precedence choice.
- Intent names are unique in each materialized default-plus-overlays result.
  `intentAdditions` may name only intents the default declares. `newIntents`
  cannot reuse a default intent name or a name the other selected overlay
  defines. All additions and dependencies are versioned with the containing
  entry.
- Variant selection follows the deterministic rules in
  [§3.4](#34-platform-variants). No matching platform overlay leaves the common
  default unchanged; it does not produce an empty policy or a no-match result.
- Symbols (`${project_root}`, `${npm_cache}`, OS well-known folders) are
  resolved by the resolver before a policy is returned; catalog data never
  ships a literal, machine-specific path.
- Embedded request access fields use the v1 SDK contract and the validation
  pipeline below; there is no standalone `SandboxPolicy` schema.

`default.requirements` is closed to the three filesystem path lists,
directional network policy, v1 UI fields, and unsigned 32-bit `timeoutMs`.
Commands, wire versions, backend configuration, runtime proxy values,
lifecycle/cleanup settings, environment data, and unknown fields are rejected,
including inside overlays. `policyAdditions` retains its access-only meaning.
When UI is present, `disable` is required; `clipboard` and `allowInputInjection`
are optional. UI/timeout composition and overlay limits remain those of §3.5.

Build validation materializes every platform/architecture/version/intent
combination, enforcing the closed field set, selectors, and additive rules.
Bind fixture symbols and a validation-only command, then expose the SDK's exact
[`OneShotRequest` before normalization](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/src/mxc-sdk/src/policy/exact/v1_0.rs#L184).
This hook must be implemented: `prepare_request` returns normalized data.
Validate the exact serialization against the SDK target's schema, initially
[`mxc-config.schema.1.0.0.json`](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/schemas/stable/mxc-config.schema.1.0.0.json),
mapping `allowInputInjection` to wire `injection` and supplying the SDK-owned
wire version. Check CIDR/exclusion containment, protocol/port relationships,
numeric bounds, and unknown fields. Run semantic normalization on a disposable
copy; its restrictive path precedence must not alter the original floors.
The fixture command is never executed or returned. Lookup repeats validation
with real symbols and the object-identity checks in §3.5. Neither stage probes
or launches a backend; enforcement and capability checks still occur at execution.

Symbol definitions are shared across entries and versioned with the selected
catalog revision. Each definition describes the symbol's permitted sources
and may include a `defaults` map from platform to path template. This extends
the catalog contract, not `ContainerRequest`. Entries continue to reference
symbols rather than repeat defaults. For example, default metadata in the
shared symbol registry can include:

```json
{
  "symbols": {
    "npm_cache": {
      "defaults": {
        "linux": "${user_home}/.npm",
        "macos": "${user_home}/.npm"
      }
    },
    "programData": {
      "source": "host",
      "description": "Windows common application-data directory."
    }
  }
}
```

This is a metadata fragment, not a complete symbol definition. Default
templates may reference approved host-known symbols; they cannot contain
commands or executable discovery logic. Shared definitions and defaults are
embedded with the entries and cannot change behind a pinned catalog revision.
Catalog/entry revisions are internal authoring, validation and troubleshooting
metadata; they are not a public lookup selector.

Symbol discovery implementations follow the
[API precedence and failure rules](mxc-policy-store-api.md#context-defaults-and-symbol-resolution).
Tool-specific discovery is library code, never executable catalog data.

### 3.3 Identity

Entries declare package-identity predicates and invocation-name fallbacks.
Catalog indexing and lookup share the rules below; the API summarizes
[matching](mxc-policy-store-api.md#identity-and-match-precedence) and
[version/intent outcomes](mxc-policy-store-api.md#version-intent-and-platform-selection).
Catalog PURL predicates admit only type, optional namespace and name; reject
version, qualifiers and subpath rather than silently stripping them.

Rank package identity above invocation-name-only identity, then a requested
intent declared in the default/applicable overlays above no such declaration,
then exact architecture above platform-neutral additions or the common default.
Distinct entries tied at the highest rank fail. Multiple matching predicates in
one entry count once at its strongest evidence; version/intent failure never
retries a weaker or different entry. Predicate/file order never breaks a tie.

PURL parsing follows the pinned
[component rules](https://github.com/package-url/purl-spec/blob/7cd2d3442fb9c88155db17ada7c911b40ec22d41/docs/specification/standard/Clause-5-Package-URL-Specification.md)
and [type definitions](https://github.com/package-url/purl-spec/tree/7cd2d3442fb9c88155db17ada7c911b40ec22d41/types).
Validate the complete candidate before ignoring version, qualifiers and subpath.
Percent-decode before comparing type, namespace and name. Type is case-insensitive;
namespace/name follow type-specific rules or exact decoded comparison when no
special rule exists. Never substitute host filesystem casing. Invalid candidates
exclude only their input, without fuzzy repair or weak-name retry.

Version ranges follow pinned
[VERS](https://github.com/package-url/vers-spec/blob/797c842a4afebf258e6710a68cd60306afc36708/docs/specification/standard/Clause-5-VERS-Specification.md)
and its [type rules](https://github.com/package-url/vers-spec/blob/797c842a4afebf258e6710a68cd60306afc36708/docs/types/vers-types.md).
Supported schemes are `npm`, `semver`, `pypi`, `nuget` and `intdot`, not `generic`.
Parse detected versions with the entry's scheme, without independently stripping
prefixes, fuzzy repair or trying another scheme. Unparseable versions skip intent
resolution. A valid out-of-range version with a newer-only intent excludes that
input rather than selecting the unavailable intent.

### 3.4 Platform variants

Each platform variant's `when` selector contains `platform` (`windows`,
`linux`, or `macos`) and optional `architecture` (`x64` or `arm64`).
It uses the add-only fields defined in [§3.2](#32-entry-shape).
Catalog validation rejects duplicate exact selectors and more than one
architecture-neutral variant for a platform.

The [API selection rules](mxc-policy-store-api.md#version-intent-and-platform-selection)
define precedence, host defaults and emulation considerations. Architecture is
catalog context, not a new `ContainerRequest` field. Variants remain
backend-neutral; execution still validates backend capabilities.

### 3.5 Dependencies and composition

The [API contract](mxc-policy-store-api.md#dependencies-and-composition) summarizes
the caller-visible outcome. The rules below govern effective access and conflicts.
Apply them within entries, across requested tools, and through
dependency closures. Caller restrictions are never inputs to floor composition.

Dependencies use `entryId` and contribute unversioned default/platform base plus
only explicitly referenced intents, for example
`{ "entryId": "tool:ssh", "intents": ["connect"] }`. Those intents must exist in
every materialized platform combination where referenced. A dependency range is
validated VERS metadata, never evidence for a version overlay. Traverse transitively,
rejecting cycles.

| Filesystem combination | Result |
|---|---|
| Read-only and read-write at the same path | Read-write |
| Read-write parent and read-only child | Read-write parent; omit redundant read-only child |
| Read-only parent and read-write child | Keep both without making the whole parent writable |
| Catalog deny overlapping required access | Remove the entire deny, not only the overlap |
| Non-overlapping deny and grant | Keep both |

No-network sources do not veto another source's network requirements.
One network source retains supported egress/ingress. Multiple scoped egress
sources union whole allow/deny rules under deny-by-default, preserving CIDR
exclusions and destination/protocol/port pairings. Remove a whole catalog deny
only when it overlaps required access after exclusion/protocol/port comparison;
retain nonoverlapping denies. Do not invent unrestricted or unselected access.

Retain `ui` or `timeoutMs` from one deduplicated source; omission adds no value.
Distinct sources setting the same field fail with `composition_conflict`, even
when values are equal. Repeated references to one source do not conflict.
No min/max/last-writer merge exists; overlays cannot add or replace those fields.
Undefined allow-by-default, non-default ingress and other merges likewise fail.
Access belongs to the combined sandbox, not separate tools within it.

De-duplicate each source layer independently within an entry/catalog revision:
default base once; platform base by selector; default intent by name; platform
intent by selector/name; version base by range; version intent by range/name.
New intents belong to their defining overlay. Do not attach a requesting
input's version or intent to a shared base key. Preserve direct and transitive
requester indexes internally so every root's complete inclusion can be accounted
for, even though that dependency attribution is not public result data.

Apply filesystem composition after validating bound symbol values and performing
the necessary object checks.
Lexical normalization respects platform syntax and actual case rules, retaining
original casing. Preserve case in comparisons when sensitivity is unknown;
lexical normalization never substitutes for object identity.
Use MXC's [object comparison primitives](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/src/mxc-sdk/src/core/mxc_common/filesystem_object.rs#L100-L265):
Windows volume serial/file ID via `CreateFileW`/`FileIdInfo`, Unix device/inode
via `stat`. Resolve existing ancestors for subtree comparison. A cleanly
missing suffix is relative to its deepest established ancestor, not an existing
alias; unreadable components and unresolvable broken links are unknown.

Preserve required alias locations, including bind mounts, symlinks, junctions,
hard links, and 8.3 names, even when object identity is shared. Retain a read-only
alias with composed read-write access when another alias requires writes.
For unknown relationships, exclude every
affected input, not just the restrictive side; remove solely owned layers and
retain shared layers for remaining contributors. Recompose complete surviving
roots. This resolver observation does not replace enforcement-time checks.

Catalog validation exercises composition with fixtures, but caller symbols and
filesystem observations require lookup-time validation too. Materialization
must not invoke the runner's restrictive normalization as the floor merge
algorithm. Unsupported composition fails explicitly.

## 4. API surface

The [Policy Store API spec](mxc-policy-store-api.md) is the authoritative
caller-facing contract: public types, signatures, defaults, behavior, errors,
result accounting and usage examples. This document owns catalog authoring and
implementation. API review comes first; implementation follows the approved
contract.

### 4.1 Runtime lookup

`resolveToolRequirements` accepts one tool or an array and returns
`ToolRequirementsResolution`: optional command-free `requirements` plus required
`unresolvedInputs`, a sorted list of original input occurrences not completely
included in the output. A complete root includes its selected dependency closure.
For nonempty inputs, output exists exactly when at least one occurrence is
included; empty/all-excluded inputs yield absence, not a fabricated empty policy.
An actual completed empty floor remains distinguishable from absence.
See [operation signatures](mxc-policy-store-api.md#6-language-bindings),
[types](mxc-policy-store-api.md#3-types-and-fields), and
[results/coverage](mxc-policy-store-api.md#results-coverage-and-attribution).

### 4.2 Results and troubleshooting

The public result reports requirements and input coverage. Applications can
retain their inputs/context and accepted requirements, but the summary alone
cannot reconstruct a per-resolution trace.

Keep the internal facts needed to explain a lookup: catalog/entry revisions,
selected source layers, root/dependency attribution, symbol sources, identity
uncertainty and the full scope/source of removed restrictions. Their internal
representation is not a public DTO or stable log-parsing protocol.
Lookup correctness and returned completeness must not depend on an active sink.

Use configured MXC diagnostic sinks, not unsolicited application stdout or a
new always-on log. Normal records minimize identifiers and contain no environment
dumps, commands, credentials or full paths. Detailed identities/symbol values
require explicit troubleshooting controls. Correlate records with an opaque
per-call ID propagated through async/native work, not identity-bearing IDs or a
global last-result slot. Logs may be disabled, redacted, rotated or unavailable;
clients must not parse them to decide completeness or authorization.

Local logging is not telemetry consent. Any telemetry remains subject to the
existing explicit-consent and administrative-policy rules; this feature does
not introduce a collection exception, sink or logging callback API.

### 4.3 Consumer obligations

Consumers own authorization, their policy layers, accepted-policy persistence,
and execution. The [API responsibilities](mxc-policy-store-api.md#5-errors-and-caller-responsibilities)
define the contract; the [trust model](#8-trust-model) explains its rationale.
The resolver never writes a consumer's store or mutates reviewed data at lookup.

## 5. Intended repository and packaging boundary

The Policy Store lives in `microsoft/mxc` and ships through the existing MXC
SDK packages.
Catalog data and resolver APIs follow the MXC contribution and release process.

One internal `policy_store` module in `mxc-sdk` uses the SDK's v1 types and
common identity helpers. Rust calls it directly; Node/.NET use panic-contained
`mxc_ffi` library exports, not launch/probe APIs. V1 data is embedded at build
time.

### 5.1 Library distribution and consumption

Resolution ships through the existing TypeScript/JavaScript,
Rust, and .NET SDKs. The [API spec](mxc-policy-store-api.md#6-language-bindings) owns
entry-point names, return types, and language conventions. SDK reference pages
and package READMEs should link that contract rather than duplicate it.

V1 data updates ship with MXC releases; catalog revision metadata does not
imply an independent download channel. A package update never rewrites a
consumer's previously accepted requirements.

### 5.2 Cross-language consistency and support

All three SDKs use the same catalog format and shared conformance
fixtures. Given the same catalog revision, tool inputs, explicit resolution
context, and relevant host/filesystem observations, they must agree on matching,
variant selection, complete-root inclusion, effective requirements, original
unresolved input indexes and failure categories. This is semantic consistency,
not byte-identical output or reproduction of another language's runtime behavior.

Each binding uses consistent, idiomatic result and error handling for its
language. Equivalent failures map to the corresponding existing MXC error
codes, while error types, message wording, and language-specific representations
may differ. Callers need not understand another binding or parse message text.
Shared fixtures compare effective requirements, summary invariants and failures,
including prescribed index ordering. Internal logs need not have identical prose
and are not a cross-language API.

Shared fixtures cover platform path semantics as well as ordinary lookup;
matching function names alone is not compatibility. Package CI must also
exercise installation, public API usage, and host-derived defaults on the
supported platforms. Binding tests exercise the shared native resolver rather
than independent implementations of the resolution rules.

Every .NET Policy Store DTO crossing the JSON FFI boundary must be registered
as a `[JsonSerializable]` root in `MxcJsonContext` and use the `MxcJson` helpers.
Its serialize/deserialize paths must be covered by
`Microsoft.Mxc.Sdk.AotSmokeTest`; reflection fallback is not permitted.

Policy Store is an ongoing SDK capability. Language parity,
documentation, and maintenance belong to the MXC SDK release process.

### 5.3 Catalog source layout and embedded data

Catalog authors edit one JSON file per tool under
`src/mxc-sdk/policy_store/catalog/entries/`. Each file contains that tool's full
entry: identity, common default, intents, all platform/version variants,
dependencies, and provenance. Do not split variants or intents into separate files.

```text
src/mxc-sdk/policy_store/
  catalog/
    contract.v1.json
    manifest.json
    entries/
      git.json
      node.json
      npm.json
    revisions/
      <catalogRevision>.json       # generated release snapshot
    views/
      <catalogRevision>.md         # generated reviewer view
      <catalogRevision>.requests.json  # generated validation requests
  schema/
    catalog.v1.schema.json
    manifest.v1.schema.json
  conformance/
```

Build tooling collects entry files recursively, validates globally unique
`entryId` values and dependency references, and assembles the complete candidate
revision in stable entry-ID order. CI checks generated snapshots/views against
their editable inputs; authors do not maintain a second policy copy by hand.
Optional category subdirectories are organizational only: paths and file order
never affect identity, lookup, or composition.

`manifest.json` selects the default revision and maps bundled revisions to
generated snapshots. Published snapshots remain immutable; changing tool data
produces a new catalog revision and the required entry revision changes.
Generating a new revision never overwrites a published one. Moving an entry
between category directories alone is not a semantic policy change.

The build embeds validated snapshots into the native library. These are source
and generated-artifact paths, not runtime lookup directories or files consumers
edit. Consumer persistence remains separate from the read-only MXC catalog.

## 6. Contribution and review

- Catalog and API contributions are pull requests in `microsoft/mxc`.
  No client or SDK can write a catalog entry at runtime.
- Every entry change includes identity evidence, supported tool version
  range(s), platform evidence, a minimized requirement set, test fixtures,
  and provenance.
- Entry and dependency `versionRange` values pass VERS syntax and supported-type
  validation during authoring/build validation. An entry's version ranges must
  use its declared scheme and must not overlap.
- Keep one unversioned default common to all versions and platforms. Define an
  intent only when its additions materially differ in network access,
  credentials, or writes outside the
  workspace. Do not create one intent per subcommand. An empty `local` intent
  identifies base-only use separately from omitted-intent aggregation.
- Intent dependencies and access additions must be justified by that intent.
  Example subcommands are caller guidance, not executable matching rules.
- CI must validate the agreed policy contract and version mapping,
  entry-ID uniqueness, dependency closure and cycle-freedom, symbol validity,
  absence of unsafe user-specific literal paths, unsupported-field rejection,
  deterministic resolution, and package inclusion.
- Build validation rejects missing/multiple defaults, version-only entries,
  variants tagged as default, and non-additive platform/version operations.
  Materialize and schema-validate every platform x architecture x version
  variant x intent combination, including omitted-intent aggregation.
- Verify default base requirements are a subset of each effective base, and
  each inherited default intent's policy/dependencies are a subset of the same
  effective intent. Overlays may add names through `newIntents`, never delete,
  rename, or redefine inherited intents. Validate dependency closures
  introduced by additions too.
- Generate rendered effective-policy views and diffs from the default for
  catalog reviewers; do not require reviewers to mentally expand overlays.
- A new entry or a requirement expansion requires one catalog-owner approval
  and one security/policy-reviewer approval, plus tool- or scenario-owner
  evidence where available.
- A requirement reduction needs regression evidence for the representative
  scenarios used to justify the entry, not a universal workflow guarantee.
- Catalog data and SDK changes follow MXC's contribution and release review.
  These requirements do not require applications to seek maintainer approval
  to use the SDK APIs.

## 7. Relationship to Learning Mode

Contributors use Learning Mode to discover tool requirements and productize
them as reviewed catalog data.

MXC's learning-mode capabilities (`learningModeLogging`,
`permissiveLearningMode`, `captureDenials`; see
[logging access denied](logging-access-denied.md)) are the
substrate a contributor can use to observe what a tool actually touches.
This is **a contributor step that happens before a pull request**, not consumer
runtime behavior or a catalog-mutation path.

Whether and how a consumer turns its own runtime capability observations into
a candidate catalog contribution or a locally scoped policy suggestion is
that consumer's design. The SDK provides no runtime submission hook or
automatic mutation of the release-bundled catalog.

## 8. Trust model

Entries assert *need*, not authorization. Incorrect data has two different outcomes:

- An understated floor omits a requirement and can cause the tool or its
  end-to-end workflow to fail under the resulting policy.
- An overstated floor can fail against a narrower consumer ceiling. If a
  consumer instead approves or adopts it and its ceiling permits the request,
  the effective policy contains unnecessary capability.

Even correct entries can yield a broader combined request than any one tool
needs. Read-write requirements supersede overlapping catalog read-only
requirements, and a conflicting catalog filesystem or egress deny is removed
in full under
[§3.5](#35-dependencies-and-composition). These changes are intentional and
reflected in the final suggested requirements; internal diagnostics can explain
them. They are not permission to remove a consumer's own restrictions, and
complete input coverage is not a safety signal.

Publication requires named-role approval
([§6](#6-contribution-and-review)) before an entry publishes, and publishes
under an immutable revision through MXC's package distribution
([§9](#9-immutable-revisions)).
That raises confidence in the data; it does not change what the data *is*. The
catalog still carries no security guarantee or independent authority. A
consumer must evaluate requirements under its own policy rather than treat the
catalog as authority. Its configured acceptance decision may be automatic or
interactive; this spec does not prescribe a UI. The catalog cannot grant
capability or override restrictive ceilings.

## 9. Immutable revisions

Published catalog revisions are immutable. A correction, including a security
fix to an over-broad entry, publishes a new `catalogRevision` and bumps the
affected `entryRevision`; it never rewrites a revision a consumer may already
have cached or recorded in an audit trail.

V1 embeds entries and shared symbol definitions in the native library at build
time and inherits MXC package signing and distribution integrity. It has no
separate catalog digest or runtime checksum. Schema validation still applies.

## 10. Backward compatibility

- No change to the v1 `ContainerRequest` or exact `ContainerConfig` schema.
- No change to executor behavior.
- New opt-in APIs in existing MXC SDKs; callers that do not use policy lookup
  see no behavior change from this feature.
- No breaking policy-schema changes within MXC 1.x; breaking changes require
  2.x. Bundled entries follow the containing SDK's compatible policy contract.

## 11. Test plan

**SDK resolver APIs (TypeScript/JavaScript, Rust, and C#/.NET)**

- Compile separate consumers in all three languages against the versioned entry
  points. Verify exact signatures, name-only conversions, optional context,
  .NET cancellation-token placement and the string-array caveat. Node must not
  block the event loop. Reuse real SDK nested types without conversions/casts.
- Compare effective requirements, original input indexes and
  [failure categories](mxc-policy-store-api.md#5-errors-and-caller-responsibilities)
  across bindings, not message prose. One input equals a one-element collection.
- Test all-complete and mixed batches, all-unmatched input, empty input, duplicate
  occurrences and an actual completed empty floor. A defined summary is required
  on every non-error path; absent output lists every original index, except
  empty input has no indexes. A defined empty aggregate is not a no-match fallback.
- Required `unresolvedInputs` must be sorted, distinct integers in original
  input range. Reject missing/malformed lists and inconsistent output accounting.
  A sole excluded root cannot leave dependency-only output. Clients may use
  partial combined requirements without an all-input gate.
- Register all JSON DTOs in `MxcJsonContext`, use `MxcJson`, and exercise them in
  `Microsoft.Mxc.Sdk.AotSmokeTest`, including absent/empty requirements and valid/
  malformed index lists. A false success must not arise from a defaulted field.
- Return only §3.2's supported fields. Reject unsupported UI and catalog keys,
  including null-valued cleanup/proxy fields. Leave caller-only
  SDK members unset and preserve uint32 timeout bounds.

**Selection, context and complete-root accounting**

- Cover version omission, in-range selection, valid out-of-range defaults and
  unparseable versions; no nearest/highest-range fallback. Cover named, omitted
  and unsupported intents, including a newer-only intent with an out-of-range
  version. Failed inputs skip their dependencies/symbols; no wildcard fills them.
- Rank package identity over invocation name, then intent specificity, then
  exact architecture. Reject distinct ties. Multiple predicates within one entry
  count once; version/intent failure never retries a weaker/different entry.
  File and input traversal order must not change effective access.
- Name-only string/object inputs both require weak matching opt-in. Invocation
  names are locale-independent insensitive on Windows/macOS and exact on Linux.
  PURL namespace/name follow type rules; Maven casing and equivalent encodings
  are covered. Validate candidate components before ignoring version/qualifiers/
  subpath; malformed candidates exclude only their input without weak-name retry.
- Test host platform, native (not emulated process) architecture, neutral/default
  fallback, explicit x64-on-ARM64 context and detection failure. Never select
  another architecture or invent missing identity/version evidence.
- Test neither project-root input, either alone, identical dual strings and
  conflicting dual strings. Conflicts fail before lookup, including empty input
  and lexically different paths naming the same object.
- Caller symbol values precede discovery and documented defaults. Resolve only
  needed symbols. Required-symbol failure suppresses all output; configuration
  read failure is an error. Another environment does not inherit this host's
  discoveries, and path overrides do not supply remote/guest object identity.
- Two versions/intents of one entry share default/platform base layers once.
  Retain distinct additions and internal direct/transitive requester attribution.
  Duplicate successful roots are not marked unresolved merely because their
  grants or dependencies were deduplicated.
- Dependencies use default/platform base and only explicitly referenced intents,
  not inferred version overlays. Validate references, intent availability and
  cycles. Exclusion removes exclusive layers, retains needed shared layers and
  recomposes only complete surviving roots.

**Composition and enforcement boundary**

- Exercise equal/nested read-only, read-write and denied paths after real symbol
  binding, within entries, across inputs and through dependencies. Read-write
  wins overlapping catalog read-only access; a read-only parent remains read-only
  outside a writable child. Remove an entire conflicting catalog deny; retain
  nonoverlapping ones.
- Test actual case rules (including case-sensitive macOS volumes/Windows
  directories), missing suffixes and unknown identity. Preserve case when unknown;
  lexical comparison must not substitute for necessary object identity checks.
- Include symlinks, junctions, hard links, bind mounts and 8.3 aliases. Keep every
  required pathname; `/data` and `/alias` must remain reachable with composed
  access. Unknown necessary identity excludes all affected roots, never only
  the restrictive side. Backend normalization must not reintroduce lost access.
- A no-network component cannot veto another's requirement. One network source
  retains supported egress/ingress; multiple scoped outbound sources preserve
  destination/exclusion/protocol/port pairings under deny-by-default.
- Remove whole conflicting egress denies only after CIDR exclusions and protocol/
  port comparison; retain nonoverlapping rules. Do not invent unrestricted
  networking. Undefined non-default ingress/allow-by-default merges fail; this
  is not a blanket ban on single-source ingress.
- UI/timeout from one deduplicated source survive; omission adds no value.
  Distinct sources setting the same field fail for equal and unequal values.
  Overlay scalar additions are rejected. The client can omit/override the timeout;
  lookup starts no execution timer and promises no minimum runtime.
- Preserve caller/OS/backend ceilings. Neither complete input coverage nor
  deletion of a restrictive catalog rule is authorization to widen those ceilings.

**Data (CI)**

- Materialize every platform/architecture/version/intent combination, including
  omitted-intent aggregation. Validate the closed field set, typed v1 request,
  exact schema and semantics without launching/probing a backend. Capture the
  exact request before normalization; never use its restrictive normalized copy
  as the floor merge input.
- Assemble per-tool sources deterministically across directories. Reject duplicate
  entry IDs, dangling references, cycles, invalid dependency intents and generated
  drift. Preserve immutable snapshots and catalog/entry revision monotonicity.
- Revalidate every bundled revision against the containing SDK's exact target;
  same-major stable older targets remain only after successful revalidation.
  Unvalidated or cross-major data is not bundled.
- Validate full catalog PURLs, then reject version/qualifiers/subpath predicates:
  `pkg:npm/foo@1`, `pkg:npm/foo?arch=x64`, `pkg:npm/foo#bin/cli.js`.
  Accept `pkg:npm/foo` when otherwise valid.
- Require one unversioned default. Reject missing/multiple defaults, version-only
  entries, default-tagged variants, duplicate platform selectors and overlapping
  version ranges, including inclusive boundaries. Cover adjacent ranges and the
  pinned npm/semver/pypi/nuget/intdot syntax and comparison rules.
- Verify add-only platform/version/intent layers retain inherited requirements
  and intents; reject narrowing, replacement, removal and rename. Shared symbol
  definitions/defaults are revision-pinned; reject unsupported default templates
  and executable catalog discovery. No literal user-specific paths or wildcard
  filesystem/network grants.
- Reviewer views and default-relative diffs show all effective base/intent access,
  dependencies and provenance.

**Internal troubleshooting**

- With a configured sink, preserve the internal reason/source facts needed to
  explain uncertainty and full removed-rule scope. Test privacy minimization,
  explicit detailed logging, per-call correlation and concurrent/async isolation.
- With logging disabled/unavailable, resolution output and failure semantics are
  unchanged. Emit no unsolicited caller stdout, no global last-result state and
  no telemetry-consent bypass. No public completion behavior depends on log parsing.

**Integration**

- All SDKs route through the shared Rust implementation and build-embedded data,
  with no dynamic fetching or sandbox execution at lookup.
- A caller uses summary requirements directly in a `ContainerRequest`, with
  caller-owned command/cwd and existing policy acceptance. Saved settings still
  receive current client restrictions; library/helper failures are not no-match.
- Lookup uses the build-validated default in the embedded manifest; a missing or
  unreadable default fails without substitution. SDK updates do not mutate saved
  policies. No binding exposes a caller-selected catalog revision.
- Representative tool workflows succeed when the accepted floor is sufficient,
  but fail when the consumer forbids required access. Caller filesystem/egress
  denies remain authoritative even when conflicting catalog denies were removed.
- Actual backend enforcement preserves composed path nesting and alias reachability
  without broadening read-only parents or recreating catalog conflicts. Resolver
  observations are never a replacement for these enforcement checks.

## 12. Open questions

| Maintainer sign-off | Recommended answer |
|---|---|
| Approve the command-free requirements API surface? | Review the [API spec](mxc-policy-store-api.md) before implementation, including inputs, results, errors, and partial-result behavior. |

## 13. Related work

- [`microsoft/mxc#779`](https://github.com/microsoft/mxc/pull/779) - Alex's original
  Sandbox Config Floors proposal, which informed this design.
- [Node v1 types](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/docs/reference/node/v1/types.md) -
  `ContainerRequest` and its access sections. Rust and .NET use their
  corresponding v1 SDK types.
- [Versioning design](development/architecture/versioning.md) - the versioning model
  [§3.1](#31-versions) builds on.
- [Package-URL VERS specification](https://github.com/package-url/vers-spec) -
  version-range syntax and supported version-type comparison references.
