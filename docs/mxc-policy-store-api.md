# Policy Store API

**Status:** Proposed API, under review before implementation.
Not part of MXC 1.0; no later release is committed.

Policy Store suggests container requirements for known tools. Lookup is
command-free and uses the SDK's bundled default catalog. It does not execute
tools, create containers, download data or save caller settings.

## 1. API overview

One operation accepts a tool or collection, plus optional lookup context:

```ts
export declare function resolveToolRequirements(
  tool: ToolInput,
  ctx?: ResolveContext,
): Promise<ToolRequirementsResolution>;
export declare function resolveToolRequirements(
  tools: readonly ToolInput[],
  ctx?: ResolveContext,
): Promise<ToolRequirementsResolution>;
```

Every non-error call returns the [two-field result](#3-types-and-fields):

| Field | Meaning |
|---|---|
| `requirements` | Suggested settings, or absence when no requirements can be returned |
| `unresolvedInputs` | Required, sorted, distinct zero-based indexes of original input occurrences not completely included |

### Results, coverage, and attribution

Resolution is best effort across **complete tool requirements and selected
dependencies**, never arbitrary fragments. Duplicate requests retain separate
input indexes even when their shared requirements are included once.

| Outcome | `requirements` | `unresolvedInputs` |
|---|---|---|
| Both inputs resolve | Combined requirements | `[]` |
| Only input 0 resolves | Input 0's requirements | `[1]` |
| Sole input does not resolve | Absent | `[0]` |
| Required symbol prevents output for two inputs | Absent | `[0, 1]` |
| Empty input list | Absent | `[]` |
| Complete input needs no additional fields | Defined empty aggregate | `[]` |

For nonempty input, output exists exactly when at least one index is not listed.
A failed sole input leaves no dependency-only output. The SDK rejects malformed
summaries, including missing, non-integer, duplicate, unsorted or out-of-range
indexes and inconsistent output presence.

A single-tool caller checks output presence. A multi-tool caller can use partial
output and report omitted inputs; there is no mandatory all-tools-covered gate.
Whole-call failures remain errors. **Neither completeness nor suggested access
is authorization or a guarantee of execution success.**

## 2. Zava Agent example

Zava Agent prepares a Git push on Windows using saved settings first, then the catalog if
enabled. Current client restrictions apply to either source. The omitted
application helpers decide acceptance and any prompting; no automatic saving or
review UI is prescribed. Paths and tool versions are illustrative.

```ts
// Proposed lookup API and its input/result types.
import { resolveToolRequirements } from "@microsoft/mxc-sdk/v1";
import type {
  ContainerRequirements, ResolveContext, ToolCandidate,
} from "@microsoft/mxc-sdk/v1";
// Existing SDK request type, used only after client acceptance.
import type { ContainerRequest } from "@microsoft/mxc-sdk/v1";

// Zava-owned helpers; implementations omitted.
declare function loadApplicableToolRequirements(
  tool: ToolCandidate, context: ResolveContext,
): Promise<ContainerRequirements | undefined>;
declare function isMxcFloorCatalogEnabled(): boolean;
declare function applyClientSettings(
  tool: ToolCandidate, requirements: ContainerRequirements,
): Promise<ContainerRequirements | undefined>;
declare function reportUnresolvedTool(tool: ToolCandidate): void;

async function createRequestForTool(
  tool: ToolCandidate,
  command: string,
  workingDirectory: string,
  context: ResolveContext,
): Promise<ContainerRequest | undefined> {
  let requirements = await loadApplicableToolRequirements(tool, context);

  if (requirements === undefined) {
    if (!isMxcFloorCatalogEnabled()) {
      return undefined;
    }

    const result = await resolveToolRequirements(tool, context);
    if (result.requirements === undefined) {
      reportUnresolvedTool(tool);
      return undefined;
    }
    requirements = result.requirements;
  }

  // Saved requirements must also respect today's client restrictions.
  const selected = await applyClientSettings(tool, requirements);
  return selected === undefined
    ? undefined
    : { ...selected, command, workingDirectory };
}

const workspace = String.raw`D:\work\repo`;
const request = await createRequestForTool(
  { invocationName: "git", detectedVersion: "2.45", intent: "push" },
  "git push",
  workspace,
  {
    projectRoot: workspace,
    allowWeakIdentityFallback: true,
    symbols: {
      git_prefix: String.raw`D:\tools\git`,
      ssh_prefix: String.raw`D:\tools\ssh`,
    },
  },
);
// Only a defined request proceeds to Zava's normal MXC run/spawn path.
```

The helpers are scoped to the user, workspace and target; saved-setting reuse
checks tool/version/intent and context. Lookup/helper exceptions propagate to
Zava's application error boundary, not an empty or uncontained fallback.
`projectRoot` binds symbols; the explicit `workingDirectory` sets the process cwd.

## 3. Types and fields

These proposed declarations are exported from `@microsoft/mxc-sdk/v1`.
Rust/.NET use equivalent versioned types and reuse their existing SDK policy
sections rather than defining a parallel policy model.

```ts
import type { ContainerRequest } from "@microsoft/mxc-sdk/v1";

export type ContainerRequirements = Pick<
  ContainerRequest,
  "filesystem" | "network" | "ui" | "timeoutMs"
>;

export interface ToolCandidate {
  invocationName: string;
  packageUrl?: string;
  detectedVersion?: string;
  intent?: string;
}

export type ToolInput = string | ToolCandidate;
export type CatalogPlatform = "windows" | "linux" | "macos";
export type CatalogArchitecture = "x64" | "arm64";

export interface ResolveContext {
  projectRoot?: string;
  symbols?: Record<string, string>;
  platform?: CatalogPlatform;
  architecture?: CatalogArchitecture;
  allowWeakIdentityFallback?: boolean;
}

export interface ToolRequirementsResolution {
  requirements: ContainerRequirements | undefined;
  unresolvedInputs: readonly number[];
}
```

| Output field | Supported content |
|---|---|
| `filesystem` | `readonlyPaths`, `readwritePaths`, `deniedPaths` |
| `network` | Directional `egress` and `ingress` policy |
| `ui` | Required `disable`; optional `clipboard` and `allowInputInjection` |
| `timeoutMs` | Optional uint32 execution-timeout suggestion, not a minimum runtime |

The reused types are broader than resolver output. `filesystem.clearPolicyOnExit`
and `network.runtimeConfig` remain unset (`undefined`/`None`/`null`); `Pick` is
not runtime validation. The caller can omit/override the timeout and owns the
command, cwd, containment, environment, cleanup, proxy runtime values and other
execution settings.

## 4. Matching and returned requirements

### Context defaults and symbol resolution

| Input omitted | Default |
|---|---|
| `ctx`, `projectRoot`, `symbols` | No caller overrides or invented project root |
| `platform` | Current host |
| `architecture` | Native host architecture, not an emulated process architecture |
| `allowWeakIdentityFallback` | `false` |
| Package identity/version | No fabricated evidence |
| `intent` | All intents in the selected effective policy |

`projectRoot` and `symbols.project_root` are aliases. If both are supplied,
different strings fail the whole context before lookup; no path normalization
or object comparison chooses a winner.

For needed symbols, use caller values, then supported local discovery, then
documented platform defaults. An unresolved required symbol suppresses all
requirements; a configuration-read failure is an error. Path overrides do not
provide remote/guest filesystem identity or execute discovery commands.
See the [symbol contract](mxc-policy-store.md#32-entry-shape) for implementation details.

### Identity and match precedence

A string input supplies only `invocationName`; weak-name matching still requires
opt-in. Callers supply identity/version evidence and map commands to intent
names; the catalog neither parses commands nor verifies the installed tool.

Rank matching entries by package identity, then requested-intent specificity,
then exact architecture. One highest-ranked entry wins; distinct ties fail.
Multiple matching predicates in one entry count once. Version/intent failure
does not retry a weaker entry or wildcard.

| Match input | Comparison |
|---|---|
| `packageUrl` | Validate the whole PURL, then compare decoded type/namespace/name using type-specific rules; ignore candidate version/qualifiers/subpath |
| `detectedVersion` | The only version evidence; parse using the entry's supported scheme |
| `invocationName` | Locale-independent, case-insensitive on Windows/macOS; exact on Linux |
| Invalid candidate PURL | Exclude that input; no repair or weak-name retry |

The [precise PURL/VERS rules](mxc-policy-store.md#33-identity) are shared by
authoring and lookup. Host filesystem casing is never package-identity casing.

### Version, intent, and platform selection

| Input | Selected requirements |
|---|---|
| Version omitted | Common default plus applicable platform additions |
| Version in one range | Default, platform and that version's additions |
| Valid version outside every range | Default plus platform additions, never nearest/highest variant |
| Unparseable version | Exclude input |
| Supported named intent | Effective base plus that intent's additions |
| Intent omitted | Effective base plus all effective intents, or base alone if none exist |
| Unsupported named intent | Exclude input, never a base/all-intents fallback |

Select at most one add-only overlay per dimension; ranges do not overlap or
cascade. A newer-only intent with an out-of-range version remains unavailable.
Exact architecture takes precedence over platform-neutral additions, otherwise
retain the common default; never select another architecture. A tool running
under emulation may need explicit architecture context. Detection failure is
a library error.

### Dependencies and composition

Return one combined sandbox suggestion, not separate permissions per tool.
Each included input brings its complete selected dependency closure; shared
layers are included once. Unknown necessary filesystem identity excludes all
affected inputs, not just the restrictive side.

Required catalog grants can supersede read-only access or remove an entire
conflicting catalog deny, including egress denies. Caller restrictions are never
removed. Undefined merges fail rather than approximate broader access.
The [composition rules](mxc-policy-store.md#35-dependencies-and-composition)
define dependency selection, alias handling, egress exclusions and scalar conflicts.

## 5. Errors and caller responsibilities

| Whole-call failure | MXC code | Optional reason |
|---|---|---|
| Invalid input/context | `malformed_request` | `invalid_context` |
| Invalid catalog, dependencies or cycles | `policy_validation` | `invalid_catalog` |
| Tied highest-ranked entries | `policy_validation` | `ambiguous_match` |
| Incompatible SDK target or undefined composition | `policy_validation` | `composition_conflict` |
| Unsupported/undetectable host | `unsupported_containment` | `unsupported_host` |
| Bundled catalog cannot be read | `backend_error` | `integrity` |

Handle primary codes; optional reasons, where exposed, do not require message
parsing. Unmatched tools, unsupported intents and other defined per-input
exclusions are different from these whole-call errors.

The caller decides acceptance and preserves its user/OS/backend ceilings.
No result authorizes uncontained fallback. The summary reports input coverage,
not per-entry provenance. [Internal troubleshooting](mxc-policy-store.md#42-results-and-troubleshooting)
does not provide a stable caller audit or log-parsing API.

## 6. Language bindings

All bindings preserve the same inputs, two-field result and partial outcomes.
TypeScript uses the [Promise-returning overloads above](#1-api-overview).
Rust is synchronous; .NET provides synchronous and Task-returning forms.

### Rust

Signature in `mxc_sdk::v1`:

```rust
pub fn resolve_tool_requirements(
    tools: &[ToolCandidate],
    context: Option<&ResolveContext>,
) -> Result<ToolRequirementsResolution, Error>;
```

One tool uses a one-element slice; `None` selects default context.
The result holds `requirements: Option<ContainerRequirements>` and
`unresolved_inputs: Vec<usize>`. `ToolCandidate::from(&str)` copies only the
invocation name into the candidate; package URL, version and intent remain `None`.

### .NET

Member signatures in `Microsoft.Mxc.Sdk.V1.MxcContainer`:

```csharp
public static ToolRequirementsResolution ResolveToolRequirements(
    ToolCandidate tool, ResolveContext? context = null);
public static ToolRequirementsResolution ResolveToolRequirements(
    IReadOnlyList<ToolCandidate> tools, ResolveContext? context = null);
public static Task<ToolRequirementsResolution> ResolveToolRequirementsAsync(
    ToolCandidate tool, ResolveContext? context = null,
    CancellationToken cancellationToken = default);
public static Task<ToolRequirementsResolution> ResolveToolRequirementsAsync(
    IReadOnlyList<ToolCandidate> tools, ResolveContext? context = null,
    CancellationToken cancellationToken = default);
```

The result has `ContainerRequirements? Requirements` and required
`IReadOnlyList<int> UnresolvedInputs`. Cancellation stops awaiting, not a native
call already in progress; the SDK owns late-result cleanup.
`ToolCandidate(string invocationName)` and implicit string conversion preserve
the name and leave other candidate fields null; a null name throws
`ArgumentNullException`. Use a typed `ToolCandidate[]` or target-typed collection:
a `string[]` does not convert element-by-element.

Neither binding's conversion trims names, parses commands/PURLs, invents identity
or enables weak matching. Converted and directly constructed candidates use
the same resolver validation.
