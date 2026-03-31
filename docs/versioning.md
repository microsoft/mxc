# MXC Schema Versioning Plan

## Two Independent Version Streams

The OS schema and MXC schema are **not lock-stepped**. They version independently:

- **OS schema** — versioned by the OS team (semver). Defines what the OS can enforce (AppContainer, UI limits, compartments, etc.)
- **MXC schema** — versioned by MXC team (semver). Defines the cross-platform policy language. MXC maps its schema onto whatever OS schema is available underneath.

MXC is responsible for adapting to multiple OS versions. The OS is rigid about what it supports.

## Versioning Semantics (Semver)

| Bump | When | Example |
|---|---|---|
| **Patch** (x.y.Z) | Bug fixes only | Fix incorrect default value |
| **Minor** (x.Y.0) | New features, backward compatible | Add UI limits, new namespace restrictions |
| **Major** (X.0.0) | Breaking changes | Redesign policy language, remove deprecated features |

**Backward compatibility commitment:** Support at minimum **N-1 major versions** (WinApp SDK pattern). When bumping to major version 3, the OS still supports version 2. When bumping to 4, version 2 is dropped.

## Default Deny Semantics

- **MXC policy layer:** Default deny — start locked down, explicitly allow what's needed. Consistent, easy to author.
- **OS technical layer:** Composable — supports both allow and deny semantics. Like ACLs: sometimes it's easier to allow a group and deny one member. The OS provides the Lego pieces; MXC assembles them.
- **0.4.0-alpha for now:** Default deny for UI policy. The deny-everywhere question (e.g., AppContainer vs LPAC) is deferred — too restrictive breaks everything.

## Runtime Validation Flow

Schema version alone doesn't guarantee a feature works. Two-step validation:

1. **Schema version check** — Does the OS support the schema version in the config? Query the OS for its current/max supported version.
2. **Runtime capability check** — Even with the right schema version, features may be unavailable (Hyper-V off, no GPU, etc.). Validation happens at execution time, not just compilation time.

```
Config JSON arrives at wxc-exec.exe / lxc-exec
        │
        ▼
Step 1: Parse JSON
        config_parser.rs → CodexRequest
        │
        ▼
Step 2: MXC schema version check
        Config version ≤ MXC SUPPORTED_VERSION?
        "Does this MXC binary understand this config format?"
        │
        ▼
Step 3: Query OS schema version (NEEDED — does not exist yet)
        MXC calls OS API to check what policy version is supported.
        MXC maps its features to the OS version.
        TODAY: MXC assumes the OS supports everything if the
        Windows build number is ≥ 26100.
        │
        ▼
Step 4: Runtime capability check (PARTIAL)
        Even with right versions, hardware/config may prevent features:
          Hyper-V off → no sandbox/VM backend
          No GPU → gpu: true fails
          iptables missing → LXC network fails
          WSLC SDK missing → wslc fails
        TODAY: Only checks Windows build ≥ 26100, LXC installed,
        proxy DLLs available.
        │
        ▼
Step 5: Execute or fail with clear error
        All checks pass → route to runner
        Any check fails → error with what failed, why, and what to do
```

**Policy compilation:** Compile on-device, not pre-compiled and shipped. Pre-compiled artifacts become invalid when the OS updates. For dynamic callers (GitHub Copilot generating policies on the fly), compilation happens at launch time.

**Error semantics:** If a policy requests something the OS can't do, fail with a clear error. No relaxation — security policy is deterministic, not fuzzy. Upper layers (MXC) may adapt; the OS layer does not.

## OS API for Version Discovery

The OS needs to expose an API for MXC to query capabilities:

**Option A — Version-based:**
```c
HRESULT TesseraGetSchemaVersion(UINT32* major, UINT32* minor, UINT32* patch);
// Returns: 1.1.0 → MXC knows OS supports up to schema 1.1 features
```

**Option B — Feature-based (DX model):**
```c
HRESULT TesseraQueryFeature(PCWSTR featureName, BOOL* supported);
// "UILimits" → TRUE
// "Compartments" → FALSE
```

**Decision:** Start with version-based (simpler). Add feature-based querying when composable features (compartments, per-namespace policies) arrive.

## Backporting

**Current stance:** Iterate forward only. Avoid backporting as long as possible — it creates N² complexity across OS branches.

**If backporting is needed:** Use semver patch versions (e.g., backport feature X from 0.6.0 to 0.4.1). The OS branch ships the patched binary. MXC adapts by querying the OS version.

**Open question:** If a security patch changes OS behavior, does it change the OS schema version? Unresolved — deferred.

## Near-Term Plan (Mid-April / 4D Milestone)

- Ship **0.4.0-alpha** schema — experimental, may change before version 1.0
- Policy must compile and configure AppContainer + UI limits end-to-end through the pipeline
- No version 1.0 schema semantics required yet
- Document the schema in a spec for team review
- Binary format decision (flat buffers vs structs) deferred — focus on semantics first

## Open Questions

1. **Policy format:** Flat buffers (forward/backward compatible, no string parsing in OS) vs versioned structs (simpler but brittle). Memory ownership semantics (caller allocates/frees).
2. **Compartments versioning:** Compartments are composable from pieces (anti-debug, thread injection prevention, APC protection). New pieces arrive incrementally as minor versions — not a single feature flag.
3. **When to bump major:** If the policy language is fundamentally redesigned (e.g., UI policy doesn't work → 1.0 to 2.0).
4. **Feature-based vs version-based OS query:** Start version-based, add feature queries when composable features arrive.
