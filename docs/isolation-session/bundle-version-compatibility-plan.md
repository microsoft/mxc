# IsolationSession Runtime Instance-Compatibility Plan

## Problem

The IsolationSession implementation binaries (`IsoSessionApp.dll`,
`IsoSessionClient.dll`, `IsoSessionServer.dll`, `IsolationProxy.exe`,
`IsoSessionProxyStub.dll`, `IsoSessionInstaller.exe`, `IsoSession.manifest`) do
**not** live in `System32`. They ship out-of-band — via an MSI (or the
`poc-assemble-2606.ps1` PoC) — into a runtime folder such as
`%ProgramFiles%\Microsoft\Agentic Runtime\2026.06`. Multiple runtime versions can
coexist, each identified by an **instance string** (e.g. `"2026.06"`).

`wxc-exec.exe` is built against a *metadata-only* NuGet
(`Microsoft.Windows.AI.IsolationSession.SDK.<version>.nupkg`) that records which
instance it was generated for. At runtime, `wxc-exec.exe` must **verify that the
runtime folder it binds is the instance it was built against** before driving the
backend, and fail cleanly with a typed error when it is not.

## The NuGet *is* the mapping (where compatibility is defined)

There is **no separate lookup table** of "which instance is compatible with which
MXC version", and there does not need to be. The compatible instance is **pinned
at build time by the NuGet MXC compiles against** — the act of building *is* the
binding.

The metadata-only NuGet
(`Microsoft.Windows.AI.IsolationSession.SDK.0.202606.0.nupkg`) contains:

| File | Role |
|---|---|
| `metadata/windows.ai.isolationsession.winmd` | Official WinRT metadata — regeneration input for `bindings.rs` |
| `metadata/windows.ai.isolationsession.preview.winmd` | Preview metadata (the surface MXC currently calls) |
| `metadata/GENERATION_INFO.toml` | **Provenance + the `instance` identity** — the only file a normal build reads |
| `*.nuspec` | Package manifest; `<version>` (`0.202606.0`) encodes the **dot-stripped** instance in its minor field (`2026.06` → `202606`) |
| `README.md`, NuGet plumbing | Docs / packaging |

It ships **no implementation DLLs**. The runtime binaries
(`IsoSessionApp.dll`, …, `IsoSession.manifest`) are delivered out-of-band by the
matching runtime MSI into `%ProgramFiles%\Microsoft\Agentic Runtime\2026.06`.

The `instance` identity is stamped by the OS repo's `pack.ps1` into
`metadata/GENERATION_INFO.toml`:

```toml
target_windows_crate = "0.62"   # gates the windows crate (build.rs uses this today)
instance     = "2026.06"        # <- THE runtime identity this metadata pairs with
runtime_dir  = "%ProgramFiles%\\Microsoft\\Agentic Runtime\\2026.06"
winmd_sha256 = "A308955792326C187..."
generated_utc = "2026-06-29T17:25:56Z"
```

Its own comment states the role: *"Runtime identity this metadata is versioned
with. Selects which MSI-installed runtime folder MXC binds at runtime."* The
nuspec echoes it: *"Version tracks the IsoSession API/runtime identity (the
'2026.06' folder/instance). Bump in lockstep with the matching MSI runtime."*

So the mapping flows like this — established at build, verified at runtime:

```
NuGet (instance = "2026.06")
        │  build.rs reads it, bakes ISOSESSION_INSTANCE=2026.06 into the binary
        ▼
wxc-exec.exe  ── carries "I was built for 2026.06" ──┐
                                                  │ runtime string compare
Installed runtime MSI -> ...\Agentic Runtime\2026.06 ┘
```

Because the contract is strict 1:1 (one NuGet ⇄ one instance), the runtime check
is a single baked value vs the installed instance — no range, no table. Owning
correctness of the mapping is a **pack-time** responsibility (the NuGet packer
stamps the right `instance` for the API surface it ships); MXC's only job is to
faithfully record what it was built against and refuse to run against anything
else.

## Background: build/runtime split (already on `user/dalegg/isosession-nuget`)

The compatibility check builds on top of design that has already landed:

- **Build side** — MXC compiles against the metadata-only NuGet (WinMD +
  `metadata/GENERATION_INFO.toml`). `bindings/build.rs` already resolves
  `GENERATION_INFO.toml` (priority `ISOSESSION_SDK_PATH` → `*.nupkg` → committed
  fallback) and version-gates `target_windows_crate`. No implementation DLLs are
  needed to build.
- **Runtime side** — the implementation binaries are loaded by full path at
  runtime. `regfree.rs` already owns this: it reads the runtime folder from
  `MXC_ISOSESSION_RUNTIME_DIR` (`RUNTIME_DIR_ENV`), establishes a side-by-side
  activation context from `IsoSession.manifest`, `LoadLibraryW`s
  `IsoSessionApp.dll` from that folder, and obtains the activation factory
  directly. `manager::check_service_available_and_activate()` already calls it.
- **The coupling is the instance identity string, not a semver.** The NuGet
  records `instance = "2026.06"` and `runtime_dir =
  %ProgramFiles%\Microsoft\Agentic Runtime\2026.06`. The `<instance>` string — not
  the MXC package version — selects the runtime folder. Build and runtime are
  bumped in lockstep but the instance string is an OS/runtime identity, distinct
  from MXC's `CARGO_PKG_VERSION`.
- Runtime identity additionally lives **inside** `IsoSession.manifest` as an
  embedded `<iso:instance name="2026.06">` element (the last child of
  `<assembly>`), so the same file drives reg-free activation and names the
  instance.

**The gap:** no runtime *instance compatibility check* exists yet. Today
`regfree.rs` silently `eprintln!`s and falls back to system activation when the
runtime dir is missing or bad. We need to compare the **build-baked expected
instance** against the **runtime actual instance** and surface a typed error on
mismatch.

## Decisions

1. **Compatibility model:** strict exact match on the **instance identity
   string** (e.g. `"2026.06"`), not the MXC package version.
2. **Build-side "expected" instance:** `bindings/build.rs` reads `instance` from
   the NuGet's `metadata/GENERATION_INFO.toml` (same parse path it already uses
   for `target_windows_crate`) and emits it as a compile-time constant
   (`cargo:rustc-env=ISOSESSION_INSTANCE=<instance>`), read at runtime via
   `option_env!`.
3. **Runtime-side "actual" instance:** derive from `MXC_ISOSESSION_RUNTIME_DIR`.
   The authoritative source is `<iso:instance name="…">` in the runtime dir's
   `IsoSession.manifest`; the leaf folder name (`…\Agentic Runtime\2026.06` →
   `2026.06`) is only a fallback when the manifest carries no instance marker.
   **Part 2 hardening:** when a runtime dir is configured it is validated
   strictly — the directory must exist and contain an `IsoSession.manifest`;
   a missing directory or missing manifest is a hard `IncompatibleVersion`
   error, not a silent skip. This closes the spoof where renaming a stub leaf
   folder could satisfy a leaf-name-only comparison.
4. **Discovery:** reuse `regfree.rs::RUNTIME_DIR_ENV`
   (`MXC_ISOSESSION_RUNTIME_DIR`). No `current_exe()` fallback.
5. **Scope:** add the instance compatibility **check** only — activation and DLL
   loading are already implemented in `regfree.rs`.
6. **Tolerant degradation (bounded):** if the expected instance is unknown
   (source-only build with no `instance` in the fallback TOML) **or** the
   runtime dir is unset, skip the check (`Ok(())`) — preserving today's
   behavior. But once a runtime dir *is* configured, the check is strict:
   a non-existent directory, a missing `IsoSession.manifest`, or a
   present-but-mismatched instance are all errors. (This is intentionally
   stricter than reg-free activation, which silently degrades on a missing
   manifest; the compatibility gate must not.)

## Build-time: taking the *correct* NuGet dependency

The runtime check is only as trustworthy as the `ISOSESSION_INSTANCE` baked into
the binary, so the build must guarantee MXC compiles against the right package.
The NuGet is **vendored** (the `.nupkg` is committed under
`external/windows-sdk/isolation-session/`, not restored from a feed), so git is
the source of truth. Today `build.rs` resolves it as
`ISOSESSION_SDK_PATH` env → first `*.nupkg` in the dir → committed
`GENERATION_INFO.toml` fallback, and only gates `target_windows_crate`. The
following gates close the "wrong package" gaps:

1. **Exactly one nupkg.** Replace the current "first `*.nupkg`" (`find_nupkg`'s
   `.find(...)`) with an assertion that the directory holds exactly one — error
   on more than one rather than picking arbitrarily by filesystem order.
2. **Triangulate the instance.** Parse the `instance` from the TOML, the
   `<version>` from the nuspec, and the version embedded in the nupkg filename
   (`…SDK.0.202606.0.nupkg`), and **fail the build if they disagree** (the
   `instance` compares dot-stripped: `2026.06` → `202606` = the version minor).
   This is what
   makes the baked `ISOSESSION_INSTANCE` provably the package's declared identity
   (a renamed/repacked file can otherwise lie).
3. **Verify `winmd_sha256`.** Hash the shipped winmd and compare to the
   `winmd_sha256` recorded in `GENERATION_INFO.toml` — a cheap integrity gate
   against a tampered or mismatched package.
4. **Keep the fallback in sync.** Add `instance` to the committed
   `external/.../GENERATION_INFO.toml`, and add a CI gate (mirroring
   `scripts/versioning/check-*.js`) that asserts the committed fallback matches
   the nupkg's `metadata/GENERATION_INFO.toml`, so a fallback build never bakes a
   stale/absent instance.
5. **Make `ISOSESSION_SDK_PATH` non-silent.** Document it as regeneration/local
   override only, and emit a `cargo:warning` whenever it is active so an override
   is never invisible.

Net effect: the only way to build MXC is against the single, integrity-checked,
self-consistent committed NuGet, so `wxc-exec.exe` carries exactly the instance
the package declares.

## Implementation steps
1. **`bindings/build.rs`** — after resolving `GENERATION_INFO.toml`, also extract
   `instance` (same line-parse style as `target_windows_crate`) and emit
   `println!("cargo:rustc-env=ISOSESSION_INSTANCE={instance}")`. Skip silently
   when absent (source-only builds). In the same pass, add the build-time
   correctness gates from the section above:
   - replace `find_nupkg`'s "first match" with an **exactly-one** assertion
     (error on >1 nupkg in the dir);
   - **triangulate** the instance — parse the nuspec `<version>` and the version
     embedded in the nupkg filename and `panic!` if either disagrees with the
     TOML `instance`;
   - **verify `winmd_sha256`** — hash the shipped winmd and compare to the TOML
     value; `panic!` on mismatch;
   - emit a `cargo:warning` whenever `ISOSESSION_SDK_PATH` is active so an
     override is never silent.
2. **`regfree.rs`** — add:
   - `expected_instance() -> Option<&'static str>` = `option_env!("ISOSESSION_INSTANCE")`.
   - `read_manifest_text(dir)` — BOM-aware read of `IsoSession.manifest`.
   - `parse_manifest_instance(xml) -> Option<String>` — extract `name` from the
     `<iso:instance …>` element only (ignoring `<assemblyIdentity>`/`<file>`).
   - `runtime_instance_from_dir(dir) -> Option<String>` = trimmed leaf folder
     name (fallback when the manifest carries no instance marker).
   - `evaluate_instance_compatibility(expected, runtime_dir)`: unset runtime dir
     or unknown expected → `Ok(())`; a configured runtime dir must **exist** and
     contain an **`IsoSession.manifest`** (else `IncompatibleVersion`); actual =
     manifest instance or leaf fallback; unequal → `IncompatibleVersion` naming
     both instances.
   - `check_instance_compatibility()` — thin wrapper reading env + build const.
3. **`manager.rs`** — call `check_instance_compatibility()` at the top of
   `check_service_available_and_activate()`, *before* `ensure_regfree_activation()`
   / `activate_from_runtime_dir()`. This single insertion point covers one-shot
   and state-aware paths.
4. **`error.rs`** — add `IsolationSessionError::IncompatibleVersion(String)`;
   `Display` includes expected (build) vs found (runtime) instance;
   `map_lifecycle_error` → `MxcError::backend_unavailable` (keeps the closed SDK
   `ErrorCode` union unchanged; the message carries the detail). Extend the
   existing mapping test.
5. **`external/.../GENERATION_INFO.toml` fallback** — add `instance` so
   source-only builds bake an expected instance too (otherwise the runtime check
   degrades to "skip" per decision 6).
6. **`scripts/versioning/check-isosession-sdk.js`** — new CI gate (mirroring the
   existing `scripts/versioning/check-*.js` pattern) that unzips the committed
   nupkg and asserts: exactly one nupkg present; the nupkg filename version,
   nuspec `<version>`, and `metadata/GENERATION_INFO.toml` `instance` all agree;
   and the committed fallback `external/.../GENERATION_INFO.toml` matches the
   nupkg's copy. Wire it into the Versioning Checks workflow.

No new `bundle.rs` module, no `serde_json` dependency, no
`MXC_ISOLATION_BUNDLE_DIR` env var — reuse `regfree.rs` + `RUNTIME_DIR_ENV`.

## File map

**New**
- `scripts/versioning/check-isosession-sdk.js` — CI gate: nupkg self-consistency
  + fallback-in-sync

**Modified**
- `src/backends/isolation_session/bindings/build.rs` — emit `ISOSESSION_INSTANCE`;
  exactly-one-nupkg + instance triangulation + `winmd_sha256` gates +
  `ISOSESSION_SDK_PATH` warning
- `src/backends/isolation_session/common/src/regfree.rs` — instance check
- `src/backends/isolation_session/common/src/manager.rs` — call the check
- `src/backends/isolation_session/common/src/error.rs` — new variant + mapping + test
- `external/windows-sdk/isolation-session/GENERATION_INFO.toml` — add `instance`
- `.github/workflows/*` (Versioning Checks) — run `check-isosession-sdk.js`
- `docs/isolation-session/state-aware-rust-initial-plan.md` — error-mapping table
- `.github/copilot-instructions.md` — IsolationSession row: instance compatibility

## Tests

**Rust (CI-safe — pure string/path + temp-dir logic, no DLL)**
- `regfree.rs` `#[cfg(test)]`:
  - `parse_manifest_instance`: extracts `<iso:instance name>`; ignores
    `<assemblyIdentity name>` / `<file name>`; tolerates the `<?xml?>` prolog;
    both quote styles.
  - `attr_value`: matches a standalone `name` attribute; rejects `filename`.
  - `read_manifest_text`: UTF-8 and UTF-16 (BOM) manifests.
  - strict `evaluate_instance_compatibility` (temp-dir based): match → `Ok`;
    mismatch → `IncompatibleVersion`; **non-existent dir → error**; **missing
    manifest → error**; leaf-name fallback when manifest has no instance;
    unset runtime-dir env → `Ok`; unknown expected instance → `Ok`.
- `error.rs`: `IncompatibleVersion` → `BackendUnavailable` mapping.

**Build-script behavior** (exercised by the CI gate + a successful build)
- the committed nupkg passes triangulation + `winmd_sha256` (build succeeds);
- `check-isosession-sdk.js` fails on a deliberately mismatched fixture
  (instance/version disagreement, or fallback out of sync).

## Validation

- `node scripts/versioning/check-isosession-sdk.js`
- `cd src; cargo build -p isolation_session_bindings -p isolation_session_common`
- `cd src; cargo test -p isolation_session_common`
- `cd src; cargo clippy -p isolation_session_common --all-targets -- -D warnings`
- `cd src; cargo fmt --all -- --check`

## Open / deferred items

- Whether to also parse `<iso:instance name>` from `IsoSession.manifest` as a
  stronger runtime-instance source than the folder leaf name (decision 3 allows
  either; the leaf name is the minimal first cut).
- Whether to add a dedicated `MxcErrorCode::IncompatibleVersion` to the SDK
  closed union (cross-cutting Rust + TS + docs change) vs reusing
  `backend_unavailable` (chosen default).
- Whether `winmd_sha256` verification should `panic!` (hard-fail the build) or
  emit a `cargo:warning` — defaulting to hard-fail, since a winmd that disagrees
  with its recorded hash means the committed `bindings.rs` provenance is
  untrustworthy.
