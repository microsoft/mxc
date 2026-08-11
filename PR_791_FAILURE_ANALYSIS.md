# PR #791 - GitHub Actions Build Failure Analysis

## Summary
All three failing workflow runs are caused by **a single root issue**: a **duplicate key error in the workspace Cargo.toml file at line 109**, specifically for the `sha2 = "0.10"` dependency entry.

## Failing Workflow Runs

### 1. Run 31447349268: Build Workflow
**Jobs Failing:**
- `dependency-feed-check / Resolve deps through MxcDependencies feed` - FAILURE
- `versioning-checks / Versioning Checks` - FAILURE

**Error Details:**
```
error: duplicate key
   --> Cargo.toml:109:1
    |
109 | sha2 = "0.10"
    | ^^^^
```

**Root Cause:** The Cargo.toml parsing fails when trying to run `cargo metadata` to validate dependencies or regenerate the schema. The duplicate key error prevents:
- Schema codegen validation (check-schema-codegen.js)
- Dependency feed resolution (cargo fetch)
- All downstream build jobs

**Failed Step in Versioning Checks:**
- Step 10: "Check schema is in sync with the Rust wire model (codegen)" → FAILURE
- Error occurs when running: `cargo run -q -p mxc_schema_gen`
- Node.js child_process throws error due to cargo exit code 101

**Command that failed:**
```bash
cargo run -q -p mxc_schema_gen -- /tmp/mxc-schema-gen-16PJDJ/generated.json
```

**Error message from child_process:**
```
Error: Command failed: cargo run -q -p mxc_schema_gen -- /tmp/mxc-schema-gen-16PJDJ/generated.json
    at genericNodeError (node:internal/errors:984:15)
    at wrappedFn (node:internal/errors:538:14)
    at checkExecSyncError (node:child_process:891:11)
    at execFileSync (node:child_process:927:15)
    at Object.<anonymous> (/home/runner/work/mxc/mxc/scripts/versioning/check-schema-codegen.js:49:3)
```

**Failed Step in Dependency Feed Check:**
- Step 6: "Fetch all locked crates through the feed (anonymous)" → FAILURE
- Error: "error: duplicate key" when running `cargo fetch`
- The error message shows a TOML parsing failure before the feed resolution can even occur
- Stack trace shows the rust-cache action's cargo metadata invocation failed

---

### 2. Run 31447349167: WXC-Exec Hyperlight (Hyperlight E2E Tests)
**Job Failing:**
- `WXC-Exec Hyperlight` - FAILURE

**Error Details:**
```
error: duplicate key
   --> Cargo.toml:109:1
    |
109 | sha2 = "0.10"
    | ^^^^
```

**Root Cause:** The build fails when attempting to build with Hyperlight support. The Cargo.toml parsing error prevents the build from starting.

**Failed Step:**
- Step: "Build with Hyperlight support"
- Command: `cargo build --features hyperlight --target x86_64-pc-windows-msvc`
- Exit code: 1
- The cargo metadata invocation by rust-cache fails due to the duplicate key error
- Even after clearing fingerprints, the build still fails because the Cargo.toml can't be parsed

**Full Error Output:**
```
error: duplicate key
   --> Cargo.toml:109:1
    |
109 | sha2 = "0.10"
    | ^^^^
##[error]Process completed with exit code 1.
```

---

### 3. Run 31447349210: WXC-Exec MicroVM (Integration Tests)
**Job Failing:**
- `WXC-Exec MicroVM` - FAILURE

**Error Details:**
```
error: duplicate key
   --> Cargo.toml:109:1
    |
109 | sha2 = "0.10"
    | ^^^^
```

**Root Cause:** Identical to Run 31447349167 - the MicroVM build fails due to the same Cargo.toml parsing error.

**Failed Step:**
- Step: "Build with MicroVM support"
- Command: `cargo build --features microvm --target x86_64-pc-windows-msvc`
- Exit code: 1
- The cargo metadata invocation fails during the dependency resolution phase

**Full Error Output:**
```
error: duplicate key
   --> Cargo.toml:109:1
    |
109 | sha2 = "0.10"
    | ^^^^
##[error]Process completed with exit code 1.
```

---

## Detailed Error Context

### From Versioning Checks (Run 31447349268):
```
2026-08-11T00:50:04.2497444Z   MXC_VERSIONING_BASE_REF: origin/main
2026-08-11T00:50:04.5771467Z info: latest update on 2026-02-12 for version 1.93.1 (01f6ddf75 2026-02-11)
2026-08-11T00:50:04.5771467Z info: downloading 5 components
2026-08-11T00:50:13.6047927Z error: duplicate key
2026-08-11T00:50:13.6048397Z    --> Cargo.toml:109:1
2026-08-11T00:50:13.6048783Z     |
2026-08-11T00:50:13.6049118Z 109 | sha2 = "0.10"
2026-08-11T00:50:13.6049438Z     | ^^^^
2026-08-11T00:50:13.6096857Z node:child_process:930
2026-08-11T00:50:13.6097441Z     throw err;
2026-08-11T00:50:13.6097761Z     ^
2026-08-11T00:50:13.6098792Z Error: Command failed: cargo run -q -p mxc_schema_gen -- /tmp/mxc-schema-gen-16PJDJ/generated.json
```

### From Dependency Feed Check (Run 31447349268):
```
2026-08-11T00:50:05.4062588Z   commandFailed: {
2026-08-11T00:50:05.4063181Z     command: 'cargo metadata --all-features --format-version 1 --no-deps',
2026-08-11T00:50:06.3383247Z error: duplicate key
2026-08-11T00:50:06.3398954Z ##[error]   --> Cargo.toml:109:1
2026-08-11T00:50:06.3409035Z     |
2026-08-11T00:50:06.3409368Z 109 | sha2 = "0.10"
2026-08-11T00:50:06.3409719Z     | ^^^^
2026-08-11T00:50:06.3419488Z ##[error]cargo fetch failed for a reason other than a feed 401 (see the log above).
2026-08-11T00:50:06.3422342Z ##[error]Process completed with exit code 1.
```

### From Hyperlight Build (Run 31447349167):
```
2026-08-11T00:50:14.6534656Z       'error: duplicate key\n' +
2026-08-11T00:50:14.6535034Z       '   --> Cargo.toml:109:1\n' +
2026-08-11T00:50:14.6535725Z       '    |\n' +
2026-08-11T00:50:14.6536035Z       '109 | sha2 = "0.10"\n' +
2026-08-11T00:50:14.6536602Z       '    | ^^^^\n'
2026-08-11T00:50:35.2574682Z error: duplicate key
2026-08-11T00:50:35.2575106Z    --> Cargo.toml:109:1
2026-08-11T00:50:35.2575415Z     |
2026-08-11T00:50:35.2575687Z 109 | sha2 = "0.10"
2026-08-11T00:50:35.2575989Z     | ^^^^
2026-08-11T00:50:35.3750957Z ##[error]Process completed with exit code 1.
```

### From MicroVM Build (Run 31447349210):
```
2026-08-11T00:50:15.4600271Z       'error: duplicate key\n' +
2026-08-11T00:50:15.4600646Z       '   --> Cargo.toml:109:1\n' +
2026-08-11T00:50:15.4601003Z       '    |\n' +
2026-08-11T00:50:15.4601253Z       '109 | sha2 = "0.10"\n' +
2026-08-11T00:50:15.4601546Z       '    | ^^^^\n'
2026-08-11T00:50:27.7480451Z error: duplicate key
2026-08-11T00:50:27.7481162Z    --> Cargo.toml:109:1
2026-08-11T00:50:27.7481560Z     |
2026-08-11T00:50:27.7481748Z 109 | sha2 = "0.10"
```

---

## Impact Analysis

### Cascading Failures
Because the schema codegen validation fails early in the build workflow, it causes a cascading failure that skips all downstream jobs:
- ✅ SDK Unit Tests (windows) - PASSED (runs independently)
- ✅ SDK Unit Tests (linux) - PASSED (runs independently)
- ❌ Lint - SKIPPED (due to early validation failure)
- ❌ Windows build - SKIPPED
- ❌ Linux build - SKIPPED
- ❌ macOS build - SKIPPED
- ❌ Package NPM SDK - SKIPPED
- ❌ SDK integration tests - SKIPPED

### Build Environments Affected
- **Linux** (runs 31447349268): Versioning checks and dependency feed checks fail
- **Windows** (runs 31447349167, 31447349210): Hyperlight and MicroVM builds fail

### All Three Runs Share Same Root Cause
Despite running on different platforms and testing different features (versioning/dependencies vs. Hyperlight vs. MicroVM), all failures trace back to the identical Cargo.toml parsing error.

---

## Next Steps

1. **Identify the duplicate key**: Examine the PR changes to `src/Cargo.toml` to locate the duplicate `sha2 = "0.10"` entry
2. **Remove the duplicate**: Delete the duplicate entry, keeping only one `sha2 = "0.10"` in the `[workspace.dependencies]` section
3. **Verify the fix locally**: Run `cargo metadata` and `cargo build` to confirm the Cargo.toml is now valid
4. **Force re-run CI**: After the fix is committed, push to force GitHub Actions to re-run

---

## File References
- Workspace Cargo.toml: `src/Cargo.toml` (line 109 area in the `[workspace.dependencies]` section)
- Schema codegen script: `scripts/versioning/check-schema-codegen.js` (line 49 executes cargo run)
- Dependency feed check script: `.github/workflows/Dependency.Feed.Check.Job.yml`

