# MXC Hyperlight Integration — Design Document

## Problem

MXC needs a **cross-platform micro-VM execution backend** with a good story
for agentic Python workloads that care about cold-start time. The backend
should work identically on Linux and Windows, boot in milliseconds, and
provide hardware-level isolation.

## Proposed Solution

Add a **Hyperlight backend** — embedded [Hyperlight](https://github.com/hyperlight-dev/hyperlight)
+ [Unikraft](https://unikraft.org/) driving a warmed-up CPython snapshot
via the [`hyperlight-unikraft-host`](https://github.com/hyperlight-dev/hyperlight-unikraft) library.

When the JSON config specifies `"containment": "hyperlight"`, `wxc-exec`
routes to `HyperlightScriptRunner`, which instantiates a Hyperlight micro-VM
directly in-process. Every `run_code(&script)` rewinds to the snapshot and runs
hermetic.

**Cross-platform:** KVM on Linux, WHP on Windows — same code path, same
library.

## Performance

> Benchmarks: bare-metal Windows (Hyper-V / WHP).
> pyhl 0.1.0 (the CLI from `hyperlight-unikraft-host` for running python-agent unikernels), CPython 3.12.0, x86_64. 15 runs.

| Metric | Median | Avg | Min | Max |
|--------|--------|-----|-----|-----|
| Hello world (`print(42)`, end-to-end) | 139 ms | 141 ms | 133 ms | 157 ms |

## Density

| Metric | Value |
|--------|-------|
| Per-VM memory | 17 MB |
| Shared snapshot (one-time, mapped read-only CoW) | ~650 MiB on disk (2 GiB apparent) |

The snapshot file is 2 GiB in apparent size but only ~650 MiB on disk
thanks to sparse-file hole-punching (`fallocate(PUNCH_HOLE)` on Linux,
`FSCTL_SET_SPARSE` on Windows). It is mmap'd read-only and shared across
all VMs — each new VM only pays for pages it actually writes.

## Ecosystem

**Hyperlight-Unikraft** builds on two open-source foundations:

- **[Unikraft](https://unikraft.org/)** — Linux Foundation project with
  an active community, regular releases, and commercial backing. Hyperlight
  platform support has been upstreamed
  ([unikraft/unikraft#1821](https://github.com/unikraft/unikraft/pull/1821),
  [unikraft/app-elfloader#102](https://github.com/unikraft/app-elfloader/pull/102),
  [unikraft/kraftkit#2797](https://github.com/unikraft/kraftkit/pull/2797)).
- **[Hyperlight](https://github.com/hyperlight-dev/hyperlight)** — CNCF
  sandbox project. Already adopted across multiple Microsoft organizations
  including Edge Actions, HorizonDB, and the Agentic Framework.

Beyond Python, hyperlight-unikraft supports .NET, Node.js, Go, Rust,
C/C++, PowerShell, and Bash/Shell runtimes.

## Why a separate `Hyperlight` variant

- **Non-breaking.** Existing containment backends are unaffected.
- **Distinct semantics.** Hyperlight has:
  - A pre-installed warm snapshot as a prerequisite (not just binaries).
  - An in-process execution model.
  - A rich stdlib (full CPython + ~20 pre-imported packages including C
    extensions: numpy, pandas, Pillow, pydantic, cryptography, lxml).
  - Live VFS forwarding for host filesystem access — guest POSIX calls
    are forwarded to the host in real-time, limited only by host disk.
- **Different artifact provenance.** Hyperlight images come from
  `hyperlight-dev/hyperlight-unikraft`'s `python-agent-driver` pipeline.
  Adding new packages is a Dockerfile change + rebuild.

## Design Decisions

1. **In-process, not subprocess.** Hyperlight is a Rust library; wxc-exec
   is a Rust binary. Linking directly avoids pipe plumbing, watchdog
   threads, and process lifecycle management.

2. **`script_code` is raw Python source.** No shell quoting, no cmdline
   limit (`run_code` takes `&str` unbounded).

3. **`--experimental` gate.** Keeps this backend off the happy path until
   artifact distribution and docs catch up.

4. **Unsupported policies are rejected.** A config specifying `network`
   or `workingDirectory` with `containment: "hyperlight"` produces a preflight
   error.

5. **Image artifacts are user-provided, not bundled.** The `--setup-hyperlight`
   flag populates the image home. The runner auto-discovers
   `$PYHL_HOME` → `<exe>/pyhl/` → `<cwd>/.pyhl/`; the first location
   with all three files wins.

6. **Exit codes.** 0 on clean completion of `run_code`; -1 on any error
   (preflight, runtime, guest crash). Distinct per-error variants go
   through `error_message`.

7. **stdout/stderr are inherited.** Guest `print(...)` reaches the user's
   terminal directly via Hyperlight's `host_print`.
   `ScriptResponse.standard_{out,err}` stay empty — consumers who need
   capture redirect wxc-exec at the process level.

## Workspace Changes

```
mxc/src/core/wxc_common/
├── Cargo.toml                 # + hyperlight-unikraft-host dependency
└── src/
    ├── lib.rs                 # + pub mod hyperlight_runner;
    ├── models.rs              # + ContainmentBackend::Hyperlight (serde "hyperlight")
    ├── config_parser.rs       # + Some("hyperlight") => Hyperlight match arm
    └── hyperlight_runner.rs   # NEW

mxc/src/core/wxc/
└── src/main.rs                # + ContainmentBackend::Hyperlight dispatch arm

mxc/tests/configs/
├── hyperlight_hello.json      # NEW — hello from Python
└── hyperlight_pandas.json     # NEW — exercises pre-imported numpy/pandas

mxc/docs/
└── hyperlight-integration-plan.md  # NEW — this document
```

## Configuration

### JSON

```json
{
  "process": {
    "commandLine": "import sys\nprint(f'Python {sys.version.split()[0]} on {sys.platform}')",
    "timeout": 30000
  },
  "containment": "hyperlight"
}
```

### Field semantics

| JSON Field | Hyperlight Behavior |
|------------|---------------|
| `process.commandLine` | ✅ Used — raw Python source |
| `process.timeout` | ✅ Used — script execution timeout (ms) |
| `containment` | ✅ Must be `"hyperlight"` |
| `filesystem.*` | ✅ `readwritePaths`/`readonlyPaths` mapped to host mounts |
| `network.*` | ❌ Rejected |
| `workingDirectory` | ❌ Rejected (guest has its own FS namespace) |

## Security Model

| Property | Hyperlight |
|----------|------|
| Isolation level | Micro VM (KVM/WHP) |
| Host FS access | Explicit mounts via `Preopen` |
| Network | None |
| Guest OS | Unikraft unikernel |
| Cold start | ~30ms KVM / ~140 ms WHP |
| Host platforms | Linux + Windows |

## Supported Workloads

### Supported out of the box (preloaded in snapshot)

| Category | Examples |
|----------|----------|
| Stdlib | `os`, `sys`, `json`, `re`, `pathlib`, `datetime`, `hashlib`, `itertools`, `functools`, `math`, `decimal`, `fractions`, `collections`, `statistics` |
| Pre-imported 3rd-party | `numpy`, `pandas`, `pydantic`, `yaml`, `jinja2`, `bs4`, `tabulate`, `click`, `tenacity`, `tqdm`, `openpyxl`, `pypdf`, `markdown_it`, `PIL`, `lxml`, `cryptography`, `dateutil`, `dotenv` |

### Not supported

| Why not | Example failure |
|---------|-----------------|
| No network stack in guest | `urllib`, `socket`, `http` — `OSError: Function not implemented` |
| Read-only sysroot by default | File writes under `/` — `OSError: Read-only file system` |
| No subprocess / fork | `subprocess.run` — `OSError: Function not implemented` |

## Testing Strategy

### Unit tests (`cargo test -p wxc_common`)

- `is_installed_false_on_empty_dir` — negative case for the install probe
- `resolve_home_errors_when_nothing_configured` — actionable error when no image
- `policy_rejects_filesystem_paths` — blocks readwritePaths/readonlyPaths/deniedPaths
- `policy_rejects_network_rules` — blocks allowed/blockedHosts
- `policy_rejects_block_default_network` — blocks `defaultNetworkPolicy: block`
- `policy_rejects_working_directory` — blocks non-empty `workingDirectory`
