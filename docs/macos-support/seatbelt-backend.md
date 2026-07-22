# macOS Sandbox Container Backend

The macOS sandbox backend provides macOS
sandbox isolation by wrapping Apple's
Seatbelt sandbox —
the same kernel-enforced sandbox that backs the App Sandbox used by every
Mac App Store application.

## Overview

On macOS, MXC executes scripts inside the macOS sandbox via
`sandbox_init()` — the same kernel-enforced Seatbelt framework that backs
the App Sandbox used by every Mac App Store application. A TinyScheme
profile is generated on-the-fly from the MXC policy and applied to the
child process via `pre_exec`, which means the child inherits the parent's
Mach bootstrap namespace. This enables both CLI commands and GUI
applications (when `guiAccess` is enabled) to run under the sandbox. This
provides:

- **Filesystem isolation** via `(allow file-read*)` / `(allow file-write*)`
  rules over `subpath` literals, with deny rules layered on top so
  `deniedPaths` overrides any broader allow.
- **Network isolation** via allow/block-all outbound rules. Seatbelt cannot
  enforce DNS host lists: `allowedHosts` degrades to allow-all outbound and
  `blockedHosts` is rejected.
- **Cooperative HTTP proxy** via `network.proxy`: `HTTP_PROXY` /
  `HTTPS_PROXY` / `ALL_PROXY` are injected into the sandbox so well-behaved
  clients route through the configured proxy (raw-socket clients can bypass it).
- **UI isolation** by denying mach-lookup of `com.apple.windowserver`,
  pasteboard, and HID iokit user clients when `ui.disable` /
  `ui.clipboard=none` / `ui.injection=false`.

The macOS sandbox is **process-scoped**, not container-scoped: there is no named
container, no lifecycle, and nothing to clean up. The sandbox lives only
as long as the spawned process tree. This is intentionally simpler than
LXC.

## Mechanism

The sandbox applies the generated Seatbelt (TinyScheme) profile to the
child process via `sandbox_init()` inside `Command::pre_exec` (after
`fork()`, before `exec()`). The profile string is passed directly to
`sandbox_init` — no temporary files are needed. The child then execs
`/bin/sh -c <script>` with the sandbox already active.

## Prerequisites

- **macOS 11 or later** (Big Sur). `sandbox_init()` ships with
  every macOS release; Apple has marked it deprecated in headers since
  10.8 but continues to ship and use it internally.
- **Xcode Command Line Tools** for building from source (`xcode-select
  --install`). Not needed for `npm install` of pre-built binaries.

No additional packages are required at runtime — the macOS sandbox is part
of the base OS.

## Environment Setup

Follow these steps to prepare a macOS machine for building and running
`mxc-exec-mac` from source.

### 1. Xcode Command Line Tools

```bash
xcode-select --install
```

Provides `clang`, `ld`, system headers, and the macOS SDK needed by the
Rust toolchain to compile native binaries.

### 2. Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After installation, follow the shell setup instructions printed by the
installer (adds `/opt/homebrew/bin` to `PATH` on Apple Silicon).

### 3. Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Add the targets needed for building:

```bash
# Native Apple Silicon (required on M-series Macs)
rustup target add aarch64-apple-darwin

# Intel (optional — needed for --all / cross-compilation)
rustup target add x86_64-apple-darwin
```

### 4. Python 3 (optional — needed for example 21)

```bash
brew install python
```

This makes `python3` available at `/opt/homebrew/bin/python3`. The example
configs that invoke Python (`21_mac_python_info.json`) require this.

> **Note:** On Apple Silicon, Homebrew installs to `/opt/homebrew`. Example
> configs that run Python include `"readonlyPaths": ["/opt/homebrew"]` so
> the sandbox can access the interpreter and its libraries.

### 5. Node.js (optional — needed for SDK)

```bash
brew install node
```

Required only if you plan to build and test the TypeScript SDK
layer (`npm run build` / `npm test`).

### Verification

After setup, verify the build works end-to-end:

```bash
# Build the binary
./build-mac.sh --rust-only

# Run a quick smoke test
./src/target/aarch64-apple-darwin/release/mxc-exec-mac --debug tests/examples/15_mac_hello_world.json
```

You should see sandbox profile generation output followed by
`hi from seatbelt`.

## Configuration

The macOS sandbox backend uses the same JSON configuration schema as the
other backends, with `containment` set to `"seatbelt"`. Backend-specific
settings live under a top-level `seatbelt` key:

```json
{
    "$schema": "../../schemas/stable/mxc-config.schema.0.7.0-alpha.json",
    "containment": "seatbelt",
    "process": {
        "commandLine": "echo hi from seatbelt",
        "timeout": 30000
    },
    "filesystem": {
        "readwritePaths": ["/tmp/output"],
        "readonlyPaths":  ["/Users/me/project"],
        "deniedPaths":    ["/Users/me/.ssh"]
    },
    "network": {
        "defaultPolicy": "block",
        "allowedHosts":  ["api.github.com"]
    },
    "seatbelt": {
        "nestedPty": true
    }
}
```

### seatbelt-specific options

| Field | Type | Default | Description |
|---|---|---|---|
| `seatbelt.profileOverride` | string | unset | Optional override of the generated TinyScheme sandbox profile. When set, the SDK-generated profile is replaced with this raw TinyScheme string verbatim — all `filesystem`/`network`/`ui` policy fields are ignored for profile generation (they are still type-checked). Use this only when the auto-generated profile is insufficient. |
| `seatbelt.guiAccess` | boolean | `false` | When `true`, adds wildcard Mach service and IOKit rules so GUI applications can create windows and render via WindowServer. Requires `ui.disable: false`. Native AppKit apps (e.g. Terminal.app) work well; Electron-based apps may escape the sandbox via re-launch patterns. |
| `seatbelt.launchMethod` | `"exec"` \| `"open"` | `"exec"` | How to launch the sandboxed process. `"exec"` (default) uses the `sandbox_init()` API in `pre_exec` then execs the command directly — works for third-party GUI apps (Alacritty, etc.) and all CLI commands. `"open"` launches Terminal.app via LaunchServices (`open -n -W -a Terminal`) then applies the sandbox to the inner shell via the `sandbox-exec` CLI tool. This is required because Terminal.app enforces Apple Launch Constraints that kill it when exec'd by unauthorized parents. Currently only Terminal.app is supported with the `"open"` method — other Apple system apps (Calculator, TextEdit) cannot be sandboxed due to Launch Constraints and lack of an inner shell to constrain. |
| `seatbelt.nestedPty` | boolean | `true` | When `true`, the inner process can allocate its own pseudo-terminals via `posix_openpt`. Required by anything that spawns a shell (test runners, `git`, `gh`, REPLs, agent tools that wrap commands in a pty). Adds `(allow pseudo-tty)` and read/write/ioctl on `/dev/ptmx` to the generated profile. Set to `false` for a tighter sandbox when the inner command does not need to allocate new ttys. |
| `seatbelt.keychainAccess` | boolean | `false` | When `true`, opens the sandbox enough for `keytar` / `Security.framework` to reach the macOS Keychain end-to-end. Adds Mach lookup for `com.apple.SecurityServer`, `com.apple.securityd`, `com.apple.trustd`, `com.apple.ocspd`, `com.apple.cfprefsd.daemon`, `com.apple.xpcd`, and the `com.apple.lsd.*` family (regex); read access to `/private/var/db/mds` (Spotlight/MDS metadata) and `/private/var/protected/trustd` (trustd protected store); and read+write access to `~/Library/Keychains` (user keychain DB) and `/private/var/folders` (XPC cache and per-user containers). The system keychain stores under `/Library/Keychains` and `/System/Library/Keychains` are already covered by the baseline `/Library` and `/System` read-only allows. Off by default — opt in only when the inner workload genuinely needs Keychain access. |

### Filesystem policy

| Policy field | Generated rule | Effect |
|---|---|---|
| `readonlyPaths` | `(allow file-read* (subpath …))` | Script can read these subtrees |
| `readwritePaths` | `(allow file-read* file-write* (subpath …))` | Script can read and write |
| `deniedPaths` | `(deny file-read* file-write* (subpath …))` emitted **last** | Overrides any broader allow above |

Apple's Seatbelt evaluates rules with last-match-wins semantics within an
operation, so denies emitted after allows correctly override them. This
matches MXC's `denied_paths` contract on every other backend.

A `readwritePaths` entry that targets a per-user Darwin temp/cache leaf —
`/var/folders/<a>/<b>/T` (`$TMPDIR` / `_CS_DARWIN_USER_TEMP_DIR`), `.../C`
(`_CS_DARWIN_USER_CACHE_DIR`), or `.../0` (misc), optionally under `/private`
— is expanded to read-write grants for all three siblings (`.../T`, `.../C`,
`.../0`). Without this, a grant of only the temp leaf leaves the sibling cache
directory unwritable and tools that stage there are denied. The expansion is
strict (only a direct `T`/`C`/`0` child of a genuine two-segment per-user
container qualifies) and covers *only* those three siblings — the enclosing
container itself is never granted, so no other directory under it becomes
writable and an expansion can never reach `/var/folders` or `/`. `deniedPaths`
still override the expanded grants, so a caller can carve any one sibling back
out.

A baseline of read-only system paths (`/usr/lib`, `/usr/libexec`,
`/usr/share`, `/System`, `/Library`, `/private/var/db/timezone`,
`/private/var/db/dyld`, `/private/etc`, `/dev/null`, `/dev/zero`,
`/dev/random`, `/dev/urandom`) is always emitted so the dynamic linker
and standard libraries continue to work. SIP-protected system paths
remain readable but unwritable; this is enforced by the kernel
independently of the profile.

### Network policy

| Policy | Generated rule |
|---|---|
| `defaultPolicy: "block"` | No `(allow network-outbound)` is emitted; the baseline `(deny default)` then blocks all sockets. |
| `defaultPolicy: "allow"` (no host list) | `(allow network-outbound)` plus `(allow network-bind (local ip))` and `(allow system-socket)`. |
| `allowedHosts` | Accepted for SDK compatibility, but Seatbelt cannot filter DNS names; the profile degrades to allow-all outbound as best-effort. |
| `blockedHosts` | Rejected during validation because Seatbelt cannot enforce hostname blocks. |
| `proxy` (loopback: `localhost` / `builtinTestServer`) | Under `defaultPolicy: "block"`, allows only the resolved `localhost:<proxy-port>`. Other loopback services and the wider network remain blocked. Under `allow`, the existing allow-all covers it. |
| `proxy` (remote `url`) | Under `defaultPolicy: "block"`, **rejected during validation** — Seatbelt cannot filter a remote proxy by DNS name, so reachability would degrade to allow-all and silently weaken the deny for raw-socket clients. Under `allow`, allows all outbound as best-effort (the proxy enforces host policy). Use a loopback proxy or `builtinTestServer` for MXC-scoped reachability under deny. |

Proxy configuration (`network.proxy`) is supported via the **cooperative
env-var model** (the same as the Bubblewrap backend): the runner launches or
points at an HTTP proxy and injects `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
(and their lowercase forms) into the sandbox environment, stripping any
caller-supplied proxy vars so sandboxed code can't override them. Well-behaved HTTP clients
(curl, requests, fetch, …) honor it; clients that open raw sockets and ignore
the env vars bypass it. `builtinTestServer` launches a bundled, testing-only
proxy (`unix-test-proxy`) and requires `--allow-testing-features`. macOS has no
per-process WinHTTP-style OS proxy policy, so unlike Windows the proxy is
cooperative rather than kernel-enforced.

### UI policy

| Policy | Generated rule |
|---|---|
| `ui.disable: true` (default) | `(deny mach-lookup …)` for `com.apple.windowserver.active`, `com.apple.windowserver.session`, and `com.apple.coreservices.launchservicesd` |
| `ui.clipboard: "none"` (default) | `(deny mach-lookup (global-name "com.apple.pasteboard.1"))` |
| `ui.injection: false` (default) | `(deny iokit-open (iokit-user-client-class "IOHIDLibUserClient"))` |

### Process environment

The host environment is **never** inherited — the sandboxed child always starts
from a cleared environment, so host secrets (cloud credentials, API tokens) can
never leak into untrusted code. `PATH` defaults to `/usr/bin:/bin:/usr/sbin:/sbin`,
and each `process.env` entry adds to / overrides that baseline. (This is
unconditional; it applies whether or not `process.env` is provided.)

### Working directory

If `process.cwd` is omitted it resolves to `readwritePaths[0]`, else
`readonlyPaths[0]`, else `/`; a `~`/`~/…` default is tilde-expanded the same way
the sandbox profile expands policy paths. `PWD` is exported to the resolved
directory so the child's `getcwd()` takes its fast `$PWD` path.

## Usage

### Command line

```bash
# Run with config file
./mxc-exec-mac config.json

# Run with base64-encoded config
./mxc-exec-mac --config-base64 <base64-string>

# Validate the config and exit without executing
./mxc-exec-mac --dry-run config.json

# Diagnostic output to console + file
./mxc-exec-mac --debug --log-file mxc.log config.json
```

### SDK

```typescript
import { spawnSandbox, SandboxPolicy } from '@microsoft/mxc-sdk';

const policy: SandboxPolicy = {
    filesystem: {
        readwritePaths: ['/tmp/output'],
        readonlyPaths:  ['/opt/tools'],
    },
    network: {
        allowOutbound: false,
    },
};

// On macOS, spawnSandbox automatically resolves to mxc-exec-mac and
// builds a seatbelt config.
const pty = spawnSandbox('echo hello', policy);
pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit:', e.exitCode));
```

## Building from source

```bash
# Native arch only
./build-mac.sh

# Both Apple silicon and Intel slices for distribution
./build-mac.sh --all

# Debug build
./build-mac.sh --debug

# Rust binary only, skip TS SDK
./build-mac.sh --rust-only
```

The script writes to `sdk/node/bin/<arch>/mxc-exec-mac` so the SDK's
`findDarwinExecutable()` picks up the dev build automatically.

### Codesigning and notarization

The binary produced by `build-mac.sh` is **unsigned**. Shipping to end
users via npm or Developer-ID download requires:

1. `codesign --options runtime --sign "Developer ID Application: …" mxc-exec-mac`
2. `xcrun notarytool submit … --wait`
3. `xcrun stapler staple mxc-exec-mac`

These steps are added to the release CI pipeline (see `ci-macos` and
`codesign-notarize` todos in the session plan), not to the local build
script — they require Apple credentials and run in a controlled
environment.

## Limitations and caveats

- **Proxy support is cooperative, not enforced.** `network.proxy` injects
  `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` into the sandbox (see [Network policy](#network-policy)).
  Clients that honor those env vars route through the proxy; clients that open
  raw sockets and ignore them bypass it. The macOS sandbox cannot interpose at
  the TLS/socket layer per process, so this matches the Bubblewrap backend
  rather than Windows' kernel-enforced WinHTTP policy.
- **Per-host network filtering (`blockedHosts`) is not supported.** Apple's
  Seatbelt profile language has no mechanism for selectively blocking individual
  hostnames while allowing all other traffic. The `blockedHosts` config field is
  rejected at validation time rather than silently ignored.

  Alternative approaches considered:

  | Approach | Status | Notes |
  |---|---|---|
  | **`pf` (Packet Filter) rules** | Not viable | Requires root privileges, operates system-wide (not per-process), and hostname → IP resolution is unstable for CDN-backed hosts. |
  | **`/etc/hosts` manipulation** | Not viable | Requires root, affects all processes on the system, and is bypassable via direct IP connections or DNS-over-HTTPS. |
  | **Network Extension framework** | Potential future path | Apple's `NEFilterDataProvider` API can filter per-process at the hostname level. Requires a signed System Extension with the `com.apple.developer.networking.networkextension` entitlement and user approval via System Preferences. Would run as a separate daemon alongside MXC. |

  To deny all network access, use `defaultPolicy: "block"` instead.

- **`sandbox_init` is technically deprecated** in headers since macOS 10.8
  but remains shipping and is used by Apple's own apps and Chromium.
  It is the same Seatbelt framework that backs the App Sandbox.
- **GUI support is limited to native apps.** Third-party AppKit-based
  apps (e.g. Alacritty) work with `guiAccess: true` and the default
  `launchMethod: "exec"` (uses `sandbox_init()` API). Terminal.app
  requires `launchMethod: "open"` which uses `sandbox-exec` on the
  inner shell — Apple Launch Constraints kill Terminal when exec'd by
  unauthorized parents. Other Apple system apps (Calculator, TextEdit)
  cannot currently be sandboxed — they are killed by Launch Constraints
  and lack an inner shell for the `"open"` path. Electron-based apps
  (VS Code, Spotify) may escape the sandbox by re-launching themselves
  via helper processes.
- **No container abstraction.** Unlike LXC, there is no persistent
  container to attach to or destroy — every invocation is a fresh
  process tree.
- **SIP overrides the profile** for protected system paths. You cannot
  grant write access to `/System` or `/usr` even with explicit
  `readwritePaths`.

## Comparison with other backends

| Feature | AppContainer (Windows) | LXC (Linux) | seatbelt (macOS) |
|---|---|---|---|
| Isolation level | Process | Container | Process |
| Startup time | Fast (~10 ms) | Medium (~1 s) | Fast (~10 ms) |
| Filesystem | BFS policy | Bind mounts | Profile `subpath` rules |
| Network | Windows Firewall | iptables/nftables | Profile `network-*` rules |
| Privileges | Optional admin | Root (or unprivileged LXC) | None — `sandbox_init` is unprivileged |
| Container lifecycle | Yes (named) | Yes (named) | No (per-process) |
| Proxy support | Yes (WinHTTP, kernel-enforced) | No | Cooperative (env-var) |
