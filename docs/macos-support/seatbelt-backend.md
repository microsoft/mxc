# macOS Sandbox Container Backend

The macOS sandbox backend provides macOS
sandbox isolation by wrapping Apple's
[Seatbelt](https://en.wikipedia.org/wiki/Seatbelt_%28software%29) sandbox —
the same kernel-enforced sandbox that backs the App Sandbox used by every
Mac App Store application.

## Overview

On macOS, MXC executes scripts inside the macOS sandbox via the system
binary `/usr/bin/sandbox-exec`, with a TinyScheme profile generated
on-the-fly from the MXC policy. This provides:

- **Filesystem isolation** via `(allow file-read*)` / `(allow file-write*)`
  rules over `subpath` literals, with deny rules layered on top so
  `deniedPaths` overrides any broader allow.
- **Network isolation** via `(allow network-outbound)` rules with
  per-host `(remote tcp …)` filters when `allowedHosts` is set, and
  `(deny network-outbound …)` for `blockedHosts`.
- **UI isolation** by denying mach-lookup of `com.apple.windowserver`,
  pasteboard, and HID iokit user clients when `ui.disable` /
  `ui.clipboard=none` / `ui.injection=false`.

The macOS sandbox is **process-scoped**, not container-scoped: there is no named
container, no lifecycle, and nothing to clean up. The sandbox lives only
as long as the spawned process tree. This is intentionally simpler than
LXC.

## Mechanism

The sandbox spawns `/usr/bin/sandbox-exec -f <profile> /bin/sh -c <script>` with
a generated Seatbelt (TinyScheme) profile. The profile is written to a temporary
file and passed to `sandbox-exec`.

## Prerequisites

- **macOS 11 or later** (Big Sur). `/usr/bin/sandbox-exec` ships with
  every macOS release; Apple has marked it deprecated in headers since
  10.7 but continues to ship and use it.
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

### 5. Node.js (optional — needed for SDK/CLI)

```bash
brew install node
```

Required only if you plan to build and test the TypeScript SDK or CLI
layers (`npm run build` / `npm test`).

### Verification

After setup, verify the build works end-to-end:

```bash
# Build the binary
./build-mac.sh --rust-only

# Run a quick smoke test
./src/target/aarch64-apple-darwin/release/mxc-exec-mac --debug examples/15_mac_hello_world.json
```

You should see sandbox profile generation output followed by
`hi from seatbelt`.

## Configuration

The macOS sandbox backend uses the same JSON configuration schema as the
other backends, with `containment` set to `"seatbelt"`. Backend-specific
settings live under `experimental.seatbelt`, and the `--experimental`
flag is required to enable the backend at runtime:

```json
{
    "$schema": "./schemas/dev/mxc-config.schema.0.6.0-dev.json",
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
    "experimental": {
        "seatbelt": {
            "mode": "exec"
        }
    }
}
```

### seatbelt-specific options

| Field | Type | Default | Description |
|---|---|---|---|
| `experimental.seatbelt.profileOverride` | string | unset | Optional override of the generated TinyScheme sandbox profile. When set, the SDK-generated profile is replaced with this raw TinyScheme string verbatim — all `filesystem`/`network`/`ui` policy fields are ignored for profile generation (they are still type-checked). Use this only when the auto-generated profile is insufficient. |

### Filesystem policy

| Policy field | Generated rule | Effect |
|---|---|---|
| `readonlyPaths` | `(allow file-read* (subpath …))` | Script can read these subtrees |
| `readwritePaths` | `(allow file-read* file-write* (subpath …))` | Script can read and write |
| `deniedPaths` | `(deny file-read* file-write* (subpath …))` emitted **last** | Overrides any broader allow above |

Apple's Seatbelt evaluates rules with last-match-wins semantics within an
operation, so denies emitted after allows correctly override them. This
matches MXC's `denied_paths` contract on every other backend.

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
| `allowedHosts` | `(allow network-outbound (remote tcp "host:*") (remote udp "host:*"))` per host. Apple's Seatbelt does not perform DNS — host filtering is best-effort and applied at connect time. |
| `blockedHosts` | `(deny network-outbound …)` emitted last so explicit blocks override allows. |

Proxy configuration (`network.proxy`) is **not supported** on macOS — the
SDK rejects it with a clear error, mirroring the Linux behavior.

### UI policy

| Policy | Generated rule |
|---|---|
| `ui.disable: true` (default) | `(deny mach-lookup …)` for `com.apple.windowserver.active`, `com.apple.windowserver.session`, and `com.apple.coreservices.launchservicesd` |
| `ui.clipboard: "none"` (default) | `(deny mach-lookup (global-name "com.apple.pasteboard.1"))` |
| `ui.injection: false` (default) | `(deny iokit-open (iokit-user-client-class "IOHIDLibUserClient"))` |

## Usage

### Command line

The `seatbelt` backend is currently experimental, so every invocation
must include the `--experimental` flag. Without it, the binary refuses to
run with a clear error.

```bash
# Run with config file
./mxc-exec-mac --experimental config.json

# Run with base64-encoded config
./mxc-exec-mac --experimental --config-base64 <base64-string>

# Validate the config and exit without executing
./mxc-exec-mac --experimental --dry-run config.json

# Diagnostic output to console + file
./mxc-exec-mac --experimental --debug --log-file mxc.log config.json
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
// builds a seatbelt config. The backend is experimental, so the
// caller must opt in via SandboxSpawnOptions.experimental.
const pty = spawnSandbox('echo hello', policy, { experimental: true });
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

# Rust binary only, skip TS SDK/CLI
./build-mac.sh --rust-only
```

The script writes to `sdk/bin/<arch>/mxc-exec-mac` so the SDK's
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

- **No proxy support.** The macOS sandbox cannot interpose at the TLS layer.
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

- **`sandbox-exec` is technically deprecated** in headers but remains
  shipping and is the same code path the App Sandbox uses.
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
| Privileges | Optional admin | Root (or unprivileged LXC) | None — `sandbox-exec` is unprivileged |
| Container lifecycle | Yes (named) | Yes (named) | No (per-process) |
| Proxy support | Yes | No | No |
