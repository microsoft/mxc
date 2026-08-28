# macOS Seatbelt Backend

Runs commands inside Apple's kernel-enforced sandbox — the same Seatbelt
framework behind the App Sandbox that every Mac App Store app uses.

## At a glance

| | |
|---|---|
| **Binary** | `mxc-exec-mac` |
| **Config value** | `"containment": "seatbelt"` |
| **Schema** | `0.8.0-alpha` recommended. `0.7.0-alpha` is the minimum and still supported. |
| **Requires** | macOS 15 (Sequoia) or later. No root, no daemon, no install. |
| **Isolation** | Process tree (no named container, no lifecycle, nothing to clean up) |
| **Enforced by** | The macOS kernel, via a generated profile |

MXC translates your JSON policy into a Seatbelt profile and applies it with
`sandbox_init()` between `fork()` and `exec()`. The profile is passed as a
string — no temp files. The child keeps the parent's Mach bootstrap namespace,
which is what lets GUI apps run under the sandbox when `guiAccess` is enabled.
The sandbox lives exactly as long as the process tree it wraps.

Continuous integration exercises the backend on **macOS 15** and **macOS 26**
(Apple silicon).

## Quick start

```json
{
    "$schema": "../../schemas/stable/mxc-config.schema.0.8.0-alpha.json",
    "version": "0.8.0-alpha",
    "containment": "seatbelt",
    "process": { "commandLine": "echo hi", "timeout": 30000 },
    "filesystem": {
        "readwritePaths": ["/tmp/output"],
        "readonlyPaths":  ["/Users/me/project"],
        "deniedPaths":    ["/Users/me/.ssh"]
    },
    "network": {
        "egress":  { "default": "deny" },
        "ingress": { "default": "deny", "hostLoopback": "deny" }
    }
}
```

That denies all network access. To open it up, see
[Network policy](#network-policy) — and read
[the `hostLoopback` trap](#the-hostloopback-trap) before setting
`egress.default: "allow"`.

```bash
./mxc-exec-mac config.json              # run it
./mxc-exec-mac --dry-run config.json    # validate only, don't execute
```

**Tip:** always run `--dry-run` first. Almost every limitation below surfaces as
an up-front validation error rather than a silent downgrade. There are two
exceptions worth knowing, because both are *valid* configs that behave
surprisingly: the [`hostLoopback` trap](#the-hostloopback-trap) and
[`guiAccess` without `ui.disable: false`](#seatbelt-specific-options).

> **Which schema version?** This doc uses the **0.8** network shape
> (`egress` / `ingress` / `runtimeConfig.networkProxy`) throughout, since that's
> the current cross-backend design. The older 0.7 fields still work — see
> [Legacy 0.7 network fields](#legacy-07-network-fields) for the mapping. A
> single config must use one shape or the other, never both.

## What Seatbelt can and can't enforce

| Capability | Supported | Notes |
|---|:---:|---|
| Read-only / read-write / denied paths | ✅ | Kernel-enforced, subtree-scoped |
| Block all outbound network | ✅ | Kernel-enforced |
| Allow all outbound network | ✅ | Kernel-enforced |
| Reach a **loopback** address / port | ✅ | Kernel-enforced, port-scoped |
| Accept inbound connections | ✅ | All-or-nothing — cannot be scoped |
| UI / clipboard / input-injection lockdown | ✅ | Kernel-enforced |
| Route traffic through an HTTP proxy | ⚠️ | Egress confinement is enforced; *using* the proxy is cooperative — see [below](#proxy-support-what-is-and-isnt-enforced) |
| Allow/deny by **hostname** | ❌ | Rejected — no such primitive in Seatbelt |
| Allow/deny by **IP, CIDR, port, or protocol** | ❌ | Rejected — no such primitive |
| Scope **inbound** to loopback only | ❌ | Rejected — not expressible |
| Firewall / packet-filter enforcement mode | ❌ | Rejected — no packet-filter layer |
| Proxy peer identity pinning | ❌ | Rejected — not supported |
| Named containers, attach, lifecycle | ❌ | Not applicable — process-scoped |

The short version: **Seatbelt gives you an on/off switch for outbound network
plus a loopback exception. It has no concept of "this host but not that one."**
Its `(remote ...)` filter accepts only `*` and `localhost` — nothing else is
even syntactically valid.

## Filesystem policy

| Field | Generated rule | Effect |
|---|---|---|
| `readonlyPaths` | `(allow file-read* (subpath …))` **plus** `(deny file-write* network-bind network-outbound (subpath …))` | Read the subtree — and explicitly *not* write it or use sockets in it |
| `readwritePaths` | `(allow file-read* file-write* network-bind network-outbound (subpath …))` | Read, write, and use AF_UNIX sockets |
| `deniedPaths` | `(deny file-read* file-write* network-bind network-outbound (subpath …))`, emitted **last** | Overrides every allow above it |

The paired deny on `readonlyPaths` is emitted for **every** read-only entry, not
just nested ones. It matters most when a read-only path sits inside a broader
`readwritePaths` subtree: the read-only `allow` names only `file-read*`, so on
its own it says nothing about writes and couldn't displace the wider grant.

Seatbelt is **last-match-wins** among rules that carry a filter, so denies
emitted after allows win. (An *unfiltered* rule doesn't participate — a blanket
`(allow network-outbound)` can't override a path-scoped deny.)

Rules are emitted shallow-to-deep, so the **deepest** matching rule wins at any
given path. `deniedPaths` sits outside that ordering and always outranks.

### How your paths get rewritten

Before a path reaches the profile, MXC:

1. **Expands `~`** against `$HOME`.
2. **Collapses** `//`, `/./`, and trailing `/`. Rejects `..` (see above).
3. **Resolves symlinked roots** — `/etc`, `/tmp`, `/var` → `/private/…`;
   `/home` → `/System/Volumes/Data/home`.
4. **Re-applies precedence** (`denied` > `readonly` > `readwrite`) to the
   *resolved* paths.

Steps 3 and 4 aren't cosmetic. Those roots are symlinks, and the kernel fully
resolves a path before matching it — a rule written against the unresolved path
is silently dead. Step 4 catches two spellings of the same path
(`readonlyPaths: ["/private/tmp/x"]` vs `readwritePaths: ["/tmp/x"]`) that the
shared parser can't see are identical.

`/Users` needs no rewriting — it's a firmlink, not a symlink.

### UNIX-domain sockets

Seatbelt matches AF_UNIX sockets by **path**, so MXC governs them with the
**filesystem** policy, not the network policy:

| | `bind()` | `connect()` |
|---|:---:|:---:|
| `readwritePaths` | ✅ | ✅ |
| `readonlyPaths` | ❌ | ❌ |
| `deniedPaths` | ❌ | ❌ |

Why: Node toolchains (tsx, vite, esbuild, jest workers) need both halves for
IPC. Gating them behind `allowLocalNetwork` would force real network ingress on
just to run a build. These rules are path-scoped, so they never widen IP
networking.

> ⚠️ **`connect()` is a capability `file-write*` alone didn't grant.** A broad
> `readwritePaths` root lets the sandbox talk to any pre-existing listener
> underneath it — and a Docker, `ssh-agent`, or `gpg-agent` socket is a control
> plane. Keep the read-write root narrow, and put sensitive sockets in
> `deniedPaths`.

### Always-on baseline

Every sandbox gets these regardless of policy, so the dynamic linker, shells,
and standard tools work:

| Access | Paths |
|---|---|
| Read-only | `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, `/usr/share`, `/System`, `/Library`, `/private/etc`, `/private/var/db/timezone`, `/private/var/db/dyld`, `/private/var/select` |
| Read **+ write** | `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom` |
| Read-data only | `/` itself — the loader can't resolve path lookups without it |

The `/dev/*` entries are writable because shell redirections (`>/dev/null`,
`</dev/urandom`) need both directions. Writes to `/dev/null` and `/dev/zero` are
discarded; writes to the entropy devices are harmless.

SIP-protected paths stay unwritable no matter what you put in
`readwritePaths` — the kernel enforces that independently of the profile.

## Network policy

Seatbelt declares support for
`EGRESS_DEFAULT | INGRESS_DEFAULT | HOST_LOOPBACK | RUNTIME_PROXY` — notably
**not** `EGRESS_RULES` (per-CIDR/port rules) and not `PROXY_PEER_IDENTITY`.
Anything it hasn't declared is rejected up front.

### Fields (schema 0.8+)

This is the cross-backend
[0.8 networking shape](../sandbox-policy/0.8.0/networking/networking.md).

> **Omitting `network` entirely denies all IP networking.** Every field below
> defaults to `deny`, so a config with no `network` block behaves exactly like
> `egress: {default: "deny"}, ingress: {default: "deny", hostLoopback: "deny"}`.
> You only need a `network` block to *open* something up.

| Field | Behavior |
|---|---|
| `egress.default` | `"deny"` → no outbound rule; baseline `(deny default)` blocks all IP sockets. `"allow"` → `(allow network-outbound)`, `(allow network-bind (local ip))`, `(allow system-socket)`. |
| `egress.allow` / `egress.deny` | **Rejected** if non-empty — no CIDR/port/protocol primitive exists |
| `ingress.default` | `"allow"` → `(allow network-inbound (local ip))`. This is what permits `listen()` — `network-bind` alone is not enough. |
| `ingress.hostLoopback` | Controls sandbox → host loopback. Must equal `ingress.default`. **Defaults to `"deny"`.** |
| `runtimeConfig.networkProxy` | Loopback `http`/`https` URL with an explicit port |

### The `hostLoopback` trap

> ⚠️ **`ingress.hostLoopback` defaults to `"deny"`.**

This config looks like "let the sandbox use the network":

```json
{ "network": { "egress": { "default": "allow" } } }
```

But `ingress` is absent, so `hostLoopback` defaults to `deny`, and the
generated profile is:

```lisp
(allow network-outbound)
(deny network-outbound (remote ip "localhost:*"))   ;; last match wins
```

**Your sandbox can reach the whole internet but not your own machine** — no
`localhost:3000` dev server, no local model endpoint. It passes validation
silently, because `ingress.default` defaulted to `deny` too and the two agree.

If you want loopback, say so explicitly:

```json
{
  "network": {
    "egress":  { "default": "allow" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  }
}
```

Two more things to know about `hostLoopback`:

- **`localhost` means "this machine", not "this network."** The rule covers
  *every* address the host is bound to, LAN IPs included. It can't be narrowed
  to `127.0.0.1` — a literal address is a Seatbelt syntax error. Other machines
  are unaffected either way.
- **`deny` also cuts the sandbox off from its own loopback listeners**, since a
  Seatbelt sandbox shares the host's network stack.

#### Why it must equal `ingress.default`

`hostLoopback` is bidirectional, but Seatbelt can only enforce the outbound
half. There's no way to scope an inbound grant by peer: `(local ip)` filters on
the sandbox's *own* bind address, and a `remote ip` inbound filter is a no-op
because the peer isn't known at bind time.

So MXC requires the two to agree rather than enforcing one direction and
silently ignoring the other. The practical consequence: **if your sandbox needs
to accept connections at all, you get an unscoped inbound grant.** That's an OS
limitation, not an MXC choice — but it's a real cost, so MXC makes you write it
down.

If you only need *outbound* loopback, `egress.default: "deny"` plus a loopback
`runtimeConfig.networkProxy` gets you there with **no** inbound exposure.

### Proxy support: what is and isn't enforced

This distinction matters, and it's easy to get backwards.

| Question | Enforced? |
|---|---|
| Can the sandbox reach anything *other than* the proxy? | **No — kernel-enforced.** |
| Will a client actually *speak to* the proxy? | Not enforced — cooperative. |
| Is traffic transparently redirected into the proxy? | No. |

**Egress confinement is real.** A proxy is only ever accepted alongside a deny
egress default (proxy + `"allow"` is [rejected](#network)), so the profile
always ends up as:

```lisp
(deny default)
(allow network-outbound (remote ip "localhost:<proxy-port>"))
```

That single port is the sandbox's entire outbound universe. The kernel enforces
it. A client that opens raw sockets and ignores `HTTP_PROXY` **cannot** reach
the internet or any other host-local service — it simply fails to connect.

**Proxy usage is cooperative.** MXC injects `HTTP_PROXY` / `HTTPS_PROXY` /
`ALL_PROXY` (and lowercase forms) and strips any caller-supplied proxy vars.
Well-behaved clients (curl, requests, fetch) honor them. A client that ignores
them doesn't *escape* — it just doesn't get anywhere. macOS has no
WinHTTP-style per-process OS proxy policy, so MXC can't force the routing the
way Windows can.

**What the profile does not control is where the proxy then connects.** MXC only
configures the destination policy of a proxy it launches itself
(`builtinTestServer`, testing-only, requires `--allow-testing-features`, and the
only form where `allowedHosts` / `blockedHosts` are enforced). An externally
supplied proxy is never told about your host lists and applies whatever policy
it was independently configured with.

> **Caveat:** Seatbelt's `localhost` token means "this machine at any address,"
> so the reachability rule also covers the host's non-loopback addresses **on
> that same port number**. It cannot be narrowed — a literal `127.0.0.1` is a
> profile syntax error.

### Legacy 0.7 network fields

Still supported for configs on `"version": "0.7.0-alpha"`. Prefer the 0.8 shape
above for new work. **A config must use one shape or the other — mixing them is
rejected.**

| Legacy (0.7) | 0.8 equivalent | Notes |
|---|---|---|
| `defaultPolicy: "block"` | `egress.default: "deny"` | Identical profile output |
| `defaultPolicy: "allow"` | `egress.default: "allow"` | Identical profile output |
| `allowLocalNetwork: true` | `ingress.default: "allow"` | Identical profile output |
| `network.proxy.localhost` / loopback `network.proxy.url` | `runtimeConfig.networkProxy` | |
| `allowedHosts` | *(no equivalent)* | Under `"allow"`: accepted but **ignored** — outbound is already unrestricted, so the list narrows nothing. **Rejected** under `"block"` unless `builtinTestServer` |
| `blockedHosts` | *(no equivalent)* | **Rejected** always |
| *(no equivalent)* | `ingress.hostLoopback` | New in 0.8 — legacy configs never emit a host-loopback rule |

The last row is the one migration hazard: 0.7 has no `hostLoopback` concept, so
`defaultPolicy: "allow"` leaves loopback **open**. Translating that to
`egress.default: "allow"` closes it, because `hostLoopback` defaults to `deny`.
Add `ingress: { "default": "allow", "hostLoopback": "allow" }` to preserve the
old behavior.

## UI policy

| Policy | Generated rule |
|---|---|
| `ui.disable: true` (default) | Denies mach-lookup of `com.apple.windowserver.active`, `com.apple.windowserver.session`, and `com.apple.coreservices.launchservicesd` |
| `ui.clipboard: "none"` (default) | Denies mach-lookup of `com.apple.pasteboard.1` |
| `ui.injection: false` (default) | Denies `iokit-open` of `IOHIDLibUserClient` |

## Seatbelt-specific options

Set under a top-level `"seatbelt"` key.

| Option | Type | Default | What it does |
|---|---|---|---|
| `nestedPty` | bool | `true` | Lets the inner process allocate its own ptys. Needed by anything that spawns a shell — test runners, `git`, `gh`, REPLs, agent tools. Set `false` for a tighter sandbox. |
| `guiAccess` | bool | `false` | Adds Mach/IOKit rules so GUI apps can create windows. **Only effective when `ui.disable` is `false`** — with UI disabled the GUI rules are silently suppressed rather than rejected. |
| `keychainAccess` | bool | `false` | Opens the sandbox enough for `keytar` / Security.framework to reach the Keychain. Opt in only if genuinely needed. |
| `launchMethod` | `"exec"` \| `"open"` | `"exec"` | `"exec"` applies `sandbox_init()` then execs directly. `"open"` launches Terminal.app via LaunchServices and sandboxes the inner shell — required only for Terminal.app. |
| `profileOverride` | string | unset | Replaces the generated profile with raw TinyScheme. **All `filesystem`/`network`/`ui` policy is ignored for profile generation.** Last resort. |
| `extraMachLookups` | string[] | `[]` | Additional Mach services the sandbox may look up, as exact `global-name` values. The escape hatch for an app that needs one XPC service without resorting to `profileOverride`. |

<details>
<summary><code>keychainAccess</code> — exactly what it opens</summary>

Mach lookup for `com.apple.SecurityServer`, `com.apple.securityd`,
`com.apple.trustd`, `com.apple.trustd.agent`, `com.apple.ocspd`,
`com.apple.cfprefsd.daemon`, `com.apple.cfprefsd.agent`, `com.apple.xpcd`, and
the `com.apple.lsd.*` family (matched by anchored regex — Seatbelt has no glob
in `global-name`). Read access to `/private/var/db/mds` and
`/private/var/protected/trustd`. Read+write on `~/Library/Keychains` and
`/private/var/folders`. System keychain stores are already covered by the
baseline `/Library` and `/System` allows.
</details>

## Process environment

**The host environment is never inherited.** The child always starts from a
cleared environment, so host secrets (cloud credentials, API tokens) can't leak
into untrusted code. This is unconditional.

- `PATH` defaults to `/usr/bin:/bin:/usr/sbin:/sbin`
- `process.env` is an array of `"KEY=VALUE"` strings, not an object. Each entry
  adds to or overrides that baseline.
- Tools installed outside the default `PATH` need both an env entry **and** a
  `readonlyPaths` grant — e.g. Homebrew on Apple silicon needs
  `"PATH=/opt/homebrew/bin:…"` plus `readonlyPaths: ["/opt/homebrew"]`.

## Working directory

`process.cwd`, if omitted, resolves to the first of: `readwritePaths[0]` →
`readonlyPaths[0]` → `/`. A `~` default is tilde-expanded the same way policy
paths are. `PWD` is exported to the resolved directory.

## Usage

### Command line

```bash
./mxc-exec-mac config.json                        # config file
./mxc-exec-mac --config-base64 <base64-string>    # inline config
./mxc-exec-mac --dry-run config.json              # validate, don't run
./mxc-exec-mac --debug --log-file mxc.log config.json
```

### SDK

```typescript
import { spawnSandbox, SandboxPolicy } from '@microsoft/mxc-sdk';

const policy: SandboxPolicy = {
    version: '0.8.0-alpha',
    filesystem: {
        readwritePaths: ['/tmp/output'],
        readonlyPaths:  ['/opt/tools'],
    },
    network: {
        egress:  { default: 'deny' },
        ingress: { default: 'deny', hostLoopback: 'deny' },
    },
};

// On macOS this resolves to mxc-exec-mac and builds a seatbelt config.
const pty = spawnSandbox('echo hello', policy);
pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit:', e.exitCode));
```

`version` is required and must fall in the supported range. The SDK rejects a
policy that mixes the 0.8 `egress`/`ingress` fields with the legacy
`allowOutbound`/`allowedHosts`/`blockedHosts` fields.

## Building from source

Requires Xcode Command Line Tools (`xcode-select --install`) and Rust. Not
needed if you install pre-built binaries via npm.

```bash
./build-mac.sh              # native arch, release
./build-mac.sh --all        # Apple silicon + Intel
./build-mac.sh --debug      # debug build
./build-mac.sh --rust-only  # skip the TypeScript SDK
```

<details>
<summary>Full machine setup from scratch</summary>

**1. Xcode Command Line Tools** — `clang`, `ld`, headers, macOS SDK.

```bash
xcode-select --install
```

**2. Rust toolchain**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add aarch64-apple-darwin   # required on M-series
rustup target add x86_64-apple-darwin    # only for --all / cross-compilation
```

**3. Homebrew** (optional — only for the tools below)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow the `PATH` instructions it prints (`/opt/homebrew/bin` on Apple silicon).

| Tool | Install | Needed for |
|---|---|---|
| Python 3 | `brew install python` | example `21_mac_python_info.json` |
| Node.js | `brew install node` | building/testing the TypeScript SDK |

> On Apple silicon Homebrew lives at `/opt/homebrew`, so example configs that
> run Python include `"readonlyPaths": ["/opt/homebrew"]` to let the sandbox
> reach the interpreter and its libraries.

**4. Verify**

```bash
./build-mac.sh --rust-only
./src/target/aarch64-apple-darwin/release/mxc-exec-mac --debug \
    tests/examples/15_mac_hello_world.json
```

Expect profile-generation output followed by `hi from seatbelt`.
</details>

Output lands in `sdk/node/bin/<arch>/mxc-exec-mac`, which the SDK's
`findDarwinExecutable()` picks up automatically.

### Codesigning and notarization

`build-mac.sh` produces an **unsigned** binary. Shipping requires:

1. `codesign --options runtime --sign "Developer ID Application: …" mxc-exec-mac`
2. `xcrun notarytool submit … --wait`
3. `xcrun stapler staple mxc-exec-mac`

These run in the release CI pipeline, not the local build script — they need
Apple credentials.

## Troubleshooting / Configs that are rejected

Run with `--debug` to print the generated profile — most surprises are obvious
once you can see the rules that were emitted.

### Common symptoms

| Symptom | Likely cause | Fix |
|---|---|---|
| Internet works, but `localhost:3000` is refused | [The `hostLoopback` trap](#the-hostloopback-trap) — you set `egress.default: "allow"` and left `ingress` out, so `hostLoopback` defaulted to `deny` | Add `ingress: {default: "allow", hostLoopback: "allow"}` |
| All network fails and you didn't configure any | Omitting `network` denies everything — it isn't "unset", it's deny | Add an explicit `egress`/`ingress` block |
| `guiAccess: true` but no window, and no error | `ui.disable` is still `true`, so the GUI rules were silently dropped | Set `ui.disable: false` |
| `readwritePaths` on `/System` or `/usr` still can't write | SIP outranks the profile | Nothing to fix — pick a different path |
| Command not found, or a tool can't find its libraries | The environment is always cleared and `PATH` resets to `/usr/bin:/bin:/usr/sbin:/sbin` | Add `process.env`, and `readonlyPaths` for the install prefix (e.g. `/opt/homebrew`) |
| A client is configured with `HTTP_PROXY` but reaches nothing | It's ignoring the proxy vars. Outbound is kernel-scoped to the proxy port, so it can't connect anywhere else | Use a proxy-aware client — see [Proxy support](#proxy-support-what-is-and-isnt-enforced) |
| A test runner or build tool fails spawning workers | `nestedPty: false`, or its IPC socket sits under a `readonlyPaths`/`deniedPaths` entry | Leave `nestedPty` at `true`; put socket directories in `readwritePaths` |
| The same config runs on Linux but is rejected on macOS | A `..` segment in a path — Seatbelt-only rejection | Pass the fully resolved path |

### What gets rejected

MXC refuses any config it cannot faithfully enforce, rather than quietly
approximating it. This is the complete list.

#### Network

Field names below are the 0.8 shape; the legacy 0.7 equivalent is noted where
the rule applies to both.

| Config | Why it's rejected | Do this instead |
|---|---|---|
| `egress.allow` / `egress.deny` (non-empty) | No CIDR/port/protocol filtering primitive | Use `egress.default` alone |
| `ingress.hostLoopback` ≠ `ingress.default` | Only the outbound half is expressible; see [the trap](#the-hostloopback-trap) | Set both to the same value |
| `runtimeConfig.networkProxy` + `egress.default: "allow"`<br>*(legacy: `network.proxy` + `defaultPolicy: "allow"`)* | Outbound is already open, so the proxy enforces nothing and traffic could silently bypass it | `egress.default: "deny"` + the proxy |
| `runtimeConfig.networkProxy` with a non-loopback host<br>*(0.8 only — rejected by the shared parser, whatever `egress.default` says)* | The runtime proxy endpoint must be loopback | Use `localhost`, `127.0.0.1`, or `[::1]` |
| Remote (non-loopback) `network.proxy` + `defaultPolicy: "block"`<br>*(legacy only — the 0.8 field never gets this far, see the row above)* | Seatbelt can't express reachability to a remote host, so the proxy would be unreachable and *nothing* could connect | Loopback proxy, or `builtinTestServer` |
| Proxy + `enforcementMode: "firewall"` or `"both"` | macOS has no packet-filter layer to enforce with | Drop `enforcementMode` — profile enforcement is implied |
| `processContainer.network.allowedProxyPeer` | Peer identity pinning isn't supported | Remove it |
| `egress`/`ingress` on schema `< 0.8.0-alpha` | Fields don't exist yet | Set `"version": "0.8.0-alpha"` |
| 0.8 fields **and** legacy fields in one config | Ambiguous | Pick one shape |
| `blockedHosts` *(legacy only)* | No per-host filtering primitive | `egress.default: "deny"` to deny everything |
| `allowedHosts` + `defaultPolicy: "block"` *(legacy only)* | Could only degrade to allow-all (the inverse of your request) or deny-all | Loopback proxy under deny, or `builtinTestServer` for tests |

#### Filesystem

| Config | Why it's rejected | Do this instead |
|---|---|---|
| Any path containing a `..` segment | macOS resolves `..` *after* following symlinks, so a lexically-resolved rule can silently point elsewhere (`/tmp/..` is `/private`, not `/`) | Pass the fully resolved path |

This one is **Seatbelt-only** — the shared parser accepts `..`, so a
cross-backend policy using it will run on Linux and fail on macOS. That's
deliberate: the alternative is a rule that matches nothing, which for
`deniedPaths` would fail *open*.

#### Streaming / GUI

| Config | Why it's rejected |
|---|---|
| `guiAccess: true` with piped stdio (SDK streaming) | GUI mode needs inherited stdio and a real terminal |
| `launchMethod: "open"` with piped stdio | Launches Terminal.app; there are no pipes to stream |

## Limitations

**No per-host network filtering.** Seatbelt's `(remote ...)` filter accepts only
`*` and `localhost`. Alternatives considered:

| Approach | Status | Why |
|---|---|---|
| `pf` packet filter | Not viable | Needs root, system-wide (not per-process), unstable hostname→IP for CDNs |
| `/etc/hosts` edits | Not viable | Needs root, affects all processes, bypassable via direct IP or DoH |
| Network Extension | Possible future | `NEFilterDataProvider` can filter per-process by hostname, but needs a signed System Extension, a special entitlement, user approval, and a separate daemon |

**Inbound access is all-or-nothing.** You cannot accept loopback connections
while refusing LAN connections — see [above](#why-it-must-equal-ingressdefault).

**Proxy routing is cooperative, but egress confinement is not.** A client that
ignores `HTTP_PROXY` cannot bypass to the internet — the kernel scopes outbound
to the proxy's port and nothing else. What isn't guaranteed is that a client
uses the proxy at all. See
[Proxy support](#proxy-support-what-is-and-isnt-enforced).

**GUI support is limited to native apps.** Third-party AppKit apps (Alacritty)
work with `guiAccess: true` and the default `launchMethod: "exec"`. Terminal.app
needs `launchMethod: "open"` because Apple Launch Constraints kill it when
exec'd by an unauthorized parent. Other Apple system apps (Calculator, TextEdit)
can't be sandboxed at all — Launch Constraints plus no inner shell to constrain.
Electron apps (VS Code, Spotify) may escape by re-launching via helper
processes.

**No container abstraction.** No persistent container to attach to or destroy —
every invocation is a fresh process tree.

**SIP overrides the profile.** You cannot grant write access to `/System` or
`/usr`, even with an explicit `readwritePaths` entry.

**`sandbox_init` is deprecated in headers** (since 10.8) but still ships and is
used by Apple's own apps and Chromium. It's the same framework behind the App
Sandbox.
