# Bubblewrap Backend

The Bubblewrap backend provides **unprivileged Linux sandboxing** using
[Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It uses
Linux user namespaces to create isolated sandbox environments without
requiring root privileges or a container runtime.

> **Status:** Experimental — requires the `--experimental` CLI flag.

## Prerequisites

- **Linux** host with kernel 3.8+ (user namespace support)
- **Bubblewrap** installed and on PATH:
  ```bash
  # Debian/Ubuntu
  sudo apt install bubblewrap

  # Fedora/RHEL
  sudo dnf install bubblewrap

  # Alpine
  apk add bubblewrap
  ```
  The deny-by-default baseline (see [How It Works](#how-it-works)) emits its
  read-only mounts via `--ro-bind-try`, which requires **bwrap 0.3.0+**
  (released 2017; every currently-supported distro ships a newer version).
- User namespaces must be enabled:
  ```bash
  # Check: should print "1"
  cat /proc/sys/kernel/unprivileged_userns_clone
  ```

## Quick Start

```json
{
  "version": "0.6.0-alpha",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "echo 'Hello from Bubblewrap sandbox'"
  }
}
```

Run with:
```bash
lxc-exec --experimental --config bubblewrap_hello.json
```

Or via base64:
```bash
lxc-exec --experimental --config-base64 "$(base64 -w0 bubblewrap_hello.json)"
```

## How It Works

Bubblewrap creates a namespace-isolated process by:

1. Unsharing user, PID, IPC, and UTS namespaces (`--unshare-*`)
2. Bind-mounting a **minimal deny-by-default baseline** read-only into the
   sandbox (`/bin`, `/sbin`, `/lib*`, `/usr/bin`, `/usr/sbin`, `/usr/lib*`,
   `/usr/libexec`, `/usr/share`, `/etc`, plus DNS stub-resolver dirs
   under `/run`). Everything else on the host — including the caller's
   `$HOME`, `/root`, `/opt`, `/var`, `/sys`, and `/run/user/<uid>` — is
   invisible inside the sandbox.
3. Layering filesystem policy overrides (read-write, read-only, denied paths)
4. Setting up minimal `/dev`, `/proc`, and `/tmp`
5. Clearing the environment and applying only requested variables
6. Executing the command via `sh -c`

The sandboxed process runs as a child of `bwrap` and dies automatically when
execution completes — no container lifecycle management required.

### Deny-by-default filesystem

The baseline mirrors the macOS Seatbelt backend's `(deny default)` posture:
the sandbox can read the dynamic linker, libc, system tools, and system
configuration — and **nothing else** — until the caller opts in via
`readonlyPaths` / `readwritePaths`. To make a host directory visible inside
the sandbox, list it explicitly:

```json
{
  "filesystem": {
    "readonlyPaths": ["/home/alice/project", "/usr/local"],
    "readwritePaths": ["/tmp/workspace"]
  }
}
```

Common consequences of this default:

- `$HOME` (e.g. `~/.aws/credentials`, `~/.ssh/id_*`, browser cookies) is
  not readable from the sandbox.
- `/opt` and `/usr/local` tooling is not on PATH; list either path under
  `readonlyPaths` if the script depends on it.
- `working_directory` must live under the baseline or a policy path — a
  `cwd` of `~/project` without a matching `readonlyPaths` entry will fail.
- DNS works on systemd-resolved, NetworkManager, and resolvconf hosts
  because the corresponding `/run/...` directories are bound. The common
  symlink targets *outside* `/run` are covered too: `/var/run/...`-routed
  `/etc/resolv.conf` symlinks resolve via a synthesised `/var/run -> /run`
  compat symlink, and WSL's `/mnt/wsl/resolv.conf` is bound directly.
  Neither exposes host `/var` or `/mnt` contents. Hosts that point
  `/etc/resolv.conf` at some other custom location still need that target
  listed in `readonlyPaths`.

Files in `/etc` that contain secrets (`/etc/shadow`, `/etc/sudoers`,
`/etc/ssh/ssh_host_*_key`) are mode `0400` / `0640` `root` and remain
unreadable to a non-root caller — user-namespace UID mapping does not
bypass kernel DAC.

## Configuration

Bubblewrap uses the shared cross-backend configuration fields. No
backend-specific config block is needed.

### Filesystem Policy

| Field | bwrap Mapping | Description |
|-------|---------------|-------------|
| `readwritePaths` | `--bind <path> <path>` | Read-write bind mount (overrides base RO) |
| `readonlyPaths` | `--ro-bind <path> <path>` | Explicit read-only bind mount |
| `deniedPaths` | `--tmpfs <path>` | Masked with empty tmpfs |

Example:
```json
{
  "version": "0.6.0-alpha",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "cat /data/input.txt && echo result > /workspace/output.txt"
  },
  "filesystem": {
    "readonlyPaths": ["/data"],
    "readwritePaths": ["/workspace"],
    "deniedPaths": ["/secrets"]
  }
}
```

### Network Policy

Bubblewrap supports two network modes:

**Full block** (`defaultPolicy: "block"`, no host lists) — uses
`--unshare-net` for complete network namespace isolation. No network stack
is available inside the sandbox (including loopback). Runs fully
unprivileged.

```json
{
  "network": {
    "defaultPolicy": "block"
  }
}
```

**Per-host filtering** (`allowedHosts`/`blockedHosts`) — shares the host
network namespace and applies iptables rules via `NetworkIptablesManager`
(the same approach used by the LXC backend). **Requires root** for
iptables.

> **IPv4 only.** Host names are resolved to IPv4 addresses only; AAAA
> records and IPv6 literals are silently dropped because `iptables` (the
> IPv4 tool) cannot accept IPv6 destinations. A host with only AAAA
> records is effectively unreachable under firewall mode. For dual-stack
> hosts, use proxy mode (below) instead.

```json
{
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowedHosts": ["api.github.com"],
    "blockedHosts": ["evil.example.com"]
  }
}
```

**Full allow** (`defaultPolicy: "allow"`, no host lists) — the sandbox
shares the host network namespace with no restrictions.

### Process Settings

Standard `process` fields work as expected:

```json
{
  "process": {
    "commandLine": "python3 script.py",
    "cwd": "/workspace",
    "env": ["PATH=/usr/bin", "HOME=/tmp"],
    "timeout": 30000
  }
}
```

## Network proxy (cooperative, unprivileged)

Bubblewrap supports an **unprivileged, cooperative network proxy** that
enforces `allowedHosts` / `blockedHosts` at the proxy layer instead of via
iptables. This is the **recommended** way to do per-host filtering on
Bubblewrap because it requires **no root and no `CAP_NET_ADMIN`**.

### How it works

1. When `network.proxy` is set, the runner launches an unprivileged HTTP
   proxy on loopback (`127.0.0.1:N`). For tests, the bundled
   `linux-test-proxy` binary is used (`builtinTestServer: true`,
   testing-only and gated behind `--experimental`); in production callers
   supply their own proxy via `localhost: <port>` or `url: <url>`.
2. The sandbox is then started **without** `--unshare-net` so the sandbox
   shares the host network namespace and can reach the loopback proxy.
3. The command builder sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and
   `https_proxy` inside the sandbox via `bwrap --setenv` (any
   caller-supplied values for these keys, including `NO_PROXY` /
   `no_proxy`, are stripped before injection). The runner deliberately
   does **not** set `NO_PROXY`: since the sandbox shares the host netns,
   a `NO_PROXY=localhost,127.0.0.1` entry would let cooperating clients
   bypass the proxy for host-loopback destinations, defeating
   `allowedHosts` / `blockedHosts` enforcement for those targets.
4. Cooperative tools (curl, wget, Python `requests`, Node `https`, etc.)
   honor the env vars and traffic flows through the proxy, which applies
   the `allowedHosts` / `blockedHosts` lists.

### Example: builtin test proxy with allowlist

```json
{
  "version": "0.6.0-alpha",
  "platform": "linux",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "curl -fsSL https://api.github.com/zen && echo OK"
  },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "builtinTestServer": true },
    "allowedHosts": ["api.github.com"]
  }
}
```

### Example: external proxy on loopback

```json
{
  "version": "0.6.0-alpha",
  "containment": "bubblewrap",
  "process": { "commandLine": "curl -fsSL https://example.com" },
  "network": {
    "proxy": { "localhost": 8080 }
  }
}
```

### Caveats

- **Cooperative model**: the runner enforces by injecting
  `HTTP_PROXY` / `HTTPS_PROXY` into the sandbox environment, so only
  well-behaved clients that honor those vars are routed through the
  proxy. Tools that bypass them (raw sockets, custom HTTP clients,
  statically-linked binaries that ignore the env) are **not enforced**.
  This applies to **both** the builtin test proxy and external (BYO)
  proxy modes — the limitation is in the env-var injection mechanism,
  not in the proxy itself; a BYO proxy can do whatever it likes for
  cooperating clients. For strict whole-network isolation, omit
  `network.proxy` so the runner can apply `--unshare-net` instead.
- **Mutually exclusive with iptables enforcement**: setting
  `network.proxy` together with `network.enforcementMode` of `"firewall"`
  or `"both"` is rejected at config-parse time because iptables-based
  enforcement requires root and would defeat the proxy's privilege story.
- **External proxy delegates policy**: when `network.proxy` uses
  `localhost: <port>` or `url: <url>` (not `builtinTestServer`), the
  external proxy is responsible for any host filtering. The runner does
  **not** forward `allowedHosts` / `blockedHosts` / `defaultPolicy: "block"`
  to it, and config combinations that would silently weaken enforcement
  are rejected at parse time.
- **`builtinTestServer` is testing-only**: gated behind `--experimental`
  and never to be used as a real production proxy. It has no auth, no
  body-size limits, and minimal hop-by-hop header handling. Use a real
  HTTP proxy for production deployments.
- **HTTPS via CONNECT**: the proxy uses HTTP `CONNECT` tunnels for TLS, so
  certificate validation continues to work end-to-end (the proxy does not
  see plaintext).

### Common pitfalls when configuring `allowedHosts`

The proxy applies `allowedHosts` and `blockedHosts` by **case-insensitive
exact host match** — there is no subdomain wildcard and no IP-vs-hostname
resolution.

- `allowedHosts: ["github.com"]` does **not** match `api.github.com`. List
  each subdomain explicitly (e.g. `["api.github.com", "objects.githubusercontent.com"]`).
- `allowedHosts: ["api.github.com"]` does **not** match a CONNECT to a raw
  IP literal such as `140.82.114.6:443`. If your workload bypasses DNS,
  include the IPs.
- `allowedHosts: ["localhost"]` does **not** match `127.0.0.1`; if you
  need both, list both.
- IPv6 literals are normalised: an allowlist entry of `"::1"` matches a
  CONNECT to `[::1]:443`, but not the unrelated `[fe80::1]:443`.

## Comparison with LXC

| Aspect | LXC | Bubblewrap |
|--------|-----|------------|
| Privileges | Root required | Unprivileged (user namespaces) |
| Rootfs | Downloads distro rootfs | Bind-mounts host filesystem |
| Startup | Create → Start → Attach | Single `bwrap` exec |
| Network isolation | iptables + veth | `--unshare-net` or iptables |
| Dependencies | `lxc-*` tools, templates | Single `bwrap` binary |
| Lifecycle | Create/destroy containers | Process dies on exit |

**When to use Bubblewrap:**
- Quick sandboxing without root access
- Environments where LXC is not available
- Fast iteration (no container create/destroy overhead)

**When to use LXC:**
- Need a separate rootfs (different distro/packages)
- Need container networking with veth interfaces
- Need persistent containers across executions

## Running Tests

```bash
# Single basic test
tests/scripts/run_bwrap_basic_test.sh

# All Bubblewrap tests
tests/scripts/run_bwrap_all_tests.sh
```

Test configs are in `tests/configs/bubblewrap_*.json`.

## Limitations

- **Experimental** — requires `--experimental` flag
- **Linux only** — Bubblewrap requires Linux kernel namespaces
- **Deny-by-default filesystem** — the sandbox sees a minimal allowlist
  of host paths (system binaries, libs, `/etc`, DNS stub-resolver dirs)
  and nothing else. `$HOME`, `/opt`, `/var`, `/sys`, `/run/user/<uid>`,
  and `/usr/local` are invisible unless explicitly listed in
  `readonlyPaths` / `readwritePaths`. There is no separate rootfs — the
  visible paths are bind-mounted from the host.
- **Network filtering** — per-host `allowedHosts`/`blockedHosts` is best
  done via the cooperative env-var **network proxy** (no privilege
  required, see above). The legacy iptables path
  (`network.enforcementMode: "firewall"` / `"both"`) still works but
  requires root and is mutually exclusive with the proxy.
- **No state-aware lifecycle** — Bubblewrap implements `ScriptRunner` only
  (one-shot), not `StatefulSandboxBackend`
