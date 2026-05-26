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
2. Bind-mounting the host root filesystem read-only as a base
3. Layering filesystem policy overrides (read-write, read-only, denied paths)
4. Setting up minimal `/dev`, `/proc`, and `/tmp`
5. Clearing the environment and applying only requested variables
6. Executing the command via `sh -c`

The sandboxed process runs as a child of `bwrap` and dies automatically when
execution completes — no container lifecycle management required.

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
   `linux-test-proxy` binary is used (`builtinTestServer: true`); in
   production callers supply their own proxy via `localhost: <port>`.
2. The sandbox is then started **without** `--unshare-net` so the sandbox
   shares the host network namespace and can reach the loopback proxy.
3. The command builder sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`,
   `https_proxy`, and `NO_PROXY=localhost,127.0.0.1` inside the sandbox
   via `bwrap --setenv` (any caller-supplied values for these keys are
   stripped before injection).
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

- **Cooperative model**: only well-behaved clients that honor `HTTP_PROXY`
  / `HTTPS_PROXY` are filtered. Tools that bypass these env vars (raw
  sockets, custom HTTP clients) are **not enforced**. This is a deliberate
  trade-off for zero-privilege operation.
- **Mutually exclusive with iptables enforcement**: setting
  `network.proxy` together with `network.enforcementMode` of `"firewall"`
  or `"both"` is rejected at config-parse time because iptables-based
  enforcement requires root and would defeat the proxy's privilege story.
- **HTTPS via CONNECT**: the proxy uses HTTP `CONNECT` tunnels for TLS, so
  certificate validation continues to work end-to-end (the proxy does not
  see plaintext).

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
test_scripts/run_bwrap_basic_test.sh

# All Bubblewrap tests
test_scripts/run_bwrap_all_tests.sh
```

Test configs are in `test_configs/bubblewrap_*.json`.

## Limitations

- **Experimental** — requires `--experimental` flag
- **Linux only** — Bubblewrap requires Linux kernel namespaces
- **Host filesystem** — the sandbox sees the host's files (read-only by
  default); there is no separate rootfs
- **Network filtering** — per-host `allowedHosts`/`blockedHosts` is best
  done via the cooperative env-var **network proxy** (no privilege
  required, see above). The legacy iptables path
  (`network.enforcementMode: "firewall"` / `"both"`) still works but
  requires root and is mutually exclusive with the proxy.
- **No state-aware lifecycle** — Bubblewrap implements `ScriptRunner` only
  (one-shot), not `StatefulSandboxBackend`
