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
- **Network filtering** — per-host `allowedHosts`/`blockedHosts` requires
  root for iptables; without host lists, only all-or-nothing isolation is
  available
- **No state-aware lifecycle** — Bubblewrap implements `ScriptRunner` only
  (one-shot), not `StatefulSandboxBackend`
