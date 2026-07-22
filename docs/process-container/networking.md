# Process Container Networking Configuration, GA

Implementation companion to the parent [MXC Network Configuration, GA](../sandbox-policy/v2/networking.md) doc, which owns the shared policy schema, the three connectivity models, and the GA goal (model 2, deny-all-except-proxy). This doc covers only how the Windows processcontainer backend enforces those models.

## 1. What this backend delivers at GA

Each sandbox gets two enforcement primitives, scoped to its container SID and applied with no UAC prompt per launch:

- **WFP outbound filters:** block all outbound traffic by default, then allow or block specific destinations by IP address or range, protocol, and port (a single port or a range), for both IPv4 and IPv6. An explicit block always wins over an allow, so a deny is expected to fall inside the allow it narrows; an allow and a deny matching the exact same destination, protocol, and port is rejected as an invalid policy. The rules apply only to this sandbox.
- **Per-container WinHTTP HTTP/S proxy:** points WinHTTP-stack clients (e.g., the WinHTTP/Chromium stack) at a caller-provided loopback proxy container. MXC also sets the proxy env vars (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, plus lowercase versions) to the same loopback endpoint. Runtimes that read those variables rather than WinHTTP (Node tooling, Python `requests` / `pip`, Go `net/http`, `curl`, `git`) route through the proxy using this mechanism. These variables are a compatibility layer for well-behaved clients, not the containment boundary. All traffic not destined for the proxy loopback will be dropped.

Each model is a specific combination of container network capabilities and enforcement. Example configs use the parent doc's proposed network schema + additional runtime.

### Model 1: direct egress, WFP-filtered (least restrictive)

- **Capabilities:** internetClient, plus a loopback exemption for same-container connections; no other network capability.
- **Enforcement:** WFP allow/block rules; no proxy.

```jsonc
{
  "network": {
    "egress": {
      "mode": "direct",
      "default": "deny",
      "allow": [
        { "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ] }
      ]
    },
    "ingress": { "hostLoopback": "deny" }
    // direct egress, filtered by WFP
  }
}
```

### Model 2: proxy-only egress (recommended)

- **Capabilities:** no AppContainer networking capabilities. A loopback exemption for inter-container (to the proxy container) and intra-container communication.
- **Enforcement:** The per-container WinHTTP proxy. With no internetClient, the only reachable egress is the loopback proxy; the system drops everything else. MXC resolves the proxy container's SID at launch to scope the loopback exemption.

```jsonc
{
  "network": {
    "ingress": { "hostLoopback": "deny" }
  },
  "runtimeConfig": { // MXC runtime metadata (not policy)
    "networkProxy": "http://127.0.0.1:8080"
  },
  "processcontainer": {
    "network": {
      "allowedPeers": [
        "agent-proxy" // AppContainer SID derived at runtime, needed for loopback rules addition
      ]
    }
  }
}
```

The proxy endpoint (e.g., 127.0.0.1:8080) is a config parameter for the process container backend and not part of the overall MXC network policy. MXC resolves the proxy container's SID at launch to scope the loopback exemption. In proxy mode there is no direct egress plane, so default, allow, and deny do not apply. MXC will not spin up the proxy for the caller. It is the caller's responsibility to spin up their own proxy inside an AppContainer, and provide MXC with the friendly name of the AppContainer that aligns with the [CreateAppContainerProfile function (userenv.h)](https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile).

### Model 3: fully blocked (most restrictive)

- **Capabilities:** none; no loopback exemptions.
- **Enforcement:** no proxy; all outbound and inbound dropped.

Since deny-all is the default, model 3 is also the result of providing no network policy at all: the explicit form, an omitted network block, and an empty `"network": {}` are equivalent:

```jsonc
// explicit (canonical blocked: direct egress, default deny, no allow rules)
{
  "network": {
    "egress": { "mode": "direct", "default": "deny" },   // no allow rules
    "ingress": { "hostLoopback": "deny" }
  }
}

// or
{ /* no "network" key at all */ }

// or
{ "network": {} }
```

### 1.1 Out of GA scope for this backend

Do not infer otherwise from the schema:

- Transparent TCP/UDP redirection through the proxy. GA proxying is WinHTTP HTTP/S only.
- L7 classification (e.g., HTTPS vs SSH on :443).
- Durable DNS-name rules.
- Encrypted-payload inspection.
- Inbound/listening policy.

See the parent doc on the last 4.

## 2. Two enforcement paths: current vs downlevel

Both (a) WFP filter writes and (b) per-container WinHTTP proxy configuration require a privileged context. How that privilege is obtained is the entire implementation story for this backend, and it splits by Windows build:

| Tier 1: the OS applies the policy in-process | Tier 2: downlevel (Windows 23H2) |
|---|---|
| On builds that expose the OS sandbox-creation API (`CreateProcessInSandbox`), the OS itself, in its own elevated context, applies the per-sandbox WFP filters and wires the WinHTTP proxy before the target process runs.<br><br>No MXC-side privileged component, no UAC. The filter lifetime is owned by the OS and bound to AppContainer. This is the preferred path and where new capabilities land first. | On builds without that API (Windows 23H2), only model 1 (direct egress, WFP-filtered) is supported. MXC applies the per-sandbox WFP filters by elevating on each launch to write them.<br><br>There is no per-container WinHTTP proxy support on 23H2, so model 2 (proxy-only egress) is available only on builds that expose `CreateProcessInSandbox`. |

### 2.1 Fail loud on version skew: never silently downgrade

`CreateProcessInSandbox` could be different between builds as the network-policy surface grows over time. A machine can expose the API but not yet honor a specific policy field MXC asks for. MXC must not silently fall back to Tier 2 in that case: the two paths have different security and cleanup properties, and the operator would not know. The contract:

- Fall back to Tier 2 only when the API is absent on the build, not when it is present but missing a requested field.
- For a present-but-incomplete API, MXC rejects the launch with a typed error naming the missing capability.

## 3. WFP is the enforcement primitive (both tiers)

AppContainers today have 3 network capabilities: internetClient, internetClientServer, and privateNetworkClientServer. For GA we only ever use the internetClient capability, which basically acts as an on or off switch for outbound internet connectivity. Beyond that, the outbound policy is enforced with the Windows Filtering Platform (WFP), the OS's built-in network-filtering engine. When the sandbox tries to open an outbound connection, the kernel will check MXC's filters and allow or block it. Each filter is scoped to the sandbox's container SID, so it applies only to that one sandbox and to nothing else on the machine.

**Admin requirement.** Adding WFP filters is admin-only. On Tier 1 the OS applies them in its own elevated context; on Tier 2 (Windows 23H2) MXC elevates on each launch to write the filters.

**Cleanup.** Filters will need to have a lifetime ≤ sandbox lifetime. In both tiers the filters will need to be cleaned up when there are no more processes running in the container.
