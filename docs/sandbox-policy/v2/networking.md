# MXC Network Configuration, GA

## Overview

The MXC network configuration describes what network access a sandboxed workload has. The schema is shared across all container types (process containers, WSLc, LXC, Bubblewrap, Seatbelt). Enforcement varies by backend and platform.

This document covers the GA scope for the General Availability release.

**GA Goal:** Reduce the network surface an AI agent can use to escape its sandbox or exfiltrate data. By default, all outbound traffic is dropped. The recommended path for GA is: localhost HTTP/S proxy for application traffic (API calls, package downloads). Direct outbound connections (raw sockets, SSH, custom TCP/UDP) are blocked by default and only allowed when explicitly permitted by IP/CIDR rules. This is a hard problem to solve across multiple platforms. GitHub Copilot expects sandboxes to behave consistently cross-platform, but each platform has different enforcement primitives. This document describes what MXC can enforce on each backend, where platform limitations exist.

### GA Commitments: What Traffic Goes Where

This document specifies the shared MXC networking schema and GA behavior for backends that support network configuration. Backend-specific support, enforcement differences, and unsupported modes are described in the GA Scope by Backend section.

#### Connectivity models

MXC defines three outbound connectivity models, listed in increasing order of network restriction. All three apply the configured L3/L4 filtering (IP/CIDR/port/protocol allow/block rules). They differ in whether a loopback HTTP(S) proxy is present and whether the sandbox can reach the internet directly:

- **Direct internet + L3/L4 filtering, no proxy (least restrictive).** The sandbox reaches the internet directly over HTTP(S) (and other protocols), subject only to IP/CIDR/port/protocol allow/block rules. No proxy is configured, so there is no application-layer (domain/URL/content) inspection.
- **No direct internet + loopback HTTP(S) proxy (more restrictive).** The sandbox has no direct internet path; the only reachable egress is the loopback proxy port, and all other outbound is dropped. Cooperating clients route their HTTP(S) to the proxy (via the proxy environment variables / platform proxy configuration), where it is fully inspectable/filterable by the consumer. A client that ignores the proxy and tries to reach the internet directly is dropped, since no other egress path exists.
- **No direct internet + no inbound (most restrictive):** This is the most restrictive we can get. In this model all network traffic is dropped.

There was a fourth model that was looked at Direct internet + L3/L4 filtering + loopback HTTP(S) proxy. However, unlike model 2 which only allows traffic through a specific loopback port, direct internet access greatly decreases the ways to control egress and increases the opportunities for agent bypass. It is not a model we will have for GA.

**GA goal:** model 2 (recommended to mxc consumers) on every backend. The shape of model 2 is the same everywhere: restrict the sandbox's outbound so the only reachable destination is the loopback proxy port, and configure the proxy information so cooperating clients route there.

This loopback-only-plus-proxy-routing pattern is a well-established way to confine sandboxed agent egress on macOS and Linux. MXC enforces a strict localhost-only egress restriction for GA. See GA Scope by Backend for per-backend details.

Throughout this document, the deny-all-except-proxy posture (the GA goal) refers to model 2.

#### Outbound Traffic Routing

**Default stance:** outbound is blocked by default. The paths below describe how allowed traffic flows.

**Proxy path (recommended for application traffic):**

- **Protocol:** HTTP and HTTPS only
- **Destination:** Localhost proxy only (e.g., 127.0.0.1, ::1)
- **Ports:** Any port within the 1 – 65535 range.
- **Routing mechanism:** This applies to HTTP(S) only, never to other protocols. The sandbox's outbound is restricted so the only reachable destination is the loopback proxy port. Cooperating clients are pointed at the proxy: via the `HTTP_PROXY`/`HTTPS_PROXY` variables on the Linux and macOS backends, and via the per-appContainer WinHTTP proxy configuration on Windows. A client that ignores it cannot reach the internet directly because the egress restriction drops everything except the localhost proxy port, so it is dropped rather than bypassing the proxy. In model 1 (where direct egress is permitted) such a client may instead egress directly, subject to the IP/CIDR/port/protocol rules.
- **What is NOT routed:** Non-HTTP traffic (raw TCP/UDP sockets, SSH, custom protocols, QUIC, WebRTC, etc.) is never redirected to the proxy. In model 2 on Windows, without the internetClient capability such connections cannot be made at all (the capability, not allow rules, gates direct egress); in model 1 they are subject to the IP/CIDR/port/protocol rules. Transparently routing this traffic through the proxy is a gap that requires further design and is out of scope for GA.

**Direct outbound path (model 1 only):**

- **When allowed:** Only when explicitly allowed by IP/CIDR + port + protocol rules in `egress.allow`. In model 2 there is no direct egress path, so these connections are not possible regardless of any allow rules.
- **Use case:** e.g. SSH to a specific dev server, a direct TCP connection to a database, UDP to a specific endpoint, ICMP for diagnostics.
- **Caveat (coarse filtering):** Rules match IP/CIDR + port + protocol, not the application protocol. A port number does not identify a service (DNS need not use 53; a database may listen on any port), so allowing or denying a port is a blunt control rather than service-level filtering.
- **Enforcement:** WFP filters (Windows process containers), network namespace + iptables (WSLc/LXC/Bubblewrap). Model 1 for macOS is not supported for GA. Seatbelt cannot filter arbitrary destinations and macOS packet filtering is not fine-grained enough for per-sandbox scenarios out of the box.

**Example:**

| Consumer scenario | Which model they should use |
|---|---|
| HTTP/HTTPS API calls → localhost proxy (e.g., port 8080) | model 2 |
| SSH to 192.0.2.10:22 → explicit allow rule required | model 1 |
| DNS to 8.8.8.8:53 → explicit allow rule required (or blocked if resolver IP not allowed) | model 1 |
| Raw TCP to 140.82.112.0/20:443 → explicit allow rule required | model 1 |

#### Host-to-Container Inbound Policy

**Default stance:** Host-to-container and external inbound traffic are blocked by default on all backends.

This does not affect intra-container loopback. Processes inside the same sandbox may communicate with each other over localhost / 127.0.0.1 / ::1.

**When allowed:** `ingress.hostLoopback: allow` (see schema) allows sandbox-local listening sockets to be reachable from the host over loopback only (127.0.0.1 / ::1), where the backend supports it. There is deliberately no setting that exposes the sandbox as a LAN/WAN server.

**Scope:**

- Intra-container loopback: always allowed
- Host-to-container inbound: blocked by default; opt-in via `ingress.hostLoopback: allow` where supported
- LAN/WAN inbound: not allowed in GA

**Use cases for `ingress.hostLoopback: allow`:**

- MCP servers in SSE/WebSocket mode (server listens on a port for client connections from host)
- Language server daemons (e.g., TypeScript language server) accessed from host IDE
- Local dev servers (e.g., npm run dev on port 3000) accessed from host browser

Enforcement and the Seatbelt bind caveat are covered in D2.

#### Inter-Container Networking Policy

**GA stance:** Only Windows process containers support this today.

- **Windows process containers:** Two AppContainers can communicate over host loopback only if AppContainer loopback-exemption rules are installed for the pair. These rules are directional, so both directions must be granted. This allows pointed container to container communication over the loopback. MXC will allow this for GA.
- **WSLc / LXC / Bubblewrap:** Each sandbox has its own network namespace, so 127.0.0.1 is private to the sandbox and separate sandboxes cannot reach each other over loopback. Inter-container communication requires explicit virtual networking (veth/bridge/routing, a shared namespace, or a brokered host proxy/IPC path). LXC has mature primitives for this; Bubblewrap would require MXC to build the networking around it. This is out of scope for GA for all 3.
- **macOS (Seatbelt):** Seatbelt does not create a network namespace, so two Seatbelt-sandboxed processes share the host loopback and can communicate over 127.0.0.1 (or Unix sockets/XPC) if both profiles allow it. This is host-level IPC, not isolated container-to-container networking, and is not a GA commitment.

#### Intra-Container Networking Policy

Loopback traffic within the same sandbox is always allowed. This enables multi-process applications, local IPC over localhost sockets, and sandbox-local helper processes. For example, on macOS Seatbelt, processes launched via posix_spawn or NSTask inherit the effective sandbox constraints of the parent process. Parent and child can communicate over allowed loopback or IPC paths.

Loopback traffic between processes in the same sandbox is not governed by outbound IP/CIDR rules or host-to-container inbound policy.

## Proposed Schema

### Connectivity model 1 and 3

Direct internet, no proxy (least restrictive). OR no egress at all: default deny with no allow rules (most restrictive)

```json
{
  "network": { // Network policy
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ]
        }
      ],
      "deny": []
    },
    "ingress": {
      "hostLoopback": "deny"
    }
  }
}
```

### Connectivity model 2

No direct internet, loopback proxy only (more restrictive). Proxy

```json
{
  "network": { // Network Policy (must be set to defaults, deny all)
    "egress": {
      "default": "deny"
    },
    "ingress": {
      "hostLoopback": "deny"
    }
  },
  "runtimeConfig": { // runtime data passed to MXC (not policy)
    // only localhost:<port>, 127.0.0.1:<port> and [::1]:<port> allowed for GA
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```

This schema follows container-ecosystem conventions (CIDR peers, egress/ingress, to/ports), modeled loosely on Kubernetes NetworkPolicy (the CNCF standard layered on CNI/OCI) rather than on platform firewall primitives. MXC keeps an explicit deny list and a per-direction default, which are a deliberate extension over pure Kubernetes NetworkPolicy (allow-only with `ipBlock.except`) to give an auditable default and block-precedence.

**Field semantics:**

- `egress.default`: `"deny"` (default) or `"allow"`, the stance for traffic not matched by a rule.
- `egress.allow[]` / `egress.deny[]`: rules in container-network style. Each rule has `to` (a list of peers) and optional `ports`. An explicit deny match overrides an allow match (block precedence). These are rejected when the mode is set to proxy.
- `ingress.hostLoopback`: `"deny"` (default) or `"allow"`. Controls whether the host may reach sandbox-local listening sockets over loopback (127.0.0.1 / ::1) only. LAN/WAN inbound is never allowed at GA; there is deliberately no CIDR-based ingress, to prevent exposing the sandbox as a LAN server. Does not affect intra-container loopback. Enforced on all backends: Windows process containers via loopback rules, WSLc/LXC/Bubblewrap via iptables INPUT, Seatbelt via profile.
- `runtimeConfig.networkProxy`: This is outside of the main network policy and allows consumers to provide their proxy URL. Only `localhost:<port>`, `127.0.0.1:<port>` and `[::1]:<port>` are allowed for GA.

Egress peer and port fields (used in `egress.allow[]` / `egress.deny[]`; not shown in the minimal example above):

| Field | Type | Notes |
|---|---|---|
| `to[].cidr` | IPv4 / IPv6 CIDR, or 0.0.0.0/0 / ::/0 for any | Single CIDR string (CNI/Kubernetes style), replacing separate address + prefix length. |
| `to[].except` | list of CIDRs, optional | Exclusions within the peer's CIDR (Kubernetes `ipBlock.except` style). Expressible on Windows process containers (WFP) and the Linux backends (iptables) as additional deny rules; not supported on Seatbelt (no destination filtering). |
| `ports[].protocol` | tcp / udp / icmp / any | `any` matches all protocols. Enforced on Windows process containers (WFP) and the Linux backends (iptables); not supported on Seatbelt. |
| `ports[].port` | uint16, optional | Destination port. Omit `ports` to match all ports/protocols. |
| `ports[].endPort` | uint16, optional | End of a port range (Kubernetes `endPort` style); requires numeric port. Supported on Windows process containers (WFP) and the Linux backends (iptables); not supported on Seatbelt. |

Ingress has no CIDR peers: `ingress.hostLoopback` is a deny/allow toggle for host loopback only, deliberately preventing LAN/WAN exposure.

## Design decisions

### D1: Default-deny outbound

**Decision:** Unlisted destinations are unreachable. A configuration that mentions nothing grants nothing.

**Why:** This ensures the configuration explicitly describes the sandbox's network permissions (auditable on enforcing backends). Forgotten rules fail closed (safer). The same configuration means the same thing on different hosts and container types (portable intent, though enforcement fidelity varies by platform).

**Limitation:** Enforcement requires an egress restriction at the OS level: WFP on Windows process containers, a network namespace plus iptables on the Linux backends, and a Seatbelt profile confining network-outbound to the loopback proxy port on macOS. Rich IP/CIDR/port allow-lists are expressible on Windows and the Linux backends but not on macOS, where Seatbelt restricts egress to the proxy port rather than filtering arbitrary destinations. A configuration a backend cannot enforce is rejected rather than run advisory, so "fully describes the workload's network view" always holds for an accepted configuration.

### D2: Inbound is blocked by default and opt-in where supported

**Decision:** GA defines outbound configuration and inbound control. Host-to-container and external inbound traffic is blocked by default (`ingress.hostLoopback: deny`). Intra-container loopback (process-to-process within same sandbox) is always allowed. When `ingress.hostLoopback: allow`, sandbox-local listening sockets are reachable from the host over loopback only (127.0.0.1 / ::1), where the backend supports it.

**Why inbound is blocked by default:**

- **Attack surface:** Allowing host-to-container inbound means the sandbox can run servers accessible from the host. For agentic workloads, this creates a risk of command-and-control servers, exfiltration channels, or lateral movement vectors.
- **Opt-in model:** Customer scenarios that need host-to-container inbound (MCP servers in SSE/WebSocket mode accessed from host, language server daemons accessed from host IDE) must explicitly set `ingress.hostLoopback: allow`.
- **GA enforcement:** `ingress.hostLoopback` is enforced on all backends, Windows process containers via loopback exemption rules scoped to the AppContainer SID, WSLc/LXC/Bubblewrap via iptables INPUT, and Seatbelt via its profile.

**Seatbelt caveat:** On Seatbelt there is no private loopback, so a profile that blocks host-to-container ingress (`ingress.hostLoopback: deny`) also blocks the sandbox from binding loopback listeners at all, breaking intra-sandbox loopback servers. For intra-sandbox IPC on macOS, Unix-domain sockets in a sandbox-private path rather than TCP loopback could be used. That said, Unix-domain sockets come with their own security questions and should be outlined in a separate macOS doc if necessary.

**Elevation caveat:** Installing these filters (WFP on Windows, iptables on the Linux backends) generally requires elevation. Elevating on every sandbox launch is out of the question, so MXC applies them through a privileged broker/service rather than from the unelevated launch path. A per-platform, per-technology elevation story must be defined in a separate MXC elevation design doc and is a prerequisite for this enforcement.

### D3: IP literals and CIDRs only (no DNS names)

**Decision:** Rule addresses must be IPv4/IPv6 literals or CIDRs. DNS names are rejected at validation time. The backend does not resolve names on behalf of callers.

**Why:** Names are bypassable and non-deterministic. A container that resolves DNS itself can map a blocked name to an IP and connect directly. These results can change between config-time and runtime (TOCTOU) and vary by resolver/TTL/cache. IP/CIDR literals are deterministic and auditable.

**GA DNS behavior:** GA does not implement domain-based DNS policy. DNS is not a first-class policy surface. If firewall rules block the DNS resolver IP, DNS queries fail. If rules allow the resolver IP, the sandbox can resolve any domain.

**Secure domain allow-listing:** For HTTP(S) routed to the proxy, the proxy can inspect the domain on each CONNECT request in the HTTP header, and then choose to allow or deny by domain. The proxy resolves the hostname on the sandbox's behalf and enforces the domain allow-list before connecting. DNS resolution security at this point is on the proxy and not MXC.

### D4: Explicit deny takes precedence over explicit allow

**Decision:** When a connection matches both an `egress.allow` rule and an `egress.deny` rule, the deny wins. With `egress.default: "deny"`, no matching allow means no outbound access. With `egress.default: "allow"`, no matching deny means unrestricted outbound.

**Why:** Fail-closed security posture. Deny rules act as overrides for broader allow rules (e.g., allow 0.0.0.0/0 but deny specific malicious IPs).

### D5: Proxy is HTTP/S via platform-native APIs; localhost only for GA

**Decision:** For GA, proxy routing covers HTTP and HTTPS traffic routed through the platform's native proxy surface. The proxy must be on localhost (same-machine loopback) for GA. Remote proxies are out of scope for GA.

**Platform-specific enforcement:**

| Platform | Enforcement Mechanism |
|---|---|
| Windows (Process Containers) | Per-AppContainer WinHTTP proxy configuration + no internetClient capability. |
| Linux (WSLc, LXC, Bubblewrap) | iptables in the sandbox network namespace: default-DROP all outbound except the configured proxy endpoint plus the explicit allow-list. This DROP is the enforcement. MXC-set `HTTP_PROXY`/`HTTPS_PROXY` env variables are an advisory routing hint; an app that ignores them does not gain direct internet access. iptables rule drops the connection and it simply fails. |
| macOS (Seatbelt) | Seatbelt profile confines network-outbound to the loopback proxy port. MXC-set `HTTP_PROXY`/`HTTPS_PROXY` env variables are an advisory routing hint; a client that ignores the variables is denied by the profile (only the proxy port is reachable), so it is dropped, not bypassed. |

**Why localhost only:** Remote proxies introduce trust boundary issues (proxy on different machine = different security context). Localhost proxy simplifies GA implementation and ensures proxy is under the same administrative control as the sandbox.

**Proxy environment-variable hygiene (all backends):** The sandbox starts with all HTTP(S)-related proxy environment variables cleared to empty (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, and their lowercase variants). The sandbox never inherits host or stale proxy settings. MXC sets these variables explicitly, and only to the configured loopback proxy, when a proxy is in use (model 2); in model 1 they remain empty.

**Consumer-provided proxy (all backends):** MXC does not provide, launch, or manage the proxy, and knows nothing about it beyond the host:port in the configuration. The consumer must start their proxy listening before launching the workload. MXC restricts the sandbox's egress to that endpoint and points the proxy variables at it. Making the proxy reachable from inside the sandbox is MXC's responsibility and is backend-specific.

What is and is not routed through the proxy is described under Outbound Traffic Routing.

### D6: Per-sandbox scoping

**Decision:** Every configuration is scoped to one sandbox instance. Two concurrent sandboxes from different clients (e.g., gh-copilot and vscode) have independent configurations. One sandbox's configuration cannot affect another's network access.

**Why:** Isolation between sandboxes prevents cross-sandbox interference and ensures configuration changes in one sandbox do not weaken another.

**Implementation:** The sandbox identity used for scoping is backend-specific (AppContainer SID on Windows process containers, network namespace on WSLc/LXC, Seatbelt profile).

### D7: Schema is container-type-agnostic; enforcement is backend-specific

**Decision:** The network schema block is shared across all container types. The same JSON configuration means the same thing whether the backend is a Windows process container, a WSLc container, or Seatbelt on macOS.

**Why:** Portable intent across platforms. Customers write one configuration that expresses their security policy; MXC maps it to backend-specific enforcement.

**Reality:** Enforcement fidelity varies. A capability available on one backend (e.g., per-AppContainer WFP filters) may not have an equivalent on another. Cooperation-dependent routing (e.g., honoring proxy env vars) is allowed only as an optimization above an enforcing layer that already blocks non-cooperative traffic; it is never the enforcement mechanism itself.

### D8: Delegation from the invoking user

**Decision:** Like the filesystem configuration, the network configuration is a delegation: the contained code receives no more network access than the invoking user could exercise themselves.

**Why:** The sandbox can only be more restricted, never less. A sandboxed process cannot reach a network destination that the invoking user's own process could not reach. Host-level firewalls, VPN configuration, and similar environmental controls still apply on top of this.

## GA Scope by Backend

GA includes all backends for their respective isolation capabilities. Network configuration enforcement varies by backend. This section describes the deny-all-except-recommended-path model for each backend.

### Process containers (Windows): GA enforcement

**Models (Connectivity models):** Model 2 (recommended) grants no internetClient, so the AppContainer reaches only the loopback proxy and all other outbound is dropped by the system. Model 1 grants internetClient, allowing direct egress under WFP IP/CIDR/port/protocol rules.

**Model 3:** grants no internetClient and no loopback exemptions for the AppContainer SID.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | WFP dynamic filters for IPv4/IPv6, scoped to AppContainer SID | |
| Port filtering | Port filtering via WFP | Port ranges supported. |
| Protocol filtering | Protocol filtering via WFP | tcp, udp, icmpv4, icmpv6, any. |
| Default-deny | WFP block-all baseline filter at lower precedence than explicit allows. AppContainer has no internetClient capability. | |
| Proxy (HTTP/S only) | Per-AppContainer WinHTTP proxy configuration. Applications using WinHTTP stack (e.g., Chromium) are transparently routed. **Loopback access to the configured localhost proxy endpoint is explicitly permitted while blocking direct internet egress.** | Non-WinHTTP stacks (raw sockets, SSH, custom TCP/UDP) and HTTP clients configured to ignore OS/env proxy settings are not proxied and traffic is dropped. |
| Per-sandbox scoping | AppContainer SID, unique per sandbox instance | |
| Inbound | Enforced via Loopback rules. When `ingress.hostLoopback: deny` (default), inbound accepts are blocked. When allow, loopback inbound to the sandbox is permitted. | Loopback only. Only AppContainer to AppContainer connection allowed. |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | High. Kernel-enforced WFP filters. Bypass requires kernel compromise or AppContainer escape (elevation). | |

**Implementation doc:** [Process Container Networking Configuration, GA](../../process-container/networking.md)

### WSLc: GA enforcement

**Default stance:** Deny all outbound (iptables default DROP in container network namespace).

**Connectivity model:** Model 2 achievable, iptables kernel-enforces deny-all-except-loopback-proxy within the container network namespace. Model 1 by relaxing the allow-list (permit direct egress) and using iptables for filtering. Model 3 is enforced with the container network namespace and iptables/nftables blocking all in and out traffic.

**Recommended path:** Localhost proxy (HTTP/S via env vars) + explicit IP/CIDR allow-list.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | iptables rules in container network namespace. | IPv4 + IPv6 at GA |
| Port filtering | iptables rules in container network namespace. | Port ranges supported. |
| Protocol filtering | iptables rules in container network namespace. | tcp, udp, icmp. |
| Default-deny | iptables rules in container network namespace. | |
| Proxy (HTTP/S only) | `HTTP_PROXY` / `HTTPS_PROXY` environment variable injection. Apps honoring these vars are routed. iptables rules allow outbound to only localhost proxy provided by MXC caller. | Apps ignoring env vars are still subject to allow/block rules (cannot bypass iptables). |
| Per-sandbox scoping | Container network namespace (each container has isolated network namespace) | |
| Inbound | Enforced via iptables INPUT chain. When `ingress.hostLoopback: deny` (default), all host/external inbound blocked. When allow, iptables rules allow host loopback inbound to the container. | Loopback only. |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | Medium. Container escape bypasses iptables, but kernel-enforced within container. | |

### LXC and Bubblewrap: GA enforcement

Same model and enforcement as WSLc (model 2 achievable; iptables/nftables on the veth interface; default-deny outbound, loopback proxy + allow-list and `ingress.hostLoopback` via INPUT).

### macOS (Seatbelt): GA enforcement

**Default stance:** Egress is confined to the loopback proxy port by the Seatbelt profile.

**Connectivity model:** Model 2 and 3 only. Model 1 (direct egress under IP/CIDR rules) is not supported because Seatbelt cannot enforce arbitrary destination policy. It can deny network entirely or allow only the localhost proxy path, but not general IP/CIDR, hostname, port, or protocol allow-lists.

**Recommended path:** Loopback proxy with the Seatbelt localhost egress restriction and proxy variables.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| Egress restriction (model 2) | Seatbelt profile: (deny default) then allow network-outbound only to `localhost:<proxyPort>`. All other outbound (direct internet, raw sockets, direct DNS) is denied by the profile. | Confines egress to the proxy port; does not filter arbitrary destinations. |
| Proxy routing (HTTP/S) | `HTTP_PROXY`/`HTTPS_PROXY` set to the loopback proxy; cooperating clients route there. | A minority of clients ignore the variables; their traffic is dropped by the egress restriction, not bypassed. |
| IP/CIDR / port / protocol allow-lists | Not supported. | |
| Per-sandbox scoping | Seatbelt profile per sandbox-exec invocation | |
| Inbound | `ingress.hostLoopback` via the Seatbelt profile (network-bind / network-inbound). deny default; allow scoped to loopback only. | Loopback only. |
| DNS | Direct outbound DNS to an external resolver is blocked (egress confined to the proxy port); cooperating clients pass hostnames to the proxy, which resolves them. All others would be blocked. | |
| Bypass resistance | Medium. Egress is profile-restricted to the proxy port, so raw-socket and direct-DNS attempts are denied. Weaker than a separate network namespace (Seatbelt shares the host network stack) and depends on a correct profile. | |

### Other backends

- **Windows Sandbox:** Guest-side firewall only, with hardcoded rules. In GA for development/testing scenarios where network isolation is not critical.
- **Isolation Session:** No network configuration support (all network/proxy fields rejected at validation time). In GA for process isolation only (filesystem, identity, lifecycle).
- **Hyperlight, Nanvix:** Not in this GA scope doc. Additional follow up is needed to confirm their capabilities and whether they align with this doc.

## Gaps and limitations

**What GA cannot do:**

- **DNS domain filtering:** The IP/CIDR schema cannot distinguish hostnames that resolve to the same IP. Domain allow/deny requires either deeper platform support or the proxy inspecting the CONNECT/request host plus blocking direct DNS egress (see D3).
- **Inter-container networking:** Containers cannot communicate with each other (except Windows process containers).
- **macOS direct-egress models:** Seatbelt cannot filter arbitrary remote destinations, so model 1 (direct egress under IP/CIDR/port/protocol rules) is not available on macOS; macOS supports model 2 (proxy-only).
- **Proxy arbitrary network traffic:** GA MXC configures proxies for HTTP/S traffic only. On Windows, only clients that use the WinHTTP stack or correctly query the platform proxy configuration are proxied. Many libraries on all 3 platforms (Windows/Linux/macOS) use proxy environment variables as their configuration mechanism. On Linux and macOS these are the standard way to apply proxy configurations; however, it is advisory only and not a full RFC standard. As far as MXC is concerned, libraries/apps that honor them will use the proxy, while libraries/apps that ignore them will not have their traffic directed to the proxy and but instead have their egress blocked.
