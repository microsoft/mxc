# Linux Backend Roadmap — June 2026

Forward-looking work items for the three Linux-side containment backends: **LXC**, **Bubblewrap**, and **WSLC**.

Each item is prioritized within its backend and tagged with an effort tier.

**Effort tiers:**

- **S** — small, hours to a day (single-file fix, doc update)
- **M** — medium, days to a week (one feature surface with tests)
- **L** — large, multi-week (new subsystem, schema changes, cross-crate refactor)

**Filesystem policy reference:** items tagged with **(D1)**–**(D8)** trace to the [MXC FS-policy semantics v1](https://github.com/microsoft/mxc/blob/user/gudge/downlevel-fs-projection-plan/docs/proposals/downlevel_support/policy_semantics_v1_summary.md) decisions. Items shared across backends note where the implementation lives (typically `wxc_common`).

**Network policy reference:** items tagged with **(N1)**–**(N8)** trace to the [MXC Network Configuration GA spec](https://microsoft-my.sharepoint-df.com/:w:/p/bbonaby/cQpR4CPfeKqgSLuQGG_a9QA2EgUCrPdXr5J7b-jWip1_VeYFUA) design decisions. The GA schema replaces the current `allowedHosts`/`blockedHosts`/`defaultPolicy` format:

```json
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{ "to": [{ "cidr": "140.82.112.0/20" }], "ports": [{ "protocol": "tcp", "port": 443 }] }],
      "deny": [{ "to": [{ "cidr": "10.0.0.0/8" }] }]
    },
    "ingress": { "hostLoopback": "deny" },
    "proxy": { "http": "127.0.0.1:8080" }
  }
}
```

**Naming:** the backend is "Bubblewrap" (used in headers and proper nouns like the `BubblewrapConfig` type or `Container-Bubblewrap` label); **Bwrap** is used as the short reference in tables and cross-cutting themes.

File:line citations reference paths under `src/backends/<backend>/...` and `src/core/...`.

---

## 🐧 LXC

### Filesystem

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 1 | **(D1) Default-deny** | ✅ Addressed | Unlisted host paths are inaccessible inside the LXC container (rootfs isolation). No gap. | — |
| 2 | **(D8) Subtree-implicit** | ✅ Addressed | A directory bind-mount exposes the full subtree. No gap. | — |
| 3 | **(D7) Implicit traversal** | ✅ Addressed | Container rootfs has a full directory tree; ancestors of a mounted path are always resolvable. No gap. | — |
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | No path-specificity engine. Mount ordering determines behavior, not longest-prefix match. Shared path-tree resolver needed in `wxc_common`. | M |

> **Example (D4).** Policy: `RW /workspace`, `RO /workspace/.git`, `D /workspace/.env`. The spec says writes to `.git/config` are denied (inner RO wins) and reads of `.env` are denied (inner D wins). Today LXC applies three independent `lxc.mount.entry` lines — the result depends on which mount comes last, not specificity.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 5 | **(D6) Object-based policy — validation** | 🟡 Actionable | Same object reachable via multiple paths (bind mounts, symlinks) should be detected as a conflict. Add `stat()` + `(st_dev, st_ino)` comparison at config time in `wxc_common`. | S |

> **Example (D6).** If `/data` is a bind mount of `/mnt/storage/data` and the policy says `RW /mnt/storage/data`, `D /data`, the agent can access the same files through the RW path — bypassing the deny. The validator should reject this as a conflict.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 6 | **(D3) Delegation check** | 🟡 Actionable | Policy grants should be bounded by the invoking user's access. Add `access_check()` in `wxc_common` that verifies the user can read/write each listed path before accepting the config. | M |

> **Example (D3).** User "alice" has no read access to `/root/secrets`. Policy: `{ readonlyPaths: ["/root/secrets"] }`. Today: accepted silently. If the container runs as root, the mount succeeds and the agent reads the secrets. Spec: validator rejects at load time.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 7 | **Same-path conflict detection** | 🟡 Actionable | Same path appearing in both `readwritePaths` and `deniedPaths` (or `readonlyPaths`) is silently accepted. Shared check in `wxc_common` should normalize via most-restrictive-wins (`deny` > `readonly` > `readwrite`). | S |
| 8 | **Paths must exist at policy-load time** | 🟡 Actionable | No existence check today. Non-existent paths cause opaque failures at container start. Add `path_exists()` check at config parse time in `wxc_common`. | S |
| 9 | **Denied-path masking is heuristic** | 🟡 Actionable | `is_file()` probes the rootfs to choose `/dev/null` (file) vs `tmpfs` (dir) masking. Suffers TOCTOU, symlink-follow, missing-path ambiguity, silent error swallowing. `filesystem_mounts.rs:74-97`. | M |

> **Example (item 9).** Policy: `deniedPaths: ["/etc/shadow"]`. If `/etc/shadow` doesn't exist in the rootfs yet, `is_file()` returns `false` → mounts a tmpfs **directory** where a file should be. If it's a symlink, `is_file()` follows the link and masks the target, not the link itself. **Fix:** add `type: "file" | "dir"` discriminator to schema; harden fallback with `symlink_metadata()`.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 10 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | Spec says denied paths remain visible in parent listings but operations fail. LXC mounts `/dev/null` or `tmpfs` over denied paths, which **hides** them entirely. Linux mount namespaces have no mechanism to show a path but deny all operations on it. | — |
| 11 | **(D6) Object-based policy — enforcement** | ⛔ Non-actionable | Even with validation, Linux mount namespaces are path-based. Denying access via one path doesn't affect access via another path to the same inode. Full enforcement would require LSM or eBPF. | — |
| 12 | **Rename across regions** | ⛔ Non-actionable | Spec says `rename()` from a denied region should fail with ACCESS_DENIED. Linux returns EXDEV (cross-device) for cross-mount renames, which prevents the operation but with a different error code. The copy+delete fallback path can leak access. | — |

### Network

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 13 | **(N1) Default-deny outbound** | 🟡 Actionable | Already in place: iptables FORWARD hook with default DROP when firewall mode + veth detected. New work: ensure hook is always applied; fail-fast if veth not found rather than silently skipping. | M |
| 14 | **(N2) Inbound control (`hostLoopback`)** | 🟡 Actionable | `allowLocalNetwork` is parsed but silently ignored. New work: add iptables FORWARD rules on the container veth — DROP new inbound by default; ACCEPT from host loopback when `ingress.hostLoopback: "allow"`. | M |

> **Example (N2).** An MCP server listens on port 3000 inside the sandbox. With `ingress.hostLoopback: "deny"` (default), the host cannot reach it. With `"allow"`, the host can connect via `127.0.0.1:3000`. Today: no enforcement — inbound is uncontrolled.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 15 | **(N3) IP/CIDR only, no DNS names** | 🟡 Actionable | Accepts hostnames, resolves to IPv4 only. IPv6 silently dropped — dual-stack bypass. No CIDR range support. New GA schema (`egress.allow[]/deny[]` with CIDR+port+protocol) replaces `allowedHosts`/`blockedHosts`. | L |

> **Example (N3).** Today: `allowedHosts: ["api.github.com"]` resolves once to `140.82.112.4`. On a dual-stack host, IPv6 `2606:50c0:8000::64` passes unfiltered. GA: `egress.allow: [{ to: [{ cidr: "140.82.112.0/20" }], ports: [{ protocol: "tcp", port: 443 }] }]` — deterministic, auditable, covers the subnet.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 16 | **(N4) Deny-wins precedence** | 🟡 Actionable | Already in place: iptables chain with allow/deny rules. New work: ensure deny rules inserted before allow rules for explicit block-precedence. | S |
| 17 | **(N5) Proxy — env vars + enforcement** | 🟡 Actionable | Schema field exists, backend ignores it. Fix: inject `HTTP_PROXY`/`HTTPS_PROXY`, clear all inherited proxy vars, and restrict egress to proxy port only via iptables. | M |

> **Example (N5).** Consumer starts proxy on `127.0.0.1:8080`. MXC sets `HTTP_PROXY=127.0.0.1:8080` inside the container and applies `iptables -A OUTPUT -d 127.0.0.1 --dport 8080 -j ACCEPT` + default DROP. An app ignoring the env var tries `connect(140.82.112.4:443)` → dropped.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 18 | **(N7) Schema migration** | 🟡 Actionable | Current schema (`allowedHosts`/`blockedHosts`/`defaultPolicy`) → GA schema (`egress.allow[]/deny[]`, `ingress.hostLoopback`, `proxy.http`). Shared parser + SDK types. | L |
| 19 | **IPv6 + CIDR parsing** | 🟡 Actionable | `NetworkIptablesManager` resolves hostnames to IPv4 only. Add proper CIDR parsing + `ip6tables` for IPv6. | M |
| 20 | **Port filtering** | 🟡 Actionable | Not implemented. iptables `--dport` natively supported. | S |
| 21 | **Protocol filtering** | 🟡 Actionable | Not implemented. iptables `-p tcp/udp/icmp` natively supported. | S |
| 22 | **Proxy env-var hygiene** | 🟡 Actionable | Clear ALL proxy vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY` + lowercase), then set only configured proxy. | S |
| 23 | **Hostname re-resolution** | 🟡 Actionable | DNS resolved once at policy install time; subsequent changes bypass the firewall. Periodic refresh needed. `network_iptables.rs:84-96`. *(see [Ext-Dep E8](#external-dependencies))* | M |
| 24 | **nftables backend** | ⏳ Deferred | GA spec lists `iptables/nftables` as valid enforcement. Today MXC uses `iptables` commands, which work on all target distros via the `iptables-nft` compatibility shim. Native `nft` command support becomes necessary when distros drop the iptables shim (Fedora 41+, RHEL 10). Not a GA blocker. | M |

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 25 | **(N6) Per-sandbox scoping** | ✅ Addressed | Each LXC container has its own network namespace. No gap. | — |
| 26 | **(N8) Delegation** | ⛔ Non-actionable | No portable way on Linux to verify at config time whether the invoking user can reach a given IP/CIDR. Can validate CIDRs are routable (routing table check) but cannot guarantee user-specific access. Platform limitation. | M |

### Misc

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 27 | **State-aware lifecycle** | 🟡 Actionable | Implement `StatefulSandboxBackend` (provision/start/exec/stop/deprovision). | L |
| 28 | **Expand `LxcConfig` + resource limits (cgroups v2)** | 🟡 Actionable | Add per-backend config surface and cgroups v2 enforcement. Schema + enforcement ship together. *(see [Ext-Dep E7](#external-dependencies))* | L |

> **More context for item #28.** LXC's per-backend config block exposes only 2 fields (`distribution`, `release`) vs WSLC's 8. Shared cgroups controller code would also serve Bubblewrap.

| # | Item | Description | Effort |
|---|---|---|---|
| 29 | **Structured denied-resource diagnostics** | Process Container surfaces structured denial reasons; LXC returns opaque "execution failed" strings — wire equivalent telemetry. | M |
| 30 | **Doc drift cleanup** | `docs/lxc-support/lxc-backend.md:38-49,102-103` references `containerName` and `removeRulesOnExit` fields that don't exist in code. | S |
| 31 | **Un-gate LXC network tests in CI** | Done for GHA (PR `user/sodas/lxc-ci-enablement`). `MXC_SKIP_LXC_NETWORK_TESTS=1` kept on both GHA and ADO. ADO egress blocks `lxcbr0` NAT'd traffic. *(see [Ext-Dep E1](#external-dependencies))* | M |

---

## 🫧 Bubblewrap

### Filesystem

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 1 | **(D1) Default-deny** | ✅ Addressed | No `--bind` = no access. Bwrap namespace isolation enforces default-deny. | — |
| 2 | **(D8) Subtree-implicit** | ✅ Addressed | `--bind` mounts the full subtree. No gap. | — |
| 3 | **(D7) Implicit traversal** | 🟡 Actionable | If policy lists `RW /home/user/project/src` but `/home/user/project` isn't bound, the path doesn't exist inside the namespace. User must manually list ancestor dirs today. | S |

> **Example (D7).** Policy: `readwritePaths: ["/home/user/project/src"]`. Today `bwrap` fails because `/home/user/project` doesn't exist. Fix: auto-add `--dir` entries for ancestor paths (empty dirs, not host content — avoids the security risk of exposing `/home`).

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | Bwrap processes `--bind`, `--ro-bind`, `--tmpfs` left-to-right. Last matching arg wins, not longest-prefix. Shared path-tree resolver needed in `wxc_common`. | M |
| 5 | **(D6) Object-based — validation** | 🟡 Actionable | Same as LXC — `stat()` + inode comparison in `wxc_common`. | S |
| 6 | **(D3) Delegation check** | 🟡 Actionable | Same as LXC — shared `access_check()` in `wxc_common`. | M |
| 7 | **Same-path conflict detection** | 🟡 Actionable | Same as LXC — shared most-restrictive-wins normalization in `wxc_common`. | S |
| 8 | **Paths must exist at policy-load time** | 🟡 Actionable | Non-existent `--bind` paths fail at runtime with unclear errors. Shared `path_exists()` in `wxc_common`. | S |
| 9 | **Denied-path file masking** | 🟡 Actionable | `--tmpfs` always treats the path as a directory. A denied *file* gets a tmpfs directory mounted over it (wrong type). Fix: use `--ro-bind /dev/null <path>` for files. | S |

> **Example (item 9).** Policy: `deniedPaths: ["/etc/shadow"]`. Today: `--tmpfs /etc/shadow` creates a directory at `/etc/shadow` — wrong. Fix: detect file vs dir (or accept `type` from schema) and use `--ro-bind /dev/null /etc/shadow` for files.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 10 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | `--tmpfs` replaces the directory entirely — original is hidden. Same Linux mount-namespace limitation as LXC. | — |
| 11 | **(D6) Object-based — enforcement** | ⛔ Non-actionable | Path-based mount namespace. Same limitation as LXC. | — |
| 12 | **Rename across regions** | ⛔ Non-actionable | Same as LXC — Linux returns EXDEV, not ACCESS_DENIED. | — |

### Network

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 13 | **(N1) Default-deny outbound** | 🟡 Actionable | Already in place: `--unshare-net` provides full cutoff when no proxy/rules. New work: with proxy active (currently shares host netns), switch to `--unshare-net` + route proxy into the namespace (slirp4netns or veth pair). Elevation required. | M |
| 14 | **(N2) Inbound control (`hostLoopback`)** | 🟡 Actionable | Already in place: `--unshare-net` inherently blocks inbound (no route). New work: when proxy mode is active (no `--unshare-net`), add host-side iptables INPUT rules. | M |
| 15 | **(N3) IP/CIDR only, no DNS names** | 🟡 Actionable | Delegates to LXC's `NetworkIptablesManager` — same IPv4-only hostname resolution, same dual-stack bypass. New GA schema needed. | L |

> **Example (N3).** Same IPv6 bypass as LXC: `allowedHosts: ["api.github.com"]` only blocks IPv4; IPv6 traffic passes unfiltered on dual-stack GHA runners (confirmed by probe).

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 16 | **(N4) Deny-wins precedence** | 🟡 Actionable | Already in place: iptables chain with rules. New work: same as LXC — insert deny before allow. | S |
| 17 | **(N5) Proxy — env vars + enforcement** | 🟡 Actionable | Already in place: HTTP_PROXY/HTTPS_PROXY env-var injection. New work: restrict egress to proxy port only — requires `--unshare-net` + route proxy into namespace (current shared-netns approach is advisory only). | M |

> **Example (N5).** Today: Bwrap sets `HTTP_PROXY=127.0.0.1:8080` but a rogue app doing `connect(1.2.3.4:443)` succeeds because it's on the host netns with no iptables. GA: that connection is dropped.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 18 | **(N7) Schema migration** | 🟡 Actionable | Same as LXC — shared parser + SDK types. | L |
| 19 | **IPv6 + CIDR parsing** | 🟡 Actionable | Same as LXC — update shared `NetworkIptablesManager`. | M |
| 20 | **Port filtering** | 🟡 Actionable | iptables `--dport` natively supported. | S |
| 21 | **Protocol filtering** | 🟡 Actionable | iptables `-p tcp/udp/icmp` natively supported. | S |
| 22 | **Proxy env-var hygiene** | 🟡 Actionable | Already in place: strips some inherited proxy vars. New work: clear ALL variants (`ALL_PROXY`, `FTP_PROXY`, `NO_PROXY` + lowercase). | S |
| 23 | **Elevation / privileged broker** | 🟡 Actionable | Already in place: CI uses `sudo -E` (root). New work: production deployment needs a privileged broker design for iptables. Platform supports it; question is architecture. | L |

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 24 | **(N6) Per-sandbox scoping** | ✅ Addressed | Each Bwrap sandbox has its own network namespace (when `--unshare-net` is used) or process identity. No gap. | — |
| 25 | **(N8) Delegation** | ⛔ Non-actionable | Same Linux platform limitation as LXC — no portable network access check at config time. | M |

### Misc

| # | Item | Description | Effort |
|---|---|---|---|
| 26 | **Add backend-specific `BubblewrapConfig`** | No per-backend config block today (every other backend has one). Needed for seccomp, cgroups, custom binds. `schemas/dev/mxc-config.schema.0.8.0-dev.json` — Bwrap has no entry at `lxc:` (line 324) / `wslc:` (line 373) equivalent. | M |

> **More context for item #26.** Table-stakes infrastructure for seccomp (#27), cgroups (#28), and promote-to-stable (#29). Same shape as `LxcConfig` expansion: schema entry, `RawBubblewrap` in `config_parser.rs`, validated `BubblewrapConfig` in `models.rs`, plumbing through `bwrap_command.rs`, SDK type — ~10-15 file PR.

| # | Item | Description | Effort |
|---|---|---|---|
| 27 | **Seccomp profile support** | No syscall filtering today. Adding a default-deny profile would close attack surface meaningfully. *(see [Ext-Dep E5](#external-dependencies))* | L |

> **More context for item #27.** Bwrap's isolation comes from namespaces only — no seccomp. Docker/Podman/Flatpak all enable seccomp by default (~40+ blocked syscalls). MXC exposes the full ~400-syscall surface including `io_uring_setup`, `keyctl`, `bpf`, `userfaultfd`.

| # | Item | Description | Effort |
|---|---|---|---|
| 28 | **Resource limits (cgroups v2)** | No CPU / memory / PID / IO governance. Same gap as LXC. *(see [Ext-Dep E7](#external-dependencies))* | L |
| 29 | **Promote bubblewrap from `experimental` → stable in 0.8.0-dev** | Move config under the stable surface per `docs/versioning.md:91-93,182-203`. | L |
| 30 | **State-aware lifecycle** | Implement `StatefulSandboxBackend` for bwrap. | L |
| 31 | **Update plan doc** | `docs/bwrap-support/bubblewrap-backend-plan.md:42-60,295-324` still describes core implementation as "planned" even though it's shipped. | M |
| 32 | **Structured per-host network decision trace** | Surface why each connection attempt was allowed/denied. | M |
| 33 | **Structured denied-resource diagnostics** | Parity with Process Container's structured denial reporting. | M |
| 34 | **CI job for `tests/scripts/run_bwrap_all_tests.sh`** | Bwrap E2E suite is manual-only today. *(see [Ext-Dep E3](#external-dependencies))* | M |
| 35 | **Add `Container-Bubblewrap` label** | Parity with `Container-WSLC`, `Container-Hyperlight`. *(see [Ext-Dep E4](#external-dependencies))* | S |

---

## 🪟🐧 WSLC

### Filesystem

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 1 | **(D1) Default-deny** | ✅ Addressed | Unmounted host paths are invisible inside the WSL container. No gap. | — |
| 2 | **(D8) Subtree-implicit** | ✅ Addressed | Volume mounts expose the full subtree. No gap. | — |
| 3 | **(D7) Implicit traversal** | ✅ Addressed | WSL distro has a full directory tree; `/mnt/<drive>/` ancestors exist naturally. | — |
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | Flat volume-mount list with no nesting awareness. Shared path-tree resolver needed in `wxc_common`. | M |

> **Example (D4).** Policy: `RW C:\project`, `RO C:\project\.git`. WSLC generates two independent volume mounts. Whether the RO mount of `.git` actually restricts writes through the parent RW mount is undefined by the WSLC SDK — likely the parent RW mount wins and `.git` remains writable.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 5 | **`deniedPaths` overlap validation** | 🟡 Actionable | At parse time, reject configs where a `deniedPaths` entry is a child of a mounted path (since the WSLC SDK cannot enforce the deny). Accept non-overlapping denied paths as implicitly enforced (unmounted = invisible). This is a workaround; *masking* a denied subtree under a mounted parent needs an SDK exclusion primitive (see [WSLC SDK dep #4](#wslc-sdk-dependencies)). | S |

> **Example (item 5).** Policy: `readwritePaths: ["C:\\project"]`, `deniedPaths: ["C:\\project\\secrets"]`. Today: `deniedPaths` silently ignored; `secrets` is fully accessible through the parent mount. Fix: reject at config time with "denied path is a child of a mounted path; WSLC cannot enforce this."

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 6 | **(D6) Object-based — validation** | 🟡 Actionable | Same as LXC/Bwrap — `stat()` + inode comparison in `wxc_common`. | S |
| 7 | **(D3) Delegation check** | 🟡 Actionable | Same as LXC/Bwrap — shared `access_check()` in `wxc_common`. | M |
| 8 | **Same-path conflict detection** | 🟡 Actionable | Same as LXC/Bwrap — shared most-restrictive-wins normalization in `wxc_common`. | S |
| 9 | **Paths must exist at policy-load time** | 🟡 Actionable | Same as LXC/Bwrap — shared `path_exists()` in `wxc_common`. | S |
| 10 | **Explicit `{ windowsPath, containerPath }` mount control** | 🟡 Actionable | Host paths always mounted at `/mnt/<drive>/`; let users specify the in-container mount point. `policy_mapping.rs:23-60`. | M |
| 11 | **Handle UNC / non-drive paths** | 🟡 Actionable | UNC paths (`\\server\share`) silently dropped with a warning; plan is to hard-error. Branch `user/sodas/wslc-reject-unc-paths`. | S |
| 12 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | Same Linux mount-namespace limitation as LXC/Bwrap — overlaying a path hides it entirely. WSLC runs on the same Linux kernel; a deny-mount API from the SDK would still produce hidden (not ACCESS_DENIED) semantics. | — |
| 13 | **(D6) Object-based — enforcement** | ⛔ Non-actionable | WSLC SDK is path-based. Same limitation as Linux backends. | — |
| 14 | **Rename across regions** | ⛔ Non-actionable | WSL uses Linux VFS — returns EXDEV, not ACCESS_DENIED. Same as LXC/Bwrap. | — |

### Network

> **WSLC SDK dependency:** Items marked "🟠 With SDK dep" require the WSLC SDK team to expose a **VM-level network policy API** — extending CreateSession to accept IP/CIDR allow/deny rules, port/protocol filters, and inbound control, enforced at the VM hosting the container. This eliminates the need for `CAP_NET_ADMIN` inside the container. *(see [WSLC SDK dep #1](#wslc-sdk-dependencies))*

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 15 | **(N1) Default-deny outbound** | 🟠 With SDK dep | Only all-or-nothing today (`NetworkingMode::None` vs `Bridged`). VM-level network policy API would provide default DROP. | M |
| 16 | **(N2) Inbound control (`hostLoopback`)** | 🟠 With SDK dep | No inbound filtering primitive. VM-level API would provide inbound control. | M |
| 17 | **(N3) IP/CIDR allow/deny rules** | 🟠 With SDK dep | Currently builds iptables rules inside container (requires `CAP_NET_ADMIN` which isn't granted). VM-level API would accept CIDR rules directly. | M |

> **Example (N3).** Today WSLC tries to run `iptables -A OUTPUT -d 140.82.112.0/20 -j ACCEPT` inside the container after start, but this fails silently because `WslcContainerFlags::Privileged` doesn't grant `CAP_NET_ADMIN`. With the VM-level API, MXC passes the rule set at CreateSession time and the VM host enforces it.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 18 | **(N4) Deny-wins precedence** | 🟠 With SDK dep | VM-level API would enforce deny-wins ordering. | S |
| 19 | **(N5) Proxy — env-var injection** | 🟡 Actionable NOW | Set `HTTP_PROXY`/`HTTPS_PROXY` via `WslcCreateContainerProcess` env parameter. No SDK dependency. | S |
| 20 | **(N5) Proxy — egress enforcement** | 🟠 With SDK dep | Restricting egress to proxy port only requires VM-level network policy API. Without it, proxy is advisory (apps can bypass env vars and connect directly). | M |
| 21 | **(N7) Schema migration** | 🟡 Actionable NOW | Same parser + SDK types as LXC/Bwrap. No SDK dependency for schema/parser work. | L |
| 22 | **IPv6 + CIDR parsing** | 🟠 With SDK dep | Same dual-stack bypass as LXC/Bwrap. VM-level API would accept IPv4 and IPv6 CIDRs. | M |
| 23 | **Port filtering** | 🟠 With SDK dep | VM-level API would accept port/port-range rules. | S |
| 24 | **Protocol filtering** | 🟠 With SDK dep | VM-level API would accept protocol specifiers. | S |
| 25 | **Proxy env-var hygiene** | 🟡 Actionable NOW | Clear all proxy vars, set only configured proxy. No SDK dependency — env manipulation at process spawn. | S |

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 26 | **(N6) Per-sandbox scoping** | ✅ Addressed | Each WSLC container is a separate instance. No gap. | — |
| 27 | **(N8) Delegation** | ⛔ Non-actionable | Same Linux platform limitation as LXC/Bwrap — WSL runs on the Linux kernel with the same routing constraints. No portable network access check at config time. | M |

### Misc

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 28 | **Finish & merge port-mapping support** | 🟡 In progress | Branch `user/sodas/wslc-port-mapping`. | M |
| 29 | **State-aware lifecycle** | 🟡 Actionable | Implement `StatefulSandboxBackend`. WSLC bears the largest startup cost — session reuse is the highest-value win. | L |
| 30 | **Structured denied-resource diagnostics** | 🟡 Actionable | Parity with Process Container's structured denial reporting. | M |
| 31 | **Un-gate WSLC tests in CI** | ⛔ Blocked | Needs `wslcsdk.dll` public NuGet (see SDK dep #2 above). | M |

### WSLC SDK Dependencies

These items depend on the WSLC SDK team and are not unilaterally schedulable.

| # | Dependency | Affects | Description |
|---|---|---|---|
| 1 | **VM-level network policy API** | Network #15–#24 | Extend CreateSession to accept IP/CIDR allow/deny rules, port/protocol filters, and inbound control, enforced at the VM hosting the container. Unblocks all iptables-dependent network enforcement on WSLC. |
| 2 | **Deterministic `wslcsdk.dll` distribution** | Misc #31 (CI), Misc build | Today MXC pulls from `external/wslc-sdk/` which isn't reproducible from a fresh clone. Need a public NuGet or vendored signed channel. |
| 3 | **Registry-auth handshake** | Private registry auth | WSLC can only pull from public registries. SDK ABI reserves the `auth_info` slot but the implementation (Basic/Bearer/ACR/GHCR/ECR, token caching, custom-CA HTTPS) isn't shipped yet. |
| 4 | **Deny-mount / path-exclusion primitive** | Filesystem #5 (`deniedPaths` enforcement) | LXC and Bubblewrap mask a `deniedPaths` entry that sits under a mounted parent by overlaying it (`/dev/null` or `tmpfs`). The WSLC SDK exposes only a flat volume-mount surface with no overlay/exclusion primitive, so a denied subtree under a mounted parent cannot be masked. Today MXC works around this by rejecting such configs at parse time (Filesystem #5); real enforcement needs an SDK exclusion primitive. (Note: this is the *basic subtree-deny* gap — spec-exact D5 "visible + ACCESS_DENIED" remains non-actionable on every Linux backend regardless, see Filesystem #12.) |

---

## Cross-cutting themes

These show up on multiple backends and are worth coordinating to avoid divergent designs:

1. **Filesystem policy alignment** — D4 (path-tree resolver), D3 (delegation check), D6 (object validation), same-path conflict (most-restrictive-wins), paths-should-exist warning all belong in `wxc_common` and serve all three backends.
2. **Network policy alignment** — N1 (default-deny), N2 (inbound), N3 (CIDR-only schema), N5 (proxy enforcement), N7 (schema migration). Shared `NetworkIptablesManager` in `wxc_common` serves LXC and Bwrap; WSLC depends on SDK VM-level API.
3. **State-aware lifecycle** — LXC #27, Bwrap #30, WSLC #29. None of the three implement `StatefulSandboxBackend` today. WSLC has the largest payoff (slowest cold start).
4. **Resource limits (cgroups v2)** — LXC #28, Bwrap #28. Same kernel API; build a shared `cgroup_controller` crate.
5. **Structured denied-resource diagnostics** — LXC #29, Bwrap #33, WSLC #30. Replicate Process Container's structured denial reporting on Linux.
6. **CI gating** — LXC #31, Bwrap #34, WSLC #31.
7. **Denied-path type discriminator** — LXC #9, Bwrap #9. Add `type: "file" | "dir"` to `deniedPaths` schema entries so backends don't have to guess.

---

## External dependencies

These items have dependencies outside the MXC repo (non-WSLC-SDK — those are listed under WSLC above).

### 🏗️ Infra & pipeline (needs build-agent or repo changes outside the source tree)

| Ref | Affected | External owner | Description |
|---|---|---|---|
| **E1** | LXC #31 | 1ES / pipeline agents | **Updated 2026-06-15 after on-runner probe** — GH-hosted `ubuntu-latest` (24.04), `ubuntu-22.04`, and `ubuntu-24.04-arm` runners all install the LXC stack cleanly, successfully create + run containers, start `lxc-net.service`, and accept full `iptables` under `sudo`. **Addendum (ADO probe)** — 1ES Hosted Pool probe confirmed LXC core works but outbound from `lxcbr0` is blocked by pool egress. Conclusion: `MXC_SKIP_LXC_NETWORK_TESTS=1` on ADO; GHA covers the network half, ADO covers core. |
| **E2** | WSLC #31 | 1ES / pipeline agents | **Updated 2026-06-15** — GH-hosted `windows-latest` / `windows-2025` support WSL2 (zero-to-shell ~28–33 s). ARM64 not capable. Only remaining gate is `wslcsdk.dll` distribution (WSLC SDK dep #2). |
| **E3** | Bwrap #34 | 1ES / pipeline agents | **Updated 2026-06-15** — Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns=1` breaks unprivileged bwrap. Workaround: run under `sudo -E` (current posture). Every GHA Linux runner is IPv6 dual-stack, confirming Bwrap Network #15 IPv6 bypass is a real exposure. |
| **E4** | Bwrap #35 | Repo admin | Create `Container-Bubblewrap` label (parity with `Container-WSLC`, `Container-Hyperlight`). |

### ⚠️ Upstream / kernel-evolution tracking

| Ref | Affected | What to track |
|---|---|---|
| **E5** | Bwrap #27 | Linux kernel keeps adding syscalls (`io_uring_*`, `clone3`, `pidfd_*`, `landlock_*`); seccomp profile needs refresh cadence. |
| **E6** | Bwrap Network #13 (eBPF option) | eBPF / CO-RE requires kernel ≥5.x with BTF. Other enforcement strategies have no such constraint. |
| **E7** | LXC #28, Bwrap #28 | cgroups v2 unified hierarchy — default on modern distros but Ubuntu < 22.04 / RHEL < 9 may still mount v1. |
| **E8** | LXC Network #23 | System resolver semantics (`systemd-resolved` / `nscd` / DNS TTL) constrain hostname re-resolution frequency. |

### ⏳ Deferred pending external user demand

Item **LXC Network #24** (nftables backend) is gated on a real user signal — see its inline note for deferral criteria.

---

## Notes

- **Issue tracking**: [open issues](https://github.com/microsoft/mxc/issues?q=is%3Aissue+is%3Aopen). None of the above are filed yet.
- **Promotion path**: Bubblewrap and WSLC are both still under `experimental` in the schema; see `docs/versioning.md` for the migration mechanics required for each promotion.
- **Labels**: re-use `Container-WSLC` and `Area-Executor-LXC`; propose adding `Container-Bubblewrap` (Bwrap #35).
