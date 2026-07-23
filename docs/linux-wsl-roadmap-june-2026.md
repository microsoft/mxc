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
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | No path-specificity engine — mount ordering determines behavior, not longest-prefix match. The shared path-tree resolver now exists in `wxc_common` (`filesystem_resolve.rs`, [PR #608](https://github.com/microsoft/mxc/pull/608)); LXC needs to consume it. | M |

> **Example (D4).** Policy: `RW /workspace`, `RO /workspace/.git`, `D /workspace/.env`. The spec says writes to `.git/config` are denied (inner RO wins) and reads of `.env` are denied (inner D wins). Today LXC applies three independent `lxc.mount.entry` lines — the result depends on which mount comes last, not specificity.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 5 | **(D6) Object-based policy — validation** | ✅ Addressed | Same object reached via multiple paths (bind mount, symlink, hard link) is detected by `(st_dev, st_ino)` comparison. Aliases carrying conflicting intents are tightened to the most-restrictive intent (deny > ro > rw), not rejected. An unresolvable path (permission denied / dead mount, not cleanly missing) with `deniedPaths` present fails closed (config rejected). Runs at the runner, enforcement-adjacent, in `wxc_common`. Done in [PR #593](https://github.com/microsoft/mxc/pull/593). | S |

> **Example (D6).** If `/data` is a bind mount of `/mnt/storage/data` and the policy says `RW /mnt/storage/data`, `D /data`, the agent could reach the same files through the RW path — bypassing the deny. MXC detects the shared object and tightens every alias to the most-restrictive intent (here: denied), closing the bypass.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 6 | **(D3) Delegation check** | ✅ Addressed | Policy grants are bounded by the invoking user's access: shared `check_delegation()` in `wxc_common` (`filesystem_access.rs`) verifies the user can read/write each listed path before accepting the config, wired into all three runners. Done in [PR #598](https://github.com/microsoft/mxc/pull/598). | M |

> **Example (D3).** User "alice" has no read access to `/root/secrets`. Policy: `{ readonlyPaths: ["/root/secrets"] }`. Today: accepted silently. If the container runs as root, the mount succeeds and the agent reads the secrets. Spec: validator rejects at load time.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 7 | **Same-path conflict detection** | ✅ Addressed | Same path appearing in both `readwritePaths` and `deniedPaths` (or `readonlyPaths`) is silently accepted. Shared check in `wxc_common` should normalize via most-restrictive-wins (`deny` > `readonly` > `readwrite`). Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
| 8 | **Paths must exist at policy-load time** | ✅ Addressed | No existence check today. Non-existent paths cause opaque failures at container start. Add `path_exists()` check at config parse time in `wxc_common`. Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
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
| 3 | **(D7) Implicit traversal** | ✅ Addressed | `bwrap` auto-creates the parent directories of every `--bind` / `--ro-bind` destination as empty dirs, so a listed path (e.g. `RW /home/user/project/src`) is reachable inside the namespace even when its ancestors aren't separately bound — and no host content is exposed. The base is already deny-by-default (a curated allowlist in `BASELINE_RO_BIND_PATHS`, **not** `--ro-bind /`), and this still holds. No gap. | — |

> **Note (D7).** Earlier drafts assumed the base was `--ro-bind / /` (ancestors present via the host root) and that a future default-deny base would break traversal. Both are stale: the base is now a curated deny-by-default allowlist (guarded by the `baseline_does_not_bind_mount_host_root` regression test), and `bwrap` creates each bind destination's parent dirs automatically — so `readwritePaths: ["/home/user/project/src"]` mounts correctly today without listing ancestors or exposing `/home`.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 4 | **(D4) Most-specific-path-wins** | ✅ Addressed | Longest-prefix (most-specific-path-wins) resolution via the shared `filesystem_resolve.rs` path-tree resolver in `wxc_common`, consumed by `bwrap_command.rs` instead of relying on left-to-right arg order. Done in [PR #608](https://github.com/microsoft/mxc/pull/608). | M |
| 5 | **(D6) Object-based — validation** | ✅ Addressed | Same as LXC — object-identity comparison (`FileIdInfo` on the Windows-hosted path side, `(st_dev, st_ino)` on Linux) with most-restrictive-wins tightening of aliases (deny > ro > rw), not rejection. Fail closed on an unresolvable path when `deniedPaths` present. In `wxc_common`. Done in [PR #593](https://github.com/microsoft/mxc/pull/593). | S |
| 6 | **(D3) Delegation check** | ✅ Addressed | Same as LXC — shared `check_delegation()` in `wxc_common`. Done in [PR #598](https://github.com/microsoft/mxc/pull/598). | M |
| 7 | **Same-path conflict detection** | ✅ Addressed | Same as LXC — shared most-restrictive-wins normalization in `wxc_common`. Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
| 8 | **Paths must exist at policy-load time** | ✅ Addressed | Non-existent `--bind` paths fail at runtime with unclear errors. Shared `path_exists()` in `wxc_common`. Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
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
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | Flat volume-mount list with no nesting awareness. The shared path-tree resolver now exists in `wxc_common` (`filesystem_resolve.rs`, [PR #608](https://github.com/microsoft/mxc/pull/608)); WSLC needs to consume it. | M |

> **Example (D4).** Policy: `RW C:\project`, `RO C:\project\.git`. WSLC generates two independent volume mounts. Whether the RO mount of `.git` actually restricts writes through the parent RW mount is undefined by the WSLC SDK — likely the parent RW mount wins and `.git` remains writable.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 5 | **`deniedPaths` overlap validation** | 🟡 Actionable | Today a `deniedPaths` entry that is a child of a mounted (`readwritePaths`/`readonlyPaths`) path is silently ignored, leaving it accessible through the parent mount. Planned: reject such configs at parse time (since the WSLC SDK cannot enforce the deny). Non-overlapping denied paths are already implicitly enforced (unmounted = invisible). This is a workaround; *masking* a denied subtree under a mounted parent needs an SDK exclusion primitive (see [WSLC SDK dep #4](#wslc-sdk-dependencies)). | S |

> **Example (item 5).** Policy: `readwritePaths: ["C:\\project"]`, `deniedPaths: ["C:\\project\\secrets"]`. Today: `deniedPaths` silently ignored; `secrets` is fully accessible through the parent mount. Fix: reject at config time with "denied path is a child of a mounted path; WSLC cannot enforce this."

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 6 | **(D6) Object-based — validation** | ✅ Addressed | Same as LXC/Bwrap — object-identity comparison with most-restrictive-wins tightening of aliases (deny > ro > rw), not rejection; fail closed on an unresolvable path when `deniedPaths` present. In `wxc_common`. Done in [PR #593](https://github.com/microsoft/mxc/pull/593). | S |
| 7 | **(D3) Delegation check** | ✅ Addressed | Same as LXC/Bwrap — shared `check_delegation()` in `wxc_common`. Done in [PR #598](https://github.com/microsoft/mxc/pull/598). | M |
| 8 | **Same-path conflict detection** | ✅ Addressed | Same as LXC/Bwrap — shared most-restrictive-wins normalization in `wxc_common`. Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
| 9 | **Paths must exist at policy-load time** | ✅ Addressed | Same as LXC/Bwrap — shared `path_exists()` in `wxc_common`. Done in [PR #551](https://github.com/microsoft/mxc/pull/551). | S |
| 10 | **Explicit `{ windowsPath, containerPath }` mount control** | 🟡 Actionable | Host paths always mounted at `/mnt/<drive>/`; let users specify the in-container mount point. `policy_mapping.rs:23-60`. | M |
| 11 | **Handle UNC / non-drive paths** | ✅ Addressed | UNC paths (`\\server\share`) now hard-error at parse time as of [PR #537](https://github.com/microsoft/mxc/pull/537) (merged 2026-06-18), instead of being silently dropped with a warning. | — |
| 12 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | Same Linux mount-namespace limitation as LXC/Bwrap — overlaying a path hides it entirely. WSLC runs on the same Linux kernel; a deny-mount API from the SDK would still produce hidden (not ACCESS_DENIED) semantics. | — |
| 13 | **(D6) Object-based — enforcement** | ⛔ Non-actionable | WSLC SDK is path-based. Same limitation as Linux backends. | — |
| 14 | **Rename across regions** | ⛔ Non-actionable | WSL uses Linux VFS — returns EXDEV, not ACCESS_DENIED. Same as LXC/Bwrap. | — |

### Network

> **WSLC SDK dependency:** Items marked "🟠 With SDK dep" require the WSLC SDK team to expose a **VM-level network policy API** — extending CreateSession to accept IP/CIDR allow/deny rules, port/protocol filters, and inbound control, enforced at the VM hosting the container. This eliminates the need for `CAP_NET_ADMIN` inside the container. *(see [WSLC SDK dep #1](#wslc-sdk-dependencies))*

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 15 | **(N1) Default-deny outbound** | 🟠 With SDK dep | Only all-or-nothing today (`NetworkingMode::None` vs `Bridged`). VM-level network policy API would provide default DROP. | M |

> **Example (N1).** The GA field is `egress.default`. WSLC's only enforcement primitive is the binary `NetworkingMode` (`None` vs `Bridged`), so the same `"default": "deny"` behaves in two very different ways depending on whether an allowlist is present.
>
> **✅ Supported today — full cutoff.** No `allow` rules → maps to `NetworkingMode::None` (`policy_mapping.rs:127-129`):
>
> ```json
> {
>   "network": {
>     "egress": { "default": "deny" }
>   }
> }
> ```
>
> The container gets no network interface, so all outbound is denied. Genuine default-deny — but the blunt form, with *zero* connectivity. Use when the workload needs no network at all.
>
> **⚠️ Needs to change — deny + allowlist.** An `allow` list → maps to `Bridged` (full NAT), then MXC tries to enforce the list with `iptables` exec'd *inside* the container (`build_iptables_rules`):
>
> ```json
> {
>   "network": {
>     "egress": {
>       "default": "deny",
>       "allow": [
>         { "to": [{ "cidr": "140.82.112.0/20" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
>       ]
>     }
>   }
> }
> ```
>
> Intended: reach **only** `140.82.112.0/20:443`. Actual: the in-container `iptables` calls fail silently because `WslcContainerFlags::Privileged` does **not** grant `CAP_NET_ADMIN`, leaving the container on full Bridged NAT with no firewall — it reaches the allowed host *and everything else*. Closing this needs the VM-level network policy API (SDK dep #1) to enforce default-DROP + allowlist at the VM host.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 16 | **(N2) Inbound control (`hostLoopback`)** | 🟠 With SDK dep | No inbound filtering primitive. VM-level API would provide inbound control. | M |

> **Example (N2).** N2 governs the inbound direction (host → sandbox): can the Windows host reach a service the container is listening on? GA field is `ingress.hostLoopback` (legacy: `allowLocalNetwork`).
>
> **✅ Supported today — explicit per-port forward.** The container runs in the NAT'd WSL2 VM, so by default the host can't reach arbitrary container ports (incidental default-deny). [PR #530](https://github.com/microsoft/mxc/pull/530) adds the per-port primitive via `WslcSetContainerSettingsPortMappings` (`wsl_container_runner.rs:975+`) — an explicit `hostLoopback: "allow"` for one TCP port:
>
> ```json
> {
>   "experimental": {
>     "wslc": {
>       "image": "python:3.12",
>       "portMappings": [
>         { "windowsPort": 3000, "containerPort": 3000, "protocol": "tcp" }
>       ]
>     }
>   }
> }
> ```
>
> This forwards host `127.0.0.1:3000` → container `:3000`. TCP only — UDP is rejected at parse time because the shipped runtime (Microsoft.WSL.Containers 2.8.1) returns `E_NOTIMPL`.
>
> **⚠️ Needs to change — policy-driven posture.** The `ingress.hostLoopback` / `allowLocalNetwork` policy field is parsed (`config_parser.rs:88-89,1095-1096`) but the WSLC runner never consults it — only the imperative `portMappings` list has any effect. There is no way to express a blanket `hostLoopback: "allow"` default (host-loopback to every exposed port) or source-scoped inbound filtering (allow `127.0.0.1`/`::1` only, deny other host interfaces). Wiring the policy field and enforcing a default inbound posture needs the VM-level network policy API (SDK dep #1), since MXC has no host-side access to the container's interface inside the VM.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 17 | **(N3) IP/CIDR allow/deny rules** | 🟠 With SDK dep | Currently builds iptables rules inside container (requires `CAP_NET_ADMIN` which isn't granted). VM-level API would accept CIDR rules directly. | M |

> **Example (N3).** N3 is the per-host egress filtering — *which* destinations are allowed/blocked. Target GA shape:
>
> ```json
> {
>   "network": {
>     "egress": {
>       "default": "deny",
>       "allow": [
>         { "to": [{ "cidr": "140.82.112.0/20" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
>       ]
>     }
>   }
> }
> ```
>
> **⚠️ Wired but non-functional today.** The enforcement path is fully plumbed on main: `needs_host_filtering` sets `WslcContainerFlags::Privileged` (`wsl_container_runner.rs:1091-1092`), `build_iptables_rules` generates an `OUTPUT` chain (ACCEPT loopback/established/DNS, ACCEPT each allowed host, default `-j DROP` — `policy_mapping.rs:194-212`), and after start `apply_iptables_rules` execs it inside the container via `WslcCreateContainerProcess` (`:1136-1142`). This does **not** work, because `Privileged` does not grant `CAP_NET_ADMIN` inside the container (confirmed with the WSLC SDK team), so `iptables -A` is rejected. Note this is **not a silent bypass**: `apply_iptables_rules` checks the exec exit code and hard-errors the entire run — `"iptables rules failed with exit code {} (image may not have iptables installed)"` (`:714`) — whether the image lacks iptables or `Privileged` lacks `NET_ADMIN`. The deny+allowlist config therefore **fails the run** rather than failing open.
>
> **✅ Needs the VM-level API.** Move enforcement off in-container iptables entirely. With the VM-level network policy API (SDK dep #1), MXC passes the rule set at `CreateSession` and the VM host enforces it — no container privilege, no image iptables dependency. Today's rules also match only a bare `-d <host>` (whole host, all ports/protocols); CIDR ranges, `--dport`, `-p tcp/udp/icmp`, and hostname rejection are the separate #22/#23/#24 rows, all on the same SDK dependency.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 18 | **(N4) Deny-wins precedence** | 🟠 With SDK dep | No `egress.deny[]` path today — the builder does allow-list XOR block-list, never both, so deny-wins ordering isn't expressed. VM-level API + N7 schema needed. | S |

> **Example (N4).** GA spec D4: when a connection matches both an `egress.allow` and an `egress.deny` rule, **the deny wins** (fail-closed). The canonical case is "allow everything except a few malicious IPs." Applies only in `mode: "direct"` (model 1) — `egress.allow`/`egress.deny` are rejected under `mode: "proxy"`.
>
> ```json
> {
>   "network": {
>     "egress": {
>       "mode": "direct",
>       "default": "allow",
>       "allow": [ { "to": [{ "cidr": "0.0.0.0/0" }] } ],
>       "deny":  [ { "to": [{ "cidr": "203.0.113.0/24" }] } ]
>     },
>     "ingress": { "hostLoopback": "deny" }
>   }
> }
> ```
>
> **❌ Not expressible today.** `build_iptables_rules` (`policy_mapping.rs:183-221`) handles only two shapes — `defaultPolicy: block` + `allowedHosts` (allow-list with trailing DROP) or `defaultPolicy: allow` + `blockedHosts` (block-list) — and **never combines** an allow-list and a deny-list in one chain. So the D4 scenario (broad allow + specific deny) has no representation: the allow side is simply ignored in the block-list branch, and there's no rule interleaving to give deny precedence. On top of that, whatever it does build doesn't enforce (in-container `iptables`, `Privileged` ≠ `CAP_NET_ADMIN` → the run hard-errors, same as N3).
>
> **✅ Needs the VM-level API + N7 schema.** Two changes: (1) model `egress.allow[]` and `egress.deny[]` together and guarantee deny-rules are evaluated before allows (the N7 migration plus a rule-ordering change), and (2) enforce at the VM host via the VM-level network policy API (SDK dep #1) rather than in-container iptables.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 19 | **(N5) Proxy — env-var injection** | 🟡 Actionable NOW | Set `HTTP_PROXY`/`HTTPS_PROXY` via `WslcCreateContainerProcess` env parameter. No SDK dependency. | S |
| 20 | **(N5) Proxy — egress enforcement** | 🟠 With SDK dep | Restricting egress to proxy port only requires VM-level network policy API. Without it, proxy is advisory (apps can bypass env vars and connect directly). | M |
| 25 | **(N5) Proxy — env-var hygiene** | 🟡 Actionable NOW | Clear all proxy vars, set only configured proxy. No SDK dependency — env manipulation at process spawn. | S |

> **Example (N5).** The proxy is the **recommended GA path** (model 2, "deny-all-except-proxy"). Per GA spec: MXC does **not** run the proxy — the consumer supplies a localhost proxy and starts it; MXC restricts egress to it and points env vars at it. Crucially, the env vars are an **advisory routing hint** — the iptables DROP is the actual enforcement; "cooperation-dependent routing… is never the enforcement mechanism itself." Under `mode: "proxy"`, `egress.allow`/`deny` are rejected.
>
> ```json
> {
>   "network": {
>     "egress": { "mode": "proxy" },
>     "proxy": { "http": "127.0.0.1:8080" },
>     "ingress": { "hostLoopback": "deny" }
>   }
> }
> ```
>
> `egress.mode: "proxy"` selects the posture; `network.proxy.http` supplies the endpoint MXC restricts egress to. The consumer must start that proxy listening before launching the workload. *(Note: the GA doc's minimal model-2 example shows only `egress.mode: "proxy"` and never defines where the host:port lives, though its text requires one "in the configuration" — the address field is carried by `network.proxy`, matching what MXC parses today.)*
>
> **❌ Not implemented today (but #19/#25 are unblocked).** WSLC has no proxy code at all. The env path exists — `request.env` is piped in via `WslcSetProcessSettingsEnvVariables` (`wsl_container_runner.rs:929-942`) — but nothing injects `HTTP_PROXY`/`HTTPS_PROXY` from the proxy config (#19), and the GA-mandated clearing of all inherited proxy vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY` + lowercase) isn't done (#25). Both are doable now through the existing env path — no SDK dependency — they're just unwritten.
>
> **❌ Enforcement blocked (#20).** The part that *matters* per the GA spec — the iptables rule that restricts egress to only the loopback proxy port and DROPs everything else — can't be done: same dead end as N1/N3 (in-container iptables, `Privileged` ≠ `CAP_NET_ADMIN`). Without it the proxy is **advisory only**, which the GA doc says is insufficient as the enforcement mechanism. Needs the VM-level network policy API (SDK dep #1).
>
> **⚠️ WSLC-specific wrinkle — NAT reachability.** Unlike Bubblewrap (which shares the host's network namespace, so the container's `127.0.0.1` *is* the host's), the WSLC container runs in the WSL2 VM — a separate kernel with its **own** loopback, behind a NAT. `127.0.0.1` is always machine-local and never routed, so `HTTP_PROXY=127.0.0.1:8080` points at the *container's own* empty loopback, not the host where the proxy listens. The connection fails — the proxy is unreachable, so model 2 is broken outright (not merely advisory). Fixing it means **not** using loopback: MXC must inject the host's VM-visible gateway IP (e.g. the address WSL puts in `/etc/resolv.conf`) instead, and the consumer's proxy must bind on a VM-reachable interface. This is the backend-specific "making the proxy reachable from inside the sandbox" the GA spec assigns to MXC, and it's a prerequisite for the env var (#19) to be of any use.
>
> **Net:** shipping #19 + #25 alone yields a *cooperative-only* proxy a rogue app bypasses; the GA-meaningful guarantee (unbypassable model 2) needs #20 (SDK-blocked) plus the NAT-reachability plumbing.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 21 | **(N7) Schema migration** | 🟡 Actionable NOW | Same parser + SDK types as LXC/Bwrap. No SDK dependency for schema/parser work. | L |

> **Example (N7).** N7 is the schema/parser/SDK work to accept the GA network block — *expressing* the policy, independent of whether a backend can *enforce* it. It's the same shared parser + SDK types as LXC/Bwrap, so no WSLC SDK dependency.
>
> **⚠️ Today — flat legacy schema only.** The parser accepts only `defaultPolicy`/`allowedHosts`/`blockedHosts` (`config_parser.rs:778-779`, flat string lists), mapped to `policy.allowed_hosts`/`blocked_hosts`. There is no `egress`/`ingress`/`proxy` structure, no `mode`, no per-rule `to[].cidr` + `ports[]`.
>
> **✅ GA target.** Parse the structured GA block (shared across all backends), with deprecation aliases from the legacy fields:
>
> ```json
> {
>   "network": {
>     "egress": {
>       "mode": "direct",
>       "default": "deny",
>       "allow": [
>         { "to": [{ "cidr": "140.82.112.0/20" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
>       ],
>       "deny": []
>     },
>     "ingress": { "hostLoopback": "deny" }
>   }
> }
> ```
>
> This is pure schema/parser/SDK work — landing it lets configs *express* CIDR/port/protocol intent. Whether WSLC can *enforce* that intent is the separate #22–#24 + VM-level API story below.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 22 | **IPv6 + CIDR parsing** | 🟠 With SDK dep | Same dual-stack bypass as LXC/Bwrap. VM-level API would accept IPv4 and IPv6 CIDRs. | M |
| 23 | **Port filtering** | 🟠 With SDK dep | VM-level API would accept port/port-range rules. | S |
| 24 | **Protocol filtering** | 🟠 With SDK dep | VM-level API would accept protocol specifiers. | S |

> **Example (#22–#24 — rule granularity).** These are three facets of one GA egress rule — *which* CIDR, *which* ports, *which* protocol — all on the same SDK dependency, because today's WSLC rule builder emits a bare `iptables -A OUTPUT -d <host> -j ACCEPT/DROP` (`policy_mapping.rs:204-219`): whole host, all ports, all protocols, IPv4 only. The GA rule below exercises all three:
>
> ```json
> {
>   "network": {
>     "egress": {
>       "default": "deny",
>       "allow": [
>         {
>           "to": [{ "cidr": "2606:50c0::/32" }],
>           "ports": [{ "protocol": "tcp", "port": 443, "endPort": 444 }]
>         }
>       ]
>     }
>   }
> }
> ```
>
> **#22 — IPv6 + CIDR.** WSLC's builder calls only `iptables` (the IPv4 tool); there is no `ip6tables`, so an IPv6 destination like `2606:50c0::/32` is never filtered — the classic dual-stack bypass (same gap LXC notes at `network_iptables.rs:88-92`). IPv4 CIDR strings (`140.82.112.0/20`) happen to pass through to `iptables -d`, but IPv6 needs a parallel `ip6tables` path. GA requires **IPv4 + IPv6** CIDRs.
>
> **#23 — Port.** The allow/deny rules carry no `--dport` — allowing a host opens it on *every* port. GA needs `ports[].port` and `ports[].endPort` (ranges) → `iptables --dport 443:444`.
>
> **#24 — Protocol.** The rules carry no `-p` — they match all transports, so a rule meant for TCP 443 also permits UDP/ICMP to that host. GA needs `ports[].protocol` (`tcp`/`udp`/`icmp`/`any`) → `iptables -p tcp`.
>
> **✅ All three need the VM-level API.** The schema to *express* them is N7 (#21, above); the granular `ip6tables`/`--dport`/`-p` *enforcement* still can't run in-container (`Privileged` ≠ `CAP_NET_ADMIN`, same dead end as N1/N3). The GA target — per the GA doc's WSLC section: IPv4+IPv6, port ranges, tcp/udp/icmp — is enforced at the VM host via the VM-level network policy API (SDK dep #1).


| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 26 | **(N6) Per-sandbox scoping** | ✅ Addressed | Each WSLC container is a separate instance. No gap. | — |
| 27 | **(N8) Delegation** | ⛔ Non-actionable | Same Linux platform limitation as LXC/Bwrap — WSL runs on the Linux kernel with the same routing constraints. No portable network access check at config time. | M |

### Misc

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 28 | **Port-mapping support** | ✅ Addressed | TCP host→container port forwarding shipped in [PR #530](https://github.com/microsoft/mxc/pull/530) (merged 2026-06-23). Provides explicit per-port inbound exposure (the `hostLoopback: "allow"` primitive for mapped ports); policy-driven `ingress.hostLoopback` default posture still needs the VM-level API (see Network #16 / SDK dep #1). | — |
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
| 4 | **Deny-mount / path-exclusion primitive** | Filesystem #5 (`deniedPaths` enforcement) | LXC and Bubblewrap mask a `deniedPaths` entry that sits under a mounted parent by overlaying it (`/dev/null` or `tmpfs`). The WSLC SDK exposes only a flat volume-mount surface with no overlay/exclusion primitive, so a denied subtree under a mounted parent cannot be masked. Today MXC silently ignores such a denied path, leaving it accessible through the parent mount; the planned near-term mitigation is to reject these configs at parse time (Filesystem #5), but real enforcement needs an SDK exclusion primitive. (Note: this is the *basic subtree-deny* gap — spec-exact D5 "visible + ACCESS_DENIED" remains non-actionable on every Linux backend regardless, see Filesystem #12.) |

> **Why network enforcement must be container-scoped (host vs. VM vs. container).** Network policy can be enforced at three layers: the Windows **host** (Windows Firewall), the WSL2 **VM**, or the **container** network namespace inside the VM. GA decision **D6 (per-sandbox scoping)** requires every sandbox's policy to be independent — concurrent WSLC containers must not affect each other's access — and names the container network namespace as WSLC's scoping identity. A machine-wide **host** firewall can't attribute traffic to one container vs. another, so it violates D6 (and per **D8**, host firewalls apply *on top of* enforcement, never *as* it). A **VM-wide** rule fails the same way when one utility VM hosts multiple containers — sandbox A's rules would bleed into sandbox B. Only the **container namespace** is inherently per-sandbox, which is why it's the required enforcement point. The catch: MXC can't install rules into that namespace today (`Privileged` doesn't grant `CAP_NET_ADMIN`, and the VM may lack iptables tooling). Hence SDK dep #1 — a VM-level API that applies rules **scoped to a specific container's namespace**: physically enforced at the VM boundary, logically attributed to one container. 
>
> **Contrast with Hyperlight/Nanvix, and the state-aware wrinkle.** Hyperlight (host-proxied sockets, per-instance) and Nanvix (per-guest egress filter) get D6 scoping for free because each sandbox *is* its own VM instance/process — no shared surface to bleed across. WSLC today is also effectively 1 sandbox : 1 VM (the one-shot flow creates a session, one container, then tears it down), but the highest-value WSLC optimization — **state-aware session reuse** (Misc #29), keeping a warm VM to amortize startup cost — makes one VM host **multiple** containers, at which point a host- or VM-wide rule genuinely bleeds across co-resident sandboxes. That is exactly when namespace-scoped enforcement (SDK dep #1) stops being merely cleaner and becomes mandatory.

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
