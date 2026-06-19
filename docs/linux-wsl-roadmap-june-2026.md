# Linux Backend Roadmap — June 2026

Forward-looking work items for the three Linux-side containment backends: **LXC**, **Bubblewrap**, and **WSLC**.

Each item is prioritized within its backend and tagged with an effort tier.

**Effort tiers:**

- **S** — small, hours to a day (single-file fix, doc update)
- **M** — medium, days to a week (one feature surface with tests)
- **L** — large, multi-week (new subsystem, schema changes, cross-crate refactor)

**Filesystem policy reference:** items tagged with **(D1)**–**(D8)** trace to the [MXC FS-policy semantics v1](https://github.com/microsoft/mxc/blob/user/gudge/downlevel-fs-projection-plan/docs/proposals/downlevel_support/policy_semantics_v1_summary.md) decisions. Items shared across backends note where the implementation lives (typically `wxc_common`).

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
| 7 | **Same-path conflict detection** | 🟡 Actionable | Same path appearing in both `readwritePaths` and `deniedPaths` (or `readonlyPaths`) is silently accepted. Shared check in `wxc_common` should reject as a validation error. | S |
| 8 | **Paths must exist at policy-load time** | 🟡 Actionable | No existence check today. Non-existent paths cause opaque failures at container start. Add `path_exists()` check at config parse time in `wxc_common`. | S |
| 9 | **Denied-path masking is heuristic** | 🟡 Actionable | `is_file()` probes the rootfs to choose `/dev/null` (file) vs `tmpfs` (dir) masking. Suffers TOCTOU, symlink-follow, missing-path ambiguity, silent error swallowing. `filesystem_mounts.rs:74-97`. | M |

> **Example (item 9).** Policy: `deniedPaths: ["/etc/shadow"]`. If `/etc/shadow` doesn't exist in the rootfs yet, `is_file()` returns `false` → mounts a tmpfs **directory** where a file should be. If it's a symlink, `is_file()` follows the link and masks the target, not the link itself. **Fix:** add `type: "file" | "dir"` discriminator to schema; harden fallback with `symlink_metadata()`.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 10 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | Spec says denied paths remain visible in parent listings but operations fail. LXC mounts `/dev/null` or `tmpfs` over denied paths, which **hides** them entirely. Linux mount namespaces have no mechanism to show a path but deny all operations on it. | — |
| 11 | **(D6) Object-based policy — enforcement** | ⛔ Non-actionable | Even with validation, Linux mount namespaces are path-based. Denying access via one path doesn't affect access via another path to the same inode. Full enforcement would require LSM or eBPF. | — |
| 12 | **Rename across regions** | ⛔ Non-actionable | Spec says `rename()` from a denied region should fail with ACCESS_DENIED. Linux returns EXDEV (cross-device) for cross-mount renames, which prevents the operation but with a different error code. The copy+delete fallback path can leak access. | — |

### Network

| # | Item | Description | Effort |
|---|---|---|---|
| 13 | **Apply `network.proxy`** | Schema advertises proxy support but LXC backend doesn't inject `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` env vars or set up iptables redirect for raw sockets. | M |
| 14 | **Apply `allowLocalNetwork`** | Inbound `bind()`/`listen()` policy is silently dropped; add iptables `INPUT` rules on the container's veth. Shared design with Bwrap and WSLC. | M |

> **Context for item #14.** `allowLocalNetwork` is honored by exactly one backend — **Seatbelt**. All three Linux backends and every Windows backend silently drop it. Either honor it or remove it from the schema.

| # | Item | Description | Effort |
|---|---|---|---|
| 15 | **nftables backend** | Docs claim nftables support but only iptables is implemented. `docs/lxc-support/lxc-backend.md:11,108,180`. **Deferred** — no concrete user ask. Default action: update docs to say "iptables" only. | S |
| 16 | **Hostname re-resolution for `allowedHosts`** | DNS is resolved once at policy install time; subsequent DNS changes silently bypass the firewall. Add periodic refresh. `network_iptables.rs:84-96`. *(see [Ext-Dep E11](#external-dependencies))* | M |

### Misc

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 17 | ~~**`process.cwd` is silently ignored**~~ | ✅ Shipped | *Shipped in [#494](https://github.com/microsoft/mxc/pull/494).* `attach_run` now wraps the user command with a `cd` prelude. | S |
| 18 | ~~**`process.env` is silently ignored**~~ | ✅ Shipped | *Shipped in [#494](https://github.com/microsoft/mxc/pull/494).* Each `KEY=VAL` becomes `--set-var`; `--clear-env` prevents host leak. | S |
| 19 | **State-aware lifecycle** | 🟡 Actionable | Implement `StatefulSandboxBackend` (provision/start/exec/stop/deprovision). | L |
| 20 | **Expand `LxcConfig` + resource limits (cgroups v2)** | 🟡 Actionable | Add per-backend config surface and cgroups v2 enforcement. Schema + enforcement ship together. *(see [Ext-Dep E10](#external-dependencies))* | L |

> **More context for item #20.** LXC's per-backend config block exposes only 2 fields (`distribution`, `release`) vs WSLC's 8. Shared cgroups controller code would also serve Bubblewrap.

| # | Item | Description | Effort |
|---|---|---|---|
| 21 | **Structured denied-resource diagnostics** | Process Container surfaces structured denial reasons; LXC returns opaque "execution failed" strings — wire equivalent telemetry. | M |
| 22 | **Doc drift cleanup** | `docs/lxc-support/lxc-backend.md:38-49,102-103` references `containerName` and `removeRulesOnExit` fields that don't exist in code. | S |
| 23 | **Un-gate LXC network tests in CI** | Done for GHA (PR `user/sodas/lxc-ci-enablement`). `MXC_SKIP_LXC_NETWORK_TESTS=1` kept on both GHA and ADO. ADO egress blocks `lxcbr0` NAT'd traffic. *(see [Ext-Dep E4](#external-dependencies))* | M |

---

## 🫧 Bubblewrap

### Filesystem

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 1 | **(D1) Default-deny** | ✅ Addressed | No `--bind` = no access. Bwrap namespace isolation enforces default-deny. | — |
| 2 | **(D8) Subtree-implicit** | ✅ Addressed | `--bind` mounts the full subtree. No gap. | — |
| 3 | **(D7) Implicit traversal** | ⚠️ Partial | If policy lists `RW /home/user/project/src` but `/home/user/project` isn't bound, the path doesn't exist inside the namespace. User must manually list ancestor dirs today. | S |

> **Example (D7).** Policy: `readwritePaths: ["/home/user/project/src"]`. Today `bwrap` fails because `/home/user/project` doesn't exist. Fix: auto-add `--dir` entries for ancestor paths (empty dirs, not host content — avoids the security risk of exposing `/home`).

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 4 | **(D4) Most-specific-path-wins** | 🟡 Actionable | Bwrap processes `--bind`, `--ro-bind`, `--tmpfs` left-to-right. Last matching arg wins, not longest-prefix. Shared path-tree resolver needed in `wxc_common`. | M |
| 5 | **(D6) Object-based — validation** | 🟡 Actionable | Same as LXC — `stat()` + inode comparison in `wxc_common`. | S |
| 6 | **(D3) Delegation check** | 🟡 Actionable | Same as LXC — shared `access_check()` in `wxc_common`. | M |
| 7 | **Same-path conflict detection** | 🟡 Actionable | Same as LXC — shared check in `wxc_common`. | S |
| 8 | **Paths must exist at policy-load time** | 🟡 Actionable | Non-existent `--bind` paths fail at runtime with unclear errors. Shared `path_exists()` in `wxc_common`. | S |
| 9 | **Denied-path file masking** | 🟡 Actionable | `--tmpfs` always treats the path as a directory. A denied *file* gets a tmpfs directory mounted over it (wrong type). Fix: use `--ro-bind /dev/null <path>` for files. | S |

> **Example (item 9).** Policy: `deniedPaths: ["/etc/shadow"]`. Today: `--tmpfs /etc/shadow` creates a directory at `/etc/shadow` — wrong. Fix: detect file vs dir (or accept `type` from schema) and use `--ro-bind /dev/null /etc/shadow` for files.

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 10 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Non-actionable | `--tmpfs` replaces the directory entirely — original is hidden. Same Linux mount-namespace limitation as LXC. | — |
| 11 | **(D6) Object-based — enforcement** | ⛔ Non-actionable | Path-based mount namespace. Same limitation as LXC. | — |
| 12 | **Rename across regions** | ⛔ Non-actionable | Same as LXC — Linux returns EXDEV, not ACCESS_DENIED. | — |

### Network

| # | Item | Description | Effort |
|---|---|---|---|
| 13 | **Schema overstates network enforcement** | Schema claims Bwrap enforces `allowedHosts` / `blockedHosts` directly, but reality is cooperative-only (env-var hints). Update wording or close the gap. `schemas/dev/mxc-config.schema.0.8.0-dev.json:180-187`. | M |
| 14 | **Apply `allowLocalNetwork`** | Field exists in schema; backend never applies it to its network namespace. Shared design with LXC and WSLC. | M |
| 15 | **Real network enforcement** | Today's path is env-var injection that clients politely honor. Pick one real-enforcement strategy (iptables+netns, eBPF, or proxy+raw-socket-redirect) and ship it. Bundles raw-socket leak, `NO_PROXY` exception, and root-requirement gaps. *(see [Ext-Dep E9](#external-dependencies) — applies only if eBPF option is chosen)* | L |
| 16 | **Policy expressiveness in `allowedHosts`** | Subdomain wildcards (e.g. `*.github.com`) and DNS-aware IPv6 paths. | M |

> **Context for item #16.** The IPv6 half is **security-critical**: on dual-stack hosts, `api.github.com` resolves to both A and AAAA records; MXC installs iptables rules only for IPv4, so IPv6 traffic passes unfiltered. Ship IPv6 first as a correctness fix; wildcards can follow as a usability improvement.

### Misc

| # | Item | Description | Effort |
|---|---|---|---|
| 17 | **Add backend-specific `BubblewrapConfig`** | No per-backend config block today (every other backend has one). Needed for seccomp, cgroups, custom binds. `schemas/dev/mxc-config.schema.0.8.0-dev.json` — Bwrap has no entry at `lxc:` (line 324) / `wslc:` (line 373) equivalent. | M |

> **More context for item #17.** Table-stakes infrastructure for seccomp (#18), cgroups (#19), and promote-to-stable (#20). Same shape as `LxcConfig` expansion: schema entry, `RawBubblewrap` in `config_parser.rs`, validated `BubblewrapConfig` in `models.rs`, plumbing through `bwrap_command.rs`, SDK type — ~10-15 file PR.

| # | Item | Description | Effort |
|---|---|---|---|
| 18 | **Seccomp profile support** | No syscall filtering today. Adding a default-deny profile would close attack surface meaningfully. *(see [Ext-Dep E8](#external-dependencies))* | L |

> **More context for item #18.** Bwrap's isolation comes from namespaces only — no seccomp. Docker/Podman/Flatpak all enable seccomp by default (~40+ blocked syscalls). MXC exposes the full ~400-syscall surface including `io_uring_setup`, `keyctl`, `bpf`, `userfaultfd`.

| # | Item | Description | Effort |
|---|---|---|---|
| 19 | **Resource limits (cgroups v2)** | No CPU / memory / PID / IO governance. Same gap as LXC. *(see [Ext-Dep E10](#external-dependencies))* | L |
| 20 | **Promote bubblewrap from `experimental` → stable in 0.8.0-dev** | Move config under the stable surface per `docs/versioning.md:91-93,182-203`. | L |
| 21 | **State-aware lifecycle** | Implement `StatefulSandboxBackend` for bwrap. | L |
| 22 | **Update plan doc** | `docs/bwrap-support/bubblewrap-backend-plan.md:42-60,295-324` still describes core implementation as "planned" even though it's shipped. | M |
| 23 | **Structured per-host network decision trace** | Surface why each connection attempt was allowed/denied. | M |
| 24 | **Structured denied-resource diagnostics** | Parity with Process Container's structured denial reporting. | M |
| 25 | **CI job for `tests/scripts/run_bwrap_all_tests.sh`** | Bwrap E2E suite is manual-only today. *(see [Ext-Dep E6](#external-dependencies))* | M |
| 26 | **Add `Container-Bubblewrap` label** | Parity with `Container-WSLC`, `Container-Hyperlight`. *(see [Ext-Dep E7](#external-dependencies))* | S |

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
| 5 | **`deniedPaths` overlap validation** | 🟡 Actionable | At parse time, reject configs where a `deniedPaths` entry is a child of a mounted path (since the WSLC SDK cannot enforce the deny). Accept non-overlapping denied paths as implicitly enforced (unmounted = invisible). | S |

> **Example (item 5).** Policy: `readwritePaths: ["C:\\project"]`, `deniedPaths: ["C:\\project\\secrets"]`. Today: `deniedPaths` silently ignored; `secrets` is fully accessible through the parent mount. Fix: reject at config time with "denied path is a child of a mounted path; WSLC cannot enforce this."

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 6 | **(D6) Object-based — validation** | 🟡 Actionable | Same as LXC/Bwrap — `stat()` + inode comparison in `wxc_common`. | S |
| 7 | **(D3) Delegation check** | 🟡 Actionable | Same as LXC/Bwrap — shared `access_check()` in `wxc_common`. | M |
| 8 | **Same-path conflict detection** | 🟡 Actionable | Same as LXC/Bwrap — shared check in `wxc_common`. | S |
| 9 | **Paths must exist at policy-load time** | 🟡 Actionable | Same as LXC/Bwrap — shared `path_exists()` in `wxc_common`. | S |
| 10 | **Explicit `{ windowsPath, containerPath }` mount control** | 🟡 Actionable | Host paths always mounted at `/mnt/<drive>/`; let users specify the in-container mount point. `policy_mapping.rs:23-60`. | M |
| 11 | **Handle UNC / non-drive paths** | 🟡 Actionable | UNC paths (`\\server\share`) silently dropped with a warning; plan is to hard-error. Branch `user/sodas/wslc-reject-unc-paths`. | S |
| 12 | **(D5) Deny = ACCESS_DENIED, not hidden** | ⛔ Blocked | No deny-mount primitive in the WSLC SDK. Unmounted paths are invisible (not ACCESS_DENIED). **Depends on WSLC SDK team** for a deny-mount API. | — |
| 13 | **(D6) Object-based — enforcement** | ⛔ Non-actionable | WSLC SDK is path-based. Same limitation as Linux backends. | — |
| 14 | **Rename across regions** | ⛔ Non-actionable | WSL uses Linux VFS — returns EXDEV, not ACCESS_DENIED. Same as LXC/Bwrap. | — |

### Network

| # | Item | Description | Effort |
|---|---|---|---|
| 15 | **Apply `network.proxy`** | Schema advertises proxy support; WSLC ignores it — needs env injection plus iptables redirect. | M |
| 16 | **Apply `allowLocalNetwork`** | Inbound listen policy silently dropped; add distro-side iptables `INPUT` rules. Shared design with LXC and Bwrap. | M |
| 17 | **Per-host filtering (`allowedHosts`/`blockedHosts`)** | `WslcContainerFlags::Privileged` does not grant `CAP_NET_ADMIN`, so iptables cannot manipulate netfilter inside the container. Host-side `nsenter -n` into the container's netns is a fragile workaround. **Depends on WSLC SDK team** to either grant `CAP_NET_ADMIN` with Privileged mode or expose a per-host network filtering API. *(see [Ext-Dep E3](#external-dependencies))* | M |

### Misc

| # | Item | Status | Description | Effort |
|---|---|---|---|---|
| 18 | **Finish & merge port-mapping support** | 🟡 In progress | Branch `user/sodas/wslc-port-mapping`. | M |
| 19 | **Private registry auth** | ⛔ Blocked | Needs WSLC SDK to ship registry-auth handshake. *(see [Ext-Dep E1](#external-dependencies))* | M (post-SDK) |
| 20 | **State-aware lifecycle** | 🟡 Actionable | Implement `StatefulSandboxBackend`. WSLC bears the largest startup cost — session reuse is the highest-value win. | L |
| 21 | **Structured denied-resource diagnostics** | 🟡 Actionable | Parity with Process Container's structured denial reporting. | M |
| 22 | **Self-contained WSLC SDK build** | ⛔ Blocked | Needs deterministic distribution channel for `wslcsdk.dll`. *(see [Ext-Dep E2](#external-dependencies))* | M |
| 23 | **Un-gate WSLC tests in CI** | ⛔ Blocked | Needs `wslcsdk.dll` public NuGet. *(see [Ext-Dep E5](#external-dependencies))* | M |

---

## Cross-cutting themes

These show up on multiple backends and are worth coordinating to avoid divergent designs:

1. **Filesystem policy alignment** — D4 (path-tree resolver), D3 (delegation check), D6 (object validation), same-path conflict detection, paths-must-exist validation all belong in `wxc_common` and serve all three backends.
2. **State-aware lifecycle** — LXC #19, Bwrap #21, WSLC #20. None of the three implement `StatefulSandboxBackend` today. WSLC has the largest payoff (slowest cold start).
3. **`allowLocalNetwork` enforcement** — LXC #14, Bwrap #14, WSLC #16. Schema-declared, silently dropped on all three. Inbound-traffic primitive design should be shared.
4. **`network.proxy` enforcement** — LXC #13, WSLC #15. (Bwrap has cooperative-only support, item #15.) Proxy injection + raw-socket redirect should be a shared utility.
5. **Resource limits (cgroups v2)** — LXC #20, Bwrap #19. Same kernel API; build a shared `cgroup_controller` crate.
6. **Structured denied-resource diagnostics** — LXC #21, Bwrap #24, WSLC #21. Replicate Process Container's structured denial reporting on Linux.
7. **CI gating** — LXC #23, Bwrap #25, WSLC #23.
8. **Denied-path type discriminator** — LXC #9, Bwrap #9. Add `type: "file" | "dir"` to `deniedPaths` schema entries so backends don't have to guess.

---

## External dependencies

These items have dependencies outside the MXC repo. Listed here so roadmap planners know what is not unilaterally schedulable and reviewers know what coordination is required.

### 🚫 Hard blockers (cannot ship until the external thing lands)

| Ref | Affected | External owner | Description |
|---|---|---|---|
| **E1** | WSLC #19 | WSLC SDK team | Registry-auth handshake (Basic / Bearer / ACR / GHCR / ECR), token caching, custom-CA HTTPS. The SDK ABI reserves the `auth_info` slot but the implementation isn't shipped yet. |
| **E2** | WSLC #22 | WSLC SDK team | Deterministic / vendored / signed distribution channel for `wslcsdk.dll` — today MXC pulls from `external/wslc-sdk/` which isn't reproducible from a fresh clone. |
| **E3** | WSLC #17 | WSLC SDK team | Per-host network filtering. `WslcContainerFlags::Privileged` does not grant `CAP_NET_ADMIN` inside the container, so iptables-based `allowedHosts`/`blockedHosts` enforcement is impossible. Need either: (a) `CAP_NET_ADMIN` granted with Privileged, or (b) a host-side per-host filtering API in the SDK. |

### 🏗️ Infra & pipeline (needs build-agent or repo changes outside the source tree)

| Ref | Affected | External owner | Description |
|---|---|---|---|
| **E4** | LXC #23 | 1ES / pipeline agents | **Updated 2026-06-15 after on-runner probe** — GH-hosted `ubuntu-latest` (24.04), `ubuntu-22.04`, and `ubuntu-24.04-arm` runners all install the LXC stack cleanly, successfully create + run containers, start `lxc-net.service`, and accept full `iptables` under `sudo`. **Addendum (ADO probe)** — 1ES Hosted Pool probe confirmed LXC core works but outbound from `lxcbr0` is blocked by pool egress. Conclusion: `MXC_SKIP_LXC_NETWORK_TESTS=1` on ADO; GHA covers the network half, ADO covers core. |
| **E5** | WSLC #23 | 1ES / pipeline agents | **Updated 2026-06-15** — GH-hosted `windows-latest` / `windows-2025` support WSL2 (zero-to-shell ~28–33 s). ARM64 not capable. Only remaining gate is `wslcsdk.dll` distribution (E2). |
| **E6** | Bwrap #25 | 1ES / pipeline agents | **Updated 2026-06-15** — Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns=1` breaks unprivileged bwrap. Workaround: run under `sudo -E` (current posture). Every GHA Linux runner is IPv6 dual-stack, confirming Bwrap #16-IPv6 is a real exposure. |
| **E7** | Bwrap #26 | Repo admin | Create `Container-Bubblewrap` label (parity with `Container-WSLC`, `Container-Hyperlight`). |

### ⚠️ Upstream / kernel-evolution tracking

| Ref | Affected | What to track |
|---|---|---|
| **E8** | Bwrap #18 | Linux kernel keeps adding syscalls (`io_uring_*`, `clone3`, `pidfd_*`, `landlock_*`); seccomp profile needs refresh cadence. |
| **E9** | Bwrap #15 (eBPF option) | eBPF / CO-RE requires kernel ≥5.x with BTF. Other enforcement strategies have no such constraint. |
| **E10** | LXC #20, Bwrap #19 | cgroups v2 unified hierarchy — default on modern distros but Ubuntu < 22.04 / RHEL < 9 may still mount v1. |
| **E11** | LXC #16 | System resolver semantics (`systemd-resolved` / `nscd` / DNS TTL) constrain hostname re-resolution frequency. |

### ⏳ Deferred pending external user demand

Item **LXC #15** (nftables backend) is gated on a real user signal — see its inline note for deferral criteria.

---

## Notes

- **Issue tracking**: [open issues](https://github.com/microsoft/mxc/issues?q=is%3Aissue+is%3Aopen). None of the above are filed yet.
- **Promotion path**: Bubblewrap and WSLC are both still under `experimental` in the schema; see `docs/versioning.md` for the migration mechanics required for each promotion.
- **Labels**: re-use `Container-WSLC` and `Area-Executor-LXC`; propose adding `Container-Bubblewrap` (Bwrap #26).
