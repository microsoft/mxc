# Linux Backend Roadmap — June 2026

Forward-looking work items for the three Linux-side containment backends: **LXC**, **Bubblewrap**, and **WSLC**.

Each item is prioritized within its backend and tagged with an effort tier and a category.

**Effort tiers:**

- **S** — small, hours to a day (single-file fix, doc update)
- **M** — medium, days to a week (one feature surface with tests)
- **L** — large, multi-week (new subsystem, schema changes, cross-crate refactor)

**Categories:**

- 🔴 **Correctness papercuts** — silent-contract violations, user-visible bugs (must fix first)
- 🟠 **Schema honesty** — fields declared in schema but ignored at runtime
- 🟡 **Feature gaps** — missing capability the backend should have
- 🟢 **Diagnostics & DX** — observability, error reporting, developer experience
- 📚 **Docs / Test / CI** — documentation drift, test coverage, pipeline gating
- 🚧 **In-flight** *(WSLC only)* — work already on a branch
- 🔥 **High-value next features** *(WSLC only)* — top priorities driven by explicit user asks

**Naming:** the backend is "Bubblewrap" (used in headers and proper nouns like the `BubblewrapConfig` type or `Container-Bubblewrap` label); **Bwrap** is used as the short reference in tables and cross-cutting themes.

File:line citations reference paths under `src/backends/<backend>/...` and `src/core/...`.

---

## 🐧 LXC

### 🔴 Correctness papercuts (do first)

| # | Item | Description | Effort |
|---|---|---|---|
| 1 | ~~**`process.cwd` is silently ignored**~~ ✅ | User-specified working directory never reaches `lxc-attach`; process starts in container default cwd (`/`). `src/backends/lxc/common/src/lxc_bindings.rs:188-209`. *Shipped in [#494](https://github.com/microsoft/mxc/pull/494) — `attach_run` now wraps the user command with a `cd -- "$1" && exec /bin/sh -c "$2"` prelude that passes cwd as a positional argument (no shell escaping needed).* | S |
| 2 | ~~**`process.env` is silently ignored**~~ ✅ | User-specified environment variables are dropped before execution; only container default env reaches the process. `src/backends/lxc/common/src/lxc_runner.rs:209-229`. *Shipped in [#494](https://github.com/microsoft/mxc/pull/494) — each `KEY=VAL` becomes a `--set-var=KEY=VAL` flag; when env is non-empty, `--clear-env` is also passed so the host env doesn't leak (matches Seatbelt's `env_clear()`-on-non-empty contract). Malformed entries (no `=`, empty key) are silently skipped.* | S |

### 🟠 Schema fields not honored

| # | Item | Description | Effort |
|---|---|---|---|
| 4 | **Apply `network.proxy`** | Schema advertises proxy support but LXC backend doesn't inject `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` env vars or set up iptables redirect for raw sockets. | M |
| 5 | **Apply `allowLocalNetwork`** | Inbound `bind()`/`listen()` policy is silently dropped; add iptables `INPUT` rules on the container's veth. | M |

> **Context for item #5.** `allowLocalNetwork` is the inbound-traffic axis of network policy (governs the sandboxed process's `bind()` / `listen()` / `accept()`), independent of `defaultPolicy` which only governs outbound `connect()`. It's currently honored by exactly one backend out of ten — **Seatbelt** (`backends/seatbelt/common/src/profile_builder.rs` lines 217 + 226–237 + tests 586–616). All three Linux backends (LXC, Bubblewrap, WSLC) and every Windows backend silently drop it — the field is in the schema, parsed into `ContainerPolicy`, and then ignored. **Why fix it on LXC:** (a) silent-contract violation — same bug class as items #1, #2, #4 — either we honor it or remove it from the schema; (b) Seatbelt established the semantic and Linux needs parity for the increasingly common "sandboxed agent server, host orchestrator talks in" pattern (MCP servers, Jupyter kernels, language servers); (c) without it, users must couple inbound to outbound, which is the wrong contract. **Defer-or-build check:** as with item #8 (nftables), if a GitHub search for user demand returns zero hits, the alternate disposition is to update the docs to say "Linux backends ignore `allowLocalNetwork`; honored by Seatbelt only" and leave implementation behind a real user ask. **Shared infrastructure opportunity:** the inbound-filter primitive should be designed once and reused by Bwrap #2 and WSLC #4 (see cross-cutting theme #2).

### 🟡 Feature gaps

| # | Item | Description | Effort |
|---|---|---|---|
| 6 | **State-aware lifecycle** | Implement `StatefulSandboxBackend` (provision/start/exec/stop/deprovision) so callers can reuse a container across multiple invocations. | L |
| 7 | **Expand `LxcConfig` + implement resource limits (cgroups v2)** | Add a per-backend config surface (`rootfsTarPath`, `storagePath`, `cpuCount`, `memoryMb`, `cgroupProfile`, `extraConfigPath`) AND the runtime enforcement (cgroups v2) so CPU / memory / PID / IO governance actually applies. Schema + enforcement ship together. *(see [Ext-Dep E9](#external-dependencies))* | L |

> **More context for item #7.** This item bundles two halves that must ship together — the **config surface** (where users express resource limits) and the **runtime enforcement** (where the kernel applies them) — to avoid the silent-contract-violation bug class we're already fixing in items #1, #2, #4, #5. On the config side, LXC's per-backend block is anemic compared to peers: it exposes only `distribution` and `release` (2 fields), while WSLC exposes 8 (`image`, `imageTarPath`, `cpuCount`, `memoryMb`, `gpu`, `storagePath`, `portMappings`, `targetOs`); LXC users have no way to specify a rootfs source, resource caps, storage path, or raw `lxc.conf` snippets, and a reasonable target mirrors WSLC's surface. On the enforcement side, cgroups v2 is the Linux kernel mechanism that actually constrains CPU / memory / PID / IO — the runner needs to write to `/sys/fs/cgroup/.../{cpu.max,memory.max,pids.max,io.max}` at container start, propagate failures, and clean up on teardown. **Shared infrastructure opportunity:** the cgroups controller code would also serve Bubblewrap (see cross-cutting theme #4).

| 8 | **nftables backend** | Docs claim nftables support but only iptables is implemented; add nftables path and let the user select per-host. `network_iptables.rs:98-115` + `docs/lxc-support/lxc-backend.md:91-103`. | M |

> **Disposition for item #8.** As of June 2026 there is no concrete user-driven ask for nftables. The four documentation hits all use "iptables/nftables" generically as a Linux netfilter category, not as a commitment. **Default action: do not build the nftables code path — instead, update the docs (`docs/lxc-support/lxc-backend.md` lines 11, 93, 163 and `docs/macos-support/seatbelt-backend.md` line 336) to say "iptables" only. Effort drops from M to S.** Promote this item back to the full nftables implementation only if a real user ask surfaces — e.g. an Azure Linux / RHEL 9+ partner reporting the `iptables-nft` shim breaking, or a deployment with thousands of `allowedHosts` rules where iptables' O(n) traversal is measurably hurting them.

| 9 | **Hostname re-resolution for `allowedHosts`** | DNS is resolved once at policy install time; subsequent DNS changes silently bypass the firewall. Add periodic refresh. `network_iptables.rs:84-96`. *(see [Ext-Dep E10](#external-dependencies))* | M |

### 🟢 Diagnostics & DX

| # | Item | Description | Effort |
|---|---|---|---|
| 10 | **Structured denied-resource diagnostics** | Process Container surfaces structured denial reasons (PR #6d5a0da); LXC returns opaque "execution failed" strings — wire equivalent telemetry. | M |
| 11 | **Filesystem denied-path masking is heuristic** | Code probes the rootfs to choose between `/dev/null` and `tmpfs` overlay strategies; make the choice explicit and deterministic. `src/backends/lxc/common/src/filesystem_mounts.rs:74-97`. | M |

> **More context for item #11.** LXC masks a `deniedPaths` entry by mounting either `/dev/null` (for files) or an empty `tmpfs` (for directories) over the path inside the container. Today the runner picks between the two by calling `std::path::Path::is_file()` against the rootfs at config time — a heuristic with five real problems: (a) **TOCTOU race** between probe and mount (worsens once state-aware containers, item #6, exist); (b) `is_file()` returns `false` for both directories *and* missing paths, so a path the user denied but the image doesn't ship silently falls into the tmpfs branch; (c) `is_file()` collapses all I/O errors (permission denied, broken symlink, unreadable parent) into `false` with no diagnostic; (d) it follows symlinks, so masking applies to the target rather than the link the policy actually named; (e) the user has no schema field to express intent — the runner makes a policy decision based on filesystem state, the exact silent-contract violation pattern items #1, #2, #4, #5 are already fixing. **Likely fix:** add a `type: "file" | "dir" | "auto"` discriminator to `deniedPaths` entries; default `"auto"` preserves current behavior with a warning log, explicit values skip the probe entirely. Shape carries to Bwrap / WSLC for cross-backend parity.

### 📚 Docs / Test / CI

| # | Item | Description | Effort |
|---|---|---|---|
| 12 | **Doc drift cleanup** | `docs/lxc-support/lxc-backend.md:38-49,102-103` references `containerName` and `removeRulesOnExit` fields that don't exist in code — remove or implement. | S |
| 13 | **Un-gate LXC network tests in CI** | Done for GHA (`user/sodas/lxc-ci-enablement` removes `MXC_SKIP_LXC_TESTS=1` + `MXC_SKIP_LXC_NETWORK_TESTS=1` from `.github/workflows/SDK.Integration.Test.Job.yml`). **Will NOT be flipped on ADO** — the 1ES Hosted Pool's egress firewall blocks `lxcbr0` NAT'd traffic from reaching the public Internet (probe confirmed). ADO continues to give us LXC core coverage; GHA covers the network half. *(see [Ext-Dep E3](#external-dependencies))* | M |

---

## 🫧 Bubblewrap

### 🟠 Schema honesty

| # | Item | Description | Effort |
|---|---|---|---|
| 1 | **Schema overstates network enforcement** | Schema claims Bwrap enforces `allowedHosts` / `blockedHosts` directly, but reality is cooperative-only (env-var hints to clients). Update wording or close the gap. `schemas/dev/mxc-config.schema.0.7.0-dev.json:149-154`. | M |
| 2 | **Apply `allowLocalNetwork`** | Field exists in schema; backend never applies it to its network namespace. | M |
| 3 | **Add backend-specific `BubblewrapConfig`** | Bwrap currently consumes only shared fields; no surface for seccomp profile, custom binds, or `bwrap`-native knobs. | M |

> **More context for item #3.** Confirmed by schema inspection: every other backend has a per-backend config block (`lxc:` at `schemas/dev/mxc-config.schema.0.7.0-dev.json:271`, `wslc:` at line 318, plus dedicated blocks for `seatbelt`, `windows_sandbox`, `isolation_session`) — Bwrap has **none**. Users can only set what's in the shared `process` / `filesystem` / `network` / `ui` sections, so every `bwrap`-native knob is unreachable: `seccompProfile` (item #7), cgroups v2 caps (item #8), `customBinds` / `tmpfsMounts` / `symlinks` for mount fixups, `dropCaps` / `keepCaps`, individual `unshare-*` toggles, `dieWithParent`, `newSession`, `argv0` / `chdir` overrides. **This is table-stakes infrastructure for items #7, #8, and #9** — seccomp needs `bubblewrap.seccompProfile`, cgroups needs `bubblewrap.resources.*`, and the promote-to-stable work (#9) gates on having a stable shape for this block. Despite its placement under "Schema honesty," practically it should land **early** in the Bwrap order. Same shape as the `LxcConfig` expansion (LXC item #7): schema entry, `RawBubblewrap` in `config_parser.rs`, validated `BubblewrapConfig` in `models.rs`, plumbing through `bwrap_command.rs`, SDK type, docs — ~10-15 file PR.

### 🟡 Feature gaps

| # | Item | Description | Effort |
|---|---|---|---|
| 4 | **State-aware lifecycle** | Implement `StatefulSandboxBackend` for the bwrap backend. | L |
| 5 | **Real network enforcement (replace cooperative-only path)** | Today's path is env-var injection that clients politely honor; the iptables fallback exists but is unreachable in normal config. Pick one real-enforcement strategy (iptables+netns, eBPF, or proxy+raw-socket-redirect) and ship it end-to-end. **Bundles three previously-separate gaps:** raw-socket `connect()` leak past proxy env vars (`src/backends/bubblewrap/common/src/bwrap_command.rs:116-135`); no `NO_PROXY` / loopback exception (`docs/bwrap-support/bubblewrap-backend.md:162-169`); iptables-vs-proxy mutual exclusion (root requirement). All three have the same root cause and must be solved together. *(see [Ext-Dep E8](#external-dependencies) — applies only if eBPF option is chosen)* | L |
| 6 | **Policy expressiveness in `allowedHosts`** | Bundle of matcher-layer gaps: subdomain wildcards (e.g. `*.github.com`) and DNS-aware IPv6 paths (schema normalizes IPv6 literals today, but there's no IPv6-resolved-from-DNS policy path). Both land in the same parser/matcher PR. | M |

> **More context for item #6.** The two halves of this bundle have **very different severity** — keep that in mind when slicing reviewer scope. The **IPv6 half is security-critical**: on any modern dual-stack Linux host (default on Azure, AWS, GCP cloud VMs), `api.github.com` resolves to both A and AAAA records; today MXC installs an iptables rule only for the IPv4 address, while glibc's `getaddrinfo` prefers IPv6 — so the sandboxed `connect()` lands on a v6 address with **no firewall rule covering it** and the packet sails through unfiltered. Silent allowlist bypass, same bug class as items #2 (`allowLocalNetwork`) and LXC items #1/#2. The **wildcards half is usability only**: without `*.example.com` support, users enumerate today's subdomains and silently lose access when a new one appears (or just set `defaultPolicy: allow` and give up). Annoying, not unsafe. **Recommendation:** if reviewer bandwidth forces a split, ship IPv6 first as a standalone correctness fix; wildcards can land separately as a usability follow-up.

| 7 | **Seccomp profile support** | No syscall filtering today; adding a default-deny seccomp profile would meaningfully close attack surface. *(see [Ext-Dep E7](#external-dependencies))* | L |

> **More context for item #7.** Bwrap's isolation today comes from Linux namespaces alone (`--unshare-user`/`pid`/`ipc`/`uts`/`net` in `bwrap_command.rs:41-44`) — no syscall filter. Unlike LXC, which inherits an upstream-LXC default seccomp profile (`/usr/share/lxc/config/common.seccomp`, ~7 blocked syscalls), `bwrap` ships **no** built-in profile and only applies one when the caller passes `--seccomp <fd>` with a pre-compiled BPF program — which the MXC runner never does. That leaves Bwrap below every shipped peer (Docker / Podman / Flatpak / Firejail all enable seccomp by default, ~40+ blocked syscalls) and exposes the full ~400-syscall surface to sandboxed code, including the historically vulnerable family (`io_uring_setup`, `keyctl`, `bpf`, `userfaultfd`, `clone3` with namespace flags) that's driven most recent kernel-CVE sandbox escapes. **L tier** because the cost isn't compiling a profile (mature crates exist — `seccompiler`, `libseccomp-rs`) but designing one that doesn't break legitimate `node`/`python`/`io_uring` workloads, plus user-override plumbing on `BubblewrapConfig` (item #3). **Shared infrastructure opportunity:** a `wxc_seccomp` crate would also let LXC narrow/extend its inherited default (today MXC has no surface to do that either).

| 8 | **Resource limits (cgroups v2)** | No CPU / memory / PID / IO governance — same gap as LXC. *(see [Ext-Dep E9](#external-dependencies))* | L |
| 9 | **Promote bubblewrap from `experimental` → stable in 0.7.0-dev** | Move config under the stable surface per `docs/versioning.md:91-93,182-203`; includes parser migration, schema bump, single-backend-section rule update, and doc cleanup. | L |
| 10 | **Update plan doc to reflect shipped state** | `docs/bwrap-support/bubblewrap-backend-plan.md:42-60,295-324` still describes core implementation as "planned" even though it's shipped — rewrite to match reality. | M |

### 🟢 Diagnostics & DX

| # | Item | Description | Effort |
|---|---|---|---|
| 11 | **Structured per-host network decision trace** | Surface why each connection attempt was allowed/denied so users can debug policy without packet captures. | M |
| 12 | **Structured denied-resource diagnostics** | Parity with Process Container's structured denial reporting. | M |

### 📚 Test / CI

| # | Item | Description | Effort |
|---|---|---|---|
| 13 | **CI job for `tests/scripts/run_bwrap_all_tests.sh`** | The bwrap E2E suite is manual-only today; add a Linux pipeline job that runs it. *(see [Ext-Dep E5](#external-dependencies))* | M |
| 14 | **Add `Container-Bubblewrap` label to repo** | Repo has `Container-WSLC`, `Container-Hyperlight`, etc. but no Bubblewrap label — prerequisite for issue triage. *(see [Ext-Dep E6](#external-dependencies))* | S |

---

## 🪟🐧 WSLC

### 🚧 In-flight

| # | Item | Description | Effort |
|---|---|---|---|
| 1 | **Finish & merge port-mapping support** | Branch `user/sodas/WslcPortMappingSupport` (commit `debeb90`) has work in progress; runner at `src/backends/wslc/common/src/wsl_container_runner.rs:520-534` says `portMappings` is "parsed but not yet applied." | M |

### 🔥 High-value next features

| # | Item | Description | Effort |
|---|---|---|---|
| 2 | **Private registry auth** *(blocked on WSLC SDK)* | WSLC can only pull from public registries today; add credential plumbing for private / authenticated registries. The SDK's `WslcPullImageOptions` already reserves an `auth_info` slot (`src/backends/wslc/common/src/wslc_bindings.rs:208`) typed for `WslcRegistryAuthenticationInformation`, but the underlying implementation is not yet shipped — per `docs/wsl/wsl-container-support-plan.md:408-410`, "private registry auth is planned for a future WSLC SDK release." MXC-side work (model the auth struct, add `experimental.wslc.registryAuth` schema field, replace `auth_info: ptr::null()` at `wsl_container_runner.rs:605`) is ~M but cannot ship until WSLC SDK delivers the registry-auth handshake (Basic / Bearer / ACR / GHCR / ECR), token caching, and custom-CA HTTPS. Track as a coordination item — not unilaterally schedulable. *(see [Ext-Dep E1](#external-dependencies))* | M (post-SDK) |

### 🟠 Schema fields not honored

| # | Item | Description | Effort |
|---|---|---|---|
| 3 | **Apply `network.proxy`** | Schema advertises proxy support; WSLC ignores it — needs env injection into the distro plus iptables redirect for raw sockets. | M |
| 4 | **Apply `allowLocalNetwork`** | Inbound listen policy silently dropped; add distro-side iptables `INPUT` rules. | M |

### 🟡 Feature gaps

| # | Item | Description | Effort |
|---|---|---|---|
| 5 | **State-aware lifecycle** | Implement `StatefulSandboxBackend`. WSLC bears the largest startup cost of the three (distro boot, image hydration), so session reuse is the highest-value win here. | L |
| 6 | **Explicit `{ windowsPath, containerPath }` mount control** | Host paths are always mounted at `/mnt/<drive>`; let users specify the in-container mount point. `src/backends/wslc/common/src/policy_mapping.rs:23-60`. | M |
| 7 | **Handle UNC / non-drive paths explicitly** | UNC paths in policy (e.g. `\\fileserver\team\report.docx`, `\\wsl$\Ubuntu\home\user`, `\\?\C:\very\long\path`) are silently dropped with only a warning; plan is to hard-error so users know the path cannot be mounted. `src/backends/wslc/common/src/policy_mapping.rs:23-60`. | S |
| 8 | **Add a real `deniedPaths` primitive** | Today `deniedPaths` means "not mounted" — there's no overlay-based deny ACE, so a sibling mount could leak access. | M |
| 9 | **Per-host filtering requires iptables-in-image** | Images without iptables silently fall back to coarse allow/deny; add a fallback (sidecar netns or host-side filter) so policy is honored regardless of image contents. | M |

### 🟢 Diagnostics & DX

| # | Item | Description | Effort |
|---|---|---|---|
| 10 | **Structured denied-resource diagnostics** | Parity with Process Container's structured denial reporting. | M |

### 📚 Build / Test / CI

| # | Item | Description | Effort |
|---|---|---|---|
| 11 | **Self-contained WSLC SDK build** | Build currently pulls from `external/wslc-sdk/`; vendor or fetch deterministically so a fresh clone can build without out-of-band setup. *(see [Ext-Dep E2](#external-dependencies))* | M |
| 12 | **Un-gate WSLC tests in CI** | Pipeline runs with `MXC_ENABLE_WSLC_TESTS=1` unset; pipeline builds the binary but never exercises it. *(see [Ext-Dep E4](#external-dependencies))* | M |

---

## Cross-cutting themes

These show up on multiple backends and are worth coordinating to avoid divergent designs:

1. **State-aware lifecycle** — LXC #6, Bwrap #4, WSLC #5. None of the three implement `StatefulSandboxBackend` today; only IsolationSession does. WSLC has the largest payoff (slowest cold start).
2. **`allowLocalNetwork` enforcement** — LXC #5, Bwrap #2, WSLC #4. Schema-declared, silently dropped on all three. Inbound-traffic primitive design should be shared.
3. **`network.proxy` enforcement** — LXC #4, WSLC #3. (Bwrap has cooperative-only support, item #5.) Proxy injection + raw-socket redirect should be a shared utility.
4. **Resource limits (cgroups v2)** — LXC #7 (combined with `LxcConfig` expansion), Bwrap #8. Same kernel API; build a shared `cgroup_controller` crate rather than per-backend implementations.
5. **Structured denied-resource diagnostics** — LXC #10, Bwrap #12, WSLC #10. Process Container's PR #6d5a0da set the bar; replicate on Linux.
6. **CI gating** — LXC #13, Bwrap #13, WSLC #12. None of the three has a dedicated CI job that actually exercises the backend; quality drift grows each release.

---

## External dependencies

These items have dependencies outside the MXC repo. Listed here so roadmap planners know what is not unilaterally schedulable and reviewers know what coordination is required.

### 🚫 Hard blockers (cannot ship until the external thing lands)

| Ref | Affected | External owner | Description |
|---|---|---|---|
| **E1** | WSLC #2 | WSLC SDK team | Registry-auth handshake (Basic / Bearer / ACR / GHCR / ECR), token caching, custom-CA HTTPS. The SDK ABI reserves the `auth_info` slot but the implementation isn't shipped yet. |
| **E2** | WSLC #11 | WSLC SDK team | Deterministic / vendored / signed distribution channel for `wslcsdk.dll` — today MXC pulls from `external/wslc-sdk/` which isn't reproducible from a fresh clone. |

### 🏗️ Infra & pipeline (needs build-agent or repo changes outside the source tree)

| Ref | Affected | External owner | Description |
|---|---|---|---|
| **E3** | LXC #13 | 1ES / pipeline agents | **Updated 2026-06-15 after on-runner probe** — GH-hosted `ubuntu-latest` (24.04), `ubuntu-22.04`, and `ubuntu-24.04-arm` runners all (a) install the `lxc lxc-utils dnsmasq-base iptables bridge-utils` stack cleanly in ≤ 8 s, (b) successfully `lxc-create -t download -d alpine -r 3.21` and run `lxc-start` + `lxc-attach` to a shell in ≤ 4 s, (c) start `lxc-net.service`, bring up the default `lxcbr0` bridge with `dnsmasq` listening on 10.0.3.1, and (d) accept full `iptables` (filter + nat, including custom chain create / append / flush / delete) under `sudo`. The probe container booted with only `lo` (the probe didn't configure a veth interface in the LXC config) — but mxc's `lxc_runner` does request `lxc.net.0.type = veth + lxc.net.0.link = lxcbr0`, and `NetworkIptablesManager` writes the per-veth allowlist via the same `iptables` calls the probe exercised. Both halves of the long-skipped network test should therefore work end-to-end on stock GHA Linux runners; the "Classic LXC is unreliable on the GHA ubuntu-latest (24.04) runner" comment in `.github/workflows/SDK.Integration.Test.Job.yml` is stale and `MXC_SKIP_LXC_TESTS=1` + `MXC_SKIP_LXC_NETWORK_TESTS=1` are both candidates to remove (with a Linux-only matrix entry that runs under `sudo`, mirroring the existing Bwrap path). Probe workflow preserved on branch `user/sodas/linux-runtime-probe` (run id 27576588204). **Addendum 2026-06-15 (ADO 1ES Hosted Pool probe)** — re-ran the same probe against `Azure-Pipelines-1ESPT-ExDShared` (ubuntu-22.04 image `Prod-Ubuntu22.04-Gen2`, Standard_D2ads_v5) on branch `user/sodas/ado-lxc-probe` (build id 149800070): LXC install + `lxc-create -t download alpine 3.21` + `lxc-start` + `lxc-attach` echo all succeed, custom-chain `iptables` writes (filter + nat) succeed, but `lxc-attach … wget https://api.github.com/zen` returns `NETWORK-FAILED` after the 10 s timeout — i.e. outbound from inside the LXC container is blocked at the host. The full SDK integration suite, run with the network-skip env var **off**, confirmed the same shape: every LXC test that does **not** need the network passes (hello, exit-code, sysinfo, backend-select, multi-cmd pipeline, mount-rw, mount-ro), and the three that **do** need it fail (`should allow outbound network access`, `should download file to writable mount`, `should access HTTPS endpoint`) after a 6 s timeout each on both `0.4.0-alpha` and `0.5.0-alpha` schema lanes. The 1ES Hosted Pool advertises eight different `Public Outgoing IP(s)` (managed NAT pool) and `Network Isolation Policy: None` at the agent level, but `lxcbr0`'s `MASQUERADE`d traffic still doesn't make it past the pool egress — most likely the same pool-level allowlist that gates `pkgs.dev.azure.com` / `feeds.dev.azure.com` access. Conclusion: keep `MXC_SKIP_LXC_NETWORK_TESTS=1` on ADO; GHA covers the LXC network half, ADO covers the LXC core half. Two complementary slices, no further work needed on the ADO side. |
| **E4** | WSLC #12 | 1ES / pipeline agents | **Updated 2026-06-15 after on-runner probe** — GH-hosted `windows-latest` and `windows-2025` both expose `HypervisorPlatform`, `VirtualMachinePlatform`, and `Microsoft-Windows-Subsystem-Linux` as `Enabled`; `wsl --install -d Ubuntu --no-launch` succeeds in ~21–25 s and `wsl -d Ubuntu -- uname -a` returns a real `6.18.x-microsoft-standard-WSL2` kernel in ~7–8 s on top of that, so total zero-to-shell is ~28–33 s. ARM64 (`windows-11-arm`) is **not** capable (`HypervisorPlatform: Disabled`, WSL not preinstalled). The "likely a new dedicated agent pool" hedge was pessimistic — stock GH-hosted x64 runners are sufficient for the WSL2 + nested-virt half, and the only remaining gate is the `wslcsdk.dll` distribution channel that **E2** (public NuGet) is on track to close. ADO 1ES Windows pool is still untested but should reuse the same approach once E2 lands. Probe workflow preserved on branch `user/sodas/wslc-probe` for re-dispatch the moment the NuGet ships. |
| **E5** | Bwrap #13 | 1ES / pipeline agents | **Updated 2026-06-15 after on-runner probe** — `kernel.unprivileged_userns_clone=1` is present on every Ubuntu runner we probed, but Ubuntu 24.04 additionally sets `kernel.apparmor_restrict_unprivileged_userns=1` (added in 24.04, absent on 22.04) which silently breaks unprivileged `bwrap` with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` on both `ubuntu-latest` and `ubuntu-24.04-arm`. Two confirmed workarounds for CI: (a) keep running bwrap under `sudo -E` (the current GHA `SDK.Integration.Test.Job.yml` posture — root bypasses the AppArmor profile), or (b) `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` once in the workflow setup, which restores the unprivileged path (verified in the probe: `hello-from-bwrap-after-aa-flip` returned `uid=1001(runner)`). The codebase's bwrap test fleet does (a) today and is unaffected. **New observation from the same probe**: every GHA Linux runner is **IPv6 dual-stack** (`net.ipv6.conf.all.disable_ipv6=0`, eth0 carries a `fe80::/64` link-local, `getent ahostsv6 ipv6.google.com` resolves to `2607:f8b0:4004:c23::8b`), which makes **Bwrap #6-IPv6** (silent allowlist bypass on dual-stack hosts) a real exposure on the same runners we use for CI, not a hypothetical. Probe workflow preserved on branch `user/sodas/linux-runtime-probe`. |
| **E6** | Bwrap #14 | Repo admin | Create `Container-Bubblewrap` label (parity with `Container-WSLC`, `Container-Hyperlight`). |

### ⚠️ Upstream / kernel-evolution tracking (not a ship-blocker, but design must track external moving parts)

| Ref | Affected | What to track |
|---|---|---|
| **E7** | Bwrap #7 | Linux kernel keeps adding syscalls (`io_uring_*`, `clone3`, `pidfd_*`, `landlock_*`); the seccomp profile needs an upstream-syscall watch + refresh cadence, or it silently allows new attack surface and/or breaks new workloads. |
| **E8** | Bwrap #5 (eBPF option) | eBPF / CO-RE requires kernel ≥5.x with BTF — choosing eBPF over iptables/proxy locks in a kernel-version floor. The other two enforcement strategies have no such constraint. |
| **E9** | LXC #7, Bwrap #8 | cgroups v2 unified hierarchy — default on modern distros but Ubuntu < 22.04 / RHEL < 9 may still mount v1; need a fallback or a documented minimum-distro declaration. |
| **E10** | LXC #9 | System resolver semantics (`systemd-resolved` / `nscd` / DNS TTL) constrain how often hostnames can be re-resolved without thrashing the host resolver. |

### ⏳ Deferred pending external user demand

Items **LXC #5** (`allowLocalNetwork`) and **LXC #8** (nftables backend) are gated on a real user signal rather than an external party — see each item's own context blockquote for the deferral criteria.

---

## Notes

- **Issue tracking**: as of June 2026 the public repo has 5 open issues, all Windows process-container. None of the above are filed yet.
- **Promotion path**: Bubblewrap and WSLC are both still under `experimental` in the schema; see `docs/versioning.md` for the migration mechanics required for each promotion.
- **Labels**: re-use `Container-WSLC` and `Area-Executor-LXC`; propose adding `Container-Bubblewrap` (item Bwrap #14).
