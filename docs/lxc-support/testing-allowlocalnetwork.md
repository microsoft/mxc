# Testing the LXC `allowLocalNetwork` rule

Covers verification of the `network.allowLocalNetwork` schema field on the
**LXC backend** at two levels:

- **Unit tests** (no root, run anywhere) pin the exact `iptables` argument
  vectors emitted by `build_firewall_rules` — including the NEW-inbound verb
  this field controls, and that the chain is hooked into `INPUT`. Run them with
  `cargo test -p lxc_common network_iptables` (see §10).
- **A root runbook** (this document) applies the rules on a real Linux host and
  verifies them both by dumping the chain **inside the container's network
  namespace** and by connecting from a peer container, because the rule lives
  in the **container's `INPUT` chain**.

Branch under test: `user/dahoehna/HonoringInboundRule`.

---

## 1. What is being tested

`allowLocalNetwork` (the GA `ingress.hostLoopback` control) governs whether
**new inbound connections to the container's sockets** are accepted. The LXC
backend enforces it with a `--state NEW` rule in the container's chain, which is
hooked into the **container's `INPUT` chain** — applied inside the container's
network namespace via `nsenter -t <init-pid> -n iptables`:

| Config | Emitted NEW-inbound rule |
| --- | --- |
| `"allowLocalNetwork": true` | `iptables -A <chain> -m state --state NEW -j ACCEPT` |
| omitted / `false` (default) | `iptables -A <chain> -m state --state NEW -j DROP` |

Loopback is always accepted (`-i lo -j ACCEPT`, unconditional) and
established/related return traffic is accepted *before* the NEW rule, so the
field only gates genuinely new inbound flows and never breaks in-container
`127.0.0.1` or the container's own outbound replies. A **terminal `-j DROP`**
makes ingress default-deny regardless of the (egress) `defaultPolicy`.

- Rule construction: the pure `build_firewall_rules` in
  `src/backends/lxc/common/src/network_iptables.rs` (unit-tested; see §10).
- Rule application runs inside the container netns, after container start:
  `src/backends/lxc/common/src/lxc_runner.rs` discovers the container's init PID
  (`LxcContainer::init_pid`) and calls `set_netns_pid`, so every `iptables`
  invocation is prefixed with `nsenter -t <pid> -n`.
- The chain name is `MXC-` + the (sanitized, ≤20-char) `containerId`. For the
  bundled configs that is **`MXC-lxc-localnet-allow`** and
  **`MXC-lxc-localnet-deny`**.

## 2. Which paths the rule governs (read this first)

The rule lives in the **container's** `INPUT` chain, so it governs every packet
**destined to a container socket**, no matter where it came from. Per the Linux
`iptables(8)` semantics, `INPUT` handles "packets destined to local sockets" —
here, local to the container's netns. That has two consequences for testing:

- **Both host→container-direct and peer/routed inbound are governed.** A packet
  from the host to the container IP (host `OUTPUT` → routed across `lxcbr0` →
  container `INPUT`) and a packet from a peer container both land in the
  container's `INPUT` chain, so the `--state NEW` verb decides ACCEPT vs DROP in
  either case. This is the correct GA behavior and differs from the earlier
  host-`FORWARD` implementation, under which a host-direct probe was *not*
  governed.
- **The chain is not on the host.** Because the rules are installed inside the
  container's netns, a host-side `iptables -S MXC-<id>` shows **nothing**. You
  must enter the netns to dump them (`nsenter -t <init-pid> -n iptables -S`).

So there are two authoritative signals, both checked by the harness: dumping the
emitted rule from inside the netns (`nsenter … iptables -S <chain>`), and a
peer-container connect (inbound to the server container's `INPUT`).

## 3. Prerequisites — you need a real Linux host

LXC is Linux-native; it does **not** run on Windows directly. Pick one:

| Option | Notes |
| --- | --- |
| **WSL2 distro** (`wsl --install -d Ubuntu-24.04`, then enable `systemd` in `/etc/wsl.conf` and `wsl --shutdown`) | **Verified working for this test** — Ubuntu-24.04, systemd on, LXC 5.0.3, `lxc-net`/`lxcbr0` up; containers get `10.0.3.x` IPs. Uses only publicly available components (no internal tooling). |
| **Hyper-V Linux VM** (IxpTools `New-TestMachine`, or any Ubuntu VM) | Also reliable for LXC bridge/NAT networking. |

> The historical CI failure in `sdk/tests/integration/test_issues.md` ("LXC
> network tests fail in CI … lack network bridge/NAT config") was CI runners
> without a bridge/NAT config — a local WSL2 distro with `systemd` enabled does
> not hit that.

**Runtime packages on that Linux host** (confirmed by `README.md:34` — the lxc
backend needs "the lxc toolset"). `util-linux` provides `nsenter`, used to enter
the container netns:

```bash
sudo apt update
sudo apt install -y lxc lxc-utils iptables bridge-utils util-linux
sudo systemctl enable --now lxc-net     # brings up the lxcbr0 bridge
```

Everything below requires **root** (container management + entering the netns +
iptables).

> Note: `lxc-exec` shells out to the `lxc-*` CLI tools (`lxc-create`,
> `lxc-start`, `lxc-attach`, `lxc-info`, `lxc-stop`, `lxc-destroy` — see
> `lxc_bindings.rs`). `ldd lxc-exec` shows **no liblxc linkage**, so the copied
> binary needs no `liblxc` at runtime. (`build.sh` installs `liblxc-dev` at
> build time; the verified run had it installed.) Firewall rules use the
> **host's** `iptables` binary via `nsenter`, so no `iptables` need exist inside
> the container image.

## 4. Get `lxc-exec` onto the Linux host — two paths

`lxc-exec` (the `-p lxc` package binary) is pure Rust with no native-library
build dependency, so either path works.

### Path A — build on the Linux host

```bash
# in the repo, on the Linux host
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
./build.sh --rust-only          # or: cd src && cargo build --release -p lxc
# -> src/target/release/lxc-exec
```

### Path B — cross-compile on Windows, copy the binary in

`lxc-exec` cross-compiles cleanly to a static musl ELF (runs on any Linux). You
need a cross-linker on Windows; `cargo-zigbuild` is the no-Docker option:

```powershell
cd C:\git\mxc\src
rustup target add x86_64-unknown-linux-musl   # added to the pinned 1.93 toolchain
cargo install cargo-zigbuild
winget install -e --id zig.zig                # or: pip install ziglang
cargo zigbuild --release -p lxc --target x86_64-unknown-linux-musl
# -> src\target\x86_64-unknown-linux-musl\release\lxc-exec  (static ELF)
```

Copy that `lxc-exec` into the Linux host (e.g. via `/mnt/c/...` from WSL, `scp`,
or the VM push scripts) so the run script can find it under `src/target/...`.

## 5. The harness files (already in the repo)

| File | Role |
| --- | --- |
| `tests/helpers/netcheck/netcheck.rs` | std-only TCP probe. `serve --port P --hold S` binds `0.0.0.0:P`, replies `PONG`, self-exits after `hold` s. `connect --host H --port P --timeout S` exits 0 = reachable, 1 = blocked. |
| `tests/configs/lxc_local_network_allow.json` | `containerId: lxc-localnet-allow`, `allowLocalNetwork: true`. Alpine 3.23, bind-mounts `/opt/mxc-netcheck` ro, runs `netcheck serve --port 5000 --hold 20`. |
| `tests/configs/lxc_local_network_deny.json` | `containerId: lxc-localnet-deny`, omits `allowLocalNetwork` (default false). Otherwise identical. |
| `tests/scripts/run_lxc_local_network_test.sh` | Orchestrator. Root-gated. Builds `netcheck` static-musl, runs each config, then asserts `[RULE]` (netns chain dump) and `[BEHAVIOR]` (peer-container connect, inbound to the server's INPUT chain). |

The helper runs inside the **Alpine** (musl) sandbox, so it must be a static
musl binary. The script builds it with:
`rustc --edition 2021 -O --target x86_64-unknown-linux-musl -C target-feature=+crt-static`
(auto-adding the target if missing).

## 6. Run the harness

```bash
cd <repo>
sudo ./tests/scripts/run_lxc_local_network_test.sh
```

Per config it: launches `lxc-exec <config>`, waits for the container IP
(`lxc-info -iH -n <containerId>`), then:

- **`[RULE]`** — resolves the container's init PID (`lxc-info -pH -n
  <containerId>`), dumps `nsenter -t <pid> -n iptables -S MXC-<containerId>`,
  and asserts the NEW-inbound verb: `-m state --state NEW -j ACCEPT` (allow) /
  `-m state --state NEW -j DROP` (deny), plus an unconditional `-i lo -j
  ACCEPT`. Any mismatch fails the script.
- **`[BEHAVIOR]`** — launches a **peer container** that runs `netcheck connect`
  against the server container's IP. Peer→server traffic is inbound to the
  server container, so it traverses the server's governed `INPUT` chain and must
  be **reachable** for the allow config and **blocked** for the deny config. A
  decisive mismatch fails the script; if the peer container cannot start the
  layer reports `INCONCLUSIVE` (never a silent pass).

Expected: `[RULE] pass=2 fail=0` and `[BEHAVIOR] pass=2 fail=0` on a host with a
working LXC bridge (container→container forwarding).

## 7. Minimal manual check (no script)

If you just want the authoritative signal by hand — note the dump must run
**inside the container's netns**:

```bash
# allow case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_allow.json &
pid=$(lxc-info -pH -n lxc-localnet-allow | grep -oE '[0-9]+' | head -n1)
sudo nsenter -t "$pid" -n iptables -S MXC-lxc-localnet-allow | grep -- '--state NEW'
#   expect:  -A MXC-lxc-localnet-allow -m state --state NEW -j ACCEPT

# deny case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_deny.json &
pid=$(lxc-info -pH -n lxc-localnet-deny | grep -oE '[0-9]+' | head -n1)
sudo nsenter -t "$pid" -n iptables -S MXC-lxc-localnet-deny | grep -- '--state NEW'
#   expect:  -A MXC-lxc-localnet-deny -m state --state NEW -j DROP
```

A host-side `iptables -S MXC-…` (without `nsenter`) will show nothing — the
chain is in the container's netns, not on the host.

## 8. Known pitfalls

- **No `--state NEW` line at all** → the container didn't start, the init PID
  couldn't be resolved (so `nsenter` had no target), or the chain wasn't
  applied. Check `/tmp/netcheck_<containerId>.log`, confirm `lxc-info -n
  <containerId>` shows the container running, and that `lxc-info -pH -n
  <containerId>` returns a PID.
- **`nsenter` permission** → entering an unprivileged container's netns to write
  iptables requires the runner to be host-root with `CAP_NET_ADMIN` over the
  child namespace. Run the harness with `sudo`.
- **WSL2 bridge/NAT** → if the container never gets an IP, `lxc-net`/`lxcbr0`
  isn't up: `sudo systemctl start lxc-net` (requires `systemd` enabled in
  `/etc/wsl.conf` + `wsl --shutdown` to apply). Verified working on Ubuntu-24.04;
  the CI failure mode was runners without a bridge/NAT config.
- **Alpine = musl** → a glibc (`-gnu`) `netcheck` will not run in the sandbox;
  it must be static musl (the script handles this).
- **Chain names are derived from `containerId`** — if you change the configs'
  `containerId`, update the `MXC-<id>` target accordingly.

## 9. Source references

| Area | Location |
| --- | --- |
| Rule construction (pure, unit-tested) | `src/backends/lxc/common/src/network_iptables.rs` — `build_firewall_rules` |
| Chain-name sanitization (`MXC-` + ≤20 chars) | `src/backends/lxc/common/src/network_iptables.rs` — `new` |
| netns-scoped execution (`nsenter -t <pid> -n iptables`) | `src/backends/lxc/common/src/network_iptables.rs` — `run_iptables` |
| Init-PID discovery → netns target | `src/backends/lxc/common/src/lxc_runner.rs` (`init_pid()` → `set_netns_pid`) |
| Container init PID (`lxc-info -p`) | `src/backends/lxc/common/src/lxc_bindings.rs` — `init_pid` |
| Container IP discovery | `src/backends/lxc/common/src/lxc_runner.rs` (`lxc-info -iH`) |
| Linux build / run | `README.md`; `build.sh` |
| LXC network CI limitation | `sdk/tests/integration/test_issues.md` |

## 10. Unit tests (no root, run anywhere)

The emitted rule set is unit-tested directly against the pure
`build_firewall_rules`, mirroring how the other backends test their
policy→artifact builders (bubblewrap `build_args`, seatbelt `build_profile`):

```bash
cd src && cargo test -p lxc_common network_iptables
```

These assert, among other things, that `allowLocalNetwork: true` emits
`--state NEW -j ACCEPT` and the default emits `--state NEW -j DROP`, that
loopback is an unconditional ACCEPT, that `ESTABLISHED,RELATED` precedes the NEW
rule and the NEW rule precedes the terminal default, that the terminal default
is **always `DROP`** regardless of the egress `defaultPolicy`, and that the
`INPUT` hook is present only when a container-netns PID is known (and absent
otherwise, so the host's own `INPUT` is never touched). They need no root, no
`iptables`, and no DNS, so they run in CI on any host.
