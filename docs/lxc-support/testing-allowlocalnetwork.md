# Testing the LXC `allowLocalNetwork` rule

Covers verification of the `network.allowLocalNetwork` schema field on the
**LXC backend** at two levels:

- **Unit tests** (no root, run anywhere) pin the exact `iptables` argument
  vectors emitted by `build_firewall_rules` — including the NEW-inbound verb
  this field controls. Run them with
  `cargo test -p lxc_common network_iptables` (see §10).
- **A root runbook** (this document) applies the rules on a real Linux host and
  verifies them both by dumping the chain and by connecting over a *forwarded*
  path, because the rule lives in the host `FORWARD` chain.

Branch under test: `user/dahoehna/HonoringInboundRule`.

---

## 1. What is being tested

`allowLocalNetwork` controls whether **new inbound connections** forwarded to
the container are accepted. The LXC backend enforces it with a `--state NEW`
rule in the container's chain (which is hooked into the host `FORWARD` chain
with `-o <veth>`):

| Config | Emitted NEW-inbound rule |
| --- | --- |
| `"allowLocalNetwork": true` | `iptables -A <chain> -m state --state NEW -j ACCEPT` |
| omitted / `false` (default) | `iptables -A <chain> -m state --state NEW -j DROP` |

Loopback is always accepted (`-i lo -j ACCEPT`, unconditional) and
established/related return traffic is accepted *before* the NEW rule, so the
field only gates genuinely new inbound flows and never breaks in-container
`127.0.0.1` or the container's own outbound replies.

- Rule construction: the pure `build_firewall_rules` in
  `src/backends/lxc/common/src/network_iptables.rs` (unit-tested; see §10).
- Rule application is host-side, after container start:
  `src/backends/lxc/common/src/lxc_runner.rs:208-221`.
- The chain name is `MXC-` + the (sanitized, ≤20-char) `containerId`. For the
  bundled configs that is **`MXC-lxc-localnet-allow`** and
  **`MXC-lxc-localnet-deny`**.

## 2. Which paths the rule governs (read this first)

The rule lives in the **host** `FORWARD` chain, hooked by `-o <veth>`, so it
governs traffic **forwarded into** the container. That has two consequences for
how you test it:

- **A peer/routed source is governed.** Container→container traffic (and any
  externally-routed inbound) is forwarded by the host and hits the `-o <veth>`
  chain, so the `--state NEW` verb decides ACCEPT vs DROP. The behavioral layer
  below uses a **second (peer) container** as the client for exactly this
  reason.
- **A host→container *direct* connection is NOT governed.** Host-originated
  packets take the host `OUTPUT` path, not `FORWARD`, so probing the container
  IP straight from the host cannot distinguish allow vs deny — it would give
  false confidence. Do not use it as the signal.

So there are two authoritative signals, both checked by the harness: dumping the
emitted rule (`iptables -S <chain>`), and a peer-container connect over the
governed forwarded path.

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
backend needs "the lxc toolset"):

```bash
sudo apt update
sudo apt install -y lxc lxc-utils iptables bridge-utils
sudo systemctl enable --now lxc-net     # brings up the lxcbr0 bridge
```

Everything below requires **root** (container management + iptables).

> Note: `lxc-exec` shells out to the `lxc-*` CLI tools (`lxc-create`,
> `lxc-start`, `lxc-attach`, `lxc-info`, `lxc-stop`, `lxc-destroy` — see
> `lxc_bindings.rs`). `ldd lxc-exec` shows **no liblxc linkage**, so the copied
> binary needs no `liblxc` at runtime. (`build.sh` installs `liblxc-dev` at
> build time; the verified run had it installed.)

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
| `tests/scripts/run_lxc_local_network_test.sh` | Orchestrator. Root-gated. Builds `netcheck` static-musl, runs each config, then asserts `[RULE]` (chain dump) and `[BEHAVIOR]` (peer-container connect over the forwarded path). |

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

- **`[RULE]`** — dumps `iptables -S MXC-<containerId>` and asserts the
  NEW-inbound verb: `-m state --state NEW -j ACCEPT` (allow) /
  `-m state --state NEW -j DROP` (deny), plus an unconditional `-i lo -j
  ACCEPT`. Any mismatch fails the script.
- **`[BEHAVIOR]`** — launches a **peer container** that runs `netcheck connect`
  against the server container's IP. Because container→container traffic is
  forwarded, it traverses the governed `-o <veth>` chain, so it must be
  **reachable** for the allow config and **blocked** for the deny config. A
  decisive mismatch fails the script; if the peer container cannot start the
  layer reports `INCONCLUSIVE` (never a silent pass).

Expected: `[RULE] pass=2 fail=0` and `[BEHAVIOR] pass=2 fail=0` on a host with a
working LXC bridge (container→container forwarding).

## 7. Minimal manual check (no script)

If you just want the authoritative signal by hand:

```bash
# allow case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_allow.json &
sudo iptables -S MXC-lxc-localnet-allow | grep -- '--state NEW'
#   expect:  -A MXC-lxc-localnet-allow -m state --state NEW -j ACCEPT

# deny case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_deny.json &
sudo iptables -S MXC-lxc-localnet-deny | grep -- '--state NEW'
#   expect:  -A MXC-lxc-localnet-deny -m state --state NEW -j DROP
```

## 8. Known pitfalls

- **No `--state NEW` line at all** → the container didn't start or the chain
  wasn't applied. Check `/tmp/netcheck_<containerId>.log` and confirm `lxc-info
  -n <containerId>` shows the container running.
- **WSL2 bridge/NAT** → if the container never gets an IP, `lxc-net`/`lxcbr0`
  isn't up: `sudo systemctl start lxc-net` (requires `systemd` enabled in
  `/etc/wsl.conf` + `wsl --shutdown` to apply). Verified working on Ubuntu-24.04;
  the CI failure mode was runners without a bridge/NAT config.
- **Alpine = musl** → a glibc (`-gnu`) `netcheck` will not run in the sandbox;
  it must be static musl (the script handles this).
- **Chain names are derived from `containerId`** — if you change the configs'
  `containerId`, update the `iptables -S MXC-<id>` target accordingly.

## 9. Source references

| Area | Location |
| --- | --- |
| Rule construction (pure, unit-tested) | `src/backends/lxc/common/src/network_iptables.rs` — `build_firewall_rules` |
| Chain-name sanitization (`MXC-` + ≤20 chars) | `src/backends/lxc/common/src/network_iptables.rs` — `new` (`:28-33`) |
| Host-side rule application | `src/backends/lxc/common/src/lxc_runner.rs:208-221` |
| Container IP discovery | `src/backends/lxc/common/src/lxc_runner.rs:59` (`lxc-info -iH`) |
| CLI shell-out (no liblxc FFI) | `src/backends/lxc/common/src/lxc_bindings.rs:202,239,251,323,358,370` |
| Linux build / run | `README.md:70-72,96,152`; `build.sh` |
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
rule and the NEW rule precedes the terminal default, and that the FORWARD hook
is present only when a veth is known. They need no root, no `iptables`, and no
DNS, so they run in CI on any host.
