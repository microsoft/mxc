# Testing the LXC `allowLocalNetwork` rule

A runbook for manually verifying the `network.allowLocalNetwork` schema field on
the **LXC backend**. There is no unit test for this path — the rule is emitted
into host-side `iptables`, so it can only be verified on a real Linux host with
the `lxc` toolset installed. This document explains exactly what to do.

Branch under test: `user/dahoehna/HonoringInboundRule`.

---

## 1. What is being tested

`allowLocalNetwork` is enforced by the LXC backend as a single loopback rule:

| Config | Emitted rule |
| --- | --- |
| `"allowLocalNetwork": true` | `iptables -A <chain> -i lo -j ACCEPT` |
| omitted / `false` (default) | `iptables -A <chain> -i lo -j DROP` |

- Enforcement: `src/backends/lxc/common/src/network_iptables.rs` (verb flip
  `:157-173`, FORWARD hook `-o <veth>` `:257-261`, chain naming `:29-36`).
- Rule application is host-side, after container start:
  `src/backends/lxc/common/src/lxc_runner.rs:208-221`.
- The chain name is `MXC-` + the (sanitized, ≤20-char) `containerId`. For the
  bundled configs that is **`MXC-lxc-localnet-allow`** and
  **`MXC-lxc-localnet-deny`**.

## 2. What is actually observable today (read this first)

With the current code the rule is placed in the **host** `FORWARD` chain, hooked
by `-o <veth>`. Neither of these traverses that path:

- in-container `127.0.0.1` — the container has its own network namespace, so its
  loopback never reaches the host chain; and
- a host→container connection — that goes through the host `OUTPUT`/container
  `INPUT` path, not host `FORWARD`.

**Consequence:** the authoritative check today is **dumping the emitted rule**
(`iptables -S <chain>`), *not* a client/server connect. A behavioral connect
test cannot distinguish allow vs deny until an inbound rule is placed in the
container's `INPUT` path (which the `HonoringInboundRule` branch is expected to
add). The harness below reports both signals and labels which is authoritative.

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
| `tests/scripts/run_lxc_local_network_test.sh` | Orchestrator. Root-gated. Builds `netcheck` static-musl, runs each config, reports `[RULE]` + `[BEHAVIOR]`. |

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

- **`[RULE]`** — dumps `iptables -S MXC-<containerId>` and asserts `-i lo -j
  ACCEPT` (allow) / `-i lo -j DROP` (deny). **This is the pass/fail signal** and
  the script's exit code (0 = all rules matched).
- **`[BEHAVIOR]`** — connects from the host to the sandbox listener.
  Informational only: with the current code it will report **reachable for both**
  configs. It starts distinguishing allow/deny automatically once the inbound
  `INPUT`-path rule lands.

Expected today: `[RULE] pass=2 fail=0`.

## 7. Minimal manual check (no script)

If you just want the authoritative signal by hand:

```bash
# allow case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_allow.json &
sudo iptables -S MXC-lxc-localnet-allow | grep -- '-i lo'
#   expect:  -A MXC-lxc-localnet-allow -i lo -j ACCEPT

# deny case
sudo ./src/target/release/lxc-exec tests/configs/lxc_local_network_deny.json &
sudo iptables -S MXC-lxc-localnet-deny | grep -- '-i lo'
#   expect:  -A MXC-lxc-localnet-deny -i lo -j DROP
```

## 8. Known pitfalls

- **No `-i lo` line at all** → the container didn't start or the chain wasn't
  applied. Check `/tmp/netcheck_<containerId>.log` and confirm `lxc-info -n
  <containerId>` shows the container running.
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
| Rule verb flip / chain / FORWARD hook | `src/backends/lxc/common/src/network_iptables.rs:29-36,157-173,257-261` |
| Host-side rule application | `src/backends/lxc/common/src/lxc_runner.rs:208-221` |
| Container IP discovery | `src/backends/lxc/common/src/lxc_runner.rs:59` (`lxc-info -iH`) |
| CLI shell-out (no liblxc FFI) | `src/backends/lxc/common/src/lxc_bindings.rs:202,239,251,323,358,370` |
| Linux build / run | `README.md:70-72,96,152`; `build.sh` |
| LXC network CI limitation | `sdk/tests/integration/test_issues.md` |
