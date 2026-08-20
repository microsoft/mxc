// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rootless private networking for Bubblewrap proxy mode.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::unistd::{access, dup2, pipe2, AccessFlags};
use tempfile::TempDir;
use wxc_common::logger::Logger;
use wxc_common::models::ProxyAddress;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single `iptables` call may block on the host's `/run/xtables.lock`.
///
/// Only the legacy backend takes that lock, and `nsenter --net` leaves the mount
/// namespace alone, so there it is shared with every other sandbox. Waiting is
/// what makes concurrent provisioning work; the ceiling keeps a wedged lock from
/// hanging startup. `nf_tables` takes no lock and ignores the wait.
const XTABLES_LOCK_WAIT: Duration = Duration::from_secs(5);
/// Lock file the legacy `iptables` backend opens before touching any table.
/// `nf_tables` does not use it. See [`iptables_backend_is_usable`].
const XTABLES_LOCK_PATH: &str = "/run/xtables.lock";
/// Number of `iptables`/`ip6tables` calls the supervisor makes. Only used to
/// size the rule-installation budget, so it is asserted against the script.
const RULE_COMMAND_COUNT: u32 = 9;
/// Work the rule phase does beyond waiting on the lock: slirp coming up, plus
/// one `nsenter` launch per rule. Headroom only — the supervisor raises a single
/// signal for both phases, so they cannot be budgeted separately.
const RULE_INSTALL_OVERHEAD: Duration =
    Duration::from_secs(STARTUP_TIMEOUT.as_secs() + RULE_COMMAND_COUNT as u64);
/// Budget for bringing slirp up and installing every egress rule.
///
/// Covers the fully contended lock case plus [`RULE_INSTALL_OVERHEAD`], so a host
/// that legitimately consumes most of its `-w` allowance is not cut off just
/// short of finishing.
const RULE_INSTALL_TIMEOUT: Duration = Duration::from_secs(
    XTABLES_LOCK_WAIT.as_secs() * RULE_COMMAND_COUNT as u64 + RULE_INSTALL_OVERHEAD.as_secs(),
);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Ceiling for a single dependency probe. Generous next to a `--version` call,
/// which returns in milliseconds, so only a genuinely wedged binary trips it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SLIRP_HOST_GATEWAY: &str = "10.0.2.2";
/// Egress chain installed inside the sandbox's own network namespace.
const EGRESS_CHAIN: &str = "MXC_EGRESS";
/// Descriptor numbers the supervisor script hardcodes. They must stay single
/// digit and below [`FD_STAGING_BASE`]: dash cannot name a descriptor >= 10 in
/// a redirection, which is the whole reason the parent pins them.
const SUPERVISOR_PID_FD: RawFd = 3;
const SUPERVISOR_EXIT_FD: RawFd = 4;
/// Descriptors are staged above every target before being landed, so a source
/// already sitting on a target cannot be clobbered mid-remap.
const FD_STAGING_BASE: RawFd = 10;
/// Brings up the private network, then closes it down to the proxy before the
/// workload runs.
///
/// Ordering is the security property: the readiness signal is written only
/// after every rule is installed, and `set -e` turns a failed rule into
/// supervisor death rather than an unenforced sandbox. Rules are applied here
/// because that needs `CAP_NET_ADMIN` in the owning user namespace, which the
/// supervisor holds (`--keep-caps`) and the caller does not.
const SUPERVISOR_SCRIPT: &str = r#"
set -eu
state_dir="$1"
proxy_ip="$2"
proxy_port="$3"
chain="$4"
lock_wait="$5"
# Inherited descriptors are remapped to fixed numbers by the parent (see
# `remap_descriptors`): 3 is the parent's PID pipe, 4 is slirp's exit pipe.
# They are hardcoded rather than passed in argv because /bin/sh is dash on
# Debian/Ubuntu, which rejects a *variable* descriptor >= 10 ("Bad fd number")
# at parse time -- a failure that depends on how many files the parent happens
# to hold open, so it surfaces nondeterministically and never in unit tests.
printf ready > "$state_dir/userns.ready"
# Block on the parent-owned PID pipe rather than polling for a file: if the
# parent dies before it can publish the PID, the read ends at EOF and this
# supervisor exits instead of spinning forever as an orphan.
if ! IFS= read -r child_pid <&3; then
    child_pid="${child_pid:-}"
fi
exec 3<&-
if [ -z "$child_pid" ]; then
    echo "mxc: parent exited before publishing the sandbox PID" >&2
    exit 1
fi

# slirp signals readiness internally so the supervisor, not slirp, decides when
# the sandbox is ready -- the rules below must be in place first. Descriptor 9
# is safe to hardcode: the parent hands this child exactly 0-4, so nothing else
# can be sitting on it.
exec 9> "$state_dir/slirp.internal"
slirp4netns --configure --mtu=65520 \
    --ready-fd 9 --exit-fd 4 \
    "$child_pid" tap0 &
slirp_pid=$!
trap 'kill "$slirp_pid" 2>/dev/null || true' TERM INT
while [ ! -s "$state_dir/slirp.internal" ]; do
    if ! kill -0 "$slirp_pid" 2>/dev/null; then
        echo "slirp4netns exited before signalling readiness" >&2
        exit 1
    fi
    sleep 0.01
done

ns="/proc/$child_pid/ns/net"
# Deny-all-except-proxy. Loopback is exempt: it is the sandbox's own isolated
# loopback, so it never leaves the sandbox. Port 53 is deliberately not opened
# -- the proxy resolves on the workload's behalf, so an accept would only be a
# DNS-tunnel exfil path out of a proxy-only posture.
#
# -w matters only on the legacy backend, the one that takes a lock: nsenter
# enters the network namespace but not the mount namespace, so concurrent
# sandboxes contend for the *host's* /run/xtables.lock, and set -e turns a lost
# race into a dead supervisor. nf_tables takes no lock and ignores the wait.
# A backend that cannot take the lock at all is refused by probe_dependencies.
nsenter --net="$ns" -- iptables -w "$lock_wait" -N "$chain"
nsenter --net="$ns" -- iptables -w "$lock_wait" -A "$chain" -o lo -j ACCEPT
nsenter --net="$ns" -- iptables -w "$lock_wait" -A "$chain" -p tcp -d "$proxy_ip" --dport "$proxy_port" -j ACCEPT
nsenter --net="$ns" -- iptables -w "$lock_wait" -A "$chain" -j DROP
nsenter --net="$ns" -- iptables -w "$lock_wait" -A OUTPUT -j "$chain"
# The proxy rule is IPv4 only, so v6 carries its closing DROP alone: IPv6
# egress fails closed rather than being left open.
nsenter --net="$ns" -- ip6tables -w "$lock_wait" -N "$chain"
nsenter --net="$ns" -- ip6tables -w "$lock_wait" -A "$chain" -o lo -j ACCEPT
nsenter --net="$ns" -- ip6tables -w "$lock_wait" -A "$chain" -j DROP
nsenter --net="$ns" -- ip6tables -w "$lock_wait" -A OUTPUT -j "$chain"

# Signalled by path, not through a descriptor: this is a plain file the parent
# polls, so it needs no shell redirection and cannot hit dash's fd limit.
printf ready > "$state_dir/slirp.ready"
wait "$slirp_pid"
"#;

/// The single destination a proxy-only sandbox may reach.
///
/// Must be an IPv4 literal: rules are IPv4 `iptables`, and DNS is closed inside
/// the sandbox, so a hostname could not be resolved even if a rule existed for
/// its address. LXC solves that with a hosts-file pin; Bubblewrap has no
/// equivalent yet and fails closed instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyEgress {
    ip: std::net::Ipv4Addr,
    port: u16,
}

impl ProxyEgress {
    /// Derive the permitted endpoint from the sandbox-visible proxy address.
    pub(crate) fn from_address(address: &ProxyAddress) -> Result<Self, String> {
        let host = address.host().trim_matches(['[', ']']);
        let ip = host.parse::<std::net::Ipv4Addr>().map_err(|_| {
            format!(
                "Bubblewrap: proxy-only egress requires an IPv4 proxy endpoint, but the \
                 sandbox-visible proxy host is '{host}'. Proxy-only egress is enforced with \
                 IPv4 iptables rules and DNS is closed inside the sandbox, so a hostname or \
                 IPv6 endpoint cannot be reached. Use a loopback or IPv4 proxy address."
            )
        })?;
        if address.port() == 0 {
            return Err("Bubblewrap: proxy-only egress requires a non-zero proxy port".to_string());
        }
        Ok(Self {
            ip,
            port: address.port(),
        })
    }
}

/// Runtime file descriptors Bubblewrap needs while establishing its child.
pub(crate) struct BwrapStartup {
    info_reader: File,
    info_writer: Option<OwnedFd>,
    gate_reader: Option<OwnedFd>,
    gate_writer: Option<OwnedFd>,
    /// Descriptors bwrap must inherit, cleared of `FD_CLOEXEC` in the child
    /// only. See [`inherit_descriptors`].
    inheritable: Vec<RawFd>,
}

impl BwrapStartup {
    /// Arrange for bwrap -- and only bwrap -- to inherit the startup
    /// descriptors.
    pub(crate) fn prepare_command(&self, command: &mut Command) {
        inherit_descriptors(command, self.inheritable.clone());
    }

    /// Close the parent copies of the descriptors inherited by Bubblewrap.
    pub(crate) fn child_spawned(&mut self) {
        self.info_writer.take();
        self.gate_reader.take();
    }

    /// Wait for Bubblewrap to report the host-visible PID of its sandbox child.
    pub(crate) fn child_pid(&mut self, child: &mut Child) -> Result<u32, String> {
        set_nonblocking(self.info_reader.as_raw_fd())?;
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut json = Vec::new();
        let mut chunk = [0_u8; 512];

        loop {
            match self.info_reader.read(&mut chunk) {
                Ok(0) => {}
                Ok(count) => json.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => {
                    return Err(format!(
                        "Bubblewrap: failed to read bwrap child information: {error}"
                    ));
                }
            }

            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&json) {
                if let Some(pid) = value.get("child-pid").and_then(|pid| pid.as_u64()) {
                    return u32::try_from(pid).map_err(|_| {
                        format!("Bubblewrap: bwrap reported an out-of-range child PID: {pid}")
                    });
                }
                return Err(format!(
                    "Bubblewrap: bwrap child information omitted 'child-pid': {value}"
                ));
            }

            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("Bubblewrap: failed to inspect bwrap startup: {error}"))?
            {
                return Err(format!(
                    "Bubblewrap: bwrap exited before publishing child information ({status})"
                ));
            }
            if Instant::now() >= deadline {
                return Err("Bubblewrap: timed out waiting for bwrap child information".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Allow Bubblewrap to execute the workload after networking is ready.
    pub(crate) fn release(mut self) -> Result<(), String> {
        let writer = self
            .gate_writer
            .take()
            .ok_or_else(|| "Bubblewrap: workload startup gate is already closed".to_string())?;
        File::from(writer)
            .write_all(&[1])
            .map_err(|error| format!("Bubblewrap: failed to release workload startup: {error}"))
    }
}

/// A same-UID user-namespace supervisor and its `slirp4netns` process.
pub(crate) struct ProxyNetworkNamespace {
    state_dir: TempDir,
    supervisor: Child,
    exit_writer: Option<OwnedFd>,
    /// Write end of the pipe carrying the sandbox PID to the supervisor.
    /// Dropping it without writing ends the supervisor's wait at EOF.
    pid_writer: Option<OwnedFd>,
    /// Handle to the supervisor's user namespace, passed to bwrap as
    /// `--userns`. Released once bwrap owns it; see [`Self::userns_handed_off`].
    userns: Option<File>,
}

impl ProxyNetworkNamespace {
    /// Create the capability-retaining namespace supervisor.
    ///
    /// `egress` is the only destination the sandbox can reach once the
    /// supervisor signals readiness; everything else is dropped.
    ///
    /// Callers reach this only after `BwrapRunner::validate` has already run
    /// [`probe_dependencies`], so the probe is not repeated here.
    pub(crate) fn start(egress: &ProxyEgress, logger: &mut Logger) -> Result<Self, String> {
        let state_dir = tempfile::Builder::new()
            .prefix("mxc-bwrap-proxy-")
            .tempdir()
            .map_err(|error| {
                format!("Bubblewrap: failed to create proxy-network state: {error}")
            })?;
        let stderr_path = state_dir.path().join("supervisor.stderr");
        let stderr = File::create(&stderr_path).map_err(|error| {
            format!("Bubblewrap: failed to create proxy-network diagnostics: {error}")
        })?;
        let (exit_reader, exit_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;
        let (pid_reader, pid_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;

        let mut command = Command::new("unshare");
        command
            .args([
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--",
                "sh",
                "-c",
                SUPERVISOR_SCRIPT,
                "mxc-bwrap-proxy-supervisor",
            ])
            .arg(state_dir.path())
            .arg(egress.ip.to_string())
            .arg(egress.port.to_string())
            .arg(EGRESS_CHAIN)
            .arg(XTABLES_LOCK_WAIT.as_secs().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        // Both pipes stay CLOEXEC in this process, so a concurrent spawn from
        // another thread cannot inherit them; only the supervisor gets them,
        // and only at the fixed numbers its script names.
        remap_descriptors(
            &mut command,
            [
                (pid_reader.as_raw_fd(), SUPERVISOR_PID_FD),
                (exit_reader.as_raw_fd(), SUPERVISOR_EXIT_FD),
            ],
        );

        let mut supervisor = command.spawn().map_err(|error| {
            format!("Bubblewrap: failed to start proxy-network supervisor: {error}")
        })?;
        drop(exit_reader);
        drop(pid_reader);

        if let Err(error) = wait_for_file(
            state_dir.path().join("userns.ready"),
            &mut supervisor,
            &stderr_path,
            "user namespace startup",
            STARTUP_TIMEOUT,
        ) {
            terminate_child(&mut supervisor);
            return Err(error);
        }

        let userns_path = format!("/proc/{}/ns/user", supervisor.id());
        let userns = match File::open(&userns_path) {
            Ok(file) => file,
            Err(error) => {
                terminate_child(&mut supervisor);
                return Err(format!(
                    "Bubblewrap: failed to open proxy user namespace {userns_path}: {error}"
                ));
            }
        };
        logger.log_line("Bubblewrap: created rootless proxy network namespace supervisor");

        Ok(Self {
            state_dir,
            supervisor,
            exit_writer: Some(exit_writer),
            pid_writer: Some(pid_writer),
            userns: Some(userns),
        })
    }

    /// Add the dynamic namespace and startup-barrier descriptors to bwrap.
    pub(crate) fn configure_bwrap(&self, args: &mut Vec<String>) -> Result<BwrapStartup, String> {
        let (info_reader, info_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;
        let (gate_reader, gate_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;

        let userns = self
            .userns
            .as_ref()
            .ok_or_else(|| "Bubblewrap: proxy user namespace is already handed off".to_string())?;

        let runtime_args = [
            "--userns".to_string(),
            userns.as_raw_fd().to_string(),
            "--info-fd".to_string(),
            info_writer.as_raw_fd().to_string(),
            "--block-fd".to_string(),
            gate_reader.as_raw_fd().to_string(),
        ];
        args.splice(0..0, runtime_args);

        Ok(BwrapStartup {
            inheritable: vec![
                userns.as_raw_fd(),
                info_writer.as_raw_fd(),
                gate_reader.as_raw_fd(),
            ],
            info_reader: File::from(info_reader),
            info_writer: Some(info_writer),
            gate_reader: Some(gate_reader),
            gate_writer: Some(gate_writer),
        })
    }

    /// Drop this process's handle to the user namespace once bwrap holds it.
    ///
    /// The namespace itself stays alive through the supervisor, which is a
    /// member of it. Releasing here bounds the window in which a concurrent
    /// spawn could pick the descriptor up to the bwrap spawn itself, rather
    /// than the whole sandbox lifetime.
    pub(crate) fn userns_handed_off(&mut self) {
        self.userns.take();
    }

    /// Give the supervisor the Bubblewrap child PID and wait for slirp readiness.
    pub(crate) fn attach(&mut self, child_pid: u32, logger: &mut Logger) -> Result<(), String> {
        let mut writer = self
            .pid_writer
            .take()
            .map(File::from)
            .ok_or_else(|| "Bubblewrap: sandbox PID was already published".to_string())?;
        writer
            .write_all(format!("{child_pid}\n").as_bytes())
            .map_err(|error| format!("Bubblewrap: failed to publish bwrap child PID: {error}"))?;
        drop(writer);

        wait_for_file(
            self.state_dir.path().join("slirp.ready"),
            &mut self.supervisor,
            &self.state_dir.path().join("supervisor.stderr"),
            // Names both phases: this signal is written after slirp is up *and*
            // every egress rule is installed, so attributing a stall to
            // slirp alone would send the reader to the wrong place.
            "slirp4netns startup and egress rule installation",
            RULE_INSTALL_TIMEOUT,
        )?;
        logger.log_line(
            "Bubblewrap: slirp4netns configured the private proxy namespace and proxy-only \
             egress rules are in force",
        );
        Ok(())
    }

    /// Stop slirp and reap the namespace supervisor.
    pub(crate) fn stop(&mut self, logger: &mut Logger) {
        // Release the PID pipe too: a supervisor still waiting for the sandbox
        // PID sees EOF and exits rather than lingering.
        self.pid_writer.take();
        self.exit_writer.take();
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match self.supervisor.try_wait() {
                Ok(Some(status)) => {
                    // A clean teardown closes the exit pipe and slirp leaves
                    // with success. Anything else means it died on its own --
                    // and since slirp carries the sandbox's only route, that
                    // is otherwise indistinguishable from the workload's own
                    // network calls failing. Say so, with whatever it wrote.
                    if !status.success() {
                        logger.log_line(&format!(
                            "WARNING: Bubblewrap: proxy network supervisor exited with {status} \
                             ({})",
                            stderr_detail(&self.state_dir.path().join("supervisor.stderr"))
                        ));
                    }
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    logger.log_line(&format!(
                        "WARNING: Bubblewrap: slirp4netns did not stop promptly; terminating it \
                         ({})",
                        stderr_detail(&self.state_dir.path().join("supervisor.stderr"))
                    ));
                    terminate_child(&mut self.supervisor);
                    return;
                }
                Err(error) => {
                    logger.log_line(&format!(
                        "WARNING: Bubblewrap: failed to inspect slirp4netns shutdown: {error}"
                    ));
                    terminate_child(&mut self.supervisor);
                    return;
                }
            }
        }
    }
}

impl Drop for ProxyNetworkNamespace {
    fn drop(&mut self) {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.stop(&mut logger);
    }
}

/// Return the proxy endpoint visible through slirp's host gateway.
pub(crate) fn sandbox_proxy_address(address: &ProxyAddress) -> Result<ProxyAddress, String> {
    let host = address.host().trim_matches(['[', ']']);
    let parsed = host.parse::<std::net::IpAddr>().ok();

    // slirp's gateway reaches the host's *IPv4* loopback only. A proxy bound
    // to `::1` listens on the IPv6 loopback exclusively, so rewriting it to
    // the gateway would hand the sandbox an address nothing answers on --
    // failing at connect time rather than at policy time. Reject it instead.
    if matches!(parsed, Some(std::net::IpAddr::V6(ip)) if ip.is_loopback()) {
        return Err(format!(
            "Bubblewrap: proxy address '{}' uses the IPv6 loopback, which the private \
             network namespace cannot reach; bind the proxy to 127.0.0.1 or a dual-stack \
             wildcard address instead",
            address.host()
        ));
    }

    // `0.0.0.0` / `::` name the host itself just as `127.0.0.1` does: a proxy
    // bound to the wildcard is reachable on the host's loopback, which the
    // sandbox's private namespace cannot see. Both need the gateway rewrite.
    // `::` is safe to rewrite to IPv4 because a dual-stack wildcard listener
    // accepts IPv4 connections, which `::1` does not.
    let is_host_local = host.eq_ignore_ascii_case("localhost")
        || parsed.is_some_and(|ip| ip.is_loopback() || ip.is_unspecified());
    if !is_host_local {
        return Ok(address.clone());
    }

    if let Some(original_url) = &address.original_url {
        let mut url = url::Url::parse(original_url).map_err(|error| {
            format!("Bubblewrap: failed to translate proxy URL for private networking: {error}")
        })?;
        url.set_host(Some(SLIRP_HOST_GATEWAY)).map_err(|_| {
            "Bubblewrap: failed to translate proxy URL host for private networking".to_string()
        })?;
        return Ok(ProxyAddress::from_url(
            url.as_str(),
            SLIRP_HOST_GATEWAY.to_string(),
            address.port(),
        ));
    }

    Ok(ProxyAddress::new(
        SLIRP_HOST_GATEWAY.to_string(),
        address.port(),
    ))
}

/// Outcome of a bounded dependency probe.
#[derive(Debug)]
struct ProbeOutput {
    status: ExitStatus,
    stdout: String,
}

/// Run `command` to completion, killing it if it outlives [`PROBE_TIMEOUT`].
///
/// `Command::output()` waits forever. These probes run inside `validate`, so a
/// single wedged binary would stall every proxy-mode execution on the host with
/// no diagnostic -- a hang is far harder to chase than a failure, so bound it
/// and name the tool that stalled.
///
/// stdout is collected only after the child exits. That is safe for probes that
/// print a version banner or a help page (kilobytes, against a 64 KiB pipe
/// buffer); a probe whose output could fill the pipe would deadlock against
/// this wait and must drain the pipe concurrently instead.
fn run_probe(mut command: Command, label: &str) -> Result<ProbeOutput, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{error}"))?;

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                // Leaving it running would keep the pipe open and strand the
                // process for the lifetime of the host process.
                terminate_child(&mut child);
                return Err(format!(
                    "Bubblewrap: '{label}' did not respond within {PROBE_TIMEOUT:?}; \
                     the host's {label} installation appears to be hung"
                ));
            }
            Err(error) => {
                terminate_child(&mut child);
                return Err(format!("failed to inspect '{label}': {error}"));
            }
        }
    };

    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    Ok(ProbeOutput { status, stdout })
}

pub(crate) fn probe_dependencies() -> Result<(), String> {
    // Probing costs five subprocess spawns, and the host's tooling does not
    // change under a running process often enough to pay that on every
    // sandbox. Cache the *success* only: a failure is usually "the operator
    // has not installed slirp4netns yet", and caching that would keep failing
    // long after they did.
    static PROBED: OnceLock<()> = OnceLock::new();
    if PROBED.get().is_some() {
        return Ok(());
    }
    probe_dependencies_uncached()?;
    let _ = PROBED.set(());
    Ok(())
}

fn probe_dependencies_uncached() -> Result<(), String> {
    let mut slirp_command = Command::new("slirp4netns");
    slirp_command.arg("--version");
    let slirp = run_probe(slirp_command, "slirp4netns").map_err(|error| {
        format!(
            "Bubblewrap: network.proxy requires 'slirp4netns' on PATH: {error}. \
             Install slirp4netns or omit network.proxy."
        )
    })?;
    if !slirp.status.success() {
        return Err(format!(
            "Bubblewrap: network.proxy requires a working slirp4netns installation \
             (slirp4netns --version exited with {})",
            slirp.status
        ));
    }

    let mut unshare_command = Command::new("unshare");
    unshare_command.arg("--help");
    let unshare = run_probe(unshare_command, "unshare").map_err(|error| {
        format!("Bubblewrap: proxy networking requires util-linux 'unshare' on PATH: {error}")
    })?;
    if !unshare.status.success()
        || !unshare.stdout.contains("--map-current-user")
        || !unshare.stdout.contains("--keep-caps")
    {
        return Err(
            "Bubblewrap: proxy networking requires util-linux unshare with \
             --map-current-user and --keep-caps support"
                .into(),
        );
    }

    // Proxy-only egress is programmed with these, so a host missing them must
    // fail here rather than deep inside supervisor startup.
    for (binary, probe, has_backend) in [
        ("nsenter", "--version", false),
        ("iptables", "--version", true),
        ("ip6tables", "--version", true),
    ] {
        let mut command = Command::new(binary);
        command.arg(probe);
        let output = run_probe(command, binary).map_err(|error| {
            format!(
                "Bubblewrap: network.proxy requires '{binary}' on PATH to enforce proxy-only \
                 egress: {error}"
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "Bubblewrap: network.proxy requires a working '{binary}' installation \
                 ({binary} {probe} exited with {})",
                output.status
            ));
        }
        // Presence is not enough: the binary can work while its backend is one
        // this supervisor cannot drive.
        if has_backend {
            iptables_backend_is_usable(binary, &output.stdout, Path::new(XTABLES_LOCK_PATH))?;
        }
    }
    Ok(())
}

/// Whether `binary`'s backend can install rules from the unprivileged supervisor.
///
/// The supervisor runs under `unshare --user --map-current-user`, so it keeps the
/// caller's uid: its capabilities apply inside the new user namespace, not to
/// root-owned files in the initial one. The legacy backend opens
/// [`XTABLES_LOCK_PATH`] before touching any table, so on a stock host (root-owned
/// `/run`, no lock file) it fails with `EACCES` and `set -e` kills the supervisor
/// at the first rule. `nf_tables` takes no lock.
///
/// The banner alone cannot decide this: legacy *does* work where the lock is
/// reachable (as root, or with a writable lock). So the backend picks the
/// question, and for legacy the lock itself is tested.
fn iptables_backend_is_usable(binary: &str, banner: &str, lock: &Path) -> Result<(), String> {
    if banner.contains("nf_tables") {
        return Ok(());
    }
    if lock_is_writable(lock) {
        return Ok(());
    }

    // A pre-1.8 banner carries no marker at all; those builds are legacy-only.
    Err(format!(
        "Bubblewrap: network.proxy requires an iptables backend the sandbox supervisor can \
         drive without privilege, but '{binary}' resolves to the legacy backend ({}) and \
         '{}' is not writable by this user. Proxy-only egress rules are installed by an \
         unprivileged supervisor in a user namespace, which keeps the caller's uid, so the \
         root-owned lock is unreachable and every rule would fail. Select the nf_tables \
         backend (for example: update-alternatives --set {binary} /usr/sbin/{binary}-nft), \
         or make '{}' writable.",
        banner.trim(),
        lock.display(),
        lock.display()
    ))
}

/// Whether the legacy backend could take its lock as the current user.
///
/// The lock is created on first use, so an absent file makes the *directory* the
/// thing that must be writable. `access` tests the real uid — the uid the
/// supervisor itself runs under.
fn lock_is_writable(lock: &Path) -> bool {
    let target = if lock.exists() {
        lock
    } else {
        match lock.parent() {
            Some(parent) => parent,
            None => return false,
        }
    };
    access(target, AccessFlags::W_OK).is_ok()
}

/// Cap on how much component stderr is quoted into a diagnostic.
///
/// A wedged component can write without bound, and this is read from `Drop`, so
/// the read itself must be bounded rather than trimmed after the fact.
const MAX_STDERR_TAIL: u64 = 2048;

/// Last [`MAX_STDERR_TAIL`] bytes of `path`, phrased for an error message.
///
/// The tail, not the head: whatever actually killed the component is written
/// last, and a truncated head would quote its startup banner instead.
fn stderr_detail(path: &std::path::Path) -> String {
    let text = read_stderr_tail(path);
    let text = text.trim();
    if text.is_empty() {
        return "no stderr output".to_string();
    }
    format!("stderr: {text}")
}

fn read_stderr_tail(path: &std::path::Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    if len > MAX_STDERR_TAIL && file.seek(SeekFrom::End(-(MAX_STDERR_TAIL as i64))).is_err() {
        return String::new();
    }
    let mut buffer = Vec::new();
    if file.take(MAX_STDERR_TAIL).read_to_end(&mut buffer).is_err() {
        return String::new();
    }
    // Seeking to a byte offset can land mid-character; lossy keeps the rest
    // readable instead of discarding the whole tail.
    String::from_utf8_lossy(&buffer).into_owned()
}

fn wait_for_file(
    path: impl AsRef<std::path::Path>,
    child: &mut Child,
    stderr_path: &std::path::Path,
    component: &str,
    timeout: Duration,
) -> Result<(), String> {
    let path = path.as_ref();
    let deadline = Instant::now() + timeout;
    loop {
        if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            format!("Bubblewrap: failed to inspect {component} startup: {error}")
        })? {
            return Err(format!(
                "Bubblewrap: {component} exited during startup ({status}): {}",
                stderr_detail(stderr_path)
            ));
        }
        if Instant::now() >= deadline {
            // Include whatever the component wrote to stderr: on a timeout it
            // is usually the only evidence of *why* startup stalled, and the
            // process is still alive so no exit status will explain it.
            return Err(format!(
                "Bubblewrap: timed out waiting for {component} after {timeout:?} ({})",
                stderr_detail(stderr_path)
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Hand `fds` to one specific child, without exposing them process-wide.
///
/// `FD_CLOEXEC` is per-process, so clearing it on the parent's copy would leak
/// the descriptors to every concurrent `Command::spawn` -- a real window, since
/// this crate is reachable from the SDK and FFI. Clearing it in the forked child
/// instead gives them to the intended child and no one else.
///
/// The number is left as the OS assigned it, which is safe here because bwrap
/// receives it in argv (`--info-fd N`) and parses it as an integer. A child
/// that must *redirect* to the descriptor from a shell needs
/// [`remap_descriptors`] instead.
fn inherit_descriptors(command: &mut Command, fds: Vec<RawFd>) {
    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `fcntl` is async-signal-safe and
    // this closure allocates nothing -- `fds` is captured by move and holds
    // plain integers.
    unsafe {
        command.pre_exec(move || {
            for fd in &fds {
                fcntl(*fd, FcntlArg::F_SETFD(FdFlag::empty())).map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
}

/// Hand `mapping` to one specific child at fixed, known descriptor numbers.
///
/// Two problems are solved together. `FD_CLOEXEC` is per-process, so clearing
/// it on the parent's copy would leak the descriptors to every concurrent
/// `Command::spawn` -- a real window, since this crate is reachable from the
/// SDK and FFI. And an OS-assigned descriptor number cannot be named from
/// `/bin/sh`: dash rejects `>&$fd` and `<&$fd` for any descriptor >= 10 with
/// `Bad fd number` at *parse* time, so interpolating a raw number breaks the
/// supervisor as soon as the parent holds enough open files.
///
/// `dup2` in the forked child solves both: it clears `FD_CLOEXEC` on the new
/// descriptor only, and it puts that descriptor on a number the script can
/// hardcode. The originals stay CLOEXEC and close at exec.
fn remap_descriptors<const N: usize>(command: &mut Command, mapping: [(RawFd, RawFd); N]) {
    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `fcntl` and `dup2` are both
    // async-signal-safe and this closure allocates nothing -- `mapping` is a
    // fixed-size array of plain integers captured by move, and the staging
    // buffer is a fixed-size array too.
    unsafe {
        command.pre_exec(move || {
            // Stage every source above the target range before landing any of
            // them: a direct `dup2` could otherwise clobber a source that
            // happens to already sit on a later target.
            let mut staged = [-1; N];
            for (index, (source, _)) in mapping.iter().enumerate() {
                staged[index] = fcntl(*source, FcntlArg::F_DUPFD_CLOEXEC(FD_STAGING_BASE))
                    .map_err(std::io::Error::from)?;
            }
            for (index, (_, target)) in mapping.iter().enumerate() {
                dup2(staged[index], *target).map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), String> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|error| format!("Bubblewrap: failed to read descriptor flags: {error}"))?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map(|_| ())
        .map_err(|error| format!("Bubblewrap: failed to make descriptor nonblocking: {error}"))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_opens_the_translated_loopback_proxy() {
        // Rules must open the translated address, not the original loopback.
        let address = ProxyAddress::new("127.0.0.1".into(), 8080);
        let translated = sandbox_proxy_address(&address).unwrap();
        let egress = ProxyEgress::from_address(&translated).unwrap();

        assert_eq!(egress.ip.to_string(), SLIRP_HOST_GATEWAY);
        assert_eq!(egress.port, 8080);
    }

    #[test]
    fn egress_accepts_a_routable_ipv4_proxy() {
        let address = ProxyAddress::new("10.1.2.3".into(), 3128);
        let egress = ProxyEgress::from_address(&address).unwrap();

        assert_eq!(egress.ip.to_string(), "10.1.2.3");
        assert_eq!(egress.port, 3128);
    }

    #[test]
    fn egress_rejects_a_hostname_proxy() {
        // DNS is closed, so a name the workload cannot resolve must fail loudly
        // rather than yield a rule that is never reachable.
        let address = ProxyAddress::from_url(
            "http://proxy.corp.example:3128",
            "proxy.corp.example".into(),
            3128,
        );
        let error = ProxyEgress::from_address(&address).unwrap_err();

        assert!(
            error.contains("proxy.corp.example"),
            "error should name the offending host: {error}"
        );
        assert!(
            error.contains("IPv4"),
            "error should explain the IPv4 requirement: {error}"
        );
    }

    #[test]
    fn egress_rejects_an_ipv6_proxy() {
        // Rules are IPv4-only, so an IPv6 endpoint would never be opened.
        let routable = ProxyAddress::new("2001:db8::1".into(), 8080);
        assert!(ProxyEgress::from_address(&routable).is_err());
    }

    /// `::1` used to be rewritten to the IPv4 gateway, which handed the sandbox
    /// an address the proxy never listens on: an IPv6-loopback listener does
    /// not accept the IPv4 connection slirp's gateway produces. Rejecting at
    /// policy time beats failing at connect time.
    #[test]
    fn rejects_an_ipv6_loopback_proxy_instead_of_translating_it() {
        for host in ["[::1]", "::1"] {
            let address = ProxyAddress::new(host.into(), 8080);
            let error = sandbox_proxy_address(&address).unwrap_err();

            assert!(
                error.contains("IPv6 loopback"),
                "error should name the unreachable address family: {error}"
            );
        }
    }

    /// The rejection must not swallow `::`: a dual-stack wildcard listener does
    /// accept the gateway's IPv4 connection, so it still translates.
    #[test]
    fn ipv6_loopback_rejection_leaves_the_ipv6_wildcard_translatable() {
        let address = ProxyAddress::new("[::]".into(), 8080);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);
    }

    #[test]
    fn egress_rejects_a_zero_port() {
        let address = ProxyAddress::new("10.0.2.2".into(), 0);
        let error = ProxyEgress::from_address(&address).unwrap_err();

        assert!(
            error.contains("non-zero"),
            "error should explain the port requirement: {error}"
        );
    }

    /// The supervisor script with the lock-wait flag elided.
    ///
    /// The flag is an operational detail, not part of the egress policy these
    /// tests pin. Normalising it away keeps a change in lock handling from
    /// failing every ordering assertion -- while
    /// `every_rule_command_waits_for_the_xtables_lock` still asserts it is
    /// present on all of them.
    fn normalised_script() -> String {
        SUPERVISOR_SCRIPT.replace(r#" -w "$lock_wait""#, "")
    }

    /// Byte offset of `needle` in the normalised supervisor script.
    fn script_offset(needle: &str) -> usize {
        normalised_script()
            .find(needle)
            .unwrap_or_else(|| panic!("supervisor script should contain {needle:?}"))
    }

    #[test]
    fn script_accepts_the_proxy_before_dropping() {
        // iptables is first-match: a DROP appended ahead of the proxy ACCEPT
        // would black-hole the proxy itself.
        let accept = script_offset(r#"-p tcp -d "$proxy_ip" --dport "$proxy_port" -j ACCEPT"#);
        let loopback = script_offset(r#"iptables -A "$chain" -o lo -j ACCEPT"#);
        let drop = script_offset(r#"iptables -A "$chain" -j DROP"#);

        assert!(loopback < accept, "loopback accept must come first");
        assert!(accept < drop, "proxy accept must precede the closing drop");
    }

    #[test]
    fn script_signals_readiness_only_after_rules_are_installed() {
        // The caller releases the workload on this signal, so emitting it early
        // would let the workload run with egress wide open.
        let last_rule = script_offset(r#"ip6tables -A OUTPUT -j "$chain""#);
        let ready = script_offset(r#"printf ready > "$state_dir/slirp.ready""#);

        assert!(
            last_rule < ready,
            "readiness must be signalled after the final rule"
        );
    }

    #[test]
    fn script_does_not_open_dns() {
        // Deliberate: the proxy resolves on the workload's behalf, so an
        // unscoped port 53 accept would only be an exfil path. Pinning the full
        // accept set catches any widening, not just DNS.
        let accepts: Vec<String> = normalised_script()
            .lines()
            .filter(|line| line.contains("-j ACCEPT"))
            .map(str::to_owned)
            .collect();

        assert_eq!(
            accepts,
            vec![
                r#"nsenter --net="$ns" -- iptables -A "$chain" -o lo -j ACCEPT"#,
                r#"nsenter --net="$ns" -- iptables -A "$chain" -p tcp -d "$proxy_ip" --dport "$proxy_port" -j ACCEPT"#,
                r#"nsenter --net="$ns" -- ip6tables -A "$chain" -o lo -j ACCEPT"#,
            ],
            "only loopback and the proxy endpoint may be accepted"
        );
    }

    #[test]
    fn script_fails_ipv6_closed() {
        let v6_drop = script_offset(r#"ip6tables -A "$chain" -j DROP"#);
        let v6_hook = script_offset(r#"ip6tables -A OUTPUT -j "$chain""#);

        assert!(v6_drop < v6_hook, "v6 chain must drop before being hooked");
        assert!(
            !normalised_script().contains(r#"ip6tables -A "$chain" -p tcp"#),
            "v6 must not carry a proxy accept"
        );
    }

    #[test]
    fn script_hooks_both_chains_into_output() {
        // An unhooked chain is never consulted and enforces nothing.
        script_offset(r#"iptables -A OUTPUT -j "$chain""#);
        script_offset(r#"ip6tables -A OUTPUT -j "$chain""#);
    }

    #[test]
    fn script_installs_rules_synchronously() {
        // Offset-based ordering assertions only hold if the rules run inline.
        // Backgrounding any of them would satisfy those tests while destroying
        // the guarantee that rules precede readiness.
        let rules_start = script_offset(r#"nsenter --net="$ns" -- iptables -N "$chain""#);
        let ready = script_offset(r#"printf ready > "$state_dir/slirp.ready""#);
        let script = normalised_script();
        let region = &script[rules_start..ready];

        for line in region.lines().filter(|line| line.contains("nsenter")) {
            assert!(
                !line.trim_end().ends_with('&'),
                "rule must not be backgrounded: {line}"
            );
            assert!(
                !line.contains('('),
                "rule must not run in a subshell: {line}"
            );
        }
    }

    #[test]
    fn translates_loopback_proxy_to_slirp_gateway() {
        let address = ProxyAddress::new("127.0.0.1".into(), 8080);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.port(), 8080);
        assert_eq!(translated.to_url(), "http://10.0.2.2:8080");
    }

    #[test]
    fn translates_loopback_url_without_losing_url_components() {
        let address = ProxyAddress::from_url("http://localhost:3128/", "localhost".into(), 3128);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.port(), 3128);
        assert_eq!(translated.to_url(), "http://10.0.2.2:3128/");
    }

    #[test]
    fn leaves_remote_proxy_unchanged() {
        let address =
            ProxyAddress::from_url("https://proxy.example:8443", "proxy.example".into(), 8443);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.to_url(), address.to_url());
    }

    /// A proxy bound to the wildcard address is reachable on the host's
    /// loopback, which the sandbox's private namespace cannot see, so it needs
    /// the same gateway rewrite `127.0.0.1` gets.
    #[test]
    fn translates_wildcard_proxy_to_slirp_gateway() {
        let address = ProxyAddress::new("0.0.0.0".into(), 8080);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.port(), 8080);
    }

    #[test]
    fn translates_bracketed_ipv6_wildcard_proxy_to_slirp_gateway() {
        let address = ProxyAddress::from_url("http://[::]:3128/", "[::]".into(), 3128);
        let translated = sandbox_proxy_address(&address).unwrap();

        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.port(), 3128);
        assert_eq!(translated.to_url(), "http://10.0.2.2:3128/");
    }

    /// The descriptor must reach the child that was prepared and no other. The
    /// obvious alternative -- clearing `FD_CLOEXEC` on the parent's copy --
    /// passes the first assertion and fails the other two.
    #[test]
    fn inherited_descriptors_reach_only_the_prepared_child() {
        let (reader, _writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let fd = reader.as_raw_fd();
        let probe = format!("test -e /proc/self/fd/{fd} && echo present || echo absent");

        let mut prepared = Command::new("sh");
        prepared.arg("-c").arg(&probe);
        inherit_descriptors(&mut prepared, vec![fd]);
        let prepared_out = prepared.output().expect("spawn prepared child");

        let bystander = Command::new("sh")
            .arg("-c")
            .arg(&probe)
            .output()
            .expect("spawn bystander child");

        assert_eq!(
            String::from_utf8_lossy(&prepared_out.stdout).trim(),
            "present",
            "the prepared child did not inherit the descriptor"
        );
        assert_eq!(
            String::from_utf8_lossy(&bystander.stdout).trim(),
            "absent",
            "an unrelated child inherited the descriptor"
        );

        let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).expect("F_GETFD"));
        assert!(
            flags.contains(FdFlag::FD_CLOEXEC),
            "the parent's own descriptor was left inheritable"
        );
    }

    /// Regression for the defect this scheme exists to prevent: dash rejects a
    /// redirection to a *variable* descriptor >= 10 at parse time, so the old
    /// `eval "... >&$fd"` form failed based on how many files the parent
    /// happened to hold open. Remapping must land the pipe on a fixed low
    /// number regardless of what the OS originally assigned.
    #[test]
    fn remapped_descriptors_land_on_fixed_numbers_from_any_source() {
        // Force a high source number -- the exact case the old scheme broke on.
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let high = fcntl(reader.as_raw_fd(), FcntlArg::F_DUPFD_CLOEXEC(20)).expect("dup high");
        assert!(high >= 20, "test needs a two-digit source descriptor");

        File::from(writer).write_all(b"4242\n").expect("write pid");

        let mut command = Command::new("sh");
        command
            .arg("-c")
            // Reads through the *literal* descriptor the script hardcodes.
            .arg(format!(
                "IFS= read -r v <&{SUPERVISOR_PID_FD}; printf %s \"$v\""
            ));
        remap_descriptors(&mut command, [(high, SUPERVISOR_PID_FD)]);

        let out = command.output().expect("spawn remapped child");
        assert!(
            out.status.success(),
            "remapped child failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "4242",
            "the pipe did not arrive on the fixed descriptor"
        );
    }

    /// A source already sitting on another mapping's target must survive the
    /// remap. A naive sequential `dup2` clobbers it and this catches that.
    #[test]
    fn remapping_survives_a_source_already_on_a_target_number() {
        let (a_reader, a_writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let (b_reader, b_writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let a = a_reader.as_raw_fd();
        let b = b_reader.as_raw_fd();

        File::from(a_writer).write_all(b"AAA\n").expect("write a");
        File::from(b_writer).write_all(b"BBB\n").expect("write b");

        // The second mapping's source is the first mapping's target, so a
        // sequential `dup2` would overwrite `b` before it had been landed.
        let mapping = [(a, b), (b, SUPERVISOR_PID_FD)];

        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "printf 'first=%s second=%s' \
             \"$(cat /proc/self/fd/{b})\" \"$(cat /proc/self/fd/{SUPERVISOR_PID_FD})\""
        ));
        remap_descriptors(&mut command, mapping);

        let out = command.output().expect("spawn remapped child");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "first=AAA second=BBB",
            "a source sitting on another target was clobbered during remap"
        );
    }

    /// The supervisor runs under `/bin/sh`, which is dash on Debian/Ubuntu.
    /// Parse it with the real shell so a construct dash rejects cannot ship.
    #[test]
    fn supervisor_script_parses_under_the_shell_that_runs_it() {
        let out = Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(SUPERVISOR_SCRIPT)
            .output()
            .expect("spawn sh");

        assert!(
            out.status.success(),
            "supervisor script is not valid /bin/sh: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The script may only name descriptors the parent actually pins. Two
    /// forms are banned: `>&$var`, which broke on dash for fd >= 10, and
    /// `{var}>`, the varfd allocation the review proposed as a fix — dash
    /// *parses* that as a plain word, so it fails silently rather than loudly
    /// and `sh -n` cannot catch it.
    #[test]
    fn supervisor_script_never_redirects_to_a_variable_descriptor() {
        for line in SUPERVISOR_SCRIPT.lines() {
            let code = line.trim();
            if code.starts_with('#') {
                continue;
            }
            assert!(
                !code.contains(">&$") && !code.contains("<&$"),
                "variable descriptor redirection breaks dash for fd >= 10: {code}"
            );
            assert!(
                !code.contains("}>") && !code.contains("}<"),
                "varfd allocation is a bash-ism; dash parses it as a word: {code}"
            );
        }
    }

    /// Every rule call must wait for the shared host lock. One unguarded call
    /// is enough to fail a concurrent launch under `set -e`.
    #[test]
    fn every_rule_command_waits_for_the_xtables_lock() {
        let rules: Vec<&str> = SUPERVISOR_SCRIPT
            .lines()
            .filter(|line| {
                let code = line.trim();
                !code.starts_with('#') && code.contains("tables ")
            })
            .collect();

        assert_eq!(
            rules.len() as u32,
            RULE_COMMAND_COUNT,
            "RULE_COMMAND_COUNT is stale, so the rule-install budget is wrong"
        );
        for rule in rules {
            assert!(
                rule.contains(r#"-w "$lock_wait""#),
                "rule may fail instantly on a contended host lock: {rule}"
            );
        }
    }

    /// Equality with the lock sum is not enough: the same deadline also spans
    /// slirp startup and one process launch per rule.
    #[test]
    fn rule_install_budget_covers_every_command_blocking_on_the_lock() {
        let contended = XTABLES_LOCK_WAIT * RULE_COMMAND_COUNT;
        assert!(
            RULE_INSTALL_TIMEOUT > contended,
            "a fully contended host would time out before -w could succeed"
        );
        assert!(
            RULE_INSTALL_TIMEOUT - contended >= STARTUP_TIMEOUT,
            "the budget leaves no room for slirp startup on top of lock contention"
        );
        assert!(
            RULE_INSTALL_TIMEOUT - contended - STARTUP_TIMEOUT
                >= Duration::from_secs(RULE_COMMAND_COUNT as u64),
            "the budget leaves no room to spawn one nsenter per rule"
        );
    }

    #[test]
    fn probe_gives_up_on_a_hung_binary_instead_of_blocking_forever() {
        let mut command = Command::new("sleep");
        command.arg("120");

        let started = Instant::now();
        let error = run_probe(command, "wedged-tool").expect_err("a hung probe must not succeed");
        let elapsed = started.elapsed();

        assert!(
            error.contains("wedged-tool"),
            "the error must name the tool that hung, got: {error}"
        );
        // The point of the change: bounded, not merely eventual. `sleep 120`
        // would blow this budget by two orders of magnitude if unbounded.
        assert!(
            elapsed < PROBE_TIMEOUT * 3,
            "probe took {elapsed:?}, expected to give up near {PROBE_TIMEOUT:?}"
        );
    }

    #[test]
    fn probe_returns_stdout_of_a_well_behaved_binary() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo probe-stdout-marker"]);

        let probe = run_probe(command, "echo").expect("a fast probe must succeed");

        assert!(
            probe.status.success(),
            "expected success, got {:?}",
            probe.status
        );
        assert!(
            probe.stdout.contains("probe-stdout-marker"),
            "stdout was not captured, got: {:?}",
            probe.stdout
        );
    }

    #[test]
    fn probe_reports_a_failing_binary_without_treating_it_as_a_hang() {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 3"]);

        let probe = run_probe(command, "failing").expect("a clean non-zero exit is not an error");

        assert!(!probe.status.success(), "expected a non-zero exit status");
    }

    /// A path whose parent does not exist, standing in for the root-owned `/run`
    /// an unprivileged supervisor meets. Keeps the test deterministic and
    /// root-free while hitting the same branch.
    fn unreachable_lock(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("no-such-dir").join("xtables.lock")
    }

    /// Verified live: with the lock absent and `/run` unwritable, `iptables-nft
    /// -N` still succeeds.
    #[test]
    fn the_nft_backend_is_accepted_even_when_the_lock_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            iptables_backend_is_usable(
                "iptables",
                "iptables v1.8.10 (nf_tables)\n",
                &unreachable_lock(&dir)
            )
            .is_ok(),
            "the nf_tables backend takes no lock, so an unreachable lock must not refuse it"
        );
    }

    /// The regression this check exists for: legacy opens the lock
    /// unconditionally, so the supervisor dies at the first rule.
    #[test]
    fn the_legacy_backend_is_refused_when_it_could_not_take_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");

        let error = iptables_backend_is_usable(
            "iptables",
            "iptables v1.8.10 (legacy)\n",
            &unreachable_lock(&dir),
        )
        .expect_err("a legacy backend with an unreachable lock cannot install rules");

        assert!(
            error.contains("iptables") && error.contains("nf_tables"),
            "the error must name the binary and the backend to switch to: {error}"
        );
    }

    /// Legacy is refused for being unable to take its lock, not for being
    /// legacy: it works as root, and rejecting that would break a valid host.
    #[test]
    fn the_legacy_backend_is_accepted_when_the_lock_is_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("xtables.lock");
        fs::write(&lock, b"").expect("create lock");

        assert!(
            iptables_backend_is_usable("iptables", "iptables v1.8.10 (legacy)\n", &lock).is_ok(),
            "a legacy backend that can take its lock installs rules fine"
        );
    }

    /// The lock is created on first use, so the check must ask about the
    /// directory rather than report the absent file as a failure.
    #[test]
    fn an_absent_lock_in_a_writable_directory_is_usable() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            lock_is_writable(&dir.path().join("xtables.lock")),
            "the lock is created on demand, so a writable directory is enough"
        );
    }

    /// Pre-1.8 builds print no backend marker and are legacy-only, so an
    /// unmarked banner must not be assumed usable.
    #[test]
    fn a_banner_without_a_backend_marker_is_treated_as_legacy() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            iptables_backend_is_usable("iptables", "iptables v1.6.1\n", &unreachable_lock(&dir))
                .is_err(),
            "a pre-1.8 build is legacy-only and must not be assumed usable"
        );
    }

    #[test]
    fn stderr_detail_keeps_the_tail_and_stays_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.stderr");
        // The interesting line is last; everything before it is noise that must
        // not push it out of the quoted region.
        let mut noise = "x".repeat(MAX_STDERR_TAIL as usize * 4);
        noise.push_str("\nfatal: the-actual-failure\n");
        fs::write(&path, &noise).expect("write stderr");

        let detail = stderr_detail(&path);

        assert!(
            detail.contains("fatal: the-actual-failure"),
            "the tail (where the failure is) was dropped: {detail}"
        );
        assert!(
            detail.len() <= MAX_STDERR_TAIL as usize + 64,
            "quoted stderr was not bounded, got {} bytes",
            detail.len()
        );
    }

    #[test]
    fn stderr_detail_reports_absence_rather_than_an_empty_string() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        assert_eq!(stderr_detail(&missing), "no stderr output");

        let empty = dir.path().join("empty.stderr");
        fs::write(&empty, "   \n").expect("write stderr");
        assert_eq!(stderr_detail(&empty), "no stderr output");
    }

    /// Counts the rule commands and fails the one named by `MXC_TEST_FAIL_AT`.
    /// The real `nsenter` needs a live namespace and `CAP_SYS_ADMIN`; the
    /// script only cares whether it succeeded.
    const FAKE_NSENTER: &str = r#"#!/bin/sh
count=$(cat "$MXC_TEST_COUNT" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s' "$count" > "$MXC_TEST_COUNT"
if [ "${MXC_TEST_FAIL_AT:-0}" = "$count" ]; then
    echo "fake nsenter: forced failure on rule $count" >&2
    exit 1
fi
exit 0
"#;

    /// Signals readiness on the descriptor the supervisor opened for it (9),
    /// then idles so the supervisor's `wait` has something to wait on.
    const FAKE_SLIRP: &str = r#"#!/bin/sh
echo $$ > "$MXC_TEST_SLIRP_PID"
if [ "${MXC_TEST_SLIRP_DIES:-0}" = "1" ]; then
    echo "fake slirp4netns: exiting before readiness" >&2
    exit 1
fi
printf ready >&9
exec sleep 30
"#;

    /// The supervisor script running for real against fake tools.
    ///
    /// The six text-matching tests above assert what the script *says*; they
    /// cannot assert what it *does*. This runs it under the same `sh` a host
    /// would use, with `nsenter`/`slirp4netns` replaced by stubs that can fail
    /// on demand, so the fail-closed ordering can be observed rather than read.
    struct FakeSupervisor {
        dir: TempDir,
        child: Child,
        pid_writer: Option<File>,
        _exit_writer: OwnedFd,
    }

    impl FakeSupervisor {
        fn state_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("state")
        }

        /// How many rule commands actually ran.
        fn rule_invocations(&self) -> u32 {
            fs::read_to_string(self.dir.path().join("rules.count"))
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)
        }

        /// Whether the supervisor told the parent the sandbox is enforced.
        fn signalled_ready(&self) -> bool {
            self.state_dir().join("slirp.ready").exists()
        }

        fn stderr(&self) -> String {
            stderr_detail(&self.dir.path().join("supervisor.stderr"))
        }

        /// Hand over a sandbox PID, as the parent does once bwrap is up.
        fn publish_sandbox_pid(&mut self) {
            let mut writer = self.pid_writer.take().expect("pid writer");
            writer.write_all(b"4242\n").expect("publish pid");
        }

        /// Close the PID pipe without writing, as a parent that died would.
        fn abandon_without_publishing_pid(&mut self) {
            drop(self.pid_writer.take());
        }

        fn wait_for_exit(&mut self) -> ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    return status;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "supervisor did not exit; stderr: {}, rules run: {}",
                self.stderr(),
                self.rule_invocations()
            );
        }

        fn wait_until_ready(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if self.signalled_ready() {
                    return;
                }
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    panic!(
                        "supervisor exited ({status}) without signalling readiness; \
                         stderr: {}, rules run: {}",
                        self.stderr(),
                        self.rule_invocations()
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "supervisor never signalled readiness; stderr: {}",
                self.stderr()
            );
        }
    }

    impl Drop for FakeSupervisor {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // `set -e` bypasses the script's TERM trap, so a stub left running
            // by an aborted supervisor has to be reaped here.
            if let Ok(pid) = fs::read_to_string(self.dir.path().join("slirp.pid")) {
                let pid = pid.trim();
                if !pid.is_empty() {
                    let _ = Command::new("kill")
                        .args(["-9", pid])
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }

    fn install_stub(path: &std::path::Path, body: &str) {
        fs::write(path, body).expect("write stub");
        let mut perms = fs::metadata(path).expect("stat stub").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(path, perms).expect("chmod stub");
    }

    fn spawn_fake_supervisor(fail_at: Option<u32>, slirp_dies: bool) -> FakeSupervisor {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        let state = dir.path().join("state");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::create_dir_all(&state).expect("state dir");
        install_stub(&bin.join("nsenter"), FAKE_NSENTER);
        install_stub(&bin.join("slirp4netns"), FAKE_SLIRP);

        let stderr = File::create(dir.path().join("supervisor.stderr")).expect("stderr");
        let (exit_reader, exit_writer) = pipe2(OFlag::O_CLOEXEC).expect("exit pipe");
        let (pid_reader, pid_writer) = pipe2(OFlag::O_CLOEXEC).expect("pid pipe");

        // The stubs shadow the real tools; the rest of PATH still supplies the
        // coreutils the script uses (`sleep`, `cat`).
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("sh");
        command
            .args(["-c", SUPERVISOR_SCRIPT, "mxc-test-supervisor"])
            .arg(&state)
            .arg("10.0.2.2")
            .arg("3128")
            .arg("mxc-test-chain")
            .arg("1")
            .env("PATH", path)
            .env("MXC_TEST_COUNT", dir.path().join("rules.count"))
            .env("MXC_TEST_SLIRP_PID", dir.path().join("slirp.pid"))
            .env(
                "MXC_TEST_FAIL_AT",
                fail_at.map(|n| n.to_string()).unwrap_or_default(),
            )
            .env("MXC_TEST_SLIRP_DIES", if slirp_dies { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        remap_descriptors(
            &mut command,
            [
                (pid_reader.as_raw_fd(), SUPERVISOR_PID_FD),
                (exit_reader.as_raw_fd(), SUPERVISOR_EXIT_FD),
            ],
        );
        let child = command.spawn().expect("spawn supervisor");
        drop(exit_reader);
        drop(pid_reader);

        FakeSupervisor {
            dir,
            child,
            pid_writer: Some(File::from(pid_writer)),
            _exit_writer: exit_writer,
        }
    }

    /// Executing the script also re-checks [`RULE_COMMAND_COUNT`] against the
    /// number of commands that actually run, which the text-offset tests can
    /// only approximate.
    #[test]
    fn the_supervisor_signals_readiness_only_after_every_rule_is_installed() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert_eq!(
            supervisor.rule_invocations(),
            RULE_COMMAND_COUNT,
            "readiness was signalled after a different number of rules than the \
             startup budget is sized for; stderr: {}",
            supervisor.stderr()
        );
    }

    /// The fail-closed guarantee of the whole feature: a rule that does not
    /// install must take the supervisor down *before* readiness, so the parent
    /// never releases a sandbox whose egress is unenforced.
    ///
    /// Asserting it for every rule position is the point. A future edit that
    /// moves one command into a pipeline, an `if` condition or a subshell
    /// escapes `set -e` and would start an unenforced sandbox while every
    /// text-matching test above stayed green.
    #[test]
    fn a_failed_rule_kills_the_supervisor_instead_of_signalling_readiness() {
        for rule in 1..=RULE_COMMAND_COUNT {
            let mut supervisor = spawn_fake_supervisor(Some(rule), false);
            supervisor.publish_sandbox_pid();
            let status = supervisor.wait_for_exit();

            assert!(
                !status.success(),
                "rule {rule} failed but the supervisor exited successfully; stderr: {}",
                supervisor.stderr()
            );
            assert!(
                !supervisor.signalled_ready(),
                "rule {rule} failed yet the sandbox was signalled ready -- it would \
                 have run with unenforced egress"
            );
            assert_eq!(
                supervisor.rule_invocations(),
                rule,
                "rule {rule} failed but the script carried on installing rules"
            );
        }
    }

    #[test]
    fn the_supervisor_gives_up_when_slirp_dies_before_signalling_readiness() {
        let mut supervisor = spawn_fake_supervisor(None, true);
        supervisor.publish_sandbox_pid();
        let status = supervisor.wait_for_exit();

        assert!(!status.success(), "a dead slirp must fail the startup");
        assert!(!supervisor.signalled_ready());
        assert!(
            supervisor.stderr().contains("before signalling readiness"),
            "the failure must say slirp never came up: {}",
            supervisor.stderr()
        );
        assert_eq!(
            supervisor.rule_invocations(),
            0,
            "rules were installed against a namespace with no connectivity"
        );
    }

    /// The blocking read on the PID pipe exists so a supervisor whose parent
    /// died exits instead of spinning as an orphan holding a namespace.
    #[test]
    fn the_supervisor_exits_when_the_parent_never_publishes_the_sandbox_pid() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.abandon_without_publishing_pid();
        let status = supervisor.wait_for_exit();

        assert!(
            !status.success(),
            "an unpublished PID must fail the startup"
        );
        assert!(!supervisor.signalled_ready());
        assert!(
            supervisor.stderr().contains("before publishing"),
            "the failure must name the missing PID: {}",
            supervisor.stderr()
        );
        assert_eq!(supervisor.rule_invocations(), 0);
    }
}
