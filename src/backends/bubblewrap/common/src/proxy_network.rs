// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rootless private networking for Bubblewrap proxy mode.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::unistd::pipe2;
use tempfile::TempDir;
use wxc_common::logger::Logger;
use wxc_common::models::ProxyAddress;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Ceiling for a single dependency probe. Generous next to a `--version` call,
/// which returns in milliseconds, so only a genuinely wedged binary trips it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SLIRP_HOST_GATEWAY: &str = "10.0.2.2";
/// Egress chain installed inside the sandbox's own network namespace.
const EGRESS_CHAIN: &str = "MXC_EGRESS";
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
ready_fd="$2"
exit_fd="$3"
pid_fd="$4"
proxy_ip="$5"
proxy_port="$6"
chain="$7"
printf ready > "$state_dir/userns.ready"
# Block on the parent-owned PID pipe rather than polling for a file: if the
# parent dies before it can publish the PID, the read ends at EOF and this
# supervisor exits instead of spinning forever as an orphan.
eval "exec 3<&$pid_fd"
if ! IFS= read -r child_pid <&3; then
    child_pid="${child_pid:-}"
fi
exec 3<&-
if [ -z "$child_pid" ]; then
    echo "mxc: parent exited before publishing the sandbox PID" >&2
    exit 1
fi

# slirp signals readiness internally so the supervisor, not slirp, decides when
# the sandbox is ready -- the rules below must be in place first.
exec 9> "$state_dir/slirp.internal"
slirp4netns --configure --mtu=65520 \
    --ready-fd 9 --exit-fd "$exit_fd" \
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
nsenter --net="$ns" -- iptables -N "$chain"
nsenter --net="$ns" -- iptables -A "$chain" -o lo -j ACCEPT
nsenter --net="$ns" -- iptables -A "$chain" -p tcp -d "$proxy_ip" --dport "$proxy_port" -j ACCEPT
nsenter --net="$ns" -- iptables -A "$chain" -j DROP
nsenter --net="$ns" -- iptables -A OUTPUT -j "$chain"
# The proxy rule is IPv4 only, so v6 carries its closing DROP alone: IPv6
# egress fails closed rather than being left open.
nsenter --net="$ns" -- ip6tables -N "$chain"
nsenter --net="$ns" -- ip6tables -A "$chain" -o lo -j ACCEPT
nsenter --net="$ns" -- ip6tables -A "$chain" -j DROP
nsenter --net="$ns" -- ip6tables -A OUTPUT -j "$chain"

eval "printf ready >&$ready_fd"
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
        let ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(state_dir.path().join("slirp.ready"))
            .map_err(|error| {
                format!("Bubblewrap: failed to create slirp readiness file: {error}")
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
            .arg(ready.as_raw_fd().to_string())
            .arg(exit_reader.as_raw_fd().to_string())
            .arg(pid_reader.as_raw_fd().to_string())
            .arg(egress.ip.to_string())
            .arg(egress.port.to_string())
            .arg(EGRESS_CHAIN)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        // These stay CLOEXEC in this process, so a concurrent spawn from
        // another thread cannot inherit them; only the supervisor gets them.
        inherit_descriptors(
            &mut command,
            vec![
                ready.as_raw_fd(),
                exit_reader.as_raw_fd(),
                pid_reader.as_raw_fd(),
            ],
        );

        let mut supervisor = command.spawn().map_err(|error| {
            format!("Bubblewrap: failed to start proxy-network supervisor: {error}")
        })?;
        drop(exit_reader);
        drop(pid_reader);
        drop(ready);

        if let Err(error) = wait_for_file(
            state_dir.path().join("userns.ready"),
            &mut supervisor,
            &stderr_path,
            "user namespace",
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
            "slirp4netns",
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
    // `0.0.0.0` / `::` name the host itself just as `127.0.0.1` does: a proxy
    // bound to the wildcard is reachable on the host's loopback, which the
    // sandbox's private namespace cannot see. Both need the gateway rewrite.
    let is_host_local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
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
    for (binary, probe) in [
        ("nsenter", "--version"),
        ("iptables", "--version"),
        ("ip6tables", "--version"),
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
    }
    Ok(())
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
) -> Result<(), String> {
    let path = path.as_ref();
    let deadline = Instant::now() + STARTUP_TIMEOUT;
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
                "Bubblewrap: timed out waiting for {component} startup after {STARTUP_TIMEOUT:?} \
                 ({})",
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
        let address = ProxyAddress::new("[::1]".into(), 8080);
        let translated = sandbox_proxy_address(&address).unwrap();

        // ::1 is loopback, so translation already yields the IPv4 gateway.
        assert_eq!(translated.host(), SLIRP_HOST_GATEWAY);

        let routable = ProxyAddress::new("2001:db8::1".into(), 8080);
        assert!(ProxyEgress::from_address(&routable).is_err());
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

    /// Byte offset of `needle` in the supervisor script.
    fn script_offset(needle: &str) -> usize {
        SUPERVISOR_SCRIPT
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
        let ready = script_offset(r#"eval "printf ready >&$ready_fd""#);

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
        let accepts: Vec<&str> = SUPERVISOR_SCRIPT
            .lines()
            .filter(|line| line.contains("-j ACCEPT"))
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
            !SUPERVISOR_SCRIPT.contains(r#"ip6tables -A "$chain" -p tcp"#),
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
        let ready = script_offset(r#"eval "printf ready >&$ready_fd""#);
        let region = &SUPERVISOR_SCRIPT[rules_start..ready];

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
}
