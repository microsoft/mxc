// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rootless private networking for Bubblewrap proxy mode.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
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
const SLIRP_HOST_GATEWAY: &str = "10.0.2.2";
const SUPERVISOR_SCRIPT: &str = r#"
set -eu
state_dir="$1"
ready_fd="$2"
exit_fd="$3"
pid_fd="$4"
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
exec slirp4netns --configure --mtu=65520 \
    --ready-fd "$ready_fd" --exit-fd "$exit_fd" \
    "$child_pid" tap0
"#;

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
    /// Callers reach this only after `BwrapRunner::validate` has already run
    /// [`probe_dependencies`], so the probe is not repeated here.
    pub(crate) fn start(logger: &mut Logger) -> Result<Self, String> {
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
        logger.log_line("Bubblewrap: slirp4netns configured the private proxy namespace");
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
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    logger.log_line(
                        "WARNING: Bubblewrap: slirp4netns did not stop promptly; terminating it",
                    );
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

pub(crate) fn probe_dependencies() -> Result<(), String> {
    // Probing costs two subprocess spawns, and the host's tooling does not
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
    let slirp = Command::new("slirp4netns")
        .arg("--version")
        .output()
        .map_err(|error| {
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

    let unshare = Command::new("unshare")
        .arg("--help")
        .output()
        .map_err(|error| {
            format!("Bubblewrap: proxy networking requires util-linux 'unshare' on PATH: {error}")
        })?;
    let help = String::from_utf8_lossy(&unshare.stdout);
    if !unshare.status.success()
        || !help.contains("--map-current-user")
        || !help.contains("--keep-caps")
    {
        return Err(
            "Bubblewrap: proxy networking requires util-linux unshare with \
             --map-current-user and --keep-caps support"
                .into(),
        );
    }
    Ok(())
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
            let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
            return Err(format!(
                "Bubblewrap: {component} exited during startup ({status}): {}",
                stderr.trim()
            ));
        }
        if Instant::now() >= deadline {
            // Include whatever the component wrote to stderr: on a timeout it
            // is usually the only evidence of *why* startup stalled, and the
            // process is still alive so no exit status will explain it.
            let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
            let stderr = stderr.trim();
            let detail = if stderr.is_empty() {
                "no stderr output".to_string()
            } else {
                format!("stderr: {stderr}")
            };
            return Err(format!(
                "Bubblewrap: timed out waiting for {component} startup after {STARTUP_TIMEOUT:?} \
                 ({detail})"
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
}
