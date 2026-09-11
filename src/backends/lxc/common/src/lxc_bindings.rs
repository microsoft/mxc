// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe Rust wrappers around the liblxc C API.

/// Fences the `lxc.mount.entry` lines this backend owns.  A reused container's
/// block can be rewritten without disturbing entries a template or an operator
/// added by hand.
const MANAGED_MOUNTS_BEGIN: &str = "# BEGIN MXC managed mounts (rewritten every run)";
const MANAGED_MOUNTS_END: &str = "# END MXC managed mounts";

/// Resolve the default LXC storage path the way liblxc does.
fn resolve_lxcpath_with_env<F, G>(get_env: F, geteuid: G) -> String
where
    F: Fn(&str) -> Option<String>,
    G: Fn() -> u32,
{
    if let Some(p) = get_env("LXC_PATH") {
        if !p.is_empty() {
            return p;
        }
    }
    if geteuid() == 0 {
        return "/var/lib/lxc".to_string();
    }
    if let Some(xdg) = get_env("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return format!("{}/lxc", xdg.trim_end_matches('/'));
        }
    }
    if let Some(home) = get_env("HOME") {
        if !home.is_empty() {
            return format!("{}/.local/share/lxc", home.trim_end_matches('/'));
        }
    }
    "/var/lib/lxc".to_string()
}

/// Resolve the default LXC storage path for the current process.
pub fn resolve_default_lxcpath() -> String {
    // The crate compiles workspace-wide (the clippy lane runs on
    // windows-latest), where this is never called; a non-root EUID stands in.
    #[cfg(target_os = "linux")]
    // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
    fn current_euid() -> u32 {
        unsafe { libc::geteuid() as u32 }
    }
    #[cfg(not(target_os = "linux"))]
    fn current_euid() -> u32 {
        1
    }

    resolve_lxcpath_with_env(|k| std::env::var(k).ok(), current_euid)
}

/// The keep-env argv shape, for tests that do not exercise env control.
#[cfg(test)]
fn build_attach_args(env: &[String], working_directory: &str, command: &str) -> Vec<String> {
    build_attach_args_with_env_control(env, working_directory, command, false)
}

/// Build the post-binary argv for `lxc-attach` (the args after the
/// `-n NAME -P lxcpath` flags `lxc_command` already appended).
///
/// An empty `env` is ambiguous: the caller expressed no opinion, or a scrub
/// removed every entry there was.  `force_clear_env` distinguishes them; only
/// the second must still shut the host environment out.
///
/// Gated to `test` and Linux: `attach_run` is a Windows stub that never calls
/// this, and the windows-latest clippy lane would otherwise flag it dead.
#[cfg(any(target_os = "linux", test))]
fn build_attach_args_with_env_control(
    env: &[String],
    working_directory: &str,
    command: &str,
    force_clear_env: bool,
) -> Vec<String> {
    let mut args: Vec<String> = Vec::with_capacity(env.len() + 8);

    if force_clear_env || !env.is_empty() {
        args.push("--clear-env".to_string());
        for kv in env {
            if let Some((key, _)) = kv.split_once('=') {
                if !key.is_empty() {
                    args.push(format!("--set-var={}", kv));
                }
            }
        }
    }

    args.push("--".to_string());
    args.push("/bin/sh".to_string());
    args.push("-c".to_string());

    if working_directory.is_empty() {
        args.push(command.to_string());
    } else {
        // cwd and command travel through sh as positional `$1`/`$2`, needing
        // no shell-escaping; `_` fills sh's `$0`.  `cd --` guards a
        // leading-dash cwd.  `exec` makes signals and timeout delivery reach
        // the user process, not this wrapper sh.
        args.push("cd -- \"$1\" && exec /bin/sh -c \"$2\"".to_string());
        args.push("_".to_string());
        args.push(working_directory.to_string());
        args.push(command.to_string());
    }

    args
}

/// Permanently drops network-admin capability from the workload when none is requested.
#[cfg(target_os = "linux")]
fn confine_network_capabilities(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // `libc` does not export this; the value is from linux/capability.h.
    const CAP_NET_ADMIN: libc::c_ulong = 12;

    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `prctl` is a bare syscall and this
    // closure allocates nothing and captures nothing.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_CAPBSET_DROP, CAP_NET_ADMIN, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Whether to start the container with its configured network or with none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartNetwork {
    FromContainerConfig,
    NoInterface,
}

impl StartNetwork {
    fn to_start_args(self) -> &'static [&'static str] {
        match self {
            StartNetwork::FromContainerConfig => &[],
            // `up` keeps 127.0.0.1 available to a workload that binds it.
            StartNetwork::NoInterface => {
                &["-s", "lxc.net.0.type=empty", "-s", "lxc.net.0.flags=up"]
            }
        }
    }
}

/// Safe wrapper around an LXC container.
pub struct LxcContainer {
    name: String,

    /// Resolved LXC storage path, passed via `-P` to every `lxc-*` invocation.
    lxc_path: String,
}

impl LxcContainer {
    /// Create a new LXC container handle.
    pub fn new(name: &str, lxc_path: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            lxc_path: lxc_path
                .map(|s| s.to_string())
                .unwrap_or_else(resolve_default_lxcpath),
        }
    }

    /// Get the container name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the resolved LXC storage path (the "lxcpath") used by this handle.
    pub fn lxc_path(&self) -> &str {
        &self.lxc_path
    }

    /// Build a `Command` for an `lxc-*` tool with `-P <lxc_path> -n <name>`
    /// already populated.
    fn lxc_command(&self, tool: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("-P").arg(&self.lxc_path).arg("-n").arg(&self.name);
        cmd
    }

    /// Run a prepared `lxc-*` command, mapping spawn / non-zero-exit failures
    /// to a `String` error tagged with the tool name.
    fn run_tool(mut cmd: std::process::Command) -> Result<(), String> {
        let tool = cmd.get_program().to_string_lossy().into_owned();
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run {}: {}", tool, e))?;
        if !output.status.success() {
            return Err(format!(
                "{} failed: {}",
                tool,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// Check if the container exists.
    pub fn is_defined(&self) -> bool {
        let output = self.lxc_command("lxc-info").output();
        matches!(output, Ok(o) if o.status.success())
    }

    /// Check if the container is running.
    pub fn is_running(&self) -> bool {
        let output = self.lxc_command("lxc-info").arg("-s").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("RUNNING"),
            Err(_) => false,
        }
    }

    /// Return the PID of the container's init process, or `None` if the
    /// container is not running or the PID cannot be parsed.
    pub fn init_pid(&self) -> Option<u32> {
        let output = self.lxc_command("lxc-info").arg("-p").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let token = line.trim();
            let token = token.strip_prefix("PID:").map(str::trim).unwrap_or(token);
            if let Ok(pid) = token.parse::<u32>() {
                if pid > 0 {
                    return Some(pid);
                }
            }
        }
        None
    }

    /// Create the container from a template/distribution.
    pub fn create(&self, distribution: &str, release: &str) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-create");
        cmd.args(["-t", "download", "--", "-d"])
            .arg(distribution)
            .arg("-r")
            .arg(release)
            .arg("-a")
            .arg(Self::current_arch());
        Self::run_tool(cmd)
    }

    /// Replace the block of `lxc.mount.entry` items this backend owns.
    ///
    /// A container preserved by `destroyOnExit = false` is reused, and its
    /// config file outlives the run that wrote it.  Replacing this block
    /// rather than adding to it stops a later run granted no filesystem
    /// policy from reading a directory an earlier run was handed.
    ///
    /// Only the marker-fenced lines this backend wrote are touched.  Entries a
    /// template or operator added by hand, and entries in files the config
    /// `lxc.include`s, are left untouched.
    pub fn set_managed_mount_entries(&self, entries: &[String]) -> Result<(), String> {
        let config_path = self.config_file_path();
        let existing = std::fs::read_to_string(&config_path).map_err(|e| {
            format!(
                "Failed to read container config to replace its mount entries: {} (config file: {})",
                e, config_path
            )
        })?;

        let mut out = Self::strip_managed_mount_entries(&existing);
        if !entries.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(MANAGED_MOUNTS_BEGIN);
            out.push('\n');
            for entry in entries {
                out.push_str("lxc.mount.entry = ");
                out.push_str(entry);
                out.push('\n');
            }
            out.push_str(MANAGED_MOUNTS_END);
            out.push('\n');
        }

        let temp_path = format!("{}.mxc-tmp", config_path);
        std::fs::write(&temp_path, out.as_bytes()).map_err(|e| {
            format!(
                "Failed to stage rewritten container config: {} (temp file: {})",
                e, temp_path
            )
        })?;
        std::fs::rename(&temp_path, &config_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            format!(
                "Failed to install rewritten container config: {} (config file: {})",
                e, config_path
            )
        })
    }

    /// Drop the marker-fenced managed block from a container config body.
    ///
    /// An opening marker with no closing one -- the shape an interrupted
    /// rewrite leaves -- is treated as fenced to end of file, clearing the
    /// leftovers rather than inheriting them.
    fn strip_managed_mount_entries(config: &str) -> String {
        let mut out = String::with_capacity(config.len());
        let mut inside = false;
        for line in config.lines() {
            let trimmed = line.trim();
            if trimmed == MANAGED_MOUNTS_BEGIN {
                inside = true;
                continue;
            }
            if trimmed == MANAGED_MOUNTS_END {
                inside = false;
                continue;
            }
            if !inside {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// Start the container with `network`.
    pub fn start(&self, network: StartNetwork) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-start");
        cmd.args(network.to_start_args());
        Self::run_tool(cmd)
    }

    /// Execute a command inside the container, capturing stdout/stderr.
    pub fn exec(
        &self,
        command: &str,
        _working_directory: &str,
        _timeout_ms: u32,
    ) -> Result<(i32, String, String), String> {
        // TODO: Implement timeout and working directory support.
        let mut cmd = self.lxc_command("lxc-execute");
        cmd.args(["--", "/bin/sh", "-c", command]);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-execute: {}", e))?;

        Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    /// Run a command inside the running container.
    ///
    /// Output streams go straight to the host; both returned strings are always
    /// empty.
    ///
    /// An empty `env` leaves this process's own environment in place, proxy
    /// variables and host credentials included.
    ///
    /// The unblocked signals are ones this process blocks for its cleanup
    /// watchdog; left blocked, the inner shell would ignore Ctrl-C.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome, Signal};

        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
        ));

        // Must run before the command is spawned; it registers a pre-exec hook.
        confine_network_capabilities(&mut cmd);

        let options = PtyOptions {
            unblock_signals: UNBLOCK,
            timeout,
            ..PtyOptions::default()
        };

        match run_with_pty(cmd, options)? {
            PtyOutcome::Exited(status) => {
                Ok((status.code().unwrap_or(-1), String::new(), String::new()))
            }

            PtyOutcome::TimedOut => {
                let ms = timeout.map(|d| d.as_millis()).unwrap_or(0);
                Err(format!("script timed out after {}ms", ms))
            }
        }
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    pub fn attach_run(
        &self,
        _command: &str,
        _working_directory: &str,
        _env: &[String],
        _force_clear_env: bool,
        _timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Stop the container by killing it, not by asking it to exit.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_tool(self.stop_command())
    }

    /// The command [`Self::stop`] runs, built without running it.
    fn stop_command(&self) -> std::process::Command {
        let mut cmd = self.lxc_command("lxc-stop");

        // -k kills the container outright.  Asking it to exit instead waits 60
        // seconds for a SIGPWR reply that systemd as PID 1 in an unprivileged
        // userns never sends.
        cmd.arg("-k");
        cmd
    }

    /// Destroy the container, removing its rootfs and config.
    pub fn destroy(&self) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-destroy");

        // -f force-stops a running container rather than waiting for it to
        // shut down on its own.
        cmd.arg("-f");
        Self::run_tool(cmd)
    }

    /// Get the path to the container's config file.
    fn config_file_path(&self) -> String {
        format!("{}/{}/config", self.lxc_path, self.name)
    }

    fn current_arch() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "amd64"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "arm64"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            "amd64"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn stop_kills_rather_than_waiting_for_a_clean_shutdown() {
        let container = LxcContainer::new("mxc-stop-test", Some("/var/lib/lxc"));
        let args: Vec<String> = container
            .stop_command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(
            args.iter().any(|a| a == "mxc-stop-test"),
            "the command must address this container, got {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "-k"),
            "stop must kill the container: a clean shutdown waits 60 seconds for an \
             init that may never answer, got {args:?}"
        );
    }

    #[test]
    fn a_run_with_no_interface_states_that_to_lxc_start() {
        assert_eq!(
            StartNetwork::NoInterface.to_start_args(),
            ["-s", "lxc.net.0.type=empty", "-s", "lxc.net.0.flags=up"],
            "lxc-start reads each config item from the -s that precedes it, \
             and loopback stays up for a workload that binds 127.0.0.1"
        );
    }

    #[test]
    fn a_run_that_keeps_the_container_config_states_nothing() {
        assert!(
            StartNetwork::FromContainerConfig.to_start_args().is_empty(),
            "the container's own config must be left to decide its interfaces"
        );
    }

    #[test]
    fn lxcpath_honors_lxc_path_env() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "LXC_PATH" {
                    Some("/custom/lxc".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/custom/lxc");
    }

    #[test]
    fn lxcpath_lxc_path_takes_precedence_over_root_default() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "LXC_PATH" {
                    Some("/srv/lxc".into())
                } else {
                    None
                }
            },
            || 0,
        );
        assert_eq!(p, "/srv/lxc");
    }

    #[test]
    fn lxcpath_root_default() {
        let p = resolve_lxcpath_with_env(no_env, || 0);
        assert_eq!(p, "/var/lib/lxc");
    }

    #[test]
    fn lxcpath_user_uses_xdg_data_home() {
        let p = resolve_lxcpath_with_env(
            |k| match k {
                "XDG_DATA_HOME" => Some("/home/u/.data".into()),
                "HOME" => Some("/home/u".into()),
                _ => None,
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.data/lxc");
    }

    #[test]
    fn lxcpath_user_strips_trailing_slash_on_xdg() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "XDG_DATA_HOME" {
                    Some("/home/u/.data/".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.data/lxc");
    }

    #[test]
    fn lxcpath_user_falls_back_to_home() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "HOME" {
                    Some("/home/u".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.local/share/lxc");
    }

    #[test]
    fn lxcpath_user_strips_trailing_slash_on_home() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "HOME" {
                    Some("/home/u/".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.local/share/lxc");
    }

    #[test]
    fn lxcpath_empty_env_values_are_ignored() {
        let p = resolve_lxcpath_with_env(
            |k| match k {
                "LXC_PATH" | "XDG_DATA_HOME" => Some(String::new()),
                "HOME" => Some("/h".into()),
                _ => None,
            },
            || 1000,
        );
        assert_eq!(p, "/h/.local/share/lxc");
    }

    #[test]
    fn lxcpath_user_with_no_env_has_safe_fallback() {
        let p = resolve_lxcpath_with_env(no_env, || 1000);
        assert_eq!(p, "/var/lib/lxc");
    }

    #[test]
    fn lxc_container_uses_resolved_lxcpath_when_none_provided() {
        let c = LxcContainer::new("any", None);
        assert!(!c.lxc_path().is_empty());
    }

    #[test]
    fn lxc_container_honors_explicit_lxc_path() {
        let c = LxcContainer::new("my-box", Some("/opt/lxc"));
        assert_eq!(c.lxc_path(), "/opt/lxc");
        assert_eq!(c.config_file_path(), "/opt/lxc/my-box/config");
    }

    #[test]
    fn config_file_path_uses_resolved_path() {
        let c = LxcContainer::new("box", Some("/var/lib/lxc"));
        assert_eq!(c.config_file_path(), "/var/lib/lxc/box/config");
    }

    /// Build a container whose config file lives in a fresh temp directory
    /// seeded with `body`.
    fn container_with_config(body: &str) -> (LxcContainer, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "mxc-lxc-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let dir = base.join("box");
        std::fs::create_dir_all(&dir).expect("temp container dir");
        let config = dir.join("config");
        std::fs::write(&config, body).expect("seed config");
        let container = LxcContainer::new("box", Some(base.to_str().unwrap()));
        (container, config)
    }

    const TEMPLATE_CONFIG: &str = "# Template used to create this container\n\
                                   lxc.include = /usr/share/lxc/config/common.conf\n\
                                   lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n\
                                   lxc.mount.entry = /opt/handwritten opt none bind 0 0\n";

    #[test]
    fn a_reused_container_does_not_inherit_an_earlier_runs_mounts() {
        let (container, config) = container_with_config(TEMPLATE_CONFIG);

        container
            .set_managed_mount_entries(&["/tmp/secret tmp/secret none bind,create=dir 0 0".into()])
            .expect("first run programs its mount");
        let after_first = std::fs::read_to_string(&config).expect("read config");
        assert!(
            after_first.contains("/tmp/secret"),
            "the first run's mount must be programmed; got:\n{after_first}"
        );

        container
            .set_managed_mount_entries(&[])
            .expect("second run grants nothing");
        let after_second = std::fs::read_to_string(&config).expect("read config");
        assert!(
            !after_second.contains("/tmp/secret"),
            "a run granting no filesystem policy must not inherit the earlier mount; got:\n{after_second}"
        );
    }

    #[test]
    fn rewriting_mounts_preserves_every_line_the_backend_does_not_own() {
        let (container, config) = container_with_config(TEMPLATE_CONFIG);

        container
            .set_managed_mount_entries(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        container
            .set_managed_mount_entries(&[])
            .expect("clear mounts");

        let body = std::fs::read_to_string(&config).expect("read config");
        for line in [
            "# Template used to create this container",
            "lxc.include = /usr/share/lxc/config/common.conf",
            "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs",
            "lxc.mount.entry = /opt/handwritten opt none bind 0 0",
        ] {
            assert!(
                body.contains(line),
                "{line:?} must survive the rewrite; got:\n{body}"
            );
        }
    }

    #[test]
    fn repeated_runs_do_not_accumulate_managed_blocks() {
        let (container, config) = container_with_config(TEMPLATE_CONFIG);

        for _ in 0..3 {
            container
                .set_managed_mount_entries(&["/data data none bind,create=dir 0 0".into()])
                .expect("program mounts");
        }

        let body = std::fs::read_to_string(&config).expect("read config");
        assert_eq!(
            body.matches("lxc.mount.entry = /data").count(),
            1,
            "the block must be replaced, not appended; got:\n{body}"
        );
        assert_eq!(
            body.matches(MANAGED_MOUNTS_BEGIN).count(),
            1,
            "exactly one managed block may exist; got:\n{body}"
        );
    }

    #[test]
    fn an_unterminated_managed_block_is_cleared_rather_than_inherited() {
        let truncated = format!(
            "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n{}\nlxc.mount.entry = /tmp/secret tmp/secret none bind 0 0\n",
            MANAGED_MOUNTS_BEGIN
        );
        let (container, config) = container_with_config(&truncated);

        container
            .set_managed_mount_entries(&[])
            .expect("clear mounts");

        let body = std::fs::read_to_string(&config).expect("read config");
        assert!(
            !body.contains("/tmp/secret"),
            "an unterminated block must not survive; got:\n{body}"
        );
        assert!(
            body.contains("lxc.rootfs.path"),
            "lines before the marker must survive; got:\n{body}"
        );
    }

    #[test]
    fn a_failed_rewrite_leaves_no_temporary_file_behind() {
        let (container, config) = container_with_config(TEMPLATE_CONFIG);
        let err = LxcContainer::new("ghost", Some("/nonexistent-mxc-base"))
            .set_managed_mount_entries(&[])
            .expect_err("a missing config must fail loudly");
        assert!(
            err.contains("ghost/config"),
            "error must name the config file, got: {err}"
        );

        container
            .set_managed_mount_entries(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        let temp = format!("{}.mxc-tmp", config.display());
        assert!(
            !std::path::Path::new(&temp).exists(),
            "the staging file must not outlive a successful rewrite"
        );
    }

    // ---- build_attach_args ----------------------------------------------

    #[test]
    fn build_attach_args_no_env_no_cwd_is_unchanged_legacy_shape() {
        let args = build_attach_args(&[], "", "echo hi");
        assert_eq!(args, vec!["--", "/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn build_attach_args_env_is_translated_to_set_var_flags() {
        let env = vec![
            "FOO=bar".to_string(),
            "EMPTY=".to_string(),
            "HAS_EQ_IN_VAL=a=b=c".to_string(),
        ];
        let args = build_attach_args(&env, "", "cmd");
        assert_eq!(
            args,
            vec![
                "--clear-env",
                "--set-var=FOO=bar",
                "--set-var=EMPTY=",
                "--set-var=HAS_EQ_IN_VAL=a=b=c",
                "--",
                "/bin/sh",
                "-c",
                "cmd",
            ]
        );
    }

    #[test]
    fn build_attach_args_env_entries_without_equals_are_skipped() {
        let env = vec!["BADENTRY".to_string(), "OK=val".to_string()];
        let args = build_attach_args(&env, "", "cmd");
        assert_eq!(
            args,
            vec![
                "--clear-env",
                "--set-var=OK=val",
                "--",
                "/bin/sh",
                "-c",
                "cmd",
            ]
        );
    }

    #[test]
    fn build_attach_args_empty_key_entries_are_skipped() {
        let env = vec![
            "=foo".to_string(),
            "=".to_string(),
            "=val=more".to_string(),
            "OK=val".to_string(),
        ];
        let args = build_attach_args(&env, "", "cmd");
        assert_eq!(
            args,
            vec![
                "--clear-env",
                "--set-var=OK=val",
                "--",
                "/bin/sh",
                "-c",
                "cmd",
            ]
        );
    }

    #[test]
    fn build_attach_args_cwd_wraps_command_with_cd_prelude() {
        let args = build_attach_args(&[], "/opt/work", "echo hi");
        assert_eq!(
            args,
            vec![
                "--",
                "/bin/sh",
                "-c",
                "cd -- \"$1\" && exec /bin/sh -c \"$2\"",
                "_",
                "/opt/work",
                "echo hi",
            ]
        );
    }

    #[test]
    fn build_attach_args_cwd_with_special_chars_does_not_require_escaping() {
        let cwd = "/tmp/has spaces & 'quotes' $vars `cmd`";
        let cmd = "printf '%s' \"$PWD\"";
        let args = build_attach_args(&[], cwd, cmd);

        assert_eq!(args[args.len() - 2], cwd);
        assert_eq!(args[args.len() - 1], cmd);

        assert!(args
            .iter()
            .any(|a| a == "cd -- \"$1\" && exec /bin/sh -c \"$2\""));
    }

    #[test]
    fn build_attach_args_combines_env_and_cwd() {
        let env = vec!["FOO=bar".to_string()];
        let args = build_attach_args(&env, "/work", "cmd");
        assert_eq!(
            args,
            vec![
                "--clear-env",
                "--set-var=FOO=bar",
                "--",
                "/bin/sh",
                "-c",
                "cd -- \"$1\" && exec /bin/sh -c \"$2\"",
                "_",
                "/work",
                "cmd",
            ]
        );
    }

    #[test]
    fn build_attach_args_emits_clear_env_when_env_non_empty() {
        let env = vec!["FOO=bar".to_string()];
        let args = build_attach_args(&env, "", "cmd");
        let clear_idx = args
            .iter()
            .position(|a| a == "--clear-env")
            .expect("--clear-env should be present when env is non-empty");
        let set_idx = args
            .iter()
            .position(|a| a == "--set-var=FOO=bar")
            .expect("--set-var entry should be present");
        assert!(
            clear_idx < set_idx,
            "--clear-env must precede --set-var entries, got {:?}",
            args
        );
    }

    #[test]
    fn build_attach_args_omits_clear_env_when_env_empty() {
        let args = build_attach_args(&[], "", "echo hi");
        assert!(
            !args.iter().any(|a| a == "--clear-env"),
            "--clear-env must not appear when env is empty, got {:?}",
            args
        );
    }

    #[test]
    fn build_attach_args_can_force_clear_env_when_env_empty() {
        let args = build_attach_args_with_env_control(&[], "", "cmd", true);
        assert_eq!(args, vec!["--clear-env", "--", "/bin/sh", "-c", "cmd"]);
    }

    #[test]
    fn build_attach_args_clears_env_even_when_all_entries_malformed() {
        let env = vec!["BADENTRY".to_string(), "=alsobad".to_string()];
        let args = build_attach_args(&env, "", "cmd");
        assert_eq!(args, vec!["--clear-env", "--", "/bin/sh", "-c", "cmd"]);
    }

    #[test]
    fn build_attach_args_caller_env_replaces_host_env() {
        let env = vec!["MXC_TEST_FOO=bar baz".to_string()];
        let args = build_attach_args(&env, "", "cmd");
        let clear_idx = args.iter().position(|a| a == "--clear-env").unwrap();
        let set_idx = args
            .iter()
            .position(|a| a == "--set-var=MXC_TEST_FOO=bar baz")
            .unwrap();
        assert!(
            clear_idx < set_idx,
            "--clear-env must precede --set-var so caller value wins, got {:?}",
            args
        );
    }

    #[test]
    fn proxy_disabled_keeps_caller_proxy_env_and_still_clears_inherited_env() {
        use wxc_common::{models::ProxyConfig, proxy_env::apply_proxy_env};
        let mut env = vec![
            "HTTP_PROXY=http://caller-proxy.example:9999".to_string(),
            "PATH=/usr/bin".to_string(),
        ];
        apply_proxy_env(&mut env, &ProxyConfig::default());
        let args = build_attach_args_with_env_control(&env, "", "cmd", true);
        assert!(
            args.iter().any(|a| a == "--clear-env"),
            "the host environment must still be cleared; got {args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a == "--set-var=HTTP_PROXY=http://caller-proxy.example:9999"),
            "a caller's own proxy variable must reach the container; got {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--set-var=PATH=/usr/bin"),
            "PATH must survive; got {args:?}"
        );
    }

    #[test]
    fn proxy_enabled_emits_clear_env_and_proxy_keys_in_attach_args() {
        use wxc_common::{
            models::{ProxyAddress, ProxyConfig},
            proxy_env::apply_proxy_env,
        };
        let proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.0.0.5".to_string(), 3128)),
            builtin_test_server: false,
        };
        let mut env = vec!["PATH=/usr/bin".to_string()];
        apply_proxy_env(&mut env, &proxy);
        let args = build_attach_args_with_env_control(&env, "", "cmd", true);
        assert!(
            args.iter().any(|a| a == "--clear-env"),
            "proxy enabled must emit --clear-env; got {args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a.starts_with("--set-var=HTTP_PROXY=http://") && a.contains(":3128")),
            "proxy enabled must set HTTP_PROXY (with port 3128); got {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--set-var=PATH=/usr/bin"),
            "PATH must survive the proxy-env merge; got {args:?}"
        );
    }
}
