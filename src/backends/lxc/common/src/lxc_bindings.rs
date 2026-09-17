// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const MANAGED_MOUNTS_BEGIN: &str = "# BEGIN MXC managed mounts (rewritten every run)";
const MANAGED_MOUNTS_END: &str = "# END MXC managed mounts";

/// The filesystem type and options of one kind of `lxc.mount.entry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountShape {
    filesystem: &'static str,
    options: &'static str,
}

impl MountShape {
    pub(crate) fn entry(self, source: &str, target: &str) -> String {
        format!(
            "{} {} {} {} 0 0",
            source, target, self.filesystem, self.options
        )
    }
}

pub(crate) const MOUNT_READWRITE: MountShape = MountShape {
    filesystem: "none",
    options: "bind,create=dir",
};
pub(crate) const MOUNT_READONLY: MountShape = MountShape {
    filesystem: "none",
    options: "bind,ro,create=dir",
};
pub(crate) const MASK_FILE: MountShape = MountShape {
    filesystem: "none",
    options: "bind,ro,create=file",
};
pub(crate) const MASK_DIR_HOLDING_MOUNTPOINTS: MountShape = MountShape {
    filesystem: "tmpfs",
    options: "size=1m,create=dir",
};
pub(crate) const MASK_DIR: MountShape = MountShape {
    filesystem: "tmpfs",
    options: "ro,size=0,create=dir",
};

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

pub fn resolve_default_lxcpath() -> String {
    // The windows-latest clippy lane compiles this and never calls it, so a
    // non-root EUID stands in.
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

#[cfg(test)]
fn build_attach_args(env: &[String], working_directory: &str, command: &str) -> Vec<String> {
    build_attach_args_with_env_control(env, working_directory, command, false)
}

/// An empty `env` is ambiguous: the caller expressed no opinion, or a scrub
/// removed every entry there was.  `force_clear_env` distinguishes them; only
/// the second must still shut the host environment out.
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
        args.push("cd -- \"$1\" && exec /bin/sh -c \"$2\"".to_string());
        args.push("_".to_string());
        args.push(working_directory.to_string());
        args.push(command.to_string());
    }

    args
}

/// Whether MXC put firewall chains in the container's network namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerFirewall {
    Installed,
    Absent,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartNetwork {
    FromContainerConfig,
    NoInterface,
}

impl StartNetwork {
    fn to_start_args(self, configured_interfaces: usize) -> Vec<String> {
        match self {
            StartNetwork::FromContainerConfig => Vec::new(),
            StartNetwork::NoInterface => {
                // Index 0 is emitted even for a container that configures no
                // interface at all: without an `lxc.net` entry LXC leaves the
                // container in the host's network namespace.
                let mut args = Vec::new();
                for index in 0..configured_interfaces.max(1) {
                    args.push("-s".to_string());
                    args.push(format!("lxc.net.{index}.type=empty"));
                    args.push("-s".to_string());
                    args.push(format!("lxc.net.{index}.flags=up"));
                }
                args
            }
        }
    }
}

pub struct LxcContainer {
    name: String,
    lxc_path: String,
}

impl LxcContainer {
    pub fn new(name: &str, lxc_path: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            lxc_path: lxc_path
                .map(|s| s.to_string())
                .unwrap_or_else(resolve_default_lxcpath),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn lxc_path(&self) -> &str {
        &self.lxc_path
    }

    fn lxc_command(&self, tool: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("-P").arg(&self.lxc_path).arg("-n").arg(&self.name);
        cmd
    }

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

    pub fn is_defined(&self) -> bool {
        let output = self.lxc_command("lxc-info").output();
        matches!(output, Ok(o) if o.status.success())
    }

    pub fn is_running(&self) -> bool {
        let output = self.lxc_command("lxc-info").arg("-s").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("RUNNING"),
            Err(_) => false,
        }
    }

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

    /// Removes existing mount points so they do not accumulate on a reused
    /// container.
    pub fn set_filesystem_access_points(&self, entries: &[String]) -> Result<(), String> {
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
            if inside {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    pub fn start(&self, network: StartNetwork) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-start");
        cmd.args(network.to_start_args(self.configured_interface_count()));
        Self::run_tool(cmd)
    }

    /// How many `lxc.net.N` interfaces the container's config declares.
    fn configured_interface_count(&self) -> usize {
        let Ok(config) = std::fs::read_to_string(self.config_file_path()) else {
            return 0;
        };
        Self::highest_interface_index(&config).map_or(0, |index| index + 1)
    }

    fn highest_interface_index(config: &str) -> Option<usize> {
        config
            .lines()
            .filter_map(|line| {
                let key = line.split('=').next()?.trim();
                let index = key.strip_prefix("lxc.net.")?.split('.').next()?;
                index.parse::<usize>().ok()
            })
            .max()
    }

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

    /// Output streams go straight to the host; both returned strings are always
    /// empty.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        timeout: Option<std::time::Duration>,
        firewall: ContainerFirewall,
    ) -> Result<(i32, String, String), String> {
        use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome, Signal};

        // This process blocks these for its cleanup watchdog; left blocked, the
        // inner shell would ignore Ctrl-C.
        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
        ));

        // The drop needs CAP_SETPCAP, which an unprivileged caller lacks, and a
        // run with no chains has nothing to protect anyway.
        if firewall == ContainerFirewall::Installed {
            confine_network_capabilities(&mut cmd);
        }

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
        _firewall: ContainerFirewall,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Stop the container by killing it, not by asking it to exit.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_tool(self.stop_command())
    }

    fn stop_command(&self) -> std::process::Command {
        let mut cmd = self.lxc_command("lxc-stop");

        // -k kills outright.  Asking it to exit instead waits 60 seconds for a
        // SIGPWR reply that systemd as PID 1 in an unprivileged userns never
        // sends.
        cmd.arg("-k");
        cmd
    }

    pub fn destroy(&self) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-destroy");

        cmd.arg("-f");
        Self::run_tool(cmd)
    }

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
            StartNetwork::NoInterface.to_start_args(1),
            ["-s", "lxc.net.0.type=empty", "-s", "lxc.net.0.flags=up"],
            "lxc-start reads each config item from the -s that precedes it, \
             and loopback stays up for a workload that binds 127.0.0.1"
        );
    }

    #[test]
    fn every_configured_interface_is_emptied_not_just_the_first() {
        assert_eq!(
            StartNetwork::NoInterface.to_start_args(3),
            [
                "-s",
                "lxc.net.0.type=empty",
                "-s",
                "lxc.net.0.flags=up",
                "-s",
                "lxc.net.1.type=empty",
                "-s",
                "lxc.net.1.flags=up",
                "-s",
                "lxc.net.2.type=empty",
                "-s",
                "lxc.net.2.flags=up",
            ],
            "an interface nobody names keeps its link, and a policy that permits \
             no network installs no chain to filter it"
        );
    }

    #[test]
    fn a_container_configuring_no_interface_still_gets_one_emptied() {
        assert_eq!(
            StartNetwork::NoInterface.to_start_args(0),
            ["-s", "lxc.net.0.type=empty", "-s", "lxc.net.0.flags=up"],
            "LXC leaves a container with no lxc.net entry in the host's network namespace"
        );
    }

    #[test]
    fn the_interface_count_comes_from_the_highest_index_the_config_names() {
        for (config, expected) in [
            ("", None),
            ("lxc.net.0.type = veth\n", Some(0)),
            ("lxc.net.0.type = veth\nlxc.net.1.type = veth\n", Some(1)),
            ("lxc.net.4.type = veth\nlxc.net.1.type = veth\n", Some(4)),
            ("  lxc.net.2.link = lxcbr0\n", Some(2)),
            // Keys that only look like an interface entry.
            ("lxc.network.0.type = veth\n", None),
            ("lxc.net.x.type = veth\n", None),
        ] {
            assert_eq!(
                LxcContainer::highest_interface_index(config),
                expected,
                "config {config:?}"
            );
        }
    }

    #[test]
    fn a_run_that_keeps_the_container_config_states_nothing() {
        assert!(
            StartNetwork::FromContainerConfig
                .to_start_args(2)
                .is_empty(),
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
            .set_filesystem_access_points(&[
                "/tmp/secret tmp/secret none bind,create=dir 0 0".into()
            ])
            .expect("first run programs its mount");
        let after_first = std::fs::read_to_string(&config).expect("read config");
        assert!(
            after_first.contains("/tmp/secret"),
            "the first run's mount must be programmed; got:\n{after_first}"
        );

        container
            .set_filesystem_access_points(&[])
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
            .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        container
            .set_filesystem_access_points(&[])
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
    fn an_unmarked_mount_is_left_to_its_author() {
        // Containers predating the managed block carry MXC's own mounts as
        // unmarked lines, but so does anyone who wrote one by hand, and the two
        // are indistinguishable. Deleting a user's mount is worse than leaving
        // a stale grant on a container MXC has not rewritten since.
        let unmarked = "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n\
                        lxc.mount.entry = /srv/mydata srv/mydata none bind,create=dir 0 0\n";
        let (container, config) = container_with_config(unmarked);

        container
            .set_filesystem_access_points(&[])
            .expect("a run granting nothing rewrites the config");

        let body = std::fs::read_to_string(&config).expect("read config");
        assert!(
            body.contains("lxc.mount.entry = /srv/mydata srv/mydata none bind,create=dir 0 0"),
            "an unmarked mount must survive; got:\n{body}"
        );
        assert!(
            body.contains("lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs"),
            "the rewrite must keep the lines it does not own; got:\n{body}"
        );
    }

    #[test]
    fn repeated_runs_do_not_accumulate_managed_blocks() {
        let (container, config) = container_with_config(TEMPLATE_CONFIG);

        for _ in 0..3 {
            container
                .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
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
            .set_filesystem_access_points(&[])
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
            .set_filesystem_access_points(&[])
            .expect_err("a missing config must fail loudly");
        assert!(
            err.contains("ghost/config"),
            "error must name the config file, got: {err}"
        );

        container
            .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        let temp = format!("{}.mxc-tmp", config.display());
        assert!(
            !std::path::Path::new(&temp).exists(),
            "the staging file must not outlive a successful rewrite"
        );
    }

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

    // The conditional in `attach_run` exists because of this: the drop is a
    // privileged operation, so applying it to every run costs an unprivileged
    // caller the whole execution.
    #[cfg(target_os = "linux")]
    #[test]
    fn confining_a_command_takes_a_privilege_an_unprivileged_caller_lacks() {
        // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
        let running_as_root = unsafe { libc::geteuid() } == 0;

        let mut confined = std::process::Command::new("/bin/true");
        confine_network_capabilities(&mut confined);

        assert_eq!(
            confined.status().is_ok(),
            running_as_root,
            "a confined command must spawn only for a caller holding CAP_SETPCAP"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unconfined_command_spawns_whoever_the_caller_is() {
        let mut unconfined = std::process::Command::new("/bin/true");

        assert!(
            unconfined.status().is_ok(),
            "a run with no chains to protect must spawn without any privilege"
        );
    }
}
