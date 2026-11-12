// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "lxc_container.rs"]
mod lxc_container;

pub use lxc_container::LxcContainer;

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

/// A `/etc/hosts` helper emits one `mxc:` diagnostic line, so this is far above
/// any legitimate output.
#[cfg(target_os = "linux")]
const MAX_CAPTURED_BYTES: u64 = 8 * 1024;

#[cfg(target_os = "linux")]
fn read_to_end_on_thread(
    reader: Option<crate::mxc_common::interruptible_reader::InterruptibleReader>,
) -> Option<std::thread::JoinHandle<String>> {
    reader.map(|reader| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut capped = std::io::Read::take(reader, MAX_CAPTURED_BYTES);
            let _ = std::io::Read::read_to_end(&mut capped, &mut buffer);

            // Drained past the cap so the child sees its pipe emptied and exits
            // on its own rather than blocking on a full one.
            let mut reader = capped.into_inner();
            let _ = std::io::copy(&mut reader, &mut std::io::sink());

            String::from_utf8_lossy(&buffer).into_owned()
        })
    })
}

#[cfg(target_os = "linux")]
fn joined_capture(handle: Option<std::thread::JoinHandle<String>>) -> String {
    handle
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default()
}

/// A reaped child's pipes are closed, so a reader still running past this grace
/// is waiting on a descendant that inherited one.
#[cfg(target_os = "linux")]
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Cancelling a read abandons whatever the pipe still held, so a child whose
/// output has not been read yet would lose it to a prompt cancel.
#[cfg(target_os = "linux")]
fn wait_for_drain(
    stdout: &Option<std::thread::JoinHandle<String>>,
    stderr: &Option<std::thread::JoinHandle<String>>,
) {
    let drained = |handle: &Option<std::thread::JoinHandle<String>>| {
        handle.as_ref().is_none_or(|handle| handle.is_finished())
    };
    let deadline = std::time::Instant::now() + DRAIN_GRACE;

    while !(drained(stdout) && drained(stderr)) {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Unblock the signals `lxc-exec` holds for its sigwait watchdog, so the child
/// does not inherit a mask that makes it ignore Ctrl-C and termination.
#[cfg(target_os = "linux")]
fn unblock_fatal_signals(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `pthread_sigmask`, which nix's
    // `thread_unblock` wraps, is async-signal-safe, and this closure allocates
    // nothing and captures nothing.
    unsafe {
        command.pre_exec(|| {
            let mut mask = nix::sys::signal::SigSet::empty();
            mask.add(nix::sys::signal::Signal::SIGHUP);
            mask.add(nix::sys::signal::Signal::SIGTERM);
            mask.add(nix::sys::signal::Signal::SIGINT);
            mask.thread_unblock().map_err(std::io::Error::from)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
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
    fn caller_proxy_env_is_preserved_and_host_env_is_cleared() {
        let env = vec![
            "HTTP_PROXY=http://caller-proxy.example:9999".to_string(),
            "PATH=/usr/bin".to_string(),
        ];
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
}
