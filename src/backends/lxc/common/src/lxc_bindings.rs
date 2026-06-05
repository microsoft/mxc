// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe Rust wrappers around the liblxc C API.
//!
//! liblxc exposes container management through a `struct lxc_container` with
//! function pointer fields. This module provides an RAII `LxcContainer` wrapper
//! that calls the appropriate function pointers and handles cleanup.

/// Resolve the default LXC storage path the way liblxc does.
///
/// Replicates the algorithm liblxc applies when no explicit `-P <lxcpath>` is
/// provided to its CLI tools, using the supplied environment lookup and
/// effective-uid hooks. Extracted into a free function so unit tests can
/// exercise every branch deterministically.
///
/// Resolution order:
///  1. `LXC_PATH` env var (if non-empty).
///  2. `/var/lib/lxc` when running as root (EUID 0).
///  3. `$XDG_DATA_HOME/lxc` if `XDG_DATA_HOME` is set and non-empty.
///  4. `$HOME/.local/share/lxc` if `HOME` is set and non-empty.
///  5. `/var/lib/lxc` as a last-resort fallback.
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
///
/// See [`resolve_lxcpath_with_env`] for the exact algorithm. This wrapper
/// reads the real environment and effective UID.
pub fn resolve_default_lxcpath() -> String {
    // lxc-exec is Linux-only at runtime, but the crate has to compile
    // workspace-wide (clippy runs on windows-latest, and macOS dev builds
    // pull lxc_common in transitively). On non-Linux targets the function
    // is never invoked in production, so fall back to a non-root EUID.
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

/// Build the post-binary argv for `lxc-attach` (the args that follow the
/// `-n NAME -P lxcpath` flags already appended by `lxc_command`).
///
/// Extracted so the env / cwd / command layering is unit-testable without
/// actually spawning `lxc-attach`. See [`LxcContainer::attach_run`] for
/// the full contract.
///
/// Gated to Linux + test builds because `attach_run` is a Windows stub
/// that never calls this helper, and the workspace clippy lane on
/// `windows-latest` would otherwise flag it as dead code.
#[cfg(any(target_os = "linux", test))]
fn build_attach_args(env: &[String], working_directory: &str, command: &str) -> Vec<String> {
    // Loose upper bound: 1 --clear-env + env.len() set-vars + up to 7 fixed
    // elements in the cwd branch. Realloc-avoidance hint only.
    let mut args: Vec<String> = Vec::with_capacity(env.len() + 8);

    // Replace-on-non-empty-env: when at least one well-formed entry survives
    // the malformed-skip, emit --clear-env so lxc-exec's caller env doesn't
    // leak into the sandbox. All-malformed and empty env both preserve
    // keep-env semantics — see `attach_run` doc for the full contract.
    let set_vars: Vec<String> = env
        .iter()
        .filter(|kv| kv.contains('='))
        .map(|kv| format!("--set-var={}", kv))
        .collect();
    if !set_vars.is_empty() {
        args.push("--clear-env".to_string());
        args.extend(set_vars);
    }

    args.push("--".to_string());
    args.push("/bin/sh".to_string());
    args.push("-c".to_string());

    if working_directory.is_empty() {
        args.push(command.to_string());
    } else {
        // Positional-arg trick: cwd and command travel through sh as $1/$2
        // verbatim, so neither needs shell-escaping; `_` fills sh's $0 slot.
        // `cd --` guards a leading-dash cwd; `exec` is required so signals
        // and timeout delivery hit the user process instead of the wrapper
        // sh. Bad-cwd surfaces as cd's exit status (see `attach_run` doc).
        args.push("cd -- \"$1\" && exec /bin/sh -c \"$2\"".to_string());
        args.push("_".to_string());
        args.push(working_directory.to_string());
        args.push(command.to_string());
    }

    args
}

/// Safe wrapper around an LXC container.
pub struct LxcContainer {
    name: String,
    /// Resolved LXC storage path (the "lxcpath"). Always populated — either
    /// from an explicit caller override or from [`resolve_default_lxcpath`].
    /// Passed via `-P <path>` to every `lxc-*` shell-out so behavior is
    /// identical regardless of how the binary is launched (e.g. cron, systemd
    /// units with non-default `HOME`).
    lxc_path: String,
}

impl LxcContainer {
    /// Create a new LXC container handle.
    ///
    /// `lxc_path`, when `Some`, overrides liblxc's default path resolution.
    /// When `None`, the default is resolved via [`resolve_default_lxcpath`].
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
    /// already populated. Centralizes the argv prefix so we can't accidentally
    /// drop `-P` again (see #274).
    fn lxc_command(&self, tool: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("-P").arg(&self.lxc_path).arg("-n").arg(&self.name);
        cmd
    }

    /// Run a prepared `lxc-*` command, mapping spawn / non-zero-exit failures
    /// to a `String` error tagged with the tool name.
    fn run_status(mut cmd: std::process::Command, tool: &str) -> Result<(), String> {
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

    /// Create the container from a template/distribution.
    pub fn create(&self, distribution: &str, release: &str) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-create");
        cmd.args(["-t", "download", "--", "-d"])
            .arg(distribution)
            .arg("-r")
            .arg(release)
            .arg("-a")
            .arg(Self::current_arch());
        Self::run_status(cmd, "lxc-create")
    }

    /// Set a configuration item on the container.
    ///
    /// Appends `key = value` to the container's config file. The error
    /// message includes the key, value, and target path so users can tell at
    /// a glance whether the failure is about the entry contents (e.g. a
    /// nonexistent mount source) or about the config file itself.
    pub fn set_config_item(&self, key: &str, value: &str) -> Result<(), String> {
        let config_path = self.config_file_path();
        let entry = format!("{} = {}\n", key, value);

        std::fs::OpenOptions::new()
            .append(true)
            .open(&config_path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(entry.as_bytes())
            })
            .map_err(|e| {
                format!(
                    "Failed to set config item {} = {}: {} (config file: {})",
                    key, value, e, config_path
                )
            })
    }

    /// Start the container.
    pub fn start(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-start"), "lxc-start")
    }

    /// Execute a command inside the container, capturing stdout/stderr.
    /// Returns (exit_code, stdout, stderr).
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

    /// Execute a command inside a running container using lxc-attach, with
    /// the inner process attached to a freshly-allocated pty via
    /// [`mxc_pty::run_with_pty`]. See that crate for the full pty-bridge
    /// contract (output streamed live to host stdio, stdin forwarded after
    /// first byte arrives from inner shell, etc.).
    ///
    /// `working_directory` is honored by wrapping the user command in a
    /// `cd -- "$1" && exec /bin/sh -c "$2"` shell prelude with cwd and
    /// command passed as positional args so neither needs additional
    /// shell escaping. Empty string preserves the container default cwd.
    /// A nonexistent or non-permitted cwd surfaces as a generic non-zero
    /// exit (typically 1, from `cd`'s own status) with no structured
    /// signal that the cwd was the cause — same observable behavior as
    /// a bad `Command::current_dir` on the other backends. Callers
    /// needing strong cwd validation should pre-check the path.
    ///
    /// `env` is honored by translating each `KEY=VAL` entry into a
    /// repeated `--set-var=KEY=VAL` argument to `lxc-attach`. Entries
    /// without `=` are silently skipped (matches the permissive
    /// `split_once('=')` semantics Seatbelt and WSLC apply).
    ///
    /// When `env` is non-empty, `--clear-env` is also passed so
    /// `lxc-exec`'s own caller environment does **not** leak into the
    /// sandbox — this is the replace-on-non-empty-env contract Seatbelt
    /// and WSLC apply, and the posture `lxc-attach(1)` itself recommends
    /// for sandbox-spawn callers. `lxc-attach` still injects a small
    /// baseline (`container`, `HOME`, `TERM`, default `PATH`, `USER`) and
    /// applies the container's `lxc.environment` config; those layers sit
    /// below the user vars and are outside this function's control.
    ///
    /// When `env` is empty, the legacy keep-env behavior is preserved so
    /// existing call sites without explicit env are undisturbed.
    ///
    /// We pass `unblock_signals = [SIGHUP, SIGTERM, SIGINT]` because
    /// [`crate::signal_cleanup::install`] blocks them in this process so
    /// its watchdog thread can `sigwait` on them; that mask is inherited
    /// across `fork`+`exec` and would otherwise make the inner shell
    /// silently ignore Ctrl-C / termination.
    ///
    /// Stdout/stderr are streamed live via the primary fd; the returned
    /// strings are always empty. Callers needing captured output should run
    /// a self-contained `commandLine` and read it back from a file.
    ///
    /// `timeout: Some(d)` kills the child if it runs longer than `d` and
    /// returns `Err("script timed out after {ms}ms")`.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome, Signal};

        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args(env, working_directory, command));

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
        _timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Stop the container.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-stop"), "lxc-stop")
    }

    /// Destroy the container (removes rootfs and config).
    ///
    /// `lxc-destroy -f` already force-stops a running container; we used to
    /// call `lxc-stop` first, but plain `lxc-stop` waits up to 60 s for a
    /// graceful shutdown — fatal for distros with systemd as PID 1 in
    /// unprivileged userns where init never cleanly responds to SIGPWR.
    /// Forcing the stop via destroy keeps this fast for both alpine and
    /// ubuntu-class images.
    pub fn destroy(&self) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-destroy");
        cmd.arg("-f");
        Self::run_status(cmd, "lxc-destroy")
    }

    /// Get the path to the container's config file.
    fn config_file_path(&self) -> String {
        format!("{}/{}/config", self.lxc_path, self.name)
    }

    /// Get the current system architecture string for LXC templates.
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
        // Even as root, LXC_PATH wins, matching liblxc's behavior.
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
        // XDG_DATA_HOME wins over HOME for unprivileged users.
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
        // Empty LXC_PATH/XDG_DATA_HOME must not be used as the path; resolution
        // should fall through to the next candidate.
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
        // Highly unusual: unprivileged process with neither HOME nor
        // XDG_DATA_HOME. We still return a deterministic path rather than
        // panicking; callers will surface the resulting filesystem error.
        let p = resolve_lxcpath_with_env(no_env, || 1000);
        assert_eq!(p, "/var/lib/lxc");
    }

    #[test]
    fn lxc_container_uses_resolved_lxcpath_when_none_provided() {
        // We can't easily mock libc::geteuid() in the real ctor, but we can
        // assert the contract: lxc_path() always returns a non-empty path,
        // even when the caller passes None.
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

    #[test]
    fn set_config_item_error_includes_key_value_and_path() {
        // Point the container at a path that does not exist so the open()
        // call reliably fails. The error message must include all three
        // diagnostic details so users can pinpoint the failure.
        let bogus_base = std::env::temp_dir().join(format!(
            "mxc-nonexistent-lxc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let container = LxcContainer::new("ghost", Some(bogus_base.to_str().unwrap()));
        let key = "lxc.mount.entry";
        let value = "/host /target none bind,create=dir 0 0";

        let err = container
            .set_config_item(key, value)
            .expect_err("set_config_item should fail when config file is missing");

        assert!(err.contains(key), "error must mention key, got: {}", err);
        assert!(
            err.contains(value),
            "error must mention value, got: {}",
            err
        );
        assert!(
            err.contains("ghost/config"),
            "error must mention container config path, got: {}",
            err
        );
    }

    // ---- build_attach_args ----------------------------------------------

    #[test]
    fn build_attach_args_no_env_no_cwd_is_unchanged_legacy_shape() {
        // Empty env + empty cwd must reproduce the original argv shape:
        // `-- /bin/sh -c <command>` so we don't perturb existing call sites
        // when neither cwd nor env is set.
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
        // Matches Seatbelt/WSLC semantics (split_once('=') drops malformed
        // entries) so a bad entry can't break the whole attach call.
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
        // The whole point of the positional-arg trick is that nasty cwd
        // values (spaces, single/double quotes, dollar signs, backticks)
        // pass through sh as `$1` verbatim — no escaping needed here.
        let cwd = "/tmp/has spaces & 'quotes' $vars `cmd`";
        let cmd = "printf '%s' \"$PWD\"";
        let args = build_attach_args(&[], cwd, cmd);

        // cwd and command must appear verbatim as the last two argv entries.
        assert_eq!(args[args.len() - 2], cwd);
        assert_eq!(args[args.len() - 1], cmd);
        // And the wrapper script must reference them positionally.
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
        // Containment guarantee: when the caller supplies env, lxc-exec's
        // own environment must NOT leak into the sandbox. `--clear-env`
        // also has to land BEFORE the `--set-var` entries so lxc-attach
        // clears first, then applies user vars on top.
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
        // Backward-compat guarantee: empty env preserves the legacy
        // keep-env shape so existing call sites with no explicit env are
        // undisturbed.
        let args = build_attach_args(&[], "", "echo hi");
        assert!(
            !args.iter().any(|a| a == "--clear-env"),
            "--clear-env must not appear when env is empty, got {:?}",
            args
        );
    }

    #[test]
    fn build_attach_args_omits_clear_env_when_env_is_only_malformed() {
        // Edge case: caller passed env but every entry was malformed
        // (no `=`). After the permissive skip there are no user vars to
        // apply, so `--clear-env` would strip the inherited env without
        // replacing it with anything — exactly the surprise we want to
        // avoid. Treat all-malformed as "no env supplied" and preserve
        // the keep-env shape.
        let env = vec!["BADENTRY".to_string(), "ALSO_BAD".to_string()];
        let args = build_attach_args(&env, "", "cmd");
        assert!(
            !args.iter().any(|a| a == "--clear-env"),
            "--clear-env must not appear when no entry survives the malformed-skip, got {:?}",
            args
        );
        assert_eq!(args, vec!["--", "/bin/sh", "-c", "cmd"]);
    }
}
