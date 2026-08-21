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

/// Environment variable stamped on every process an exec starts inside the
/// container, so a timeout can find its descendants and kill them.
///
/// A timeout tears down `lxc-attach` on the host, which says nothing about the
/// processes the script started inside the container's PID namespace.  The
/// container is persistent — it outlives the exec and lives until deprovision
/// — so those survivors keep holding CPU, memory, handles, and network inside a
/// sandbox the caller believes is idle, and the next exec shares the container
/// with them.
///
/// The marker rides on the environment, which every `fork`/`exec` inherits, so
/// it reaches descendants at any depth.  But the environment belongs to the
/// workload: anything that scrubs it escapes, so this cleans up after work that
/// is not trying to escape and is not a boundary against work that is.
/// `lxc-attach` joins the container's existing namespaces via `setns` and cannot
/// create one, so a per-exec PID namespace would have to be unshared by the
/// attached command itself — real, but a design that needs a live host to
/// validate, so #871 carries it rather than this improvising one.
///
/// The name is **reserved**: `build_attach_args` drops any caller-supplied
/// entry that uses it, so a caller cannot set it to another exec's token and be
/// reaped by that exec's timeout.
#[cfg(any(target_os = "linux", test))]
const EXEC_MARKER_VAR: &str = "MXC_EXEC_ID";

/// Mint a token for one exec, unique to this process and this call.
///
/// Uniqueness matters in both directions: two execs in the same container must
/// not reap each other, and a stale token from an earlier process must not
/// match anything live.
pub fn mint_exec_marker() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        wxc_common::id::mint_random_token()
    )
}

/// Build the post-binary argv for the `lxc-attach` that reaps an exec's
/// leftovers, given the marker value that exec was stamped with.
///
/// The marker travels as a positional argument rather than being spliced into
/// the script, so nothing in it can be read as shell syntax.  Only `cat` and
/// `kill` are used beyond shell builtins: `grep`'s `-a` and `-F` flags are not
/// dependable across the busybox and GNU userlands MXC containers are built
/// from.  Command substitution drops the NULs that separate `environ` entries,
/// which concatenates neighbors but leaves each `KEY=VALUE` intact, so the
/// substring test still holds.
///
/// The reaping shell is attached *without* the marker, so it cannot match
/// itself.
///
/// `/proc/[0-9]*` is expanded once per pass, so a workload that forks after
/// the expansion has a child the pass never sees.  The scan therefore stops
/// what it finds before killing anything: a stopped process cannot fork again,
/// so each pass shrinks the set that is still able to grow, and the loop
/// repeats until a pass discovers no marked process it had not already seen.
/// Only then is the collected set killed.  The pass count is bounded so a
/// deliberate fork bomb cannot spin here forever.
///
/// That is containment by convergence, not by construction.  A per-exec cgroup
/// or PID namespace would make it race-free outright, and `lxc-attach` offers
/// neither.
#[cfg(any(target_os = "linux", test))]
fn build_reap_args(marker: &str) -> Vec<String> {
    vec![
        "--".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        "seen=\" \"; i=0; \
         while [ \"$i\" -lt 8 ]; do \
           found=0; \
           for d in /proc/[0-9]*; do \
             p=${d#/proc/}; \
             case \"$seen\" in *\" $p \"*) continue ;; esac; \
             e=$(cat \"$d/environ\" 2>/dev/null) || continue; \
             case \"$e\" in *\"$1\"*) \
               kill -STOP \"$p\" 2>/dev/null; \
               seen=\"$seen$p \"; \
               found=1 ;; \
             esac; \
           done; \
           [ \"$found\" -eq 0 ] && break; \
           i=$((i + 1)); \
         done; \
         for p in $seen; do kill -KILL \"$p\" 2>/dev/null; done; \
         exit 0"
            .to_string(),
        "_".to_string(),
        format!("{}={}", EXEC_MARKER_VAR, marker),
    ]
}

/// The keep-env argv shape, for tests that do not exercise env control.
///
/// No production caller wants it, so outside `cfg(test)` this is dead code,
/// and the workspace clippy lane runs with `-D warnings`.
#[cfg(test)]
fn build_attach_args(
    env: &[String],
    working_directory: &str,
    command: &str,
    marker: Option<&str>,
) -> Vec<String> {
    build_attach_args_with_env_control(env, working_directory, command, false, marker)
}

/// Build the post-binary argv for `lxc-attach` (the args that follow the
/// `-n NAME -P lxcpath` flags already appended by `lxc_command`).
///
/// `marker`, when present, is stamped into the child's environment as
/// [`EXEC_MARKER_VAR`] so a timeout can locate the whole process tree later;
/// see [`build_reap_args`].  It is only supplied when the caller set a timeout,
/// so the no-timeout argv is unchanged.
///
/// Extracted so the env / cwd / command layering is unit-testable without
/// actually spawning `lxc-attach`. See [`LxcContainer::attach_run`] for
/// the full contract.
///
/// An empty `env` is ambiguous: it is both "the caller expressed no opinion"
/// and "a scrub removed every entry there was". `force_clear_env` is how a
/// caller says which one it means, because only the second still has to shut
/// the host environment out.
///
/// Gated to Linux + test builds because `attach_run` is a Windows stub
/// that never calls this helper, and the workspace clippy lane on
/// `windows-latest` would otherwise flag it as dead code.
#[cfg(any(target_os = "linux", test))]
fn build_attach_args_with_env_control(
    env: &[String],
    working_directory: &str,
    command: &str,
    force_clear_env: bool,
    marker: Option<&str>,
) -> Vec<String> {
    // Loose upper bound; realloc-avoidance hint only.
    let mut args: Vec<String> = Vec::with_capacity(env.len() + 8);

    // Replace semantics: any non-empty env opts the caller into a clean
    // slate, even if every entry is malformed. Matches Seatbelt exactly
    // and is the posture lxc-attach(1) recommends for sandbox callers.
    // See `attach_run` doc for the full contract.
    if force_clear_env || !env.is_empty() {
        args.push("--clear-env".to_string());
        for kv in env {
            // Well-formed = "KEY=VAL" with a non-empty KEY. `"=foo"` and
            // `"BADENTRY"` are both silently skipped; embedded `=` in
            // VAL is fine because split_once stops at the first one.
            if let Some((key, _)) = kv.split_once('=') {
                // `EXEC_MARKER_VAR` is reserved. Dropping a caller's copy is
                // not just tidiness: the marker is what a timeout kills by, so
                // a caller that set this name to another exec's token would be
                // reaped by that exec. The drop is unconditional because a
                // concurrent exec's timeout can reap this one even when this
                // one carries no marker of its own.
                if !key.is_empty() && key != EXEC_MARKER_VAR {
                    args.push(format!("--set-var={}", kv));
                }
            }
        }
    }

    // Stamped after the caller's entries so `--clear-env` still leads, and
    // outside the `env.is_empty()` gate so a caller that set no env still gets
    // a reapable exec.
    if let Some(token) = marker {
        args.push(format!("--set-var={}={}", EXEC_MARKER_VAR, token));
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

/// What liblxc says the container's network interfaces are.
///
/// Read through `lxc-info -c` rather than by parsing the container's config
/// file, because `lxc.include` can declare interfaces that file never mentions.
/// liblxc has already resolved those includes, so its answer is the set that
/// will actually be brought up; a count taken from the file alone would
/// understate the container and let a policy claim to be enforced when it is
/// not.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NetInterfaceConfig {
    /// How many interfaces liblxc will bring up.
    pub count: usize,
    /// The declared type of the container's only interface, present only when
    /// `count == 1`.
    ///
    /// Enforcement refuses anything that is not a `veth`, so the type is read
    /// to decide that. It comes from the same `lxc.net` read as the count, so
    /// no separate indexed probe is needed and there is no window between
    /// reading the count and reading the type.
    pub sole_kind: Option<String>,
}

/// Interpret an `lxc-info -c <key>` answer as the values liblxc holds for that
/// key.
///
/// liblxc prints the first value on a `key = value` line and any further values
/// bare on lines of their own. Each line is trimmed; a line beginning with
/// `key` followed by optional whitespace and `=` yields what follows, and any
/// other line is taken whole. Results are trimmed and empties dropped, so an
/// absent or empty key yields no values.
///
/// The prefix is keyed on `key` rather than split on the first `=` anywhere in
/// the line: a continuation value can itself contain `=` (a hook command does),
/// and splitting on `=` would truncate it.
fn interpret_config_values(key: &str, stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(|line| line.trim())
        .map(|line| {
            line.strip_prefix(key)
                .map(|rest| rest.trim_start())
                .and_then(|rest| rest.strip_prefix('='))
                .map_or(line, |value| value)
                .trim()
        })
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect()
}

/// Build the `lxc.hook.start-host` value that runs the veth-pin script.
///
/// The script takes the desired host veth name as its sole argument, so the
/// value is the script path and the target name separated by a space.
fn veth_pin_hook_command(script_path: &str, target_veth: &str) -> String {
    format!("{} {}", script_path, target_veth)
}

/// Shell body of the `lxc.hook.start-host` hook that renames the container's
/// host-side veth to the name passed as `$1`.
///
/// It finds the container's sole peered interface (a veth in the netns prints
/// `eth0@if<N>`; `lo` has no `@if`, so it is naturally excluded), resolves that
/// host ifindex to its current name, and renames it. It is idempotent and fails
/// closed.
const VETH_PIN_SCRIPT: &str = r#"#!/bin/sh
set -e
target="$1"
i=$(nsenter -t "$LXC_PID" -n ip -o link | sed -n 's/^[0-9]*: [^:@]*@if\([0-9]*\):.*/\1/p' | head -n1)
[ -n "$i" ] || { echo "mxc: no peered interface in container netns" >&2; exit 1; }
c=$(ip -o link | sed -n "s/^$i: \([^:@]*\)[@:].*/\1/p" | head -n1)
[ -n "$c" ] || { echo "mxc: host ifindex $i not resolvable" >&2; exit 1; }
[ "$c" = "$target" ] || ip link set "$c" name "$target"
"#;

/// Read an `lxc-info` run as "does this container exist?".
///
/// Split out as a pure function so the three-way answer is testable without
/// `lxc-info` on the box.
///
/// A nonzero exit is ambiguous on its own: `lxc-info` reports a container it
/// does not know that way, but so do a permission error, a transient runtime
/// failure, and a malformed config.  "Defined" means LXC has a config file for
/// the container, so that file settles the ambiguity, and `try_exists` reports
/// `false` only when it can prove absence -- a directory it cannot read is an
/// `Err`, not a `false`.
///
/// The layout assumption is `{lxc_path}/{name}/config`.  If that is ever wrong
/// the failure lands on `Ok(true)` for the config probe and therefore on `Err`
/// here, which refuses the phase; the old code returned `Ok(false)` and
/// unfiltered a live container.  Wrong in the safe direction.
fn interpret_defined_probe(
    probe_succeeded: bool,
    stderr: &str,
    config: &std::path::Path,
    name: &str,
) -> Result<bool, String> {
    if probe_succeeded {
        return Ok(true);
    }
    let detail = stderr.trim();
    match config.try_exists() {
        Ok(false) => Ok(false),
        Ok(true) => Err(format!(
            "lxc-info failed for container {name:?} but its config file at {} is present, so \
             whether the container is defined is unknown: {detail}",
            config.display()
        )),
        Err(e) => Err(format!(
            "lxc-info failed for container {name:?} and its config file at {} could not be \
             checked ({e}), so whether the container is defined is unknown: {detail}",
            config.display()
        )),
    }
}

/// The `lxc-info -s` states that still have a live container behind them.
///
/// `STOPPED` is the only state that does not.  `FROZEN` and `FREEZING` have
/// processes that thaw straight back into a running container, so unfiltering
/// one is the same fail-open as unfiltering a running one.  The transitional
/// states count as live for the same reason: stopping a container that is
/// already going down is harmless, and unfiltering one that is coming up is
/// not.
const LIVE_STATES: [&str; 7] = [
    "RUNNING", "FROZEN", "FREEZING", "THAWED", "STARTING", "STOPPING", "ABORTING",
];

/// Read `lxc-info -s` output as "is this container running?".
///
/// Split out as a pure function so the three-way answer is testable without a
/// container on the box.  Only a `State:` line answers the question; anything
/// else is an error rather than `false`, because callers treat a stopped
/// container as safe to unfilter and safe to skip stopping.  Guessing
/// "stopped" from output we could not read is the one answer that turns a
/// broken probe into an unfiltered running container.
fn interpret_state_output(stdout: &str) -> Result<bool, String> {
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() == "State" {
            let state = value.trim();
            if state == "STOPPED" {
                return Ok(false);
            }
            if LIVE_STATES.contains(&state) {
                return Ok(true);
            }
            return Err(format!(
                "lxc-info -s named an unrecognized state {state:?}, so whether the container is \
                 running is unknown"
            ));
        }
    }
    // No `State:` line. If a live-state name shows up anyway, answer in the
    // safe direction rather than give up: reporting "running" only ever costs a
    // refused operation, whereas reporting "stopped" is what unfilters a live
    // container.
    if LIVE_STATES.iter().any(|s| stdout.contains(s)) {
        return Ok(true);
    }
    Err(format!(
        "lxc-info -s named no state, so whether the container is running is unknown (output: {:?})",
        stdout.trim()
    ))
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

    /// Whether the container exists.
    ///
    /// `Err` means the probe could not answer, which is not evidence of
    /// absence.  Collapsing that into `false` reads "the probe broke" as "the
    /// container is gone", which let deprovision skip the destroy and then
    /// strip the firewall from a container that was still running.
    ///
    /// See [`interpret_defined_probe`] for why a nonzero exit is not an answer
    /// on its own.
    pub fn is_defined(&self) -> Result<bool, String> {
        let output = self
            .lxc_command("lxc-info")
            .output()
            .map_err(|e| format!("failed to run lxc-info: {e}"))?;
        let config = self.config_file_path();
        interpret_defined_probe(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
            std::path::Path::new(&config),
            &self.name,
        )
    }

    /// Whether the container is running.
    ///
    /// `Err` covers both a probe that could not run and one whose output names
    /// no state we recognize.  Neither is evidence that the container is
    /// stopped, and callers treat "stopped" as safe to unfilter or safe to
    /// skip stopping -- so an unreadable probe must not answer `false`.
    pub fn is_running(&self) -> Result<bool, String> {
        let output = self
            .lxc_command("lxc-info")
            .arg("-s")
            .output()
            .map_err(|e| format!("failed to run lxc-info -s: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "lxc-info -s failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        interpret_state_output(&String::from_utf8_lossy(&output.stdout))
    }

    /// Return the PID of the container's init process, or `None` if the
    /// container isn't running or the PID can't be parsed. Used to enter the
    /// container's network namespace (`nsenter -t <pid> -n`) for inbound
    /// iptables enforcement.
    ///
    /// `lxc-info -p` prints "just the container's pid"; depending on the LXC
    /// version this is either a bare number or a `PID: <n>` line, so both
    /// forms are accepted.
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
        Self::run_status(cmd, "lxc-create")
    }

    /// Marker comment written immediately above every `lxc.mount.entry` line
    /// that MXC itself adds, so
    /// [`replace_mxc_mount_entries`](Self::replace_mxc_mount_entries) can
    /// rewrite only MXC's own mounts and leave baseline entries the distro
    /// template or the user placed in the config untouched. It is a real LXC
    /// comment (`#`), so liblxc ignores it when parsing the file.
    const MXC_MOUNT_MARKER: &'static str = "# mxc-managed-mount";

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

    /// Replace the container's config file with `contents` in one atomic step.
    ///
    /// [`std::fs::write`] truncates in place, so a signal, crash, or OOM between
    /// the truncate and the last byte leaves the container's durable config
    /// partial or empty. liblxc re-reads that file on every start, so a
    /// half-written rewrite silently drops the entries a tightened policy
    /// depends on -- the failure lands on the next start, far from the write
    /// that caused it. Writing a sibling temporary and renaming it over the
    /// target makes the swap atomic: a concurrent reader observes either the
    /// whole old config or the whole new one, never a truncated prefix.
    ///
    /// The temporary is created beside the target so the rename stays inside one
    /// filesystem, and it is flushed before the rename so the bytes are durable
    /// before anything points at them. It carries the process id so two
    /// processes rewriting the same config cannot clobber each other's
    /// temporary, and it is removed on every failure path so a failed rewrite
    /// leaves no residue.
    ///
    /// A rename swaps in a *new* inode, so the target's mode and ownership are
    /// whatever the temporary had rather than what the operator set. That would
    /// silently relax a hardened `0600` root-owned config to a umask-derived
    /// `0644` on the first start, and would hand the file to the executor's uid
    /// when it runs as root. The original's metadata is therefore captured
    /// before the write and restored onto the temporary before the rename. The
    /// temporary is opened `0600` so its contents are never briefly readable by
    /// anyone the final mode would exclude; when there is no original to mirror,
    /// the platform default is left alone rather than a policy being invented.
    fn write_config_atomically(config_path: &str, contents: &str) -> std::io::Result<()> {
        use std::io::Write;

        let temp_path = format!("{}.mxc-tmp-{}", config_path, std::process::id());
        let original = std::fs::metadata(config_path).ok();
        let write_temp = || -> std::io::Result<()> {
            let mut file = Self::create_config_temp(&temp_path, original.is_some())?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()
        };
        if let Err(e) = write_temp() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        if let Some(ref meta) = original {
            if let Err(e) = Self::mirror_config_metadata(&temp_path, meta) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(e);
            }
        }
        if let Err(e) = std::fs::rename(&temp_path, config_path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        Ok(())
    }

    /// Open the rewrite temporary, restricted to the owner when there is an
    /// existing config whose mode will be restored before the rename.
    #[cfg(unix)]
    fn create_config_temp(temp_path: &str, has_original: bool) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        if !has_original {
            return std::fs::File::create(temp_path);
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(temp_path)
    }

    #[cfg(not(unix))]
    fn create_config_temp(temp_path: &str, _has_original: bool) -> std::io::Result<std::fs::File> {
        std::fs::File::create(temp_path)
    }

    /// Put the replaced config's mode and ownership onto its replacement.
    ///
    /// Ownership is restored only when it actually differs, so an unprivileged
    /// executor rewriting a config it already owns is not failed by a `chown`
    /// it never needed permission to make.
    #[cfg(unix)]
    fn mirror_config_metadata(
        temp_path: &str,
        original: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        // Masked to the permission bits: the mode read back from a `Metadata`
        // also carries the file-type bits, which are not this call's to set.
        std::fs::set_permissions(
            temp_path,
            std::fs::Permissions::from_mode(original.mode() & 0o7777),
        )?;
        let temp_meta = std::fs::metadata(temp_path)?;
        if temp_meta.uid() != original.uid() || temp_meta.gid() != original.gid() {
            std::os::unix::fs::chown(temp_path, Some(original.uid()), Some(original.gid()))
                .map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!(
                            "could not restore the config's owner {}:{} onto its replacement, so \
                             the rewrite was abandoned rather than silently changing who owns it: \
                             {e}",
                            original.uid(),
                            original.gid()
                        ),
                    )
                })?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn mirror_config_metadata(
        temp_path: &str,
        original: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        std::fs::set_permissions(temp_path, original.permissions())
    }

    /// Remove every configuration line for `key` from the container's config
    /// file.
    ///
    /// [`set_config_item`](Self::set_config_item) *appends* a `key = value`
    /// line, and list-type keys such as `lxc.mount.entry` accumulate one line
    /// per call. liblxc replays every occurrence when it parses the file at
    /// start, so a caller that re-derives a list from policy on each start must
    /// clear the previous run's lines first — otherwise a restart inherits
    /// stale entries (e.g. mounts a tightened policy meant to drop).
    ///
    /// A line matches when the token before its first `=` (trimmed) equals
    /// `key`, so `lxc.mount.entry` is matched but neighbouring keys like
    /// `lxc.mount` are left intact, and `=` inside a value (e.g.
    /// `create=dir`) is irrelevant. A missing config file is treated as
    /// already-clear (`Ok`).
    pub fn clear_config_item(&self, key: &str) -> Result<(), String> {
        let config_path = self.config_file_path();
        let contents = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "Failed to read config to clear {}: {} (config file: {})",
                    key, e, config_path
                ))
            }
        };

        let mut out = String::with_capacity(contents.len());
        for line in contents.lines() {
            let matches_key = line
                .split_once('=')
                .map(|(lhs, _)| lhs.trim() == key)
                .unwrap_or(false);
            if !matches_key {
                out.push_str(line);
                out.push('\n');
            }
        }

        Self::write_config_atomically(&config_path, &out).map_err(|e| {
            format!(
                "Failed to rewrite config to clear {}: {} (config file: {})",
                key, e, config_path
            )
        })
    }

    /// Replace MXC's whole mount set in one atomic config rewrite.
    ///
    /// Each entry is written as [`MXC_MOUNT_MARKER`](Self::MXC_MOUNT_MARKER) on
    /// its own line followed by `lxc.mount.entry = value`.  liblxc treats the
    /// marker as a comment and the entry exactly as if it had been added with
    /// [`set_config_item`](Self::set_config_item).
    ///
    /// The set is the unit that matters: a container configured with half of
    /// its policy's bind mounts is not a weaker sandbox, it is a different one.
    /// Clearing and then appending each entry separately committed a config
    /// per mount, so a crash, a signal, or a rejected path partway through left
    /// a durable config that matched no policy anyone wrote.  One rewrite means
    /// a reader sees either the previous run's mounts or this run's, never a
    /// prefix of this run's.
    ///
    /// Only MXC's own entries are replaced.  Each is tagged with
    /// [`MXC_MOUNT_MARKER`](Self::MXC_MOUNT_MARKER) on the line above it, which
    /// liblxc treats as a comment; foreign `lxc.mount.entry` lines placed by the
    /// distribution template or the operator carry no marker and survive
    /// untouched.  Clearing those instead would silently detach container
    /// storage nobody asked us to manage.
    ///
    /// A missing config file is already free of MXC mounts, so an empty set
    /// succeeds against one.  A non-empty set does not: writing mount entries
    /// into a config that liblxc never created would produce a container
    /// definition with no template behind it.
    pub fn replace_mxc_mount_entries(&self, values: &[String]) -> Result<(), String> {
        let config_path = self.config_file_path();
        let contents = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if values.is_empty() {
                    return Ok(());
                }
                return Err(format!(
                    "Failed to set {} MXC mount entries: no config file at {}",
                    values.len(),
                    config_path
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read config to rewrite MXC mounts: {} (config file: {})",
                    e, config_path
                ))
            }
        };

        let mut out = Self::strip_mxc_mount_entries(&contents);
        for value in values {
            out.push_str(Self::MXC_MOUNT_MARKER);
            out.push('\n');
            out.push_str("lxc.mount.entry = ");
            out.push_str(value);
            out.push('\n');
        }

        Self::write_config_atomically(&config_path, &out).map_err(|e| {
            format!(
                "Failed to rewrite config with {} MXC mount entries: {} (config file: {})",
                values.len(),
                e,
                config_path
            )
        })
    }

    /// `contents` with every MXC-added mount line removed.
    ///
    /// A marker line and the `lxc.mount.entry` line immediately following it are
    /// dropped together.  An orphaned marker -- one left by a config written
    /// before the rewrite became atomic -- is dropped on its own so stray
    /// comments cannot accumulate.
    ///
    /// Pure so the line-pairing is testable without a container on the box.
    fn strip_mxc_mount_entries(contents: &str) -> String {
        let lines: Vec<&str> = contents.lines().collect();
        let mut out = String::with_capacity(contents.len());
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.trim() == Self::MXC_MOUNT_MARKER {
                let next_is_entry = lines
                    .get(i + 1)
                    .map(|l| {
                        l.split_once('=')
                            .map(|(lhs, _)| lhs.trim() == "lxc.mount.entry")
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                i += if next_is_entry { 2 } else { 1 };
                continue;
            }
            out.push_str(line);
            out.push('\n');
            i += 1;
        }
        out
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
    /// that are malformed — no `=` (e.g. `"BADENTRY"`) or an empty key
    /// (e.g. `"=foo"`) — are silently skipped.
    ///
    /// When `env` is non-empty, `--clear-env` is also passed (regardless
    /// of how many entries survive validation) so `lxc-exec`'s own caller
    /// environment does **not** leak into the sandbox. This matches
    /// Seatbelt's `env_clear()`-on-non-empty contract and is the posture
    /// `lxc-attach(1)` recommends for sandbox-spawn callers. `lxc-attach`
    /// still injects a small baseline (`container`, `HOME`, `TERM`,
    /// default `PATH`, `USER`) and applies the container's
    /// `lxc.environment` config; those layers sit below the user vars
    /// and are outside this function's control.
    ///
    /// When `env` is empty, the legacy keep-env behavior is preserved so
    /// existing call sites without explicit env are undisturbed unless
    /// `force_clear_env` is true. An empty `env` is ambiguous -- it is both
    /// "no caller opinion" and "a scrub removed every entry there was" -- and
    /// keep-env is only the right reading of the first, because it is the
    /// mode under which this process's own environment, proxy variables and
    /// host credentials included, reaches the container.
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
    ///
    /// `marker: Some(token)` stamps the exec so its container-side processes
    /// can be reaped later; see [`mint_exec_marker`].  The caller owns the
    /// token because a timeout is not the only way an exec ends early -- a
    /// signal kills this process outright, and the watchdog needs the same
    /// token to reap on its way out.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        timeout: Option<std::time::Duration>,
        marker: Option<&str>,
    ) -> Result<(i32, String, String), String> {
        use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome, Signal};

        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
            marker,
        ));

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

                // Killing lxc-attach ended the caller's view of the work, not
                // the work.  Reap before reporting, and if the reap fails say
                // so: a bare timeout message would tell the caller the script
                // stopped when it may still be running.  A reap that succeeds
                // is not a containment guarantee either — see
                // `reap_marked_processes` for what escapes it.
                if let Some(token) = marker {
                    if let Err(e) = self.reap_marked_processes(token) {
                        return Err(format!(
                            "script timed out after {}ms, and its processes could not be \
                             reaped from the container, so they may still be running: {}",
                            ms, e
                        ));
                    }
                }

                Err(format!("script timed out after {}ms", ms))
            }
        }
    }

    /// Kill every process in the container whose environment carries `marker`.
    ///
    /// Called on timeout by [`attach_run`](Self::attach_run) and on a fatal
    /// signal by the cleanup watchdog.  Reaching into the container's PID
    /// namespace requires a second attach; the alternative the issue raised —
    /// stopping and restarting the container — would discard the ingress chain
    /// that lives in its network namespace and the rest of the start-time
    /// enforcement, so it trades an orphaned process for an unfiltered sandbox.
    ///
    /// The guarantee is exactly what the sentence above says and no more: this
    /// reaps processes *carrying the marker*, not every descendant of the exec.
    /// The marker is inherited across `fork`/`exec`, so it reaches descendants
    /// at any depth — but the environment belongs to the workload, and a
    /// workload that scrubs it (`env -i`, `env -u MXC_EXEC_ID`, an explicit
    /// `unsetenv`) drops off the list and survives the reap.  Returning `Ok(())`
    /// means every *marked* process was killed, not that the container is quiet.
    ///
    /// **This is hygiene, not containment.**  Contained code is untrusted, so a
    /// handle the workload can erase is not a boundary against it — it only
    /// cleans up after work that is not trying to escape, which is the case that
    /// actually leaks into the next exec today.  A boundary needs kernel-owned
    /// membership the workload cannot leave (a per-exec PID namespace or
    /// cgroup); #871 carries that design and the host-dependent questions it
    /// has to answer first, because a containment mechanism that silently fails
    /// is worse than one documented not to be one.
    #[cfg(target_os = "linux")]
    pub(crate) fn reap_marked_processes(&self, marker: &str) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_reap_args(marker));
        Self::run_status(cmd, "lxc-attach (reap)")
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
        _marker: Option<&str>,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Stop the container.
    ///
    /// Graceful: `lxc-stop` asks init to shut down and waits. That is right for
    /// an explicit lifecycle stop, and wrong for every rollback -- see
    /// [`kill`](Self::kill).
    pub fn stop(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-stop"), "lxc-stop")
    }

    /// Stop the container immediately, without waiting for a graceful shutdown.
    ///
    /// `lxc-stop` on its own waits up to 60 s for init to respond, and on
    /// distros running systemd as PID 1 in an unprivileged userns init never
    /// cleanly responds to SIGPWR at all -- so the wait can be the full timeout
    /// and the stop can still fail.
    ///
    /// That is merely slow when a caller asked to stop a sandbox. It is a hole
    /// when a rollback is stopping a container *because its isolation is not in
    /// force*: the container keeps running, and keeps accepting traffic, for as
    /// long as the graceful stop takes. Rollback paths use this instead, so the
    /// exposure ends now rather than after a shutdown negotiation the guest can
    /// decline.
    pub fn kill(&self) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-stop");
        cmd.arg("-k");
        Self::run_status(cmd, "lxc-stop -k")
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
    pub(crate) fn config_file_path(&self) -> String {
        format!("{}/{}/config", self.lxc_path, self.name)
    }

    /// What liblxc says this container's network interfaces are.
    ///
    /// Provision adopts an existing container as readily as it creates one, and
    /// an adopted container can carry more network interfaces than the single
    /// `lxc.net.0` MXC configures for itself. A caller that filters egress needs
    /// to know that before it claims to have filtered anything.
    ///
    /// The question goes to liblxc rather than to the config file because
    /// `lxc.include` can add interfaces the file never mentions, and resolving
    /// includes here -- relative paths and directory globs both -- would mean
    /// reimplementing liblxc's own resolution and getting it subtly wrong.
    /// liblxc answers for a stopped container, so the answer is available while
    /// there is still time to act on it before start.
    ///
    /// The count and the sole interface's type both come from a single
    /// `lxc.net` read, so there is no longer a window between reading the count
    /// and reading the interface. This is not atomic with respect to the start
    /// itself -- the config could still change before liblxc reads it -- only
    /// with respect to this pair of observations.
    ///
    /// A probe that cannot run is an error rather than an empty answer: no
    /// evidence of an interface is not evidence of no interface.
    pub fn configured_net_interfaces(&self) -> Result<NetInterfaceConfig, String> {
        let values = interpret_config_values("lxc.net", &self.query_config_item("lxc.net")?);
        let count = values.len();
        // The type only matters when there is exactly one interface; every
        // other count is refused upstream without reference to it.
        let sole_kind = if count == 1 {
            values.into_iter().next()
        } else {
            None
        };
        Ok(NetInterfaceConfig { count, sole_kind })
    }

    /// Install the `lxc.hook.start-host` hook that pins the container's
    /// host-side veth to `target_veth`.
    ///
    /// The hook runs after liblxc has created the veth pair and attached it to
    /// the bridge but before the container's init execs, so the deterministic
    /// name is in place before anything in the container can transmit. The hook
    /// key is container-global -- it carries no `lxc.net.<N>` index -- so
    /// enforcement no longer depends on which index the interface uses.
    ///
    /// The script is written fresh every time so it cannot go stale, and made
    /// executable. The hook entry is appended only when an identical one is not
    /// already present; the key is never cleared, because a container's own
    /// config may declare start-host hooks that clearing would destroy.
    pub fn ensure_veth_pin_hook(&self, target_veth: &str) -> Result<(), String> {
        let script_path = format!("{}/{}/mxc-veth-pin.sh", self.lxc_path, self.name);

        std::fs::write(&script_path, VETH_PIN_SCRIPT)
            .map_err(|e| format!("Failed to write veth pin hook script {script_path}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to chmod veth pin hook script {script_path}: {e}"))?;
        }

        if self.has_veth_pin_hook(target_veth)? {
            return Ok(());
        }
        self.set_config_item(
            "lxc.hook.start-host",
            &veth_pin_hook_command(&script_path, target_veth),
        )
    }

    /// Whether this container's own config already pins its veth to
    /// `target_veth`.
    ///
    /// A container carrying this hook has had its host-side veth renamed by the
    /// time its init execs, because the hook runs before that and a nonzero
    /// exit aborts the start. So the answer decides which name describes the
    /// live interface: with the hook, the pinned name; without it, whatever
    /// liblxc recorded when it created the pair.
    ///
    /// This asks the container rather than the host on purpose. Asking the host
    /// whether an interface of the pinned name exists answers a different
    /// question -- it cannot tell this container's interface from a stranger's
    /// that happens to hold the name, and it turns a transient failure of the
    /// probe into the wrong answer rather than into an error.
    ///
    /// It reuses the comparison `ensure_veth_pin_hook` writes with, so the
    /// reader and the writer cannot drift apart.
    pub fn has_veth_pin_hook(&self, target_veth: &str) -> Result<bool, String> {
        let script_path = format!("{}/{}/mxc-veth-pin.sh", self.lxc_path, self.name);
        let value = veth_pin_hook_command(&script_path, target_veth);
        let existing = interpret_config_values(
            "lxc.hook.start-host",
            &self.query_config_item("lxc.hook.start-host")?,
        );
        Ok(existing.iter().any(|present| present == &value))
    }

    /// Ask liblxc for one config key, with any `lxc.include` already resolved.
    ///
    /// A key liblxc does not hold is not a failure -- it reports that on stderr
    /// and exits zero, leaving stdout empty -- so only a nonzero exit is treated
    /// as one.
    fn query_config_item(&self, key: &str) -> Result<String, String> {
        let output = self
            .lxc_command("lxc-info")
            .arg("-c")
            .arg(key)
            .output()
            .map_err(|e| format!("failed to run lxc-info -c {key}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "lxc-info -c {} failed: {}",
                key,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
    fn an_atomic_config_rewrite_replaces_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("mxc-atomic-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test temp dir");
        let target = dir.join("config");
        let path = target.to_string_lossy().to_string();

        std::fs::write(&target, "lxc.mount.entry = old\nlxc.mount.entry = stale\n")
            .expect("seed the original config");
        LxcContainer::write_config_atomically(&path, "lxc.mount.entry = new\n")
            .expect("rewrite must succeed");

        assert_eq!(
            std::fs::read_to_string(&target).expect("read the rewritten config"),
            "lxc.mount.entry = new\n",
            "the rewrite must fully replace the previous contents"
        );

        // The swap must not leave its sibling behind. liblxc reads the config
        // directory, and a surviving *.mxc-tmp-* is a second copy of a policy
        // that was meant to be replaced, not merely litter.
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .expect("list the config directory")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name != "config")
            .collect();
        assert!(
            leftovers.is_empty(),
            "a successful write must leave no temporary, found: {:?}",
            leftovers
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_atomic_config_rewrite_reports_failure_without_touching_the_original() {
        // A directory standing where the config should be makes both the
        // temporary create and the rename fail. The original must survive an
        // unwritable target rather than being truncated on the way to an error,
        // which is the whole reason the write does not go in place.
        let dir = std::env::temp_dir().join(format!("mxc-atomic-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config")).expect("test temp dir");

        let err = LxcContainer::write_config_atomically(
            &dir.join("config").to_string_lossy(),
            "lxc.mount.entry = new\n",
        );
        assert!(err.is_err(), "writing over a directory must report failure");
        assert!(
            dir.join("config").is_dir(),
            "the failed write must not have replaced the target"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_atomic_config_rewrite_keeps_the_operator_s_permissions() {
        use std::os::unix::fs::PermissionsExt;

        // A rename swaps in a new inode, so without explicit restoration a
        // hardened config silently relaxes to whatever the umask allows the
        // first time a start rewrites it. An operator who set 0600 gets to keep
        // it.
        let dir = std::env::temp_dir().join(format!("mxc-atomic-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test temp dir");
        let target = dir.join("config");
        let path = target.to_string_lossy().to_string();

        std::fs::write(&target, "lxc.mount.entry = old\n").expect("seed the original config");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("harden the original config");

        LxcContainer::write_config_atomically(&path, "lxc.mount.entry = new\n")
            .expect("rewrite must succeed");

        let mode = std::fs::metadata(&target)
            .expect("stat the rewritten config")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the rewrite must not widen the config's permissions"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
    fn one_interface_reports_one() {
        assert_eq!(
            interpret_config_values("lxc.net", "lxc.net = veth\n\n").len(),
            1
        );
    }

    #[test]
    fn a_state_line_answers_whether_the_container_is_running() {
        assert_eq!(
            interpret_state_output("State:          RUNNING\n"),
            Ok(true)
        );
        assert_eq!(
            interpret_state_output("State:          STOPPED\n"),
            Ok(false)
        );
    }

    #[test]
    fn stripping_drops_mxc_mounts_and_keeps_baseline_ones() {
        let config = concat!(
            "lxc.uts.name = box\n",
            "lxc.mount.entry = /srv /srv none bind 0 0\n",
            "# mxc-managed-mount\n",
            "lxc.mount.entry = /tmp/a a none bind,create=dir 0 0\n",
            "lxc.rootfs.path = /var/lib/lxc/box/rootfs\n",
        );
        let out = LxcContainer::strip_mxc_mount_entries(config);
        assert!(
            out.contains("/srv /srv none bind 0 0"),
            "a baseline mount the operator placed must survive, got {out:?}"
        );
        assert!(
            !out.contains("/tmp/a"),
            "MXC's own mount must go, got {out:?}"
        );
        assert!(!out.contains("mxc-managed-mount"), "got {out:?}");
        assert!(out.contains("lxc.rootfs.path"), "got {out:?}");
    }

    #[test]
    fn stripping_drops_a_marker_left_without_its_entry() {
        // Configs written before the rewrite became atomic can hold a marker
        // whose entry never landed. Left behind, those accumulate one stray
        // comment per interrupted start.
        let out = LxcContainer::strip_mxc_mount_entries("# mxc-managed-mount\nlxc.uts.name = b\n");
        assert_eq!(out, "lxc.uts.name = b\n");
    }

    #[test]
    fn a_mount_set_replaces_the_previous_one_in_a_single_config() {
        let dir = std::env::temp_dir().join(format!("mxc-mountset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("box")).expect("test temp dir");
        let config = dir.join("box").join("config");
        std::fs::write(
            &config,
            "lxc.uts.name = box\n# mxc-managed-mount\nlxc.mount.entry = /old old none bind 0 0\n",
        )
        .expect("seed config");

        let container = LxcContainer::new("box", Some(&dir.to_string_lossy()));
        container
            .replace_mxc_mount_entries(&[
                "/new new none bind,create=dir 0 0".to_string(),
                "/two two none bind,ro,create=dir 0 0".to_string(),
            ])
            .expect("rewrite must succeed");

        let after = std::fs::read_to_string(&config).expect("read back");
        assert!(
            !after.contains("/old"),
            "the previous run's mounts must not accumulate, got {after:?}"
        );
        assert!(after.contains("/new new"), "got {after:?}");
        assert!(after.contains("/two two"), "got {after:?}");
        assert!(after.contains("lxc.uts.name = box"), "got {after:?}");
        assert_eq!(
            after.matches("# mxc-managed-mount").count(),
            2,
            "one marker per entry, got {after:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_mount_set_clears_the_previous_one() {
        let dir = std::env::temp_dir().join(format!("mxc-mountclear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("box")).expect("test temp dir");
        let config = dir.join("box").join("config");
        std::fs::write(
            &config,
            "lxc.uts.name = box\n# mxc-managed-mount\nlxc.mount.entry = /old old none bind 0 0\n",
        )
        .expect("seed config");

        LxcContainer::new("box", Some(&dir.to_string_lossy()))
            .replace_mxc_mount_entries(&[])
            .expect("an empty set is a valid policy");

        let after = std::fs::read_to_string(&config).expect("read back");
        assert!(!after.contains("/old"), "got {after:?}");
        assert!(after.contains("lxc.uts.name = box"), "got {after:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_successful_probe_answers_defined_without_touching_the_filesystem() {
        // The common path: `lxc-info` knows the container, so the config file
        // never needs consulting.
        assert_eq!(
            interpret_defined_probe(
                true,
                "",
                std::path::Path::new("/nonexistent/box/config"),
                "b"
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_failed_probe_with_no_config_file_means_absent() {
        let dir = std::env::temp_dir().join(format!("mxc-defined-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config = dir.join("no-such-container").join("config");
        assert_eq!(
            interpret_defined_probe(false, "container not found", &config, "no-such-container"),
            Ok(false)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_probe_with_a_config_file_present_is_unknown_rather_than_absent() {
        // The fail-open this closes: a permission or transient error made
        // deprovision skip `destroy()` and then authoritatively strip the
        // firewall from a container that was still running. The config file
        // proves the container is defined, so the honest answer is "unknown".
        let dir = std::env::temp_dir().join(format!("mxc-defined-live-{}", std::process::id()));
        let container = dir.join("box");
        std::fs::create_dir_all(&container).expect("temp dir");
        let config = container.join("config");
        std::fs::write(&config, "lxc.uts.name = box\n").expect("config file");

        let answer = interpret_defined_probe(false, "permission denied", &config, "box");
        assert!(
            answer.is_err(),
            "a present config file must not read as absent, got {answer:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_frozen_container_is_live_not_stopped() {
        // A frozen container still has processes; thawing resumes them. Reading
        // it as stopped is what lets `stop` skip `lxc-stop`, tear the firewall
        // down as authoritative, and leave a thawable container unfiltered.
        assert_eq!(interpret_state_output("State:          FROZEN\n"), Ok(true));
        assert_eq!(
            interpret_state_output("State:          FREEZING\n"),
            Ok(true)
        );
        assert_eq!(interpret_state_output("State:          THAWED\n"), Ok(true));
    }

    #[test]
    fn a_transitional_state_is_live_not_stopped() {
        // STOPPED is the only state with nothing left to unfilter. Stopping a
        // container that is already going down costs an idempotent `lxc-stop`;
        // unfiltering one that is coming up costs the isolation.
        assert_eq!(
            interpret_state_output("State:          STARTING\n"),
            Ok(true)
        );
        assert_eq!(
            interpret_state_output("State:          STOPPING\n"),
            Ok(true)
        );
        assert_eq!(
            interpret_state_output("State:          ABORTING\n"),
            Ok(true)
        );
    }

    #[test]
    fn a_state_name_we_do_not_know_is_unknown_rather_than_stopped() {
        // A state added by a future liblxc must not default into the answer
        // that unfilters a container.
        assert!(interpret_state_output("State:          MARVELLOUS\n").is_err());
    }

    #[test]
    fn output_that_names_no_state_is_unknown_rather_than_stopped() {
        // The whole point of the three-way answer. Callers read "stopped" as
        // safe to unfilter and safe to skip stopping, so inferring it from
        // output we could not read is what turns a broken probe into an
        // unfiltered running container.
        assert!(interpret_state_output("").is_err());
        assert!(interpret_state_output("Name:  box\n").is_err());
    }

    #[test]
    fn an_unlabelled_running_is_still_read_as_running() {
        // The negative control for the test above: unknown must not swallow a
        // state we can plainly see. If the label ever changes, the failure has
        // to land on the safe side -- a refused operation, never an unfiltered
        // container.
        assert_eq!(interpret_state_output("RUNNING\n"), Ok(true));
    }

    #[test]
    fn every_interface_is_counted_so_a_caller_can_refuse_to_half_filter() {
        // liblxc prints the first value inline and the rest bare. The count is
        // what decides whether one FORWARD hook covers the container, so a
        // second interface has to survive the parse -- including one that only
        // an lxc.include declared, which is why the question goes to liblxc.
        assert_eq!(
            interpret_config_values("lxc.net", "lxc.net = veth\nveth\n\n").len(),
            2
        );
    }

    #[test]
    fn a_container_with_no_network_reports_no_interfaces() {
        assert_eq!(interpret_config_values("lxc.net", "lxc.net =\n").len(), 0);
    }

    #[test]
    fn a_netdev_of_type_empty_still_counts_as_an_interface() {
        // A config that declares lxc.net.0 properties without a type does not
        // leave the type undeclared -- liblxc supplies `empty`, a real netdev
        // type that gives the container only a loopback. The absence signal is
        // an empty value, so reading the word as absence would report no
        // interface for a container that has one and refuse it for the wrong
        // reason.
        assert_eq!(
            interpret_config_values("lxc.net", "lxc.net = empty\n").len(),
            1
        );
    }

    #[test]
    fn trailing_blank_lines_are_not_counted_as_interfaces() {
        // Counting them would report a second interface that does not exist and
        // refuse a container MXC can fully filter.
        assert_eq!(
            interpret_config_values("lxc.net", "lxc.net = veth\n\n\n\n").len(),
            1
        );
    }

    #[test]
    fn a_single_value_is_returned_intact() {
        assert_eq!(
            interpret_config_values("lxc.net", "lxc.net = veth\n"),
            vec!["veth".to_string()]
        );
    }

    #[test]
    fn multiple_values_span_the_inline_and_continuation_lines() {
        // liblxc prints the first value on the key line and the rest bare, so
        // every value has to be recovered regardless of which line carries it.
        assert_eq!(
            interpret_config_values(
                "lxc.hook.start-host",
                "lxc.hook.start-host = /a/one.sh\n/a/two.sh\n"
            ),
            vec!["/a/one.sh".to_string(), "/a/two.sh".to_string()]
        );
    }

    #[test]
    fn an_empty_value_yields_no_values() {
        assert!(interpret_config_values("lxc.net", "lxc.net =\n").is_empty());
    }

    #[test]
    fn a_value_containing_an_equals_sign_is_returned_intact() {
        // A hook command can carry `=` in an argument. Splitting on the first
        // `=` anywhere in the line would truncate it; keying the strip on the
        // config key preserves the whole value -- both on the inline line and
        // on a bare continuation line.
        assert_eq!(
            interpret_config_values(
                "lxc.hook.start-host",
                "lxc.hook.start-host = /a/pin.sh --name=veth0\n/a/other.sh k=v\n"
            ),
            vec![
                "/a/pin.sh --name=veth0".to_string(),
                "/a/other.sh k=v".to_string()
            ]
        );
    }

    #[test]
    fn leading_and_trailing_blank_lines_are_ignored() {
        assert_eq!(
            interpret_config_values("lxc.net", "\n\nlxc.net = veth\n\n"),
            vec!["veth".to_string()]
        );
    }

    #[test]
    fn the_pin_hook_command_passes_the_target_as_a_separate_argument() {
        // The script reads the target from $1, so the value has to be the
        // script path and the target separated by whitespace, not concatenated.
        let cmd = veth_pin_hook_command("/var/lib/lxc/box/mxc-veth-pin.sh", "mxcveth-box");
        assert!(cmd.contains("/var/lib/lxc/box/mxc-veth-pin.sh"), "{cmd}");
        assert!(cmd.contains("mxcveth-box"), "{cmd}");
        let mut parts = cmd.split_whitespace();
        assert_eq!(parts.next(), Some("/var/lib/lxc/box/mxc-veth-pin.sh"));
        assert_eq!(parts.next(), Some("mxcveth-box"));
    }

    #[test]
    fn an_unreadable_container_is_an_error_rather_than_an_empty_answer() {
        // No evidence of an interface is not evidence of no interface. Answering
        // "none" would send the caller down the zero-interface path and report a
        // refusal reason that was never established.
        let c = LxcContainer::new("definitely-not-provisioned", Some("/nonexistent-lxcpath"));
        assert!(c.configured_net_interfaces().is_err());
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

    #[test]
    fn clear_config_item_removes_only_matching_key_lines() {
        // Set up a real config file with two `lxc.mount.entry` lines (the
        // list-type key that accumulates across restarts), a similarly-named
        // key that must be preserved, and unrelated keys.
        let base = std::env::temp_dir().join(format!(
            "mxc-clear-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let name = "box";
        std::fs::create_dir_all(base.join(name)).unwrap();
        let container = LxcContainer::new(name, Some(base.to_str().unwrap()));

        let original = "lxc.arch = amd64\n\
             lxc.mount.entry = /host/a a none bind,create=dir 0 0\n\
             lxc.mount = /some/fstab\n\
             lxc.mount.entry = /host/b b none bind,ro,create=dir 0 0\n\
             lxc.uts.name = box\n";
        std::fs::write(container.config_file_path(), original).unwrap();

        container.clear_config_item("lxc.mount.entry").unwrap();

        let after = std::fs::read_to_string(container.config_file_path()).unwrap();
        assert!(
            !after.contains("lxc.mount.entry"),
            "all lxc.mount.entry lines must be removed, got:\n{after}"
        );
        // The prefix-sharing `lxc.mount` key and unrelated keys survive.
        assert!(after.contains("lxc.mount = /some/fstab"));
        assert!(after.contains("lxc.arch = amd64"));
        assert!(after.contains("lxc.uts.name = box"));

        // Re-clearing is idempotent.
        container.clear_config_item("lxc.mount.entry").unwrap();
        let after2 = std::fs::read_to_string(container.config_file_path()).unwrap();
        assert_eq!(after, after2);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn clear_config_item_missing_file_is_ok() {
        // A container whose config file does not exist is already "clear".
        let bogus_base = std::env::temp_dir().join(format!(
            "mxc-clear-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let container = LxcContainer::new("ghost", Some(bogus_base.to_str().unwrap()));
        assert!(container.clear_config_item("lxc.mount.entry").is_ok());
    }

    #[test]
    fn build_attach_args_no_env_no_cwd_is_unchanged_legacy_shape() {
        // Empty env + empty cwd must reproduce the original argv shape:
        // `-- /bin/sh -c <command>` so we don't perturb existing call sites
        // when neither cwd nor env is set.
        let args = build_attach_args(&[], "", "echo hi", None);
        assert_eq!(args, vec!["--", "/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn build_attach_args_env_is_translated_to_set_var_flags() {
        let env = vec![
            "FOO=bar".to_string(),
            "EMPTY=".to_string(),
            "HAS_EQ_IN_VAL=a=b=c".to_string(),
        ];
        let args = build_attach_args(&env, "", "cmd", None);
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
        // Malformed entry can't poison the whole attach call.
        let env = vec!["BADENTRY".to_string(), "OK=val".to_string()];
        let args = build_attach_args(&env, "", "cmd", None);
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
        // `"=foo"` and `"="` both have an empty key — `--set-var==foo`
        // would either be rejected by lxc-attach or create a phantom
        // unnamed var. Drop them the same way we drop entries without `=`.
        let env = vec![
            "=foo".to_string(),
            "=".to_string(),
            "=val=more".to_string(),
            "OK=val".to_string(),
        ];
        let args = build_attach_args(&env, "", "cmd", None);
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
        let args = build_attach_args(&[], "/opt/work", "echo hi", None);
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
        let args = build_attach_args(&[], cwd, cmd, None);

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
        let args = build_attach_args(&env, "/work", "cmd", None);
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
        let args = build_attach_args(&env, "", "cmd", None);
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
        let args = build_attach_args(&[], "", "echo hi", None);
        assert!(
            !args.iter().any(|a| a == "--clear-env"),
            "--clear-env must not appear when env is empty, got {:?}",
            args
        );
    }

    #[test]
    fn build_attach_args_can_force_clear_env_when_env_empty() {
        let args = build_attach_args_with_env_control(&[], "", "cmd", true, None);
        assert_eq!(args, vec!["--clear-env", "--", "/bin/sh", "-c", "cmd"]);
    }

    #[test]
    fn build_attach_args_clears_env_even_when_all_entries_malformed() {
        // Caller opted into env control by populating the field. Even if
        // every entry is malformed, `--clear-env` must still fire so the
        // host env doesn't leak in through a back door. lxc-attach's own
        // baseline (HOME, PATH, USER, ...) keeps the child runnable.
        let env = vec!["BADENTRY".to_string(), "=alsobad".to_string()];
        let args = build_attach_args(&env, "", "cmd", None);
        assert_eq!(args, vec!["--clear-env", "--", "/bin/sh", "-c", "cmd"]);
    }

    #[test]
    fn build_attach_args_caller_env_replaces_host_env() {
        // Documents the host-vs-caller collision contract: when both the
        // host and the caller set the same KEY, the caller's value wins
        // because `--clear-env` lands BEFORE the `--set-var` entries, so
        // lxc-attach wipes the inherited slot and then re-sets it from
        // the caller's value. The integration test in
        // `tests/scripts/run_lxc_env_cwd_test.sh` exports a host-side
        // `MXC_TEST_FOO=HOST_LEAK_SHOULD_NOT_APPEAR` and asserts the
        // child sees the config's `MXC_TEST_FOO=bar baz`.
        let env = vec!["MXC_TEST_FOO=bar baz".to_string()];
        let args = build_attach_args(&env, "", "cmd", None);
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
    fn a_timed_exec_is_stamped_so_its_descendants_can_be_found() {
        // The marker is the only handle a timeout has on work that outlived
        // the attach.  Without it the reap has nothing to match.
        let args = build_attach_args(&[], "", "sleep 99", Some("tok123"));
        assert!(
            args.iter().any(|a| a == "--set-var=MXC_EXEC_ID=tok123"),
            "timed exec must carry the marker, got {:?}",
            args
        );
    }

    // ── End-to-end: proxy policy → env → attach args ─────────────────────────
    // These tests drive apply_proxy_env then build_attach_args_with_env_control
    // together so the observable output (the lxc-attach argv) is what is
    // asserted, not just an intermediate bool.

    #[test]
    fn proxy_disabled_keeps_caller_proxy_env_and_still_clears_inherited_env() {
        // With no MXC proxy there is no egress path of ours for a caller's own
        // proxy variable to bypass, and the firewall chain -- not an
        // environment variable -- is what enforces the policy either way.
        use wxc_common::{models::ProxyConfig, proxy_env::apply_proxy_env};
        let mut env = vec![
            "HTTP_PROXY=http://caller-proxy.example:9999".to_string(),
            "PATH=/usr/bin".to_string(),
        ];
        apply_proxy_env(&mut env, &ProxyConfig::default());
        let args = build_attach_args_with_env_control(&env, "", "cmd", true, None);
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
    fn stamping_a_marker_does_not_clear_an_untouched_environment() {
        // `--clear-env` is the caller's choice, keyed on the caller's env.
        // Reaping must not smuggle in a wipe of the container's own
        // environment as a side effect.
        let args = build_attach_args(&[], "", "sleep 99", Some("tok123"));
        assert!(
            !args.iter().any(|a| a == "--clear-env"),
            "marker must not pull in --clear-env, got {:?}",
            args
        );
    }

    #[test]
    fn the_marker_is_applied_after_the_environment_is_cleared() {
        // Same ordering rule as the caller's own vars: a marker set before
        // `--clear-env` would be wiped, leaving a timed exec unreapable.
        let env = vec!["FOO=bar".to_string()];
        let args = build_attach_args(&env, "", "cmd", Some("tok123"));
        let clear_idx = args.iter().position(|a| a == "--clear-env").unwrap();
        let marker_idx = args
            .iter()
            .position(|a| a == "--set-var=MXC_EXEC_ID=tok123")
            .expect("marker should be present");
        assert!(
            clear_idx < marker_idx,
            "--clear-env must precede the marker, got {:?}",
            args
        );
    }

    #[test]
    fn a_caller_cannot_supply_its_own_marker() {
        // A caller that sets the reserved name could otherwise be reaped by
        // whichever exec owns that token, so the entry is dropped whether or
        // not this exec carries a marker of its own.
        let env = vec!["MXC_EXEC_ID=stolen".to_string(), "KEEP=yes".to_string()];

        let timed = build_attach_args(&env, "", "cmd", Some("mine"));
        assert!(
            timed.iter().any(|a| a == "--set-var=KEEP=yes"),
            "unrelated caller vars must survive, got {:?}",
            timed
        );
        assert!(
            !timed.iter().any(|a| a == "--set-var=MXC_EXEC_ID=stolen"),
            "the caller's marker must not reach the guest, got {:?}",
            timed
        );
        assert_eq!(
            timed
                .iter()
                .filter(|a| a.starts_with("--set-var=MXC_EXEC_ID="))
                .count(),
            1,
            "exactly one marker must survive, got {:?}",
            timed
        );

        let untimed = build_attach_args(&env, "", "cmd", None);
        assert!(
            !untimed
                .iter()
                .any(|a| a.starts_with("--set-var=MXC_EXEC_ID=")),
            "an untimed exec must carry no marker at all, got {:?}",
            untimed
        );
    }

    #[test]
    fn an_untimed_exec_carries_no_marker() {
        // Nothing can time out, so nothing needs reaping, and the argv stays
        // exactly what it was before reaping existed.
        let args = build_attach_args(&[], "", "echo hi", None);
        assert!(
            !args.iter().any(|a| a.contains("MXC_EXEC_ID")),
            "untimed exec must not be stamped, got {:?}",
            args
        );
    }

    #[test]
    fn the_reaper_matches_the_marker_of_exactly_one_exec() {
        // Two concurrent execs in one container must not reap each other, so
        // the argv has to carry the specific token and not just the var name.
        let mine = build_reap_args("tok123");
        let theirs = build_reap_args("tok456");
        assert_eq!(mine.last().unwrap(), "MXC_EXEC_ID=tok123");
        assert_eq!(theirs.last().unwrap(), "MXC_EXEC_ID=tok456");
        assert_ne!(mine, theirs);
    }

    #[test]
    fn the_reaper_never_splices_the_marker_into_its_script() {
        // The token reaches the shell as `$1`.  Spliced in, a token bearing
        // shell syntax would run as code inside the container.
        let args = build_reap_args("t'; rm -rf /; #");
        let script = args
            .iter()
            .find(|a| a.contains("/proc/"))
            .expect("reap script should be present");
        assert!(
            !script.contains("rm -rf"),
            "marker must not appear in the script body, got {:?}",
            script
        );
        assert!(
            script.contains("\"$1\""),
            "script must read the marker positionally, got {:?}",
            script
        );
    }

    #[test]
    fn the_reaper_reports_success_when_nothing_matched() {
        // `kill` finding no targets is the normal case for a script that had
        // already finished; a nonzero exit there would be read as a failed
        // reap and reported to the caller as possibly-still-running work.
        let args = build_reap_args("tok123");
        let script = args.iter().find(|a| a.contains("/proc/")).unwrap();
        assert!(
            script.trim_end().ends_with("exit 0"),
            "reap script must end with an unconditional success, got {:?}",
            script
        );
    }

    #[test]
    fn the_reaper_stops_a_process_before_it_kills_anything() {
        // The `/proc` glob expands once per pass, so a workload that forks
        // after the expansion has a child that pass never sees. Stopping first
        // means a process that has been found cannot fork again, so the set
        // that can still grow only shrinks.
        let script = build_reap_args("tok123")
            .into_iter()
            .find(|a| a.contains("/proc/"))
            .expect("reap script should be present");
        let stop = script.find("kill -STOP").expect("must stop what it finds");
        let kill = script.find("kill -KILL").expect("must then kill it");
        assert!(
            stop < kill,
            "the stop pass has to precede the kill pass, got {script:?}"
        );
    }

    #[test]
    fn the_reaper_rescans_until_it_finds_nothing_new() {
        // One pass cannot see a process forked after its glob expanded, so a
        // single pass leaves that child alive to outlive the exec.
        let script = build_reap_args("tok123")
            .into_iter()
            .find(|a| a.contains("/proc/"))
            .expect("reap script should be present");
        assert!(
            script.contains("while ["),
            "the scan must repeat, got {script:?}"
        );
        assert!(
            script.contains("break"),
            "the scan must stop once a pass finds nothing new, got {script:?}"
        );
    }

    #[test]
    fn the_reaper_names_its_signals_rather_than_numbering_them() {
        // SIGSTOP is 19 on x86 and ARM but 17 on Alpha and SPARC and 23 on
        // MIPS. A number here would stop the wrong thing on those hosts.
        let script = build_reap_args("tok123")
            .into_iter()
            .find(|a| a.contains("/proc/"))
            .expect("reap script should be present");
        assert!(!script.contains("kill -9"), "got {script:?}");
        assert!(!script.contains("kill -19"), "got {script:?}");
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
        let args = build_attach_args_with_env_control(&env, "", "cmd", true, None);
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
