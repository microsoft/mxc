// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::unistd::{geteuid, getuid, Pid};

use crate::mxc_common::filesystem_object::FilesystemPolicyError;
use crate::mxc_common::filesystem_probe::FilesystemProbe;
use crate::mxc_common::models::ContainerPolicy;

use super::{host_tools, probe_exec, proxy_network::above_stdio};

const MAPPING_SIZE: u32 = 65_536;
const WORKLOAD_ID: u32 = 1_000;

// Bubblewrap only applies --gid when it differs from the launcher's real GID.
const BWRAP_LAUNCH_GID: u32 = 0;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ALLOCATION_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    uid_base: u32,
    gid_base: u32,
}

impl RootIdentity {
    pub(crate) fn for_caller() -> Result<Option<Self>, String> {
        match (getuid().is_root(), geteuid().is_root()) {
            (false, false) => return Ok(None),
            (true, true) => {}
            _ => {
                return Err(
                    "Bubblewrap: root launches require both the real and effective UID to be 0; \
                     use a fully root or fully unprivileged caller"
                        .into(),
                );
            }
        }
        FilesystemProbe::default().run("/etc/subuid and /etc/subgid", |_| {
            for path in ["/proc/self/uid_map", "/proc/self/gid_map"] {
                let contents = std::fs::read_to_string(path)
                    .map_err(|error| format!("Bubblewrap: could not read {path}: {error}"))?;
                if map_entries(&contents) != Some(vec![0, 0, u32::MAX]) {
                    return Err(
                        "Bubblewrap: root launches require an unshifted host user namespace; \
                         launch MXC in the host user namespace or as a non-root user"
                            .into(),
                    );
                }
            }
            let subuid = read_allocations("/etc/subuid")?;
            let subgid = read_allocations("/etc/subgid")?;
            let passwd = account_database("passwd")?;
            let group = account_database("group")?;
            Self::from_databases(&subuid, &subgid, &passwd, &group).map(Some)
        })?
    }

    fn from_databases(
        subuid: &str,
        subgid: &str,
        passwd: &str,
        group: &str,
    ) -> Result<Self, String> {
        let mut users = Vec::new();
        for line in passwd.lines().filter(|line| !line.is_empty()) {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() != 7 || fields[0].is_empty() {
                return Err("Bubblewrap: getent returned an invalid passwd entry".into());
            }
            users.push((
                fields[0],
                decimal_id(fields[2], "passwd UID")?,
                decimal_id(fields[3], "passwd GID")?,
            ));
        }
        let root_names: Vec<_> = users
            .iter()
            .filter_map(|(name, uid, _)| (*uid == 0).then_some(*name))
            .collect();
        if root_names.is_empty() {
            return Err("Bubblewrap: getent passwd did not identify a root account".into());
        }
        let identity = Self {
            uid_base: select_range(subuid, "/etc/subuid", &root_names)?,
            gid_base: select_range(subgid, "/etc/subgid", &root_names)?,
        };
        for (_, uid, gid) in users {
            identity.reject_account(uid, true)?;
            identity.reject_account(gid, false)?;
        }
        for line in group.lines().filter(|line| !line.is_empty()) {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() != 4 || fields[0].is_empty() {
                return Err("Bubblewrap: getent returned an invalid group entry".into());
            }
            identity.reject_account(decimal_id(fields[2], "group GID")?, false)?;
        }
        Ok(identity)
    }

    fn reject_account(self, id: u32, uid: bool) -> Result<(), String> {
        let (base, kind) = if uid {
            (self.uid_base, "UID")
        } else {
            (self.gid_base, "GID")
        };
        if (base..base + MAPPING_SIZE).contains(&id) {
            return Err(format!(
                "Bubblewrap: root's subordinate {kind} range overlaps host account {kind} {id}; \
                 reserve an unused range before launching"
            ));
        }
        Ok(())
    }

    pub(crate) fn create_namespace(self) -> Result<File, String> {
        FilesystemProbe::default().run("Bubblewrap workload user namespace", move |_| {
            let mut child = IdentityChild::start(ChildOperation::Namespace)
                .map_err(|error| format!("Bubblewrap: could not create user namespace: {error}"))?;
            child.result().map_err(|error| {
                format!("Bubblewrap: could not unshare workload identity: {error}")
            })?;
            let proc = format!("/proc/{}", child.pid);
            for (name, contents) in [
                ("setgroups", "deny\n".to_string()),
                ("uid_map", format!("0 {} {MAPPING_SIZE}\n", self.uid_base)),
                ("gid_map", format!("0 {} {MAPPING_SIZE}\n", self.gid_base)),
            ] {
                std::fs::write(format!("{proc}/{name}"), contents).map_err(|error| {
                    format!("Bubblewrap: could not install workload {name}: {error}")
                })?;
            }
            for (name, base) in [("uid_map", self.uid_base), ("gid_map", self.gid_base)] {
                let actual = std::fs::read_to_string(format!("{proc}/{name}"))
                    .map_err(|error| format!("Bubblewrap: could not verify {name}: {error}"))?;
                if map_entries(&actual) != Some(vec![0, base, MAPPING_SIZE]) {
                    return Err(format!(
                        "Bubblewrap: workload {name} differs from its reserved range"
                    ));
                }
            }
            let namespace = File::open(format!("{proc}/ns/user"))
                .and_then(|file| above_stdio(file).map_err(io::Error::from))
                .map_err(|error| {
                    format!("Bubblewrap: could not open workload user namespace: {error}")
                })?;
            child
                .finish()
                .map_err(|error| format!("Bubblewrap: could not reap identity helper: {error}"))?;
            Ok(namespace)
        })?
    }

    pub(crate) fn check_delegation(
        self,
        policy: &ContainerPolicy,
    ) -> Result<(), FilesystemPolicyError> {
        let mut probe = FilesystemProbe::default();
        for (paths, list, mask) in [
            (&policy.readonly_paths, "readonlyPaths", libc::R_OK),
            (
                &policy.readwrite_paths,
                "readwritePaths",
                libc::R_OK | libc::W_OK,
            ),
        ] {
            for path in paths {
                let result = self
                    .probe_access(&mut probe, path, mask)
                    .map_err(FilesystemPolicyError::Host)?;
                match result {
                    Ok(()) => {}
                    Err(error)
                        if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {}
                    Err(error) => {
                        let message = format!(
                            "Filesystem path '{path}' ({list}): mapped Bubblewrap UID {} / GID {} \
                             with no supplementary groups cannot use this grant ({error}); \
                             provision access for that identity without changing the root caller",
                            self.uid_base + WORKLOAD_ID,
                            self.gid_base + WORKLOAD_ID,
                        );
                        return Err(
                            if matches!(
                                error.raw_os_error(),
                                Some(libc::EACCES | libc::EPERM | libc::EROFS | libc::EINVAL)
                            ) {
                                FilesystemPolicyError::Policy(message)
                            } else {
                                FilesystemPolicyError::Host(message)
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn check_read(self, path: &str) -> Result<(), String> {
        match self.probe_access(&mut FilesystemProbe::default(), path, libc::R_OK)? {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                Ok(())
            }
            Err(error) => Err(format!(
                "mapped Bubblewrap UID {} / GID {} cannot read {path}: {error}",
                self.uid_base + WORKLOAD_ID,
                self.gid_base + WORKLOAD_ID,
            )),
        }
    }

    fn probe_access(
        self,
        probe: &mut FilesystemProbe,
        path: &str,
        mask: i32,
    ) -> Result<io::Result<()>, String> {
        probe.run(path, move |path| {
            let path =
                CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            let mut child = IdentityChild::start(ChildOperation::Access {
                uid: self.uid_base + WORKLOAD_ID,
                gid: self.gid_base + WORKLOAD_ID,
                path,
                mask,
            })?;
            let result = child.result();
            child.finish()?;
            result
        })
    }

    pub(crate) fn configure_command(self, command: &mut Command) {
        command.gid(BWRAP_LAUNCH_GID);

        // SAFETY: only the forked child changes groups; setgroups allocates no Rust state.
        unsafe {
            command.pre_exec(|| nix::unistd::setgroups(&[]).map_err(io::Error::from));
        }
    }

    pub(crate) fn configure_args(self, args: &mut Vec<String>) {
        if args.first().is_some_and(|arg| arg == "--unshare-user") {
            args.remove(0);
        }
        args.splice(
            0..0,
            [
                "--uid".into(),
                WORKLOAD_ID.to_string(),
                "--gid".into(),
                WORKLOAD_ID.to_string(),
            ],
        );
    }
}

fn map_entries(contents: &str) -> Option<Vec<u32>> {
    contents
        .split_whitespace()
        .map(|field| field.parse().ok())
        .collect()
}

fn decimal_id(value: &str, description: &str) -> Result<u32, String> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        if let Ok(value) = value.parse::<u32>() {
            if value != u32::MAX {
                return Ok(value);
            }
        }
    }
    Err(format!("Bubblewrap: invalid {description}: '{value}'"))
}

fn select_range(contents: &str, path: &str, root_names: &[&str]) -> Result<u32, String> {
    let mut ranges = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(':').collect();
        let invalid = || {
            format!(
                "Bubblewrap: invalid subordinate allocation in {path}:{}",
                index + 1
            )
        };
        if fields.len() != 3 || fields[0].is_empty() || fields[0].trim() != fields[0] {
            return Err(invalid());
        }
        let start = decimal_id(fields[1], path)?;
        let count = decimal_id(fields[2], path)?;
        if start == 0 || count == 0 || start.checked_add(count).is_none() {
            return Err(invalid());
        }
        let root = if fields[0].bytes().all(|byte| byte.is_ascii_digit()) {
            decimal_id(fields[0], path)? == 0
        } else {
            root_names.contains(&fields[0])
        };
        ranges.push((root, start, count));
    }
    let (selected, &(_, start, count)) = ranges
        .iter()
        .enumerate()
        .find(|(_, (root, _, count))| *root && *count >= MAPPING_SIZE)
        .ok_or_else(|| {
            format!(
                "Bubblewrap: root requires a reserved allocation of at least {MAPPING_SIZE} IDs \
                 in {path}; ask the administrator to provision an unused subordinate range"
            )
        })?;
    for (index, &(_, other_start, other_count)) in ranges.iter().enumerate() {
        if index != selected && start < other_start + other_count && other_start < start + count {
            return Err(format!(
                "Bubblewrap: root's allocation in {path} overlaps another subordinate allocation"
            ));
        }
    }
    Ok(start)
}

fn read_allocations(path: &str) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            format!("Bubblewrap: could not read root's allocation in {path}: {error}")
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Bubblewrap: could not inspect {path}: {error}"))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "Bubblewrap: {path} must be a regular root-owned file, not writable by group or others"
        ));
    }
    let mut contents = String::new();
    file.take(MAX_ALLOCATION_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("Bubblewrap: could not read {path}: {error}"))?;
    if contents.len() as u64 > MAX_ALLOCATION_BYTES {
        return Err(format!(
            "Bubblewrap: {path} exceeds the subordinate allocation size limit"
        ));
    }
    Ok(contents)
}

fn account_database(database: &str) -> Result<String, String> {
    let getent = host_tools::find("getent").map_err(|error| {
        format!("Bubblewrap: checking root's reserved IDs requires getent: {error}")
    })?;
    let output = probe_exec::run_bounded(
        Command::new(getent).arg(database),
        Instant::now() + PROBE_TIMEOUT,
    )
    .map_err(|error| format!("Bubblewrap: could not check getent {database}: {error:?}"))?;
    if !output.status.success() || output.stdout.truncated || output.stderr.truncated {
        return Err(format!(
            "Bubblewrap: getent {database} failed or returned an incomplete account database ({})",
            output.status
        ));
    }
    if let Some(error) = output.cleanup_error {
        return Err(format!(
            "Bubblewrap: could not stop getent {database} helpers: {error}"
        ));
    }
    String::from_utf8(output.stdout.bytes)
        .map_err(|error| format!("Bubblewrap: getent {database} returned invalid text: {error}"))
}

enum ChildOperation {
    Namespace,
    Access {
        uid: u32,
        gid: u32,
        path: CString,
        mask: i32,
    },
}

struct IdentityChild {
    pid: libc::pid_t,
    channel: UnixStream,
    reaped: bool,
}

impl IdentityChild {
    fn start(operation: ChildOperation) -> io::Result<Self> {
        let (parent, child) = UnixStream::pair()?;
        parent.set_read_timeout(Some(PROBE_TIMEOUT))?;
        let parent_pid = nix::unistd::getpid().as_raw();
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();

        // SAFETY: getrlimit initializes the supplied record on success.
        let max_fd = unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            limit.assume_init().rlim_max.min(i32::MAX as libc::rlim_t) as u32
        };
        let fd = child.as_raw_fd();
        let mut previous_signals = SigSet::empty();

        // Inherited signal handlers must not run inside the syscall-only helper.
        pthread_sigmask(
            SigmaskHow::SIG_SETMASK,
            Some(&SigSet::all()),
            Some(&mut previous_signals),
        )?;

        // SAFETY: the child uses only syscall wrappers and preallocated values, then _exit.
        let pid = unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let result = close_child_descriptors(fd, max_fd)
                    .and_then(|()| arm_parent_death(parent_pid))
                    .and_then(|()| run_child_operation(&operation, parent_pid));

                let status = match result {
                    Ok(access_error) => [0, access_error],
                    Err(setup_error) => [setup_error, 0],
                };
                let length = std::mem::size_of_val(&status);
                let sent = libc::send(fd, status.as_ptr().cast(), length, libc::MSG_NOSIGNAL);
                if sent == length as isize && matches!(operation, ChildOperation::Namespace) {
                    let mut byte = 0_u8;
                    while libc::read(fd, (&mut byte as *mut u8).cast(), 1) < 0
                        && *libc::__errno_location() == libc::EINTR
                    {}
                }
                libc::_exit(0);
            }
            pid
        };
        let fork_error = (pid < 0).then(io::Error::last_os_error);
        let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous_signals), None);
        if let Some(error) = fork_error {
            restored?;
            return Err(error);
        }
        let helper = Self {
            pid,
            channel: parent,
            reaped: false,
        };
        restored?;
        Ok(helper)
    }

    fn result(&mut self) -> io::Result<()> {
        let mut code = [0_u8; 8];
        self.channel.read_exact(&mut code)?;
        let setup_error = i32::from_ne_bytes([code[0], code[1], code[2], code[3]]);
        if setup_error != 0 {
            return Err(io::Error::other(format!(
                "identity helper setup failed: {}",
                io::Error::from_raw_os_error(setup_error)
            )));
        }
        match i32::from_ne_bytes([code[4], code[5], code[6], code[7]]) {
            0 => Ok(()),
            error => Err(io::Error::from_raw_os_error(error)),
        }
    }

    fn finish(mut self) -> io::Result<()> {
        self.terminate()?;
        self.reap()
    }

    fn terminate(&self) -> io::Result<()> {
        match kill(Pid::from_raw(self.pid), Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn reap(&mut self) -> io::Result<()> {
        loop {
            let mut status = 0;

            // SAFETY: this PID belongs to this helper and has not been reaped.
            if unsafe { libc::waitpid(self.pid, &mut status, 0) } >= 0 {
                self.reaped = true;
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                self.reaped = error.raw_os_error() == Some(libc::ECHILD);
                return Err(error);
            }
        }
    }
}

impl Drop for IdentityChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate();
            let _ = self.reap();
        }
    }
}

unsafe fn close_child_descriptors(keep: i32, max_fd: u32) -> Result<(), i32> {
    let mut supported = true;
    for (first, last) in [(0, keep as u32), (keep as u32 + 1, u32::MAX)] {
        if first < last && libc::syscall(libc::SYS_close_range, first, last - 1, 0_u32) != 0 {
            let error = *libc::__errno_location();
            if error != libc::ENOSYS {
                return Err(error);
            }
            supported = false;
        }
    }
    if supported {
        return Ok(());
    }
    for fd in 0..max_fd {
        if fd != keep as u32 && libc::close(fd as i32) != 0 {
            let error = *libc::__errno_location();
            if error != libc::EBADF && error != libc::EINTR {
                return Err(error);
            }
        }
    }
    Ok(())
}

unsafe fn arm_parent_death(parent: libc::pid_t) -> Result<(), i32> {
    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
        return Err(*libc::__errno_location());
    }
    if libc::getppid() != parent {
        return Err(libc::ESRCH);
    }
    Ok(())
}

unsafe fn run_child_operation(operation: &ChildOperation, parent: libc::pid_t) -> Result<i32, i32> {
    if libc::setgroups(0, std::ptr::null()) != 0 {
        return Err(*libc::__errno_location());
    }
    match operation {
        ChildOperation::Namespace => {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(*libc::__errno_location());
            }
        }
        ChildOperation::Access {
            uid,
            gid,
            path,
            mask,
        } => {
            if libc::setresgid(*gid, *gid, *gid) != 0 || libc::setresuid(*uid, *uid, *uid) != 0 {
                return Err(*libc::__errno_location());
            }
            arm_parent_death(parent)?;

            // Linux capability ABI v3 takes a two-word header and two three-word records.
            let header = [0x2008_0522_u32, 0];
            let capabilities = [0_u32; 6];
            if libc::syscall(libc::SYS_capset, header.as_ptr(), capabilities.as_ptr()) != 0 {
                return Err(*libc::__errno_location());
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if libc::stat(path.as_ptr(), stat.as_mut_ptr()) != 0 {
                return Ok(*libc::__errno_location());
            }
            let mask = if stat.assume_init().st_mode & libc::S_IFMT == libc::S_IFDIR {
                *mask | libc::X_OK
            } else {
                *mask
            };
            if libc::access(path.as_ptr(), mask) != 0 {
                return Ok(*libc::__errno_location());
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n";
    const GROUP: &str = "root:x:0:\nuser:x:1000:\n";

    #[test]
    fn credential_probe_errors_leave_the_callers_credentials_and_signal_mask_unchanged() {
        let uid = getuid();
        let gid = nix::unistd::getgid();
        let groups = nix::unistd::getgroups().unwrap();
        let mut signals = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_SETMASK, None, Some(&mut signals)).unwrap();
        let mut child = IdentityChild::start(ChildOperation::Access {
            uid: uid.as_raw(),
            gid: gid.as_raw(),
            path: CString::new("/mxc-identity-probe-does-not-exist/path").unwrap(),
            mask: libc::R_OK,
        })
        .unwrap();
        let error = child.result().unwrap_err();
        assert!(
            error.raw_os_error() == Some(libc::ENOENT)
                || error
                    .to_string()
                    .starts_with("identity helper setup failed: "),
            "{error}"
        );
        child.finish().unwrap();
        let mut after = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_SETMASK, None, Some(&mut after)).unwrap();
        assert_eq!(signals, after);
        assert_eq!(getuid(), uid);
        assert_eq!(nix::unistd::getgid(), gid);
        assert_eq!(nix::unistd::getgroups().unwrap(), groups);
    }

    #[test]
    #[ignore = "requires root with subordinate ranges and Bubblewrap network prerequisites"]
    fn root_sdk_streaming_and_pty_use_mapped_identity() {
        use crate::v1::{
            spawn, spawn_with_pty, ContainerRequest, MxcPtySize, NetworkAction,
            NetworkEgressPolicy, NetworkPolicy, SpawnWithPtyOptions, WaitResult,
        };
        use std::io::Write;

        assert!(getuid().is_root(), "this regression requires a root caller");
        let groups = nix::unistd::getgroups().unwrap();
        let gid = nix::unistd::getgid();
        let namespace = std::fs::read_link("/proc/self/ns/user").unwrap();
        RootIdentity::for_caller().unwrap().expect("root identity");
        let command = "set -e; test \"$(id -u)\" = 1000; test \"$(id -g)\" = 1000; \
                       read -r value; printf 'MAPPED:%s\\n' \"$value\"";
        let request = |command: &str| ContainerRequest {
            timeout_ms: Some(10_000),
            network: Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    default: Some(NetworkAction::Allow),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..ContainerRequest::new(command)
        };
        let mut process = spawn(request(command), Default::default()).expect("mapped pipe launch");
        let mut input = process.take_stdin().unwrap();
        input.write_all(b"pipes\n").unwrap();
        drop(input);
        let output = process.wait_with_output().unwrap();
        assert_eq!(output.outcome, WaitResult::Exited(0), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("MAPPED:pipes"));

        let terminal = spawn_with_pty(
            request(&format!("{command}; stty size < /dev/tty")),
            SpawnWithPtyOptions {
                size: MxcPtySize {
                    rows: 24,
                    cols: 80,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .expect("mapped PTY launch");
        terminal
            .resize(MxcPtySize {
                rows: 40,
                cols: 120,
                ..Default::default()
            })
            .unwrap();
        let mut reader = terminal.try_clone_reader().unwrap();
        let read = std::thread::spawn(move || {
            let mut text = String::new();
            reader.read_to_string(&mut text).unwrap();
            text
        });
        let mut writer = terminal.take_writer().unwrap();
        writer.write_all(b"terminal\n").unwrap();
        drop(writer);
        assert_eq!(terminal.wait().unwrap(), WaitResult::Exited(0));
        let output = read.join().unwrap();
        assert!(
            output.contains("MAPPED:terminal") && output.contains("40 120"),
            "{output}"
        );
        assert!(getuid().is_root() && geteuid().is_root());
        assert_eq!(nix::unistd::getgid(), gid);
        assert_eq!(nix::unistd::getgroups().unwrap(), groups);
        assert_eq!(std::fs::read_link("/proc/self/ns/user").unwrap(), namespace);
        if std::env::var_os("MXC_BWRAP_ROOT_GID_FIXTURE").is_none() {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "root_sdk_streaming_and_pty_use_mapped_identity",
                    "--nocapture",
                ])
                .env("MXC_BWRAP_ROOT_GID_FIXTURE", "1")
                .gid(WORKLOAD_ID);

            // SAFETY: close runs only in the fixture child, before exec.
            unsafe {
                command.pre_exec(|| {
                    libc::close(libc::STDIN_FILENO);
                    Ok(())
                });
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "root caller with GID 1000 failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    #[ignore = "requires root with subordinate ranges and Bubblewrap network prerequisites"]
    fn root_backend_hostname_pin_uses_mapped_identity() {
        use std::net::{TcpListener, TcpStream};
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};

        use nix::mount::{mount, umount, MsFlags};

        use crate::bwrap_common::bwrap_runner::BubblewrapScriptRunner;
        use crate::mxc_common::logger::{Logger, Mode};
        use crate::mxc_common::models::{ExecutionRequest, ProxyAddress};
        use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};

        const PARENT_MOUNT: &str = "MXC_BWRAP_PIN_PARENT_MOUNT";
        assert!(getuid().is_root());
        RootIdentity::for_caller().unwrap().expect("root identity");
        let mount_namespace = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        let Some(parent_mount) = std::env::var_os(PARENT_MOUNT) else {
            let output = Command::new(host_tools::find("unshare").unwrap())
                .args(["--mount", "--propagation", "private", "--"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "root_backend_hostname_pin_uses_mapped_identity",
                    "--nocapture",
                ])
                .env(PARENT_MOUNT, mount_namespace)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        assert_ne!(mount_namespace, PathBuf::from(parent_mount));
        let directory = tempfile::tempdir().unwrap();
        let bind_text = |name: &str, target: &str, contents: &str| {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            mount(
                Some(path.as_path()),
                Path::new(target),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .unwrap();
        };
        let hostname = format!("mxc-{}.invalid", uuid::Uuid::new_v4().simple());
        bind_text(
            "hosts",
            "/etc/hosts",
            &format!(
                "{}\n127.0.0.1 {hostname}\n",
                std::fs::read_to_string("/etc/hosts").unwrap()
            ),
        );
        let nsswitch = Path::new("/etc/nsswitch.conf");
        let has_nsswitch = nsswitch.exists();
        if has_nsswitch {
            let contents = std::fs::read_to_string(nsswitch).unwrap();
            let mut lines: Vec<_> = contents
                .lines()
                .filter(|line| line.split(':').next().unwrap_or("").trim() != "hosts")
                .collect();
            lines.push("hosts: files dns");
            bind_text("nsswitch", "/etc/nsswitch.conf", &(lines.join("\n") + "\n"));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        let port = address.port();
        let mut request = ExecutionRequest {
            script_code: format!(
                "python3 -c \"import os,socket; \
                 assert os.getuid() == 1000 and os.getgid() == 1000; \
                 assert socket.gethostbyname('{hostname}') == '10.0.2.2'; \
                 socket.create_connection(('{hostname}', {port}), timeout=5).close(); \
                 print('MAPPED_HOSTNAME_PIN')\""
            ),
            script_timeout: 15_000,
            ..Default::default()
        };

        // The JSON contract only allows loopback proxies, so this tests the backend directly.
        request.policy.network_proxy.address = Some(ProxyAddress::from_url(
            &format!("http://{hostname}:{port}"),
            hostname,
            port,
        ));
        let mut logger = Logger::new(Mode::Buffer);
        let mut process = BubblewrapScriptRunner::new()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .expect("mapped backend hostname launch");
        let mut stdout = process.take_stdout().unwrap();
        let reader = std::thread::spawn(move || {
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            output
        });
        let status = process.wait().unwrap();
        let output = reader.join().unwrap();
        if has_nsswitch {
            umount(nsswitch).unwrap();
        }
        umount("/etc/hosts").unwrap();
        assert_eq!(status, 0, "{output}\n{}", logger.get_buffer());
        assert!(output.contains("MAPPED_HOSTNAME_PIN"), "{output}");
    }

    #[test]
    fn independent_uid_and_gid_ranges_preserve_the_reserved_bases() {
        assert_eq!(
            RootIdentity::from_databases("root:100000:65536\n", "0:300000:131072\n", PASSWD, GROUP),
            Ok(RootIdentity {
                uid_base: 100000,
                gid_base: 300000
            })
        );
    }

    #[test]
    fn unavailable_or_conflicting_allocations_are_rejected() {
        for allocation in [
            "",
            "user:100000:65536\n",
            "root:100000:65535\n",
            "root:0:65536\n",
            "root:4294960000:65536\n",
            "root:100000:0\n",
            "root:100000:-1\n",
            "root:+100000:65536\n",
            "root:100000:65536:extra\n",
            "root:100000:65536\nuser:165535:65536\n",
            "root:100000:65536\n0:100000:65536\n",
            "root:100000:65536\nbroken\n",
        ] {
            assert!(
                RootIdentity::from_databases(allocation, "root:300000:65536\n", PASSWD, GROUP)
                    .is_err(),
                "{allocation}"
            );
        }
    }

    #[test]
    fn accounts_groups_and_primary_groups_must_not_occupy_the_mapping() {
        for (passwd, group) in [
            (
                format!("{PASSWD}occupied:x:100000:1000::/:/bin/sh\n"),
                GROUP.to_string(),
            ),
            (
                format!("{PASSWD}occupied:x:165535:1000::/:/bin/sh\n"),
                GROUP.to_string(),
            ),
            (
                format!("{PASSWD}occupied:x:2000:301000::/:/bin/sh\n"),
                GROUP.to_string(),
            ),
            (PASSWD.to_string(), format!("{GROUP}occupied:x:300000:\n")),
        ] {
            assert!(RootIdentity::from_databases(
                "root:100000:65536\n",
                "root:300000:65536\n",
                &passwd,
                &group
            )
            .is_err());
        }
    }

    #[test]
    fn adjacent_ranges_and_accounts_outside_the_mapping_are_allowed() {
        let passwd = format!("{PASSWD}outside:x:165536:365536::/:/bin/sh\n");
        assert!(RootIdentity::from_databases(
            "user:34464:65536\nroot:100000:65536\nother:165536:65536\n",
            "root:300000:65536\n",
            &passwd,
            GROUP
        )
        .is_ok());
    }

    #[test]
    fn numeric_allocations_work_for_a_renamed_root_account() {
        assert!(RootIdentity::from_databases(
            "1000:100000:65536\n",
            "0:300000:65536\n",
            "1000:x:0:0::/root:/bin/sh\n",
            GROUP
        )
        .is_err());
        assert!(RootIdentity::from_databases(
            "0:100000:65536\n",
            "admin:300000:65536\n",
            "admin:x:0:0::/root:/bin/sh\n",
            GROUP
        )
        .is_ok());
        assert!(RootIdentity::from_databases(
            "root:100000:65536\n",
            "root:300000:65536\n",
            "admin:x:0:0::/root:/bin/sh\nroot:x:1000:1000::/:/bin/sh\n",
            GROUP
        )
        .is_err());
    }

    #[test]
    fn first_sufficient_root_allocation_is_selected() {
        assert_eq!(
            select_range(
                "# reserved\nroot:50000:100\nroot:200000:65536\nroot:400000:65536\n",
                "/etc/subuid",
                &["root"]
            )
            .unwrap(),
            200000
        );
    }

    #[test]
    fn mapped_arguments_do_not_rewrite_environment_or_command_values() {
        let identity = RootIdentity {
            uid_base: 100000,
            gid_base: 200000,
        };
        let mut args = vec![
            "--unshare-user",
            "--setenv",
            "VALUE",
            "--unshare-user",
            "--",
            "sh",
            "-c",
            "--unshare-user",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        identity.configure_args(&mut args);
        assert_eq!(
            args,
            [
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--setenv",
                "VALUE",
                "--unshare-user",
                "--",
                "sh",
                "-c",
                "--unshare-user"
            ]
        );
    }
}
