// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, IoSliceMut, Read};
use std::mem::offset_of;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
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
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

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
        let deadline = Instant::now() + PROBE_TIMEOUT;
        FilesystemProbe::default().run("/etc/subuid and /etc/subgid", move |_| {
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
            let passwd = account_database("passwd", deadline)?;
            let group = account_database("group", deadline)?;
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
        let grants: Vec<_> = policy
            .readonly_paths
            .iter()
            .map(|path| (path, "readonlyPaths", libc::R_OK))
            .chain(
                policy
                    .readwrite_paths
                    .iter()
                    .map(|path| (path, "readwritePaths", libc::R_OK | libc::W_OK)),
            )
            .collect();
        let paths: Vec<_> = grants.iter().map(|(path, ..)| path.to_string()).collect();
        let requests = grants
            .iter()
            .map(|(path, _, mask)| (CString::new(path.as_str()).ok(), *mask))
            .collect();
        let (uid, gid) = self.workload_ids();
        let results = FilesystemProbe::default()
            .run_batch(
                &paths,
                |result: &io::Result<()>| result.as_ref().is_err_and(|error| !is_missing(error)),
                move |report| check_access_as(uid, gid, requests, report),
            )
            .map_err(FilesystemPolicyError::Host)?;
        for ((path, list, _), result) in grants.into_iter().zip(results) {
            let error = match result {
                Err(error) if !is_missing(&error) => error,
                _ => continue,
            };
            return Err(
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EACCES | libc::EPERM | libc::EROFS | libc::EINVAL)
                ) {
                    FilesystemPolicyError::Policy(format!(
                        "Filesystem path '{path}' ({list}): mapped Bubblewrap UID {uid} / GID \
                         {gid} with no supplementary groups cannot use this grant ({error}); \
                         provision access for that identity without changing the root caller"
                    ))
                } else {
                    FilesystemPolicyError::Host(format!(
                        "Filesystem path '{path}' ({list}): could not check access for mapped \
                         Bubblewrap UID {uid} / GID {gid} ({error}); refusing sandbox startup"
                    ))
                },
            );
        }
        Ok(())
    }

    fn open(self, path: &Path, flags: libc::c_int) -> io::Result<File> {
        let shown = path.display().to_string();
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
        let (uid, gid) = self.workload_ids();
        let opened = FilesystemProbe::default()
            .run(&shown, move |_| {
                let mut child = IdentityChild::start(ChildOperation::Open {
                    uid,
                    gid,
                    path,
                    flags,
                })?;
                let result = child.result();
                child.finish()?;
                result?.ok_or_else(|| io::Error::other("identity helper returned no descriptor"))
            })
            .map_err(io::Error::other)?;
        opened.map(File::from).map_err(|error| match error.kind() {
            ErrorKind::NotFound => error,
            kind => io::Error::new(
                kind,
                format!(
                    "{error}; opened as mapped Bubblewrap UID {uid} / GID {gid} with no \
                     supplementary groups"
                ),
            ),
        })
    }

    pub(crate) fn share_with_workload(self, directory: &Path) -> Result<(), String> {
        let (uid, gid) = self.workload_ids();
        let shown = directory.display().to_string();
        let directory = std::fs::canonicalize(directory)
            .and_then(|directory| share_tree(&directory, gid).map(|()| directory))
            .map_err(|error| {
                format!(
                    "Bubblewrap: could not give mapped Bubblewrap GID {gid} access to {shown}: \
                     {error}"
                )
            })?;
        let path = CString::new(directory.as_os_str().as_bytes())
            .map_err(|_| format!("Bubblewrap: {shown} contains a NUL byte"))?;
        FilesystemProbe::default()
            .run(&shown, move |_| {
                let mut child = IdentityChild::start(ChildOperation::Access {
                    uid,
                    gid,
                    paths: vec![(Some(path), libc::R_OK)],
                })?;
                let result = child.result();
                child.finish()?;
                result.map(drop)
            })?
            .map_err(|error| {
                format!(
                    "Bubblewrap: mapped Bubblewrap UID {uid} / GID {gid} cannot reach private \
                     storage {shown} ({error}); set TMPDIR to a directory that identity can \
                     traverse"
                )
            })
    }

    pub(crate) fn watch_sandbox(
        self,
        sandbox: u32,
        launcher: u32,
    ) -> Result<SandboxWatchdog, String> {
        let (uid, gid) = self.workload_ids();
        let pid = |pid: u32| {
            libc::pid_t::try_from(pid)
                .map_err(|_| format!("Bubblewrap: process ID {pid} is out of range"))
        };
        let operation = ChildOperation::Watch {
            uid,
            gid,
            sandbox: pid(sandbox)?,
            launcher: pid(launcher)?,
        };
        let mut helper = IdentityChild::start(operation).map_err(|error| {
            format!("Bubblewrap: could not start the sandbox watchdog: {error}")
        })?;
        match helper.result() {
            Ok(_) => Ok(SandboxWatchdog { helper, uid }),
            Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => Err(
                "Bubblewrap: root launches require Linux 5.3 or later; MXC needs pidfd_open to \
                 stop the sandbox when the run ends or MXC exits. On this kernel, run MXC as a \
                 non-root user"
                    .into(),
            ),
            Err(error) if error.raw_os_error().is_some() => Err(format!(
                "Bubblewrap: could not watch the sandbox ({error}); root launches need \
                 pidfd_open and pidfd_send_signal to stop the sandbox when the run ends or MXC \
                 exits"
            )),
            Err(error) => Err(format!("Bubblewrap: could not watch the sandbox: {error}")),
        }
    }

    fn workload_ids(self) -> (u32, u32) {
        (self.uid_base + WORKLOAD_ID, self.gid_base + WORKLOAD_ID)
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

pub(crate) fn open_as_workload(
    identity: Option<RootIdentity>,
    path: &Path,
    flags: libc::c_int,
) -> io::Result<File> {
    match identity {
        Some(identity) => identity.open(path, flags),

        // An unprivileged caller's workload keeps the caller's identity.
        None => OpenOptions::new().read(true).custom_flags(flags).open(path),
    }
}

pub(crate) fn read_as_workload(identity: Option<RootIdentity>, path: &Path) -> io::Result<String> {
    let mut file = open_as_workload(identity, path, libc::O_NONBLOCK)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn check_access_as(
    uid: u32,
    gid: u32,
    paths: Vec<(Option<CString>, i32)>,
    report: &dyn Fn(io::Result<()>) -> bool,
) {
    let count = paths.len();
    let mut child = match IdentityChild::start(ChildOperation::Access { uid, gid, paths }) {
        Ok(child) => child,
        Err(error) => {
            report(Err(error));
            return;
        }
    };
    for _ in 0..count {
        if !report(child.result().map(drop)) {
            break;
        }
    }
    let _ = child.finish();
}

fn is_missing(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
}

fn share_tree(directory: &Path, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(directory, None, Some(gid))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o750))?;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            share_tree(&entry.path(), gid)?;
        }
    }
    Ok(())
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

fn account_database(database: &str, deadline: Instant) -> Result<String, String> {
    let getent = host_tools::find("getent").map_err(|error| {
        format!("Bubblewrap: checking root's reserved IDs requires getent: {error}")
    })?;
    let output = probe_exec::run_bounded(Command::new(getent).arg(database), deadline)
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
        paths: Vec<(Option<CString>, i32)>,
    },
    Open {
        uid: u32,
        gid: u32,
        path: CString,
        flags: libc::c_int,
    },
    Watch {
        uid: u32,
        gid: u32,
        sandbox: libc::pid_t,
        launcher: libc::pid_t,
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
                let entered = close_child_descriptors(fd)
                    .and_then(|()| arm_parent_death(parent_pid))
                    .and_then(|()| enter_identity(&operation, parent_pid));
                let status = match entered {
                    Ok(()) => run_child_operation(&operation, fd),
                    Err(setup_error) => {
                        send_reply(fd, [setup_error, 0], None);
                        0
                    }
                };
                libc::_exit(status);
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

    fn result(&mut self) -> io::Result<Option<OwnedFd>> {
        let mut code = [0_u8; 8];
        let mut received = 0;
        let mut file = None;
        while received < code.len() {
            let mut control = nix::cmsg_space!(libc::c_int);
            let mut buffer = [IoSliceMut::new(&mut code[received..])];
            let reply = match recvmsg::<()>(
                self.channel.as_raw_fd(),
                &mut buffer,
                Some(&mut control),
                MsgFlags::MSG_CMSG_CLOEXEC,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EAGAIN) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        format!(
                            "identity helper did not answer within {}s",
                            PROBE_TIMEOUT.as_secs()
                        ),
                    ))
                }
                reply => reply?,
            };
            for item in reply.cmsgs()? {
                if let ControlMessageOwned::ScmRights(descriptors) = item {
                    for descriptor in descriptors {
                        // SAFETY: the kernel installed this descriptor for this process only.
                        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                        file.get_or_insert(descriptor);
                    }
                }
            }
            if reply.flags.contains(MsgFlags::MSG_CTRUNC) {
                return Err(io::Error::other("identity helper reply was truncated"));
            }
            if reply.bytes == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            received += reply.bytes;
        }
        let setup_error = i32::from_ne_bytes([code[0], code[1], code[2], code[3]]);
        if setup_error != 0 {
            return Err(io::Error::other(format!(
                "identity helper setup failed: {}",
                io::Error::from_raw_os_error(setup_error)
            )));
        }
        match i32::from_ne_bytes([code[4], code[5], code[6], code[7]]) {
            0 => Ok(file),
            error => Err(io::Error::from_raw_os_error(error)),
        }
    }

    fn finish(mut self) -> io::Result<()> {
        self.terminate();
        self.reap().map(drop)
    }

    fn terminate(&self) {
        // Root without CAP_KILL cannot signal a helper running as the mapped UID.
        // Closing the socket makes that helper exit at its next reply instead.
        let _ = kill(Pid::from_raw(self.pid), Signal::SIGKILL);
        let _ = self.channel.shutdown(Shutdown::Both);
    }

    fn reap(&mut self) -> io::Result<libc::c_int> {
        loop {
            let mut status = 0;

            // SAFETY: this PID belongs to this helper and has not been reaped.
            if unsafe { libc::waitpid(self.pid, &mut status, 0) } >= 0 {
                self.reaped = true;
                return Ok(status);
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
            self.terminate();
            let _ = self.reap();
        }
    }
}

pub(crate) struct SandboxWatchdog {
    helper: IdentityChild,
    uid: u32,
}

impl SandboxWatchdog {
    pub(crate) fn stop(mut self) -> Result<(), String> {
        self.stop_sandbox()
    }

    fn stop_sandbox(&mut self) -> Result<(), String> {
        // Closing the socket, not killing the helper, is what makes it stop the sandbox.
        let _ = self.helper.channel.shutdown(Shutdown::Both);
        match self.helper.reap() {
            Ok(status) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => Ok(()),
            Ok(_) => Err(format!(
                "Bubblewrap: could not confirm that the sandbox stopped; its processes may still \
                 be running as host UID {}",
                self.uid
            )),
            Err(error) => Err(format!(
                "Bubblewrap: could not wait for the sandbox watchdog: {error}"
            )),
        }
    }
}

impl Drop for SandboxWatchdog {
    fn drop(&mut self) {
        if !self.helper.reaped {
            let _ = self.stop_sandbox();
        }
    }
}

unsafe fn close_child_descriptors(keep: i32) -> Result<(), i32> {
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
        Ok(())
    } else {
        close_listed_descriptors(keep)
    }
}

// Kernels before 5.9 lack close_range, so close what /proc/self/fd lists rather
// than every number up to the descriptor limit.
unsafe fn close_listed_descriptors(keep: i32) -> Result<(), i32> {
    #[repr(C, align(8))]
    struct Listing([u8; 1024]);

    let directory = libc::open(
        c"/proc/self/fd".as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if directory < 0 {
        return Err(*libc::__errno_location());
    }
    let mut listing = Listing([0; 1024]);
    let result = 'listing: loop {
        let length = libc::syscall(
            libc::SYS_getdents64,
            directory,
            listing.0.as_mut_ptr(),
            listing.0.len(),
        );
        if length <= 0 {
            break if length == 0 {
                Ok(())
            } else {
                Err(*libc::__errno_location())
            };
        }
        let mut closed = false;
        let mut offset = 0;
        while offset < length as usize {
            let record = listing.0.as_ptr().add(offset);
            let size = usize::from(
                record
                    .add(offset_of!(libc::dirent64, d_reclen))
                    .cast::<u16>()
                    .read_unaligned(),
            );
            if size == 0 {
                break 'listing Err(libc::EIO);
            }
            if let Some(fd) = descriptor_number(record.add(offset_of!(libc::dirent64, d_name))) {
                if fd != keep && fd != directory {
                    libc::close(fd);
                    closed = true;
                }
            }
            offset += size;
        }

        // Closing descriptors changes the listing, so read it again from the start.
        if closed && libc::lseek(directory, 0, libc::SEEK_SET) != 0 {
            break Err(*libc::__errno_location());
        }
    };
    libc::close(directory);
    result
}

unsafe fn descriptor_number(mut name: *const u8) -> Option<i32> {
    if !(*name).is_ascii_digit() {
        return None;
    }
    let mut number = 0_i32;
    while (*name).is_ascii_digit() {
        number = number
            .checked_mul(10)?
            .checked_add(i32::from(*name - b'0'))?;
        name = name.add(1);
    }
    (*name == 0).then_some(number)
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

unsafe fn enter_identity(operation: &ChildOperation, parent: libc::pid_t) -> Result<(), i32> {
    if libc::setgroups(0, std::ptr::null()) != 0 {
        return Err(*libc::__errno_location());
    }
    let (uid, gid) = match operation {
        ChildOperation::Namespace => {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(*libc::__errno_location());
            }
            return Ok(());
        }
        ChildOperation::Access { uid, gid, .. }
        | ChildOperation::Open { uid, gid, .. }
        | ChildOperation::Watch { uid, gid, .. } => (*uid, *gid),
    };
    if libc::setresgid(gid, gid, gid) != 0 || libc::setresuid(uid, uid, uid) != 0 {
        return Err(*libc::__errno_location());
    }

    // The watchdog outlives MXC, even when MXC's whole process group is killed, so that it
    // can stop the sandbox after MXC exits.
    if matches!(operation, ChildOperation::Watch { .. }) {
        if libc::setsid() < 0 {
            return Err(*libc::__errno_location());
        }
    } else {
        arm_parent_death(parent)?;

        // Root without CAP_KILL cannot signal this helper, so a stalled check must end it.
        terminate_on_alarm()?;
    }
    let header = [LINUX_CAPABILITY_VERSION_3, 0];
    let capabilities = [0_u32; 6];
    if libc::syscall(libc::SYS_capset, header.as_ptr(), capabilities.as_ptr()) != 0 {
        return Err(*libc::__errno_location());
    }
    Ok(())
}

unsafe fn terminate_on_alarm() -> Result<(), i32> {
    let mut alarm: libc::sigset_t = std::mem::zeroed();
    let default: libc::sigaction = std::mem::zeroed();
    if libc::sigemptyset(&mut alarm) != 0
        || libc::sigaddset(&mut alarm, libc::SIGALRM) != 0
        || libc::sigaction(libc::SIGALRM, &default, std::ptr::null_mut()) != 0
        || libc::sigprocmask(libc::SIG_UNBLOCK, &alarm, std::ptr::null_mut()) != 0
    {
        return Err(*libc::__errno_location());
    }
    Ok(())
}

unsafe fn run_child_operation(operation: &ChildOperation, socket: libc::c_int) -> libc::c_int {
    let probe_seconds = PROBE_TIMEOUT.as_secs() as libc::c_uint;
    match operation {
        ChildOperation::Namespace => {
            if send_reply(socket, [0, 0], None) {
                let mut byte = 0_u8;
                while libc::read(socket, (&mut byte as *mut u8).cast(), 1) < 0
                    && *libc::__errno_location() == libc::EINTR
                {}
            }
        }
        ChildOperation::Access { paths, .. } => {
            for (path, mask) in paths {
                libc::alarm(probe_seconds);
                let error = match path {
                    Some(path) => check_access(path, *mask),
                    None => libc::EINVAL,
                };
                if !send_reply(socket, [0, error], None) {
                    break;
                }
            }
        }
        ChildOperation::Open { path, flags, .. } => {
            libc::alarm(probe_seconds);
            let file = libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | flags,
            );
            if file < 0 {
                send_reply(socket, [0, *libc::__errno_location()], None);
            } else {
                send_reply(socket, [0, 0], Some(file));
            }
        }
        ChildOperation::Watch {
            sandbox, launcher, ..
        } => {
            let watched = open_process(*sandbox)
                .and_then(|sandbox| signal_process(sandbox, 0).map(|()| sandbox))
                .and_then(|sandbox| open_process(*launcher).map(|launcher| (sandbox, launcher)));
            match watched {
                Ok((sandbox, launcher)) => {
                    if send_reply(socket, [0, 0], None) {
                        wait_for_exit_or_disconnect(launcher, socket);
                    }
                    return if stop_process(sandbox) { 0 } else { 1 };
                }
                Err(error) => {
                    send_reply(socket, [0, error], None);
                }
            }
        }
    }
    0
}

unsafe fn open_process(pid: libc::pid_t) -> Result<libc::c_int, i32> {
    let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0_u32);
    if pidfd < 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(pidfd as libc::c_int)
    }
}

unsafe fn signal_process(pidfd: libc::c_int, signal: libc::c_int) -> Result<(), i32> {
    let result = libc::syscall(
        libc::SYS_pidfd_send_signal,
        pidfd,
        signal,
        std::ptr::null::<libc::siginfo_t>(),
        0_u32,
    );
    if result != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(())
    }
}

unsafe fn stop_process(pidfd: libc::c_int) -> bool {
    if matches!(signal_process(pidfd, libc::SIGKILL), Err(error) if error != libc::ESRCH) {
        return false;
    }
    let mut exited = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    libc::poll(&mut exited, 1, PROBE_TIMEOUT.as_millis() as libc::c_int) == 1
}

unsafe fn wait_for_exit_or_disconnect(launcher: libc::c_int, socket: libc::c_int) {
    let mut watched = [launcher, socket].map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    while libc::poll(watched.as_mut_ptr(), 2, -1) < 0 && *libc::__errno_location() == libc::EINTR {}
}

unsafe fn check_access(path: &CString, mask: i32) -> i32 {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if libc::stat(path.as_ptr(), stat.as_mut_ptr()) != 0 {
        return *libc::__errno_location();
    }
    let mask = if stat.assume_init().st_mode & libc::S_IFMT == libc::S_IFDIR {
        mask | libc::X_OK
    } else {
        mask
    };
    if libc::access(path.as_ptr(), mask) != 0 {
        *libc::__errno_location()
    } else {
        0
    }
}

unsafe fn send_reply(socket: libc::c_int, status: [i32; 2], file: Option<libc::c_int>) -> bool {
    #[repr(C, align(8))]
    struct Control([u8; 64]);

    let mut control = Control([0; 64]);
    let mut buffer = libc::iovec {
        iov_base: status.as_ptr().cast_mut().cast(),
        iov_len: std::mem::size_of_val(&status),
    };
    let mut message: libc::msghdr = std::mem::zeroed();
    message.msg_iov = &mut buffer;
    message.msg_iovlen = 1;
    if let Some(file) = file {
        let length = std::mem::size_of::<libc::c_int>() as u32;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(length) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(length) as _;
        libc::CMSG_DATA(header)
            .cast::<libc::c_int>()
            .write_unaligned(file);
    }
    libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) == buffer.iov_len as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bwrap_common::bwrap_runner::BubblewrapScriptRunner;
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::ExecutionRequest;
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};

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
            paths: vec![(
                Some(CString::new("/mxc-identity-probe-does-not-exist/path").unwrap()),
                libc::R_OK,
            )],
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
    fn descriptor_fallback_closes_everything_but_the_reply_socket() {
        let (parent, child) = UnixStream::pair().unwrap();
        let extra = File::open("/dev/null").unwrap();
        let keep = child.as_raw_fd();
        let closed = [
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            parent.as_raw_fd(),
            extra.as_raw_fd(),
        ];

        // SAFETY: the child calls only syscalls before _exit.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                let passed = close_listed_descriptors(keep).is_ok()
                    && closed.iter().all(|&fd| {
                        libc::fcntl(fd, libc::F_GETFD) == -1
                            && *libc::__errno_location() == libc::EBADF
                    })
                    && libc::fcntl(keep, libc::F_GETFD) != -1;
                let answer = [u8::from(passed)];
                libc::write(keep, answer.as_ptr().cast(), 1);
                libc::_exit(0);
            }
        }
        assert!(pid > 0, "{}", io::Error::last_os_error());
        drop((child, extra));
        let mut answer = [0_u8; 1];
        let read = (&parent).read_exact(&mut answer);
        let mut status = 0;

        // SAFETY: pid is this test's unreaped child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        read.unwrap();
        assert_eq!(answer, [1]);
    }

    fn fork_watchdog(
        sandbox: &std::process::Child,
        launcher: &std::process::Child,
    ) -> SandboxWatchdog {
        let (parent, child) = UnixStream::pair().unwrap();
        parent.set_read_timeout(Some(PROBE_TIMEOUT)).unwrap();
        let operation = ChildOperation::Watch {
            uid: getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            sandbox: libc::pid_t::try_from(sandbox.id()).unwrap(),
            launcher: libc::pid_t::try_from(launcher.id()).unwrap(),
        };

        // Switching identity needs root, so this child runs only the watch loop.
        // SAFETY: the child calls only syscalls before _exit.
        let helper = unsafe { libc::fork() };
        if helper == 0 {
            unsafe {
                let status = match close_child_descriptors(child.as_raw_fd()) {
                    Ok(()) => run_child_operation(&operation, child.as_raw_fd()),
                    Err(_) => 1,
                };
                libc::_exit(status);
            }
        }
        assert!(helper > 0, "{}", io::Error::last_os_error());
        let mut helper = IdentityChild {
            pid: helper,
            channel: parent,
            reaped: false,
        };
        helper.result().unwrap();
        SandboxWatchdog {
            helper,
            uid: getuid().as_raw(),
        }
    }

    #[test]
    fn a_watchdog_kills_its_sandbox_when_the_launcher_exits_or_its_socket_closes() {
        use std::os::unix::process::ExitStatusExt;

        struct Fixture(std::process::Child);

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        // SAFETY: pidfd_open takes no pointers, and the descriptor it returns is owned here.
        match unsafe { open_process(libc::getpid()) } {
            Ok(pidfd) => drop(unsafe { OwnedFd::from_raw_fd(pidfd) }),
            Err(libc::ENOSYS) => {
                println!("SKIPPED: the sandbox watchdog requires pidfd_open (Linux 5.3 or later)");
                return;
            }
            Err(error) => panic!("pidfd_open: {}", io::Error::from_raw_os_error(error)),
        }
        for launcher_exits in [true, false] {
            let mut sandbox = Fixture(Command::new("sleep").arg("60").spawn().unwrap());
            let mut launcher = Fixture(Command::new("sleep").arg("60").spawn().unwrap());
            let watchdog = fork_watchdog(&sandbox.0, &launcher.0);
            if launcher_exits {
                launcher.0.kill().unwrap();
            }
            assert_eq!(watchdog.stop(), Ok(()));
            assert_eq!(sandbox.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        }
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
        const GID_FIXTURE: &str = "MXC_BWRAP_ROOT_GID_FIXTURE";
        if std::env::var_os(GID_FIXTURE).is_some() {
            // The Rust runtime reopens a closed stdin at startup, so close it here.
            // SAFETY: this re-executed process runs only this test.
            unsafe { libc::close(libc::STDIN_FILENO) };
            assert_eq!(
                unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFD) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
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
        if std::env::var_os(GID_FIXTURE).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "root_sdk_streaming_and_pty_use_mapped_identity",
                    "--nocapture",
                ])
                .env(GID_FIXTURE, "1")
                .gid(WORKLOAD_ID)
                .output()
                .unwrap();
            assert_one_test_passed(output);
        }
    }

    #[derive(Default)]
    struct Restrictions {
        without_kill_capability: bool,
        denied_syscall: Option<libc::c_long>,
    }

    fn reran_in_private_namespaces(test: &str, restrictions: Restrictions) -> bool {
        const PARENT_MOUNT: &str = "MXC_BWRAP_PARENT_MOUNT_NAMESPACE";
        const DENIED_SYSCALL: &str = "MXC_BWRAP_DENIED_SYSCALL";
        let namespace = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        if let Some(parent) = std::env::var_os(PARENT_MOUNT) {
            assert_ne!(namespace, std::path::PathBuf::from(parent));
            assert_eq!(
                std::process::id(),
                1,
                "the rerun must be PID 1 of its own PID namespace, so its leftover processes \
                 end with it"
            );
            if let Ok(syscall) = std::env::var(DENIED_SYSCALL) {
                deny_syscall(syscall.parse().unwrap());
            }
            return false;
        }
        let mut command = Command::new(host_tools::find("unshare").unwrap());
        command.args([
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--mount-proc",
            "--",
        ]);
        if restrictions.without_kill_capability {
            command.arg(host_tools::find("setpriv").unwrap()).args([
                "--inh-caps=-kill",
                "--ambient-caps=-kill",
                "--bounding-set=-kill",
                "--",
            ]);
        }
        if let Some(syscall) = restrictions.denied_syscall {
            command.env(DENIED_SYSCALL, syscall.to_string());
        }
        let output = command
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", test, "--nocapture"])
            .env(PARENT_MOUNT, namespace)
            .output()
            .unwrap();
        assert_one_test_passed(output);
        true
    }

    fn deny_syscall(syscall: libc::c_long) {
        let instruction = |code: u32, jf: u8, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf,
            k,
        };

        // Load the syscall number, then fail that syscall with EPERM and allow every other.
        let program = [
            instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0),
            instruction(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                1,
                syscall as u32,
            ),
            instruction(
                libc::BPF_RET | libc::BPF_K,
                0,
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
            instruction(libc::BPF_RET | libc::BPF_K, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let filter = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr().cast_mut(),
        };

        // SAFETY: the filter and the program it points to outlive the call, which copies them.
        let installed = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &filter as *const libc::sock_fprog,
            )
        };
        assert_eq!(installed, 0, "{}", io::Error::last_os_error());
    }

    fn live_processes_owned_by(uid: u32) -> Vec<String> {
        let uid = uid.to_string();
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path().join("status")).ok())
            .filter(|status| {
                let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
                field("Uid:").is_some_and(|ids| ids.split_whitespace().any(|id| id == uid))
                    && !field("State:").is_some_and(|state| state.trim_start().starts_with('Z'))
            })
            .collect()
    }

    fn assert_one_test_passed(output: std::process::Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn bind_fixture(directory: &Path, target: &Path, mode: u32, contents: &str) {
        use std::os::unix::fs::PermissionsExt;

        let fixture = directory.join(uuid::Uuid::new_v4().simple().to_string());
        std::fs::write(&fixture, contents).unwrap();
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(mode)).unwrap();
        nix::mount::mount(
            Some(fixture.as_path()),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
    }

    fn run_backend(
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<(i32, String), String> {
        let mut process = BubblewrapScriptRunner::new()
            .spawn(request, logger, StdioMode::Pipes)
            .map_err(|response| response.error_message)?;
        let mut stdout = process.take_stdout().unwrap();
        let reader = std::thread::spawn(move || {
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            output
        });
        let status = process.wait().unwrap();
        Ok((status, reader.join().unwrap()))
    }

    #[test]
    #[ignore = "requires root with subordinate ranges and Bubblewrap network prerequisites"]
    fn root_backend_hostname_pin_uses_mapped_identity() {
        use std::net::{TcpListener, TcpStream};

        use crate::mxc_common::models::ProxyAddress;

        assert!(getuid().is_root());
        RootIdentity::for_caller().unwrap().expect("root identity");
        if reran_in_private_namespaces(
            "root_backend_hostname_pin_uses_mapped_identity",
            Restrictions::default(),
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let hosts = Path::new("/etc/hosts");
        let hostname = format!("mxc-{}.invalid", uuid::Uuid::new_v4().simple());
        let pinned_hosts = format!(
            "{}\n127.0.0.1 {hostname}\n",
            std::fs::read_to_string(hosts).unwrap()
        );
        bind_fixture(directory.path(), hosts, 0o644, &pinned_hosts);
        let nsswitch = Path::new("/etc/nsswitch.conf");
        if nsswitch.exists() {
            let contents = std::fs::read_to_string(nsswitch).unwrap();
            let mut lines: Vec<_> = contents
                .lines()
                .filter(|line| line.split(':').next().unwrap_or("").trim() != "hosts")
                .collect();
            lines.push("hosts: files dns");
            bind_fixture(
                directory.path(),
                nsswitch,
                0o644,
                &(lines.join("\n") + "\n"),
            );
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
        let (status, output) =
            run_backend(&request, &mut logger).expect("mapped backend hostname launch");
        assert_eq!(status, 0, "{output}\n{}", logger.get_buffer());
        assert!(output.contains("MAPPED_HOSTNAME_PIN"), "{output}");

        nix::mount::umount(hosts).unwrap();
        bind_fixture(directory.path(), hosts, 0o600, &pinned_hosts);
        let error = run_backend(&request, &mut Logger::new(Mode::Buffer))
            .expect_err("an unreadable hosts file must reject the pin before launch");
        assert!(
            error.contains("/etc/hosts") && error.contains("mapped Bubblewrap UID"),
            "{error}"
        );
    }

    #[test]
    #[ignore = "requires root with subordinate ranges and Bubblewrap network prerequisites"]
    fn root_resolver_inputs_use_mapped_identity() {
        use crate::mxc_common::filesystem_probe::MAX_PROBE_WORKERS;
        use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy};

        assert!(getuid().is_root());
        RootIdentity::for_caller().unwrap().expect("root identity");
        let restrictions = Restrictions {
            without_kill_capability: true,
            ..Default::default()
        };
        if reran_in_private_namespaces("root_resolver_inputs_use_mapped_identity", restrictions) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let resolver = link_resolver_outside_etc(directory.path());
        let mut request = ExecutionRequest {
            script_code: "test \"$(id -u)\" = 1000".into(),
            script_timeout: 15_000,
            ..Default::default()
        };
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });

        // One launch more than there are probe workers fails if each stalled read keeps a worker.
        nix::unistd::mkfifo(&resolver, nix::sys::stat::Mode::from_bits_truncate(0o644)).unwrap();
        for _ in 0..=MAX_PROBE_WORKERS {
            let mut logger = Logger::new(Mode::Buffer);
            let (status, output) = run_backend(&request, &mut logger).unwrap();
            assert_eq!(status, 0, "{output}\n{}", logger.get_buffer());
            assert!(
                logger
                    .warnings()
                    .iter()
                    .any(|warning| warning.contains("is not a regular file")),
                "{:?}",
                logger.warnings()
            );
        }
        std::fs::remove_file(&resolver).unwrap();

        let marker = format!("mxc-{}.invalid", uuid::Uuid::new_v4().simple());
        request.script_code =
            "set -e; test \"$(id -u)\" = 1000; cat /etc/resolv.conf || true".into();
        for (mode, readable) in [(0o644, true), (0o600, false)] {
            std::fs::write(
                &resolver,
                format!("nameserver 127.0.0.53\nsearch {marker}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(mode)).unwrap();
            let mut logger = Logger::new(Mode::Buffer);
            let (status, output) = run_backend(&request, &mut logger).unwrap();
            assert_eq!(status, 0, "{output}\n{}", logger.get_buffer());
            assert_eq!(
                output.contains(&marker),
                readable,
                "mode {mode:o}: {output}"
            );
            assert_eq!(
                logger
                    .warnings()
                    .iter()
                    .any(|warning| warning.contains("mapped Bubblewrap UID")),
                !readable,
                "{:?}",
                logger.warnings()
            );
        }
    }

    fn link_resolver_outside_etc(directory: &Path) -> std::path::PathBuf {
        use crate::bwrap_common::bwrap_command::WSL_RESOLV_CONF;
        use nix::mount::{mount, MsFlags};

        let scratch = directory.join("etc");
        std::fs::create_dir(&scratch).unwrap();
        mount(
            Some("tmpfs"),
            &scratch,
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();
        for layer in ["upper", "work"] {
            std::fs::create_dir(scratch.join(layer)).unwrap();
        }
        let options = format!(
            "lowerdir=/etc,upperdir={0}/upper,workdir={0}/work",
            scratch.display()
        );
        mount(
            Some("overlay"),
            "/etc",
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .unwrap();
        mount(
            Some("tmpfs"),
            "/mnt",
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();
        let resolver = Path::new(WSL_RESOLV_CONF);
        std::fs::create_dir_all(resolver.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file("/etc/resolv.conf");
        std::os::unix::fs::symlink(resolver, "/etc/resolv.conf").unwrap();
        resolver.to_path_buf()
    }

    #[test]
    #[ignore = "requires root with subordinate ranges"]
    fn root_missing_denied_path_overlay_uses_mapped_identity() {
        use crate::bwrap_common::bwrap_version::{probe_bwrap_uncached, BwrapVersion};

        assert!(getuid().is_root());
        RootIdentity::for_caller().unwrap().expect("root identity");
        if reran_in_private_namespaces(
            "root_missing_denied_path_overlay_uses_mapped_identity",
            Restrictions::default(),
        ) {
            return;
        }
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
        let grant = tempfile::tempdir().unwrap();
        std::fs::set_permissions(grant.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let denied = grant.path().join("missing");
        let mut request = ExecutionRequest {
            script_code: format!(
                "set -e; test -d '{0}'; test -z \"$(ls -A '{0}')\"; \
                 if touch '{0}/written' 2>/dev/null; then exit 1; fi; echo MISSING_PATH_MASKED",
                denied.display()
            ),
            script_timeout: 15_000,
            ..Default::default()
        };
        request.policy.readonly_paths = vec![grant.path().display().to_string()];
        request.policy.denied_paths = vec![denied.display().to_string()];
        let result = run_backend(&request, &mut Logger::new(Mode::Buffer));
        assert!(
            !denied.exists(),
            "the private overlay created {} on the host",
            denied.display()
        );
        if probe_bwrap_uncached().unwrap().version < BwrapVersion::new(0, 11, 0) {
            let error = result.expect_err("bwrap before 0.11 cannot mask a missing path");
            assert!(error.contains("requires bwrap 0.11.0"), "{error}");
            return;
        }
        let (status, output) = result.expect("mapped launch with a missing denied path");
        assert_eq!(status, 0, "{output}");
        assert!(output.contains("MISSING_PATH_MASKED"), "{output}");
    }

    #[test]
    #[ignore = "requires root with subordinate ranges"]
    fn root_launch_fails_closed_when_the_watchdog_cannot_open_the_sandbox() {
        assert_failed_watchdog_never_releases_the_workload(
            "root_launch_fails_closed_when_the_watchdog_cannot_open_the_sandbox",
            libc::SYS_pidfd_open,
        );
    }

    #[test]
    #[ignore = "requires root with subordinate ranges"]
    fn root_launch_fails_closed_when_the_watchdog_cannot_signal_the_sandbox() {
        assert_failed_watchdog_never_releases_the_workload(
            "root_launch_fails_closed_when_the_watchdog_cannot_signal_the_sandbox",
            libc::SYS_pidfd_send_signal,
        );
    }

    fn assert_failed_watchdog_never_releases_the_workload(test: &str, denied: libc::c_long) {
        assert!(getuid().is_root());
        let identity = RootIdentity::for_caller().unwrap().expect("root identity");
        let restrictions = Restrictions {
            without_kill_capability: true,
            denied_syscall: Some(denied),
        };
        if reran_in_private_namespaces(test, restrictions) {
            return;
        }
        let grant = tempfile::tempdir().unwrap();
        std::fs::set_permissions(grant.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = grant.path().join("started");
        let mut request = ExecutionRequest {
            script_code: format!("touch '{}'", marker.display()),
            script_timeout: 15_000,
            ..Default::default()
        };
        request.policy.readwrite_paths = vec![grant.path().display().to_string()];
        let error = run_backend(&request, &mut Logger::new(Mode::Buffer))
            .expect_err("a launch whose watchdog cannot work must fail");
        assert!(error.contains("could not watch the sandbox"), "{error}");
        std::thread::sleep(Duration::from_secs(2));
        assert!(!marker.exists(), "the workload ran after: {error}");
        let survivors = live_processes_owned_by(identity.workload_ids().0);
        assert!(survivors.is_empty(), "{survivors:#?}");
    }

    #[test]
    #[ignore = "requires root with subordinate ranges"]
    fn root_account_lookups_stop_at_the_validation_deadline() {
        use std::os::unix::fs::PermissionsExt;

        const SLOW_GETENT: &str = "MXC_BWRAP_SLOW_GETENT";
        const TEST: &str = "root_account_lookups_stop_at_the_validation_deadline";
        assert!(getuid().is_root());
        let Some(shim) = std::env::var_os(SLOW_GETENT) else {
            let directory = tempfile::tempdir().unwrap();
            let shim = directory.path().join("getent");
            let script = format!(
                "#!/bin/sh\ntouch \"$0.$1.started\"\nsleep 3\ntouch \"$0.$1.finished\"\n\
                 exec {} \"$@\"\n",
                host_tools::find("getent").unwrap().display()
            );
            std::fs::write(&shim, script).unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = std::iter::once(directory.path().to_str().unwrap())
                .chain(host_tools::FALLBACK_DIRECTORIES)
                .collect::<Vec<_>>()
                .join(":");
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", TEST, "--nocapture"])
                .env(SLOW_GETENT, &shim)
                .env("PATH", path)
                .output()
                .unwrap();
            assert_one_test_passed(output);
            return;
        };
        let marker = |name: &str| {
            let mut path = shim.clone();
            path.push(format!(".group.{name}"));
            std::path::PathBuf::from(path)
        };
        let error = RootIdentity::for_caller()
            .expect_err("account lookups past the validation deadline must reject startup");
        std::thread::sleep(Duration::from_secs(2));
        assert!(marker("started").exists(), "{error}");
        assert!(
            !marker("finished").exists(),
            "getent group kept running after the validation deadline: {error}"
        );
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
    fn allocation_files_match_the_shared_ci_fixtures() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/bubblewrap/root_allocations.json"
        ))
        .unwrap();
        let passwd = fixtures["passwd"].as_str().unwrap();
        let group = fixtures["group"].as_str().unwrap();
        let other = "root:400000:65536\n";
        for case in fixtures["cases"].as_array().unwrap() {
            let allocations = case["allocations"].as_str().unwrap();
            for uid in [true, false] {
                let (subuid, subgid) = if uid {
                    (allocations, other)
                } else {
                    (other, allocations)
                };
                let result =
                    RootIdentity::from_databases(subuid, subgid, passwd, group).map(|identity| {
                        if uid {
                            identity.uid_base
                        } else {
                            identity.gid_base
                        }
                    });
                match (&case["expect"], &result) {
                    (serde_json::Value::Number(base), Ok(selected)) => {
                        assert_eq!(base.as_u64(), Some(u64::from(*selected)), "{allocations:?}");
                    }
                    (serde_json::Value::String(kind), Err(error))
                        if kind == "missing" || kind == "invalid" =>
                    {
                        assert_eq!(
                            kind == "missing",
                            error.contains("requires a reserved allocation"),
                            "{allocations:?}: {error}"
                        );
                    }
                    (expected, result) => {
                        panic!("{allocations:?}: expected {expected}, got {result:?}")
                    }
                }
            }
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
    fn accounts_outside_the_mapping_are_allowed() {
        let passwd = format!("{PASSWD}outside:x:165536:365536::/:/bin/sh\n");
        assert!(RootIdentity::from_databases(
            "root:100000:65536\n",
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
