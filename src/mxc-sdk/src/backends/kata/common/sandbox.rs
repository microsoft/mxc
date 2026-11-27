// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A Kata sandbox: one microVM, its bundle, and the host resources it uses.
//!
//! The sandbox follows the container lifecycle: [`Sandbox::provision`]
//! allocates the host resources (bundle, network namespace, writable layer),
//! [`Sandbox::start`] boots the VM, [`Sandbox::exec`] runs a process in it,
//! [`Sandbox::stop`] shuts the VM down but keeps the resources, and
//! [`Sandbox::deprovision`] releases them.
//!
//! State lives on disk, in a directory per sandbox, because a sandbox started
//! by one call is used by later ones, possibly from another process. A create-
//! and-run request drives the same operations in sequence through [`Ephemeral`].

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::kata_common::error::KataError;
use crate::kata_common::execution::{Execution, KillScope};
use crate::kata_common::host::{self, Install};
use crate::kata_common::mounts;
use crate::kata_common::netns::NetNs;
use crate::kata_common::oci;
use crate::kata_common::policy::{Plan, RootfsKind};
use crate::kata_common::rootfs;
use crate::kata_common::shim::{self, Shim};
use crate::kata_common::task_api::{self, CreateRequest, StdioPaths, TaskClient};
use crate::kata_common::ttrpc::Client;
use crate::mxc_common::id::mint_random_token;
use crate::mxc_common::models::{ExecutionRequest, KataHypervisor};

/// Prefix of the shim id and of the sandbox's directory name.
const ID_PREFIX: &str = "mxc-kata-";
const RECORD_FILE: &str = "sandbox.json";
const LOCK_FILE: &str = "lock";
/// How long to wait for the init process to report its exit during stop.
const INIT_EXIT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum State {
    /// Resources are allocated; no VM is running.
    Provisioned,
    /// The VM is running and can execute processes.
    Running,
}

/// Everything a later call needs to find the sandbox again.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    id: String,
    hypervisor: KataHypervisor,
    shim_binary: PathBuf,
    config: PathBuf,
    rootfs: PathBuf,
    rootfs_kind: RootfsKind,
    state: State,
    shim: Option<Shim>,
    /// The sandbox exists for one create-and-run request. Its owner holds the
    /// directory lock for as long as it lives, so an unlocked ephemeral
    /// sandbox has no owner and can be reclaimed.
    #[serde(default)]
    ephemeral: bool,
}

/// An exclusive lock on the sandbox's directory, held while one call changes
/// the sandbox, so concurrent lifecycle calls on one id run one at a time.
#[derive(Debug)]
struct DirLock(#[allow(dead_code)] File);

impl DirLock {
    /// Locks `path`, waiting for the holder when `wait` is set. Returns `None`
    /// instead of waiting when `wait` is not set and another holder has it.
    fn lock(path: &Path, wait: bool) -> std::io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)?;
        use std::os::fd::AsRawFd;
        let operation = if wait {
            libc::LOCK_EX
        } else {
            libc::LOCK_EX | libc::LOCK_NB
        };
        // SAFETY: `flock` takes a descriptor that is open for the call.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(Self(file)))
    }

    fn acquire(path: &Path) -> std::io::Result<Self> {
        Self::lock(path, true).map(|lock| lock.expect("a waiting lock always succeeds"))
    }
}

#[derive(Debug)]
pub(crate) struct Sandbox {
    dir: PathBuf,
    record: Record,
    _lock: DirLock,
    /// Held while the VM runs in this process's call, so the init process's
    /// standard input stays open.
    init_stdin: Option<File>,
}

/// Whether `token` has the shape [`Sandbox::token`] produces. Checked before it
/// names a directory.
pub(crate) fn is_valid_token(token: &str) -> bool {
    token.len() == 8
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp, path)
}

impl Sandbox {
    fn bundle(&self) -> PathBuf {
        self.dir.join("bundle")
    }

    fn io_dir(&self) -> PathBuf {
        self.dir.join("io")
    }

    fn netns_path(&self) -> PathBuf {
        self.dir.join("netns")
    }

    fn save(&self) -> Result<(), KataError> {
        let bytes = serde_json::to_vec_pretty(&self.record)
            .map_err(|e| KataError::failed(format!("encoding the sandbox record: {e}")))?;
        write_atomically(&self.dir.join(RECORD_FILE), &bytes)
            .map_err(|e| KataError::failed(format!("writing the sandbox record: {e}")))
    }

    /// The identifier callers hold: the part of the id that follows the prefix.
    pub(crate) fn token(&self) -> &str {
        &self.record.id[ID_PREFIX.len()..]
    }

    pub(crate) fn state(&self) -> State {
        self.record.state
    }

    /// The shim's pid while the sandbox runs, for callers that report one.
    pub(crate) fn shim_pid(&self) -> Option<u32> {
        self.record.shim.as_ref().map(|shim| shim.process.pid)
    }

    fn task_client(&self) -> Result<TaskClient, KataError> {
        let shim = self.record.shim.as_ref().ok_or_else(|| {
            KataError::NotStarted(format!(
                "sandbox {} is not running; start it first",
                self.token()
            ))
        })?;
        Ok(TaskClient::new(Client::new(&shim.address)))
    }

    /// Allocates a sandbox for `plan`: its directory, network namespace,
    /// writable layer, and bundle. No VM is started.
    pub(crate) fn provision(
        plan: &Plan,
        install: &Install,
        state_root: &Path,
        ephemeral: bool,
    ) -> Result<Self, KataError> {
        host::check_prerequisites().map_err(KataError::unavailable)?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_root)
            .map_err(|e| KataError::failed(format!("creating {}: {e}", state_root.display())))?;
        let id = format!("{ID_PREFIX}{}", mint_random_token());
        let dir = state_root.join(&id);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| KataError::failed(format!("creating {}: {e}", dir.display())))?;
        let lock = DirLock::acquire(&dir.join(LOCK_FILE)).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            KataError::failed(format!("locking {}: {e}", dir.display()))
        })?;

        let mut sandbox = Self {
            dir,
            record: Record {
                id,
                hypervisor: plan.hypervisor,
                shim_binary: install.shim.clone(),
                config: install.config.clone(),
                rootfs: plan.rootfs.clone(),
                rootfs_kind: plan.rootfs_kind,
                state: State::Provisioned,
                shim: None,
                ephemeral,
            },
            _lock: lock,
            init_stdin: None,
        };
        if let Err(error) = sandbox.allocate(plan) {
            let leftovers = sandbox.release_resources();
            return Err(if leftovers.is_empty() {
                error
            } else {
                KataError::failed(format!("{error}. Cleanup left: {}", leftovers.join("; ")))
            });
        }
        Ok(sandbox)
    }

    fn allocate(&mut self, plan: &Plan) -> Result<(), KataError> {
        for sub in ["bundle/rootfs", "io"] {
            std::fs::create_dir_all(self.dir.join(sub)).map_err(|e| {
                KataError::failed(format!("creating {}: {e}", self.dir.join(sub).display()))
            })?;
        }
        NetNs::create(&self.netns_path()).map_err(|e| {
            KataError::failed(format!(
                "creating the sandbox's network namespace at {}: {e}",
                self.netns_path().display()
            ))
        })?;
        rootfs::prepare(&self.dir, plan.rootfs_kind, &plan.rootfs)?;
        let spec = oci::bundle_spec(&plan.filesystem, &self.netns_path());
        let bytes = serde_json::to_vec_pretty(&spec)
            .map_err(|e| KataError::failed(format!("encoding config.json: {e}")))?;
        write_atomically(&self.bundle().join("config.json"), &bytes)
            .map_err(|e| KataError::failed(format!("writing config.json: {e}")))?;
        self.save()
    }

    /// Finds a sandbox provisioned earlier and locks it.
    pub(crate) fn open(state_root: &Path, token: &str) -> Result<Self, KataError> {
        if !is_valid_token(token) {
            return Err(KataError::Stale(format!(
                "{token:?} is not a Kata sandbox identifier"
            )));
        }
        let dir = state_root.join(format!("{ID_PREFIX}{token}"));
        let stale = || {
            KataError::Stale(format!(
                "no Kata sandbox {token} exists on this host; it was deprovisioned, or the host \
                 restarted"
            ))
        };
        if !dir.join(RECORD_FILE).is_file() {
            return Err(stale());
        }
        let lock = DirLock::acquire(&dir.join(LOCK_FILE))
            .map_err(|e| KataError::failed(format!("locking {}: {e}", dir.display())))?;
        Self::load(dir, lock).ok_or_else(stale)?
    }

    /// Reads the record of the sandbox in `dir`, whose lock is held. `None`
    /// when a call that held the lock before removed the sandbox.
    fn load(dir: PathBuf, lock: DirLock) -> Option<Result<Self, KataError>> {
        let bytes = std::fs::read(dir.join(RECORD_FILE)).ok()?;
        Some(
            serde_json::from_slice::<Record>(&bytes)
                .map(|record| Self {
                    dir: dir.clone(),
                    record,
                    _lock: lock,
                    init_stdin: None,
                })
                .map_err(|e| {
                    KataError::failed(format!(
                        "the record of the sandbox in {} is damaged: {e}",
                        dir.display()
                    ))
                }),
        )
    }

    /// Reclaims create-and-run sandboxes whose process ended without cleaning
    /// up, for example after SIGINT or SIGKILL. A live request holds its
    /// sandbox's lock, so an ephemeral sandbox whose lock is free is orphaned.
    /// Sandboxes kept by the container lifecycle operations are never touched.
    /// Returns what could not be reclaimed.
    pub(crate) fn reclaim_orphans(state_root: &Path) -> Vec<String> {
        let mut failures = Vec::new();
        let Ok(entries) = std::fs::read_dir(state_root) else {
            return failures;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            let named_like_a_sandbox = dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(ID_PREFIX));
            if !named_like_a_sandbox || !dir.join(RECORD_FILE).is_file() {
                continue;
            }
            let Ok(Some(lock)) = DirLock::lock(&dir.join(LOCK_FILE), false) else {
                continue;
            };
            let Some(Ok(mut sandbox)) = Self::load(dir.clone(), lock) else {
                continue;
            };
            if !sandbox.record.ephemeral {
                continue;
            }
            if sandbox.state() == State::Running {
                if let Err(error) = sandbox.stop() {
                    failures.push(error.to_string());
                    continue;
                }
            }
            if let Err(error) = sandbox.deprovision() {
                failures.push(error.to_string());
            }
        }
        failures
    }

    /// Clears what an earlier run of the shim left in the bundle: its address
    /// and pid files, logs, and the hypervisor's control sockets, which a new
    /// run would fail to bind. `config.json` and the root filesystem mount
    /// point stay.
    fn reset_bundle(&self) -> Result<(), KataError> {
        let bundle = self.bundle();
        // Deleting below a mount that stays would delete what it exposes.
        mounts::unmount_all(&bundle).map_err(KataError::failed)?;
        let entries = std::fs::read_dir(&bundle)
            .map_err(|e| KataError::failed(format!("reading {}: {e}", bundle.display())))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name == "config.json" || name == "rootfs" {
                continue;
            }
            let path = entry.path();
            let removed = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.map_err(|e| KataError::failed(format!("removing {}: {e}", path.display())))?;
        }
        Ok(())
    }

    /// Boots the VM and starts the init process.
    pub(crate) fn start(&mut self) -> Result<(), KataError> {
        if self.record.state == State::Running {
            return Err(KataError::AlreadyStarted(format!(
                "sandbox {} is already running",
                self.token()
            )));
        }
        host::check_prerequisites().map_err(KataError::unavailable)?;
        self.reset_bundle()?;

        // Hold the init process's standard input open and silent, so its
        // `read` blocks for as long as the VM runs.
        let init_stdin_path = self.io_dir().join("init.in");
        let _ = std::fs::remove_file(&init_stdin_path);
        nix::unistd::mkfifo(
            &init_stdin_path,
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| KataError::failed(format!("creating {}: {e}", init_stdin_path.display())))?;
        let init_stdin = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&init_stdin_path)
            .map_err(|e| {
                KataError::failed(format!("opening {}: {e}", init_stdin_path.display()))
            })?;

        let (root, _loop_device) =
            rootfs::root_mount(&self.dir, self.record.rootfs_kind, &self.record.rootfs)?;

        let shim = shim::start(
            &self.record.shim_binary,
            &self.record.id,
            &self.bundle(),
            &self.dir.join("containerd.sock"),
        )?;
        let task = TaskClient::new(Client::new(&shim.address));
        let created = task
            .create(&CreateRequest {
                id: self.record.id.clone(),
                bundle: self.bundle().display().to_string(),
                rootfs: vec![root],
                stdio: StdioPaths {
                    stdin: init_stdin_path.display().to_string(),
                    ..Default::default()
                },
                options: Some(task_api::runtime_options(
                    &self.record.config.display().to_string(),
                )),
            })
            .map_err(|e| {
                KataError::failed(format!(
                    "the Kata shim could not create the {} sandbox: {e}",
                    self.record.hypervisor.wire_name()
                ))
            })
            .and_then(|_| {
                task.start(&self.record.id, "")
                    .map(drop)
                    .map_err(|e| KataError::failed(format!("the sandbox did not start: {e}")))
            });
        // The record is written last, so failing to write it stops the shim
        // like any other failed start instead of leaving it running unrecorded.
        let started = created.and_then(|()| {
            self.record.state = State::Running;
            self.record.shim = Some(shim.clone());
            self.save()
        });
        if let Err(error) = started {
            self.record.state = State::Provisioned;
            self.record.shim = None;
            // The shim cannot exit while it still reads the init process's
            // standard input, so release it first.
            drop(init_stdin);
            let _ = task.close_stdin(&self.record.id, "");
            let cleanup = self.stop_shim(&shim, &task);
            return Err(match cleanup {
                Ok(()) => error,
                Err(more) => KataError::failed(format!("{error}. Cleanup: {more}")),
            });
        }

        self.init_stdin = Some(init_stdin);
        Ok(())
    }

    /// Stops the shim and removes what it leaves behind on the host.
    fn stop_shim(&self, shim: &Shim, task: &TaskClient) -> Result<(), KataError> {
        let stopped = shim::stop(shim, task, &self.record.id);
        // What containerd does once a shim is gone: the shim's own cleanup of
        // its socket and persisted state. It also covers a shim that was
        // killed. Failing is not fatal because the sweep below does the rest.
        let _ = shim::delete(
            &self.record.shim_binary,
            &self.record.id,
            &self.bundle(),
            &self.dir.join("containerd.sock"),
        );
        // The shim unmounts the root filesystem and its shared directories on a
        // clean shutdown. A shim that was killed cannot, so sweep.
        let leftovers = mounts::unmount_all(&self.bundle());
        shim::remove_leftovers(&self.record.id, Some(&shim.address));
        stopped?;
        leftovers.map_err(KataError::failed)
    }

    /// Runs `request`'s process in the started sandbox.
    pub(crate) fn exec(
        &mut self,
        request: &ExecutionRequest,
        scope: KillScope,
    ) -> Result<Execution, KataError> {
        if self.record.state != State::Running {
            return Err(KataError::NotStarted(format!(
                "sandbox {} is not running; start it first",
                self.token()
            )));
        }
        let task = self.task_client()?;
        let exec_id = format!("x{}", mint_random_token());
        Execution::start(
            &task,
            &self.record.id,
            &exec_id,
            &oci::exec_process(request),
            &self.io_dir(),
            scope,
        )
    }

    /// Shuts the VM down. The sandbox stays provisioned, with its writable
    /// layer, and can be started again.
    pub(crate) fn stop(&mut self) -> Result<(), KataError> {
        let Some(shim) = self
            .record
            .shim
            .clone()
            .filter(|_| self.record.state == State::Running)
        else {
            return Err(KataError::AlreadyStopped(format!(
                "sandbox {} is not running",
                self.token()
            )));
        };
        let task = self.task_client()?;
        let id = self.record.id.clone();

        // The order containerd uses. A step that fails (the VM may already be
        // gone) does not stop the teardown, and a shim that is already gone
        // has nothing to answer.
        self.init_stdin = None;
        if shim.process.is_alive() {
            let _ = task.kill(&id, "", task_api::SIGKILL, true);
            let (sender, receiver) = mpsc::channel();
            let waiter = task.clone();
            let wait_id = id.clone();
            std::thread::spawn(move || {
                let _ = sender.send(waiter.wait(&wait_id, ""));
            });
            let _ = receiver.recv_timeout(INIT_EXIT_TIMEOUT);
            // The shim keeps reading the init process's standard input until
            // its end of file. Without this it cannot exit after Shutdown.
            let _ = task.close_stdin(&id, "");
            let _ = task.delete(&id, "");
        }

        let result = self.stop_shim(&shim, &task);
        if let Ok(entries) = std::fs::read_dir(self.io_dir()) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        if result.is_ok() || !shim.process.is_alive() {
            self.record.state = State::Provisioned;
            self.record.shim = None;
            self.save()?;
        }
        result
    }

    /// Releases the sandbox's host resources. The sandbox must not be running.
    pub(crate) fn deprovision(mut self) -> Result<(), KataError> {
        if self.record.state == State::Running {
            return Err(KataError::AlreadyStarted(format!(
                "sandbox {} is still running; stop it before deprovisioning",
                self.token()
            )));
        }
        let leftovers = self.release_resources();
        if leftovers.is_empty() {
            Ok(())
        } else {
            Err(KataError::failed(format!(
                "sandbox {} was not fully released: {}. It is still recorded; deprovision it \
                 again once the cause is fixed",
                self.token(),
                leftovers.join("; ")
            )))
        }
    }

    /// Unmounts, unpins, and deletes everything the sandbox owns. Returns what
    /// could not be released; the directory stays when anything remains, so a
    /// later deprovision can finish the job.
    fn release_resources(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        match mounts::unmount_under(&self.dir) {
            Ok(failed) => failures.extend(
                failed
                    .into_iter()
                    .map(|(mount, e)| format!("unmounting {}: {e}", mount.display())),
            ),
            Err(e) => failures.push(format!("listing mounts: {e}")),
        }
        if failures.is_empty() {
            if let Err(e) = NetNs::at(&self.netns_path()).destroy() {
                failures.push(format!("removing the network namespace: {e}"));
            }
        }
        if failures.is_empty() {
            if let Err(e) = std::fs::remove_dir_all(&self.dir) {
                failures.push(format!("removing {}: {e}", self.dir.display()));
            }
        }
        shim::remove_leftovers(
            &self.record.id,
            self.record.shim.as_ref().map(|shim| shim.address.as_str()),
        );
        failures
    }
}

/// A sandbox that lives for one create-and-run request: it is provisioned and
/// started up front and, whatever happens, stopped and deprovisioned when the
/// request ends.
pub(crate) struct Ephemeral {
    sandbox: Option<Sandbox>,
}

impl Ephemeral {
    /// Provisions and starts a sandbox, releasing it again if either fails.
    pub(crate) fn create(
        plan: &Plan,
        install: &Install,
        state_root: &Path,
    ) -> Result<Self, KataError> {
        // An earlier request that was killed leaves its VM behind.
        let _ = Sandbox::reclaim_orphans(state_root);
        let mut sandbox = Sandbox::provision(plan, install, state_root, true)?;
        if let Err(error) = sandbox.start() {
            let mut ephemeral = Self {
                sandbox: Some(sandbox),
            };
            let leftovers = ephemeral.teardown();
            return Err(if leftovers.is_empty() {
                error
            } else {
                KataError::failed(format!("{error}. Cleanup: {}", leftovers.join("; ")))
            });
        }
        Ok(Self {
            sandbox: Some(sandbox),
        })
    }

    pub(crate) fn sandbox(&mut self) -> &mut Sandbox {
        self.sandbox
            .as_mut()
            .expect("sandbox is released only by teardown")
    }

    /// Stops and deprovisions. Returns what could not be cleaned up. Safe to
    /// call again.
    pub(crate) fn teardown(&mut self) -> Vec<String> {
        let Some(mut sandbox) = self.sandbox.take() else {
            return Vec::new();
        };
        let mut failures = Vec::new();
        if sandbox.state() == State::Running {
            if let Err(error) = sandbox.stop() {
                failures.push(error.to_string());
            }
        }
        if let Err(error) = sandbox.deprovision() {
            failures.push(error.to_string());
        }
        failures
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_eight_lowercase_hex_characters_name_a_sandbox() {
        assert!(is_valid_token("0a1b2c3d"));
        for bad in [
            "",
            "0a1b2c3",
            "0a1b2c3d4",
            "0A1B2C3D",
            "../../etc",
            "0a1b2c3g",
            "0a1b 2c3",
        ] {
            assert!(!is_valid_token(bad), "{bad:?}");
        }
        assert!(is_valid_token(&mint_random_token()));
    }

    #[test]
    fn opening_a_sandbox_that_does_not_exist_is_a_stale_id() {
        let dir = tempfile::tempdir().unwrap();
        let err = Sandbox::open(dir.path(), "0a1b2c3d").unwrap_err();
        assert!(matches!(err, KataError::Stale(_)), "{err:?}");
        assert!(err.message().contains("0a1b2c3d"), "{err:?}");

        let err = Sandbox::open(dir.path(), "../escape").unwrap_err();
        assert!(matches!(err, KataError::Stale(_)), "{err:?}");
    }

    #[test]
    fn a_record_round_trips_and_a_damaged_one_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let sb_dir = dir.path().join("mxc-kata-0a1b2c3d");
        std::fs::create_dir(&sb_dir).unwrap();
        let record = Record {
            id: "mxc-kata-0a1b2c3d".into(),
            hypervisor: KataHypervisor::Dragonball,
            shim_binary: "/kata/shim".into(),
            config: "/kata/conf.toml".into(),
            rootfs: "/srv/rootfs".into(),
            rootfs_kind: RootfsKind::Directory,
            state: State::Provisioned,
            shim: None,
            ephemeral: false,
        };
        std::fs::write(
            sb_dir.join(RECORD_FILE),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        let opened = Sandbox::open(dir.path(), "0a1b2c3d").unwrap();
        assert_eq!(opened.token(), "0a1b2c3d");
        assert_eq!(opened.record.hypervisor, KataHypervisor::Dragonball);
        assert_eq!(opened.state(), State::Provisioned);
        drop(opened);

        std::fs::write(sb_dir.join(RECORD_FILE), b"{not json").unwrap();
        let err = Sandbox::open(dir.path(), "0a1b2c3d").unwrap_err();
        assert!(err.message().contains("damaged"), "{err:?}");
    }

    fn write_record(root: &Path, token: &str, ephemeral: bool) -> PathBuf {
        let dir = root.join(format!("{ID_PREFIX}{token}"));
        std::fs::create_dir(&dir).unwrap();
        let record = Record {
            id: format!("{ID_PREFIX}{token}"),
            hypervisor: KataHypervisor::Qemu,
            shim_binary: "/kata/shim".into(),
            config: "/kata/conf.toml".into(),
            rootfs: "/srv/rootfs".into(),
            rootfs_kind: RootfsKind::Directory,
            state: State::Provisioned,
            shim: None,
            ephemeral,
        };
        std::fs::write(dir.join(RECORD_FILE), serde_json::to_vec(&record).unwrap()).unwrap();
        dir
    }

    #[test]
    fn a_killed_requests_sandbox_is_reclaimed_but_live_and_kept_ones_are_not() {
        let root = tempfile::tempdir().unwrap();
        let orphan = write_record(root.path(), "00000001", true);
        let kept = write_record(root.path(), "00000002", false);
        let live = write_record(root.path(), "00000003", true);
        // A live request holds its sandbox's lock for as long as it runs.
        let _owner = DirLock::acquire(&live.join(LOCK_FILE)).unwrap();
        // Not a sandbox, whatever it holds.
        let unrelated = root.path().join("something-else");
        std::fs::create_dir(&unrelated).unwrap();

        let failures = Sandbox::reclaim_orphans(root.path());

        assert!(failures.is_empty(), "{failures:?}");
        assert!(!orphan.exists(), "the orphaned sandbox must be removed");
        assert!(kept.exists(), "a lifecycle sandbox has no owning process");
        assert!(
            live.exists(),
            "a sandbox whose owner holds the lock is live"
        );
        assert!(unrelated.exists());
    }

    #[test]
    fn reclaiming_with_no_state_directory_is_a_no_op() {
        let root = tempfile::tempdir().unwrap();
        assert!(Sandbox::reclaim_orphans(&root.path().join("missing")).is_empty());
    }

    #[test]
    fn lifecycle_calls_on_a_sandbox_in_the_wrong_state_say_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let sb_dir = dir.path().join("mxc-kata-0a1b2c3d");
        std::fs::create_dir(&sb_dir).unwrap();
        let record = Record {
            id: "mxc-kata-0a1b2c3d".into(),
            hypervisor: KataHypervisor::Qemu,
            shim_binary: "/kata/shim".into(),
            config: "/kata/conf.toml".into(),
            rootfs: "/srv/rootfs".into(),
            rootfs_kind: RootfsKind::Directory,
            state: State::Provisioned,
            shim: None,
            ephemeral: false,
        };
        std::fs::write(
            sb_dir.join(RECORD_FILE),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        let mut sandbox = Sandbox::open(dir.path(), "0a1b2c3d").unwrap();
        let request = ExecutionRequest {
            script_code: "true".into(),
            ..Default::default()
        };
        assert!(matches!(
            sandbox.exec(&request, KillScope::Process).unwrap_err(),
            KataError::NotStarted(_)
        ));
        assert!(matches!(
            sandbox.stop().unwrap_err(),
            KataError::AlreadyStopped(_)
        ));
    }
}
