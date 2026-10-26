// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Seek};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};

use crate::mxc_common::filesystem_resolve::FsIntent;
use crate::mxc_common::filesystem_symlink::resolve_through_symlinks;
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::ContainerPolicy;

use super::bwrap_command::{
    path_intent, path_is_denied, PolicyMount, BASELINE_RO_BIND_PATHS, COMPAT_RUN_LINK,
    COMPAT_RUN_TARGET, RESOLVER_DIRS, WSL_RESOLV_CONF,
};
use super::proxy_network::above_stdio;

// Linux path_resolution(7) limits a lookup to 40 symbolic links.
const MAX_SYMLINKS: usize = 40;

#[derive(Debug)]
pub(crate) struct ResolverFile {
    snapshot: Option<File>,
    destination: String,
    layout_args: Vec<String>,
    links: Vec<SandboxLink>,
}

#[derive(Debug)]
struct SandboxLink {
    path: PathBuf,
    target: PathBuf,
    host_symlink: bool,
}

struct ResolverLayout {
    destination: PathBuf,
    args: Vec<String>,
    links: Vec<SandboxLink>,
}

impl ResolverFile {
    pub(crate) fn for_host(policy: &ContainerPolicy, logger: &mut Logger) -> Option<Self> {
        match Self::from_resolver(Path::new("/etc/resolv.conf"), policy, |target| {
            implicit_source_paths(target)
                .iter()
                .any(|source| !path_is_denied(policy, source))
        }) {
            Ok(resolver) => resolver,
            Err(error) => {
                logger.warning_line(&format!(
                    "WARNING: Bubblewrap: {error}. Resolver runtime directories remain hidden; \
                     DNS may be unavailable inside the sandbox."
                ));
                None
            }
        }
    }

    fn from_resolver(
        path: &Path,
        policy: &ContainerPolicy,
        is_visible: impl FnOnce(&Path) -> bool,
    ) -> Result<Option<Self>, String> {
        let destination = match fs::canonicalize(path) {
            Ok(destination) => destination,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!("could not resolve {}: {error}", path.display()));
            }
        };
        let supplied = matches!(
            path_intent(policy, &destination),
            Some(FsIntent::ReadOnly | FsIntent::ReadWrite)
        );
        if path_is_denied(policy, &destination) || (!is_visible(&destination) && !supplied) {
            return Ok(None);
        }

        let layout = resolver_layout(path)?;
        if layout.destination != destination {
            return Err(format!(
                "{} changed while preparing its resolver mount",
                path.display()
            ));
        }

        let in_baseline = BASELINE_RO_BIND_PATHS.iter().any(|root| {
            resolve_through_symlinks(Path::new(root))
                .is_some_and(|root| destination.starts_with(root))
        });
        let snapshot = if supplied || in_baseline {
            None
        } else {
            Some(snapshot_file(&destination)?)
        };
        Ok(Some(Self {
            snapshot,
            destination: path_text(&destination)?.to_owned(),
            layout_args: layout.args,
            links: layout.links,
        }))
    }

    pub(crate) fn mount_args(
        &self,
        mounts: &mut [PolicyMount],
        denied_files: &HashSet<String>,
    ) -> Result<Vec<String>, String> {
        self.translate_policy_mounts(mounts)?;
        let Some(file) = &self.snapshot else {
            return Ok(self.layout_args.clone());
        };
        let destination = sandbox_mount_path(&self.destination);
        let parent = Path::new(&destination)
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_string_lossy()
            .into_owned();
        let mut args = vec!["--tmpfs".into(), parent.clone()];
        args.extend(self.layout_args.iter().cloned());

        // A linked sandbox file permits later policy and DNS-pin mounts over it.
        args.extend([
            "--file".into(),
            file.as_raw_fd().to_string(),
            destination.clone(),
        ]);
        for (index, mount) in mounts.iter().enumerate() {
            let target = Path::new(&mount.destination);
            if target == Path::new(&parent)
                || target == Path::new(&destination)
                || !target.starts_with(&parent)
                || mounts[..index]
                    .iter()
                    .any(|previous| target.starts_with(&previous.destination))
            {
                continue;
            }
            let is_dir = match mount.intent {
                FsIntent::Denied => !denied_files.contains(&mount.source),
                _ => fs::metadata(&mount.source)
                    .map_err(|error| {
                        format!("could not inspect policy path {}: {error}", mount.source)
                    })?
                    .is_dir(),
            };
            if is_dir {
                args.extend(["--dir".into(), mount.destination.clone()]);
            } else {
                args.extend([
                    "--ro-bind".into(),
                    "/dev/null".into(),
                    mount.destination.clone(),
                ]);
            }
        }
        args.extend(["--remount-ro".into(), parent]);
        Ok(args)
    }

    fn translate_policy_mounts(&self, mounts: &mut [PolicyMount]) -> Result<(), String> {
        let mut active = vec![true; self.links.len()];
        for mount in mounts {
            let mut destination = PathBuf::from(&mount.destination);
            let mut followed = 0;
            while let Some(link) = self
                .links
                .iter()
                .enumerate()
                .filter(|(index, link)| active[*index] && destination.starts_with(&link.path))
                .max_by_key(|(_, link)| link.path.components().count())
                .map(|(_, link)| link)
            {
                followed += 1;
                if followed > MAX_SYMLINKS {
                    return Err(format!(
                        "too many sandbox resolver symlinks in {}",
                        mount.source
                    ));
                }
                destination = link
                    .target
                    .join(destination.strip_prefix(&link.path).map_err(|error| {
                        format!("could not translate policy path {}: {error}", mount.source)
                    })?);
            }
            mount.destination = path_text(&destination)?.to_owned();
            for (index, link) in self.links.iter().enumerate() {
                if link.path == destination {
                    active[index] = false;
                } else if link.path.starts_with(&destination) {
                    active[index] = mount.intent != FsIntent::Denied && link.host_symlink;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn snapshot_fd(&self) -> Option<RawFd> {
        self.snapshot.as_ref().map(AsRawFd::as_raw_fd)
    }
}

fn snapshot_file(source: &Path) -> Result<File, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(source)
        .map_err(|error| format!("could not open {}: {error}", source.display()))?;
    if !file
        .metadata()
        .map_err(|error| format!("could not inspect {}: {error}", source.display()))?
        .is_file()
    {
        return Err(format!(
            "{} is not a regular resolver file",
            source.display()
        ));
    }
    let fd = memfd_create(
        c"mxc-resolver",
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING,
    )
    .map_err(|error| format!("could not create a resolver snapshot: {error}"))?;
    let mut snapshot = File::from(fd);
    std::io::copy(&mut file, &mut snapshot)
        .map_err(|error| format!("could not copy {}: {error}", source.display()))?;
    snapshot
        .rewind()
        .map_err(|error| format!("could not rewind the resolver snapshot: {error}"))?;
    fcntl(
        snapshot.as_raw_fd(),
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SEAL
                | SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK,
        ),
    )
    .map_err(|error| format!("could not seal the resolver snapshot: {error}"))?;
    above_stdio(snapshot)
        .map_err(|error| format!("could not move the resolver descriptor: {error}"))
}

fn implicit_source_paths(target: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = BASELINE_RO_BIND_PATHS
        .iter()
        .chain(RESOLVER_DIRS)
        .filter_map(|root| {
            let resolved = resolve_through_symlinks(Path::new(root))?;
            target
                .strip_prefix(resolved)
                .ok()
                .map(|suffix| Path::new(root).join(suffix))
        })
        .collect();
    if resolve_through_symlinks(Path::new(WSL_RESOLV_CONF)).is_some_and(|file| target == file) {
        paths.push(PathBuf::from(WSL_RESOLV_CONF));
    }
    paths
}

pub(crate) fn resolver_target_is_denied(policy: &ContainerPolicy, target: &Path) -> bool {
    if let Some(intent) = path_intent(policy, target) {
        return intent == FsIntent::Denied;
    }
    let sources = implicit_source_paths(target);
    !sources.is_empty() && sources.iter().all(|source| path_is_denied(policy, source))
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("{} is not a UTF-8 resolver path", path.display()))
}

fn resolver_layout(path: &Path) -> Result<ResolverLayout, String> {
    let mut pending: VecDeque<_> = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut current = PathBuf::new();
    let mut args = Vec::new();
    let host_symlink = match fs::symlink_metadata(COMPAT_RUN_LINK) {
        Ok(metadata) => metadata.file_type().is_symlink(),
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => return Err(format!("could not inspect {COMPAT_RUN_LINK}: {error}")),
    };
    let mut links = vec![SandboxLink {
        path: PathBuf::from(COMPAT_RUN_LINK),
        target: PathBuf::from(COMPAT_RUN_TARGET),
        host_symlink,
    }];
    let mut followed = 0;
    while let Some(component) = pending.pop_front() {
        if component == ".." {
            current.pop();
            continue;
        }
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("could not inspect {}: {error}", current.display()))?;
        let needs_layout = current != Path::new("/")
            && current != Path::new(COMPAT_RUN_LINK)
            && !BASELINE_RO_BIND_PATHS
                .iter()
                .any(|root| current.starts_with(root));
        if needs_layout && metadata.is_dir() {
            args.extend(["--dir".into(), sandbox_mount_path(path_text(&current)?)]);
        }
        if !metadata.file_type().is_symlink() {
            continue;
        }
        followed += 1;
        if followed > MAX_SYMLINKS {
            return Err(format!("too many resolver symlinks in {}", path.display()));
        }
        let target = fs::read_link(&current)
            .map_err(|error| format!("could not read {}: {error}", current.display()))?;
        if needs_layout {
            let resolved = fs::canonicalize(&current)
                .map_err(|error| format!("could not resolve {}: {error}", current.display()))?;
            let link = sandbox_mount_path(path_text(&current)?);
            let destination = sandbox_mount_path(path_text(&resolved)?);
            if link != destination {
                links.push(SandboxLink {
                    path: PathBuf::from(&link),
                    target: PathBuf::from(&destination),
                    host_symlink: true,
                });
                args.extend(["--symlink".into(), destination, link]);
            }
        }
        current.pop();
        for component in target.components().rev() {
            pending.push_front(component.as_os_str().to_owned());
        }
    }
    Ok(ResolverLayout {
        destination: current,
        args,
        links,
    })
}

// Bubblewrap cannot create mount points through the sandbox's /var/run symlink.
pub(crate) fn sandbox_mount_path(host_path: &str) -> String {
    host_path
        .strip_prefix(COMPAT_RUN_LINK)
        .filter(|rest| rest.starts_with('/'))
        .map(|rest| format!("{COMPAT_RUN_TARGET}{rest}"))
        .unwrap_or_else(|| host_path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    #[test]
    fn preserves_relative_links_and_symlinked_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("run/real/sub")).unwrap();
        let file = root.join("run/real/resolv.conf");
        fs::write(&file, "nameserver 192.0.2.53\n").unwrap();
        symlink("real/sub", root.join("run/link")).unwrap();
        symlink("../run/link/../resolv.conf", root.join("etc/resolv.conf")).unwrap();
        let _socket = UnixListener::bind(root.join("run/real/io.systemd.Resolve")).unwrap();

        let resolver = ResolverFile::from_resolver(
            &root.join("etc/resolv.conf"),
            &ContainerPolicy::default(),
            |_| true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(Path::new(&resolver.destination), file);
        assert!(resolver.layout_args.windows(3).any(|args| {
            args[0] == "--symlink"
                && Path::new(&args[1]) == root.join("run/real/sub")
                && Path::new(&args[2]) == root.join("run/link")
        }));
        assert!(resolver.layout_args.windows(2).any(|args| {
            args[0] == "--dir" && Path::new(&args[1]) == root.join("run/real/sub")
        }));
        let args = resolver.mount_args(&mut [], &HashSet::new()).unwrap();
        assert!(args.windows(3).any(|args| args
            == [
                "--file",
                &resolver.snapshot_fd().unwrap().to_string(),
                path_text(&file).unwrap(),
            ]));
        assert!(!args.iter().any(|arg| arg.contains("io.systemd.Resolve")));
    }

    #[test]
    fn retains_the_regular_file_when_its_path_becomes_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.53\n").unwrap();
        let mut resolver =
            ResolverFile::from_resolver(&path, &ContainerPolicy::default(), |_| true)
                .unwrap()
                .unwrap();
        fs::remove_file(&path).unwrap();
        let _socket = UnixListener::bind(&path).unwrap();

        let snapshot = resolver.snapshot.as_mut().unwrap();
        let mut contents = String::new();
        snapshot.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "nameserver 192.0.2.53\n");
        assert!(snapshot.write_all(b"changed").is_err());
        assert!(snapshot.set_len(0).is_err());
        assert!(snapshot.as_raw_fd() > libc::STDERR_FILENO);
        assert!(resolver
            .mount_args(&mut [], &HashSet::new())
            .unwrap()
            .iter()
            .all(|arg| arg != "--ro-bind"));
    }

    #[test]
    fn rejects_nonregular_sources_without_blocking_on_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let socket = dir.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        for path in [dir.path(), fifo.as_path(), socket.as_path()] {
            assert!(
                ResolverFile::from_resolver(path, &ContainerPolicy::default(), |_| true).is_err(),
                "accepted {}",
                path.display()
            );
        }
    }

    #[test]
    fn missing_resolvers_are_optional_but_link_loops_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        assert!(
            ResolverFile::from_resolver(&path, &ContainerPolicy::default(), |_| true)
                .unwrap()
                .is_none()
        );
        symlink("resolv.conf", &path).unwrap();
        assert!(ResolverFile::from_resolver(&path, &ContainerPolicy::default(), |_| true).is_err());
        assert!(implicit_source_paths(&path).is_empty());
    }

    #[test]
    fn does_not_copy_an_ungranted_resolver_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.53\n").unwrap();
        assert!(
            ResolverFile::from_resolver(&path, &ContainerPolicy::default(), |target| {
                !implicit_source_paths(target).is_empty()
            })
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn explicitly_granted_targets_keep_links_without_an_automatic_copy() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = root.join("private.conf");
        let intermediate = root.join("intermediate.conf");
        let resolver = root.join("resolv.conf");
        fs::write(&target, "nameserver 192.0.2.53\n").unwrap();
        symlink(&target, &intermediate).unwrap();
        symlink(&intermediate, &resolver).unwrap();
        let policy = ContainerPolicy {
            readonly_paths: vec![target.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let mount = ResolverFile::from_resolver(&resolver, &policy, |_| false)
            .unwrap()
            .unwrap();
        assert!(mount.snapshot.is_none());
        assert!(mount
            .mount_args(&mut [], &HashSet::new())
            .unwrap()
            .windows(3)
            .any(|args| { args[0] == "--symlink" && Path::new(&args[2]) == intermediate }));
    }

    #[test]
    fn policy_translation_respects_masks_and_restored_ancestor_grants() {
        let resolver = ResolverFile {
            snapshot: None,
            destination: "/var/lib/resolvconf/resolv.conf".into(),
            layout_args: Vec::new(),
            links: vec![SandboxLink {
                path: PathBuf::from("/run/systemd/resolve"),
                target: PathBuf::from("/var/lib/resolvconf"),
                host_symlink: true,
            }],
        };
        let file = "/run/systemd/resolve/resolv.conf";
        for (denied, parent, expected) in [
            (false, None, "/var/lib/resolvconf/resolv.conf"),
            (true, None, file),
            (
                true,
                Some("/run/systemd"),
                "/var/lib/resolvconf/resolv.conf",
            ),
            (true, Some("/run/systemd/resolve"), file),
        ] {
            let mut policy = ContainerPolicy {
                readonly_paths: vec![file.into()],
                ..Default::default()
            };
            if denied {
                policy.denied_paths.push("/run".into());
            }
            if let Some(parent) = parent {
                policy.readwrite_paths.push(parent.into());
            }
            let original = super::super::bwrap_command::policy_mounts(&policy);
            let mut translated = original.clone();
            resolver.translate_policy_mounts(&mut translated).unwrap();
            assert!(
                original.iter().zip(&translated).all(|(before, after)| {
                    before.source == after.source && before.intent == after.intent
                }),
                "translation must preserve policy order, sources, and access modes"
            );
            assert_eq!(
                translated
                    .iter()
                    .find(|mount| mount.source == file)
                    .unwrap()
                    .destination,
                expected,
                "denied={denied}, parent={parent:?}"
            );
        }
    }
}
