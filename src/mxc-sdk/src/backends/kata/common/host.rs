// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Where the Kata install lives and whether this host can run it.
//!
//! Nothing here assumes an install prefix. The operator names it with
//! `MXC_KATA_ROOT`, or the shim is found on `PATH`.

use std::path::{Path, PathBuf};

use crate::mxc_common::models::KataHypervisor;

/// Prefix of a Kata install such as the static release tarball, which keeps
/// the shim under `runtime-rs/bin` and the configuration files under
/// `share/defaults`.
pub(crate) const ENV_ROOT: &str = "MXC_KATA_ROOT";
/// Hypervisor to use when the request does not name one.
pub(crate) const ENV_HYPERVISOR: &str = "MXC_KATA_HYPERVISOR";
/// Directory that holds sandbox state. Defaults to [`DEFAULT_STATE_DIR`].
pub(crate) const ENV_STATE_DIR: &str = "MXC_KATA_STATE_DIR";

const SHIM_BINARY: &str = "containerd-shim-kata-v2";
const DEFAULT_STATE_DIR: &str = "/run/mxc-kata";
/// Where a distribution package puts the runtime-rs configuration files, used
/// when no install root is named.
const DISTRO_CONFIG_DIR: &str = "/usr/share/defaults/kata-containers/runtime-rs";
/// The same directory relative to an install root.
const ROOT_CONFIG_DIR: &str = "share/defaults/kata-containers/runtime-rs";

/// Looks up an environment variable. A parameter so tests need no process-wide
/// environment.
pub(crate) type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment.
pub(crate) fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

/// The runtime-rs configuration file for a hypervisor in a standard install.
fn config_file_name(hypervisor: KataHypervisor) -> &'static str {
    match hypervisor {
        KataHypervisor::Qemu => "configuration-qemu-runtime-rs.toml",
        KataHypervisor::Clh => "configuration-clh-runtime-rs.toml",
        KataHypervisor::Firecracker => "configuration-rs-fc.toml",
        KataHypervisor::Dragonball => "configuration-dragonball.toml",
    }
}

/// The variable that names an explicit configuration file for a hypervisor.
/// Needed when the shipped file cannot be used as is, for example the
/// Firecracker file in Kata 4.3.1 fails the shim's timeout validation.
pub(crate) fn config_override_var(hypervisor: KataHypervisor) -> &'static str {
    match hypervisor {
        KataHypervisor::Qemu => "MXC_KATA_CONFIG_QEMU",
        KataHypervisor::Clh => "MXC_KATA_CONFIG_CLH",
        KataHypervisor::Firecracker => "MXC_KATA_CONFIG_FIRECRACKER",
        KataHypervisor::Dragonball => "MXC_KATA_CONFIG_DRAGONBALL",
    }
}

/// The hypervisor to run when the request names none.
pub(crate) fn default_hypervisor(env: EnvLookup<'_>) -> Result<KataHypervisor, String> {
    match env(ENV_HYPERVISOR) {
        Some(name) => name
            .parse()
            .map_err(|e| format!("{ENV_HYPERVISOR} is invalid: {e}")),
        None => Ok(KataHypervisor::Qemu),
    }
}

/// The shim binary and the configuration file for one hypervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Install {
    pub(crate) shim: PathBuf,
    pub(crate) config: PathBuf,
}

impl Install {
    /// The same install with relative paths resolved against `cwd`. The shim
    /// runs in the bundle directory, where a relative path no longer resolves.
    fn relative_to(self, cwd: &Path) -> Install {
        Install {
            shim: cwd.join(self.shim),
            config: cwd.join(self.config),
        }
    }
}

/// Finds the shim and the configuration file for `hypervisor`.
///
/// `is_file` and `path_dirs` are parameters so the search is testable without
/// touching the host.
pub(crate) fn locate_install(
    hypervisor: KataHypervisor,
    env: EnvLookup<'_>,
    is_file: &dyn Fn(&Path) -> bool,
    path_dirs: &[PathBuf],
) -> Result<Install, String> {
    let root = env(ENV_ROOT).map(PathBuf::from);
    let shim = locate_shim(root.as_deref(), is_file, path_dirs)?;
    let config = locate_config(hypervisor, root.as_deref(), env, is_file)?;
    Ok(Install { shim, config })
}

fn locate_shim(
    root: Option<&Path>,
    is_file: &dyn Fn(&Path) -> bool,
    path_dirs: &[PathBuf],
) -> Result<PathBuf, String> {
    let mut tried = Vec::new();
    let candidates: Vec<PathBuf> = match root {
        Some(root) => vec![
            root.join("runtime-rs/bin").join(SHIM_BINARY),
            root.join("bin").join(SHIM_BINARY),
        ],
        None => path_dirs.iter().map(|dir| dir.join(SHIM_BINARY)).collect(),
    };
    for candidate in candidates {
        if is_file(&candidate) {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    Err(match root {
        Some(root) => format!(
            "the Kata shim {SHIM_BINARY} was not found under {ENV_ROOT}={}; looked for {}",
            root.display(),
            tried.join(", ")
        ),
        None => format!(
            "the Kata shim {SHIM_BINARY} was not found on PATH; install Kata Containers \
             (runtime-rs) or set {ENV_ROOT} to its install prefix"
        ),
    })
}

fn locate_config(
    hypervisor: KataHypervisor,
    root: Option<&Path>,
    env: EnvLookup<'_>,
    is_file: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    let override_var = config_override_var(hypervisor);
    if let Some(path) = env(override_var) {
        let path = PathBuf::from(path);
        return if is_file(&path) {
            Ok(path)
        } else {
            Err(format!(
                "{override_var} names {}, which is not a file",
                path.display()
            ))
        };
    }
    let dir = match root {
        Some(root) => root.join(ROOT_CONFIG_DIR),
        None => PathBuf::from(DISTRO_CONFIG_DIR),
    };
    let path = dir.join(config_file_name(hypervisor));
    if is_file(&path) {
        Ok(path)
    } else {
        Err(format!(
            "the Kata configuration for {} was not found at {}; set {override_var} to a \
             configuration file, or {ENV_ROOT} to the install prefix",
            hypervisor.wire_name(),
            path.display()
        ))
    }
}

/// [`locate_install`] against the running host.
pub(crate) fn locate_installed(hypervisor: KataHypervisor) -> Result<Install, String> {
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    let install = locate_install(
        hypervisor,
        &process_env,
        &|path: &Path| path.is_file(),
        &path_dirs,
    )?;
    let cwd = std::env::current_dir()
        .map_err(|e| format!("cannot determine the current directory: {e}"))?;
    Ok(install.relative_to(&cwd))
}

/// The directory that holds sandbox state.
pub(crate) fn state_dir(env: EnvLookup<'_>) -> PathBuf {
    env(ENV_STATE_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
}

/// What the host must provide before a sandbox can start: root privileges for
/// the shim and mounts, and KVM for the hypervisor.
pub(crate) fn check_prerequisites() -> Result<(), String> {
    // SAFETY: `geteuid` has no preconditions and no side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "the Kata backend needs root: the Kata shim and the sandbox's mounts and network \
             namespace require it. Run as root, or with sudo"
                .to_string(),
        );
    }
    check_kvm(Path::new("/dev/kvm"))
}

fn check_kvm(device: &Path) -> Result<(), String> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "{} does not exist. The Kata backend needs hardware virtualization: enable it in \
             the firmware, and on a virtual machine enable nested virtualization",
            device.display()
        )),
        Err(e) => Err(format!(
            "cannot open {} for reading and writing ({e}); the Kata backend needs KVM access",
            device.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    fn files(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let set: HashSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |path| set.contains(path)
    }

    #[test]
    fn an_install_root_locates_the_runtime_rs_shim_and_the_shipped_config() {
        let install = locate_install(
            KataHypervisor::Clh,
            &env_of(&[(ENV_ROOT, "/kata")]),
            &files(&[
                "/kata/runtime-rs/bin/containerd-shim-kata-v2",
                "/kata/share/defaults/kata-containers/runtime-rs/configuration-clh-runtime-rs.toml",
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(
            install.shim,
            Path::new("/kata/runtime-rs/bin/containerd-shim-kata-v2")
        );
        assert_eq!(
            install.config,
            Path::new(
                "/kata/share/defaults/kata-containers/runtime-rs/configuration-clh-runtime-rs.toml"
            )
        );
    }

    #[test]
    fn relative_install_paths_are_resolved_against_the_caller_directory() {
        let install = locate_install(
            KataHypervisor::Qemu,
            &env_of(&[(ENV_ROOT, "kata")]),
            &files(&[
                "kata/runtime-rs/bin/containerd-shim-kata-v2",
                "kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml",
            ]),
            &[],
        )
        .unwrap()
        .relative_to(Path::new("/work"));
        assert_eq!(
            install.shim,
            Path::new("/work/kata/runtime-rs/bin/containerd-shim-kata-v2")
        );
        assert!(install.config.starts_with("/work/kata/"));

        let absolute = Install {
            shim: PathBuf::from("/opt/shim"),
            config: PathBuf::from("/etc/kata.toml"),
        }
        .relative_to(Path::new("/work"));
        assert_eq!(absolute.shim, Path::new("/opt/shim"));
        assert_eq!(absolute.config, Path::new("/etc/kata.toml"));
    }

    #[test]
    fn the_root_bin_directory_is_the_second_choice_for_the_shim() {
        let install = locate_install(
            KataHypervisor::Qemu,
            &env_of(&[(ENV_ROOT, "/kata")]),
            &files(&[
                "/kata/bin/containerd-shim-kata-v2",
                "/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml",
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(install.shim, Path::new("/kata/bin/containerd-shim-kata-v2"));
    }

    #[test]
    fn without_a_root_the_shim_comes_from_path_and_config_from_the_distro_directory() {
        let install = locate_install(
            KataHypervisor::Dragonball,
            &env_of(&[]),
            &files(&[
                "/usr/local/bin/containerd-shim-kata-v2",
                "/usr/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml",
            ]),
            &[PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")],
        )
        .unwrap();
        assert_eq!(
            install.shim,
            Path::new("/usr/local/bin/containerd-shim-kata-v2")
        );
    }

    #[test]
    fn a_per_hypervisor_override_wins_over_the_shipped_config() {
        let install = locate_install(
            KataHypervisor::Firecracker,
            &env_of(&[
                (ENV_ROOT, "/kata"),
                ("MXC_KATA_CONFIG_FIRECRACKER", "/etc/mxc/fc.toml"),
            ]),
            &files(&[
                "/kata/runtime-rs/bin/containerd-shim-kata-v2",
                "/kata/share/defaults/kata-containers/runtime-rs/configuration-rs-fc.toml",
                "/etc/mxc/fc.toml",
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(install.config, Path::new("/etc/mxc/fc.toml"));
    }

    #[test]
    fn a_missing_override_file_is_an_error_not_a_fallback() {
        let err = locate_install(
            KataHypervisor::Firecracker,
            &env_of(&[
                (ENV_ROOT, "/kata"),
                ("MXC_KATA_CONFIG_FIRECRACKER", "/etc/mxc/gone.toml"),
            ]),
            &files(&["/kata/runtime-rs/bin/containerd-shim-kata-v2"]),
            &[],
        )
        .unwrap_err();
        assert!(err.contains("MXC_KATA_CONFIG_FIRECRACKER"), "{err}");
        assert!(err.contains("/etc/mxc/gone.toml"), "{err}");
    }

    #[test]
    fn a_missing_shim_names_every_place_that_was_searched() {
        let err = locate_install(
            KataHypervisor::Qemu,
            &env_of(&[(ENV_ROOT, "/kata")]),
            &files(&[]),
            &[],
        )
        .unwrap_err();
        assert!(
            err.contains("/kata/runtime-rs/bin/containerd-shim-kata-v2"),
            "{err}"
        );
        assert!(err.contains("/kata/bin/containerd-shim-kata-v2"), "{err}");

        let err = locate_install(
            KataHypervisor::Qemu,
            &env_of(&[]),
            &files(&[]),
            &[PathBuf::from("/usr/bin")],
        )
        .unwrap_err();
        assert!(err.contains("PATH") && err.contains(ENV_ROOT), "{err}");
    }

    #[test]
    fn a_missing_config_says_how_to_point_at_one() {
        let err = locate_install(
            KataHypervisor::Clh,
            &env_of(&[(ENV_ROOT, "/kata")]),
            &files(&["/kata/runtime-rs/bin/containerd-shim-kata-v2"]),
            &[],
        )
        .unwrap_err();
        assert!(err.contains("MXC_KATA_CONFIG_CLH"), "{err}");
        assert!(err.contains("configuration-clh-runtime-rs.toml"), "{err}");
    }

    #[test]
    fn each_hypervisor_has_its_own_override_variable_and_config_name() {
        let vars: HashSet<_> = KataHypervisor::ALL.map(config_override_var).into();
        let names: HashSet<_> = KataHypervisor::ALL.map(config_file_name).into();
        assert_eq!(vars.len(), 4);
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn the_default_hypervisor_is_qemu_unless_the_host_says_otherwise() {
        assert_eq!(default_hypervisor(&env_of(&[])), Ok(KataHypervisor::Qemu));
        assert_eq!(
            default_hypervisor(&env_of(&[(ENV_HYPERVISOR, "cloud-hypervisor")])),
            Ok(KataHypervisor::Clh)
        );
        let err = default_hypervisor(&env_of(&[(ENV_HYPERVISOR, "xen")])).unwrap_err();
        assert!(err.contains(ENV_HYPERVISOR) && err.contains("xen"), "{err}");
    }

    #[test]
    fn the_state_directory_defaults_and_can_be_moved() {
        assert_eq!(state_dir(&env_of(&[])), Path::new("/run/mxc-kata"));
        assert_eq!(
            state_dir(&env_of(&[(ENV_STATE_DIR, "/var/lib/mxc")])),
            Path::new("/var/lib/mxc")
        );
    }

    #[test]
    fn a_missing_kvm_device_says_how_to_get_one() {
        let err = check_kvm(Path::new("/nonexistent/kvm")).unwrap_err();
        assert!(err.contains("virtualization"), "{err}");
    }
}
