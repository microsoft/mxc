// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OCI runtime configuration for the sandbox and for the processes run in it.
//!
//! The bundle's `config.json` describes the container the shim creates: a root
//! filesystem, the default mounts, the filesystem policy as extra mounts, and a
//! keepalive init process. Each workload then runs as an exec process, so a
//! create-and-run request and the container lifecycle operations share one path.

use std::path::Path;

use serde_json::{json, Value};

use crate::kata_common::policy::FilesystemMapping;
use crate::mxc_common::default_env::resolve_env;
use crate::mxc_common::models::{sandbox_absolute_path, ExecutionRequest};

const OCI_VERSION: &str = "1.1.0";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEFAULT_TERM: &str = "xterm-256color";

/// The init process: a shell that blocks reading standard input, which the
/// backend holds open and never writes. It needs only `sh`, which the
/// workload's `sh -c` needs anyway, and does not depend on `sleep`.
pub(crate) const INIT_COMMAND: &[&str] = &["/bin/sh", "-c", "read -r _"];

/// containerd's default capability set for an unprivileged-by-default
/// container. The VM, not capability dropping, is the isolation boundary.
const CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

const MASKED_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
    "/proc/scsi",
];

const READONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

fn process(args: Vec<String>, env: Vec<String>, cwd: &str) -> Value {
    json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": args,
        "env": env,
        "cwd": cwd,
        "capabilities": {
            "bounding": CAPABILITIES,
            "effective": CAPABILITIES,
            "permitted": CAPABILITIES,
        },
        "noNewPrivileges": true,
    })
}

fn default_mounts() -> Vec<Value> {
    vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc",
               "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
               "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
        json!({"destination": "/dev/pts", "type": "devpts", "source": "devpts",
               "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620",
                           "gid=5"]}),
        json!({"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
               "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]}),
        json!({"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
               "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/sys", "type": "sysfs", "source": "sysfs",
               "options": ["nosuid", "noexec", "nodev", "ro"]}),
        json!({"destination": "/run", "type": "tmpfs", "source": "tmpfs",
               "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
    ]
}

/// The bundle's `config.json`.
///
/// The root filesystem is writable because the backend always supplies a
/// per-sandbox layer on top of the caller's read-only source. `netns` is the
/// sandbox's own, empty, network namespace.
pub(crate) fn bundle_spec(filesystem: &FilesystemMapping, netns: &Path) -> Value {
    let mut mounts = default_mounts();
    mounts.extend(filesystem.mounts.iter().cloned());

    let mut masked: Vec<String> = MASKED_PATHS.iter().map(|p| p.to_string()).collect();
    masked.extend(filesystem.masked_paths.iter().cloned());

    json!({
        "ociVersion": OCI_VERSION,
        "process": process(
            INIT_COMMAND.iter().map(|a| a.to_string()).collect(),
            vec![format!("PATH={DEFAULT_PATH}")],
            "/",
        ),
        "root": {"path": "rootfs", "readonly": false},
        "hostname": "mxc-kata",
        "mounts": mounts,
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
                {"type": "network", "path": netns},
            ],
            // The shim requires the section to exist even when empty. Only CPU
            // and memory limits would apply in the guest, and none is set.
            "resources": {},
            "maskedPaths": masked,
            "readonlyPaths": READONLY_PATHS,
        },
    })
}

/// The directory the workload starts in: the request's `process.cwd`,
/// normalized against the guest root, or `/`.
pub(crate) fn start_directory(request: &ExecutionRequest) -> String {
    if request.working_directory.trim().is_empty() {
        "/".to_string()
    } else {
        sandbox_absolute_path(&request.working_directory)
    }
}

/// The default environment: `PATH`, `TERM`, and `HOME` when a working
/// directory was named, the same block the other Linux backends supply.
fn default_env(request: &ExecutionRequest) -> Vec<(String, String)> {
    let mut entries = vec![("PATH".to_string(), DEFAULT_PATH.to_string())];
    if !request.working_directory.trim().is_empty() {
        entries.push(("HOME".to_string(), start_directory(request)));
    }
    entries.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
    entries
}

/// The OCI process for a workload: `process.commandLine` run by `/bin/sh -c`.
pub(crate) fn exec_process(request: &ExecutionRequest) -> Value {
    process(
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            request.script_code.clone(),
        ],
        resolve_env(request, || default_env(request)),
        &start_directory(request),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(script: &str) -> ExecutionRequest {
        ExecutionRequest {
            script_code: script.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_command_line_runs_under_a_shell_as_one_argument() {
        let process = exec_process(&request("echo 'a b'; exit 3"));
        assert_eq!(
            process["args"],
            json!(["/bin/sh", "-c", "echo 'a b'; exit 3"])
        );
        assert_eq!(process["terminal"], false);
        assert_eq!(process["user"], json!({"uid": 0, "gid": 0}));
        assert_eq!(process["noNewPrivileges"], true);
        assert_eq!(process["cwd"], "/");
    }

    #[test]
    fn an_omitted_environment_gets_the_default_block_without_home() {
        let env = exec_process(&request("true"))["env"].clone();
        assert_eq!(
            env,
            json!([
                format!("PATH={DEFAULT_PATH}"),
                format!("TERM={DEFAULT_TERM}")
            ])
        );
    }

    #[test]
    fn a_working_directory_is_normalized_and_becomes_home() {
        let mut r = request("pwd");
        r.working_directory = "/work/./sub/../out".to_string();
        let process = exec_process(&r);
        assert_eq!(process["cwd"], "/work/out");
        assert!(process["env"]
            .as_array()
            .unwrap()
            .contains(&json!("HOME=/work/out")));

        // A relative directory is anchored at the guest root, not the host cwd.
        r.working_directory = "work".to_string();
        assert_eq!(exec_process(&r)["cwd"], "/work");
    }

    #[test]
    fn the_caller_environment_replaces_the_default_unless_it_inherits() {
        let mut r = request("env");
        r.env = Some(vec!["A=1".to_string()]);
        assert_eq!(exec_process(&r)["env"], json!(["A=1"]));

        r.env = Some(vec![]);
        assert_eq!(exec_process(&r)["env"], json!([]));

        r.env = Some(vec!["PATH=/custom".to_string(), "A=1".to_string()]);
        r.inherit_default_env = true;
        assert_eq!(
            exec_process(&r)["env"],
            json!(["PATH=/custom", format!("TERM={DEFAULT_TERM}"), "A=1"])
        );
    }

    #[test]
    fn the_bundle_runs_a_keepalive_init_in_the_sandbox_network_namespace() {
        let spec = bundle_spec(
            &FilesystemMapping::default(),
            Path::new("/run/mxc-kata/a/netns"),
        );
        assert_eq!(spec["process"]["args"], json!(INIT_COMMAND));
        assert_eq!(spec["root"], json!({"path": "rootfs", "readonly": false}));
        let namespaces = spec["linux"]["namespaces"].as_array().unwrap();
        assert!(namespaces.contains(&json!({"type": "network", "path": "/run/mxc-kata/a/netns"})));
        for kind in ["pid", "ipc", "uts", "mount"] {
            assert!(namespaces.contains(&json!({"type": kind})), "{kind}");
        }
    }

    #[test]
    fn policy_mounts_follow_the_defaults_and_masked_files_join_the_standard_masks() {
        let fs = FilesystemMapping {
            mounts: vec![
                json!({"destination": "/work", "type": "bind", "source": "/work",
                                "options": ["rbind", "rw"]}),
            ],
            masked_paths: vec!["/work/.env".to_string()],
        };
        let spec = bundle_spec(&fs, Path::new("/n"));
        let mounts = spec["mounts"].as_array().unwrap();
        assert_eq!(mounts.first().unwrap()["destination"], "/proc");
        assert_eq!(mounts.last().unwrap()["destination"], "/work");
        let masked = spec["linux"]["maskedPaths"].as_array().unwrap();
        assert!(masked.contains(&json!("/proc/kcore")));
        assert!(masked.contains(&json!("/work/.env")));
    }
}
