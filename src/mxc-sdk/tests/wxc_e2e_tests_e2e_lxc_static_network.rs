// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use std::fs;
use std::process::Command;
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value, LXC_ARCH};

#[test]
fn existing_containers_keep_their_static_network_configuration() {
    if !has_platform_exec() || !has_lxc_host() {
        return;
    }

    for (family, ipv4) in [("dual", true), ("ipv6", false)] {
        let name = format!("lxc-static-{family}-{}", std::process::id());
        let bridge = format!("mx{family}{}", std::process::id());
        let outcome = std::panic::catch_unwind(|| {
            let created = Command::new("lxc-create")
                .args([
                    "-n", &name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a",
                    LXC_ARCH,
                ])
                .output()
                .expect("create existing static-network container");
            assert!(
                created.status.success(),
                "static-network container creation failed: {created:?}"
            );
            let created = Command::new("ip")
                .args(["link", "add", &bridge, "type", "bridge"])
                .output()
                .expect("create custom bridge");
            assert!(
                created.status.success(),
                "custom bridge creation failed: {created:?}"
            );
            let activated = Command::new("ip")
                .args(["link", "set", &bridge, "up"])
                .output()
                .expect("activate custom bridge");
            assert!(
                activated.status.success(),
                "custom bridge activation failed: {activated:?}"
            );

            let definition = format!("/var/lib/lxc/{name}/config");
            let mut contents = fs::read_to_string(&definition).expect("read existing definition");
            contents.push_str(&format!(
                "\nlxc.net.0.link = {bridge}\n\
                 lxc.net.0.name = eth0\n\
                 lxc.net.0.ipv4.address =\n\
                 lxc.net.0.ipv4.gateway =\n\
                 lxc.net.0.ipv6.address =\n\
                 lxc.net.0.ipv6.gateway =\n\
                 lxc.net.0.ipv6.address = 2001:db8:1688::2/64\n\
                 lxc.net.0.ipv6.gateway = 2001:db8:1688::1\n"
            ));
            if ipv4 {
                contents.push_str(
                    "lxc.net.0.ipv4.address = 192.0.2.2/24\n\
                     lxc.net.0.ipv4.address = 192.0.2.3/24\n\
                     lxc.net.0.ipv4.gateway = 192.0.2.1\n",
                );
            }
            fs::write(&definition, contents).expect("configure existing static network");
            fs::write(
                format!("/var/lib/lxc/{name}/rootfs/etc/network/interfaces"),
                "auto lo\niface lo inet loopback\n",
            )
            .expect("leave static eth0 configuration to LXC instead of guest DHCP");
            let resolver = format!("/var/lib/lxc/{name}/rootfs/etc/resolv.conf");
            fs::remove_file(&resolver).expect("remove original resolver or symlink");
            fs::write(&resolver, "nameserver 2001:db8:1688::53\n").expect("write static resolver");
            let config = json!({
                "version": "0.9.0-alpha",
                "containerId": name,
                "containment": "lxc",
                "process": {
                    "commandLine": "sh -c 'ip address show dev eth0 && ip -4 route show default && ip -6 route show default && cat /etc/resolv.conf'"
                },
                "lifecycle": { "destroyOnExit": false },
                "lxc": { "distribution": "alpine", "release": "3.23" },
                "network": { "egress": { "default": "allow" } }
            });
            let result =
                run_platform_config_value("existing LXC static network", &config, &[], None);
            let output = result.combined_output();

            let mut expected = vec![
                "inet6 2001:db8:1688::2/64",
                "default via 2001:db8:1688::1",
                "nameserver 2001:db8:1688::53",
            ];
            if ipv4 {
                expected.extend([
                    "inet 192.0.2.2/24",
                    "inet 192.0.2.3/24",
                    "default via 192.0.2.1",
                ]);
            }
            assert!(
                result.code == Some(0)
                    && expected.iter().all(|value| output.contains(value))
                    && (ipv4 || !output.contains("inet ")),
                "{family} static networking lost its configured addresses, gateways, or resolver\n{output}"
            );
        });
        let destroyed = Command::new("lxc-destroy")
            .args(["-n", &name, "-f"])
            .output();
        let removed = Command::new("ip")
            .args(["link", "delete", &bridge])
            .output();
        outcome.expect("existing static-network fixture failed");
        assert!(
            destroyed
                .as_ref()
                .is_ok_and(|output| output.status.success())
                && removed.as_ref().is_ok_and(|output| output.status.success()),
            "static-network fixture cleanup failed: container={destroyed:?}, bridge={removed:?}"
        );
    }
}

#[test]
fn ctrl_c_during_address_acquisition_removes_temporary_host_networking() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use nix::errno::Errno;
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::signal::{kill, killpg, Signal};
    use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
    use nix::unistd::{getpgid, Pid};
    use serde_json::Value;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    if !has_platform_exec() || !has_lxc_host() {
        return;
    }

    let fixture = tempfile::Builder::new()
        .prefix("lxc-cancel-address-")
        .tempdir_in(".")
        .expect("create address acquisition fixture");
    let directory = fixture.path().canonicalize().expect("resolve fixture path");
    let name = directory
        .file_name()
        .expect("fixture directory name")
        .to_str()
        .expect("fixture directory name is UTF-8");
    let definition = format!("/var/lib/lxc/{name}/config");
    if std::path::Path::new(&definition).exists() {
        panic!("address acquisition fixture would overwrite an existing container: {name}");
    }
    let entered = directory.join("entered");
    let read_links = || -> Result<Vec<Value>, String> {
        let output = Command::new("ip")
            .args(["-j", "-d", "link", "show"])
            .output()
            .map_err(|error| format!("read host links: {error}"))?;
        if !output.status.success() {
            return Err(format!("host link observation failed: {output:?}"));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("decode host links: {error}; output={output:?}"))
    };
    let same_link = |left: &Value, right: &Value| left["ifindex"] == right["ifindex"];
    let read_process = |pid: Pid| -> Result<Option<(Pid, u64)>, String> {
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("observe helper process {pid}: {error}")),
        };

        // After the command field, PPID and start time are fields 4 and 22.
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .ok_or_else(|| format!("unreadable process stat for {pid}: {stat}"))?
            .1
            .split_whitespace()
            .collect();
        let parent = fields.get(1).and_then(|value| value.parse::<i32>().ok());
        let started = fields.get(19).and_then(|value| value.parse::<u64>().ok());
        match (parent, started) {
            (Some(parent), Some(started)) => Ok(Some((Pid::from_raw(parent), started))),
            _ => Err(format!("unreadable process identity for {pid}: {stat}")),
        }
    };
    let signal_pidfd = |pidfd: &OwnedFd, signal: i32| -> Result<(), Errno> {
        // SAFETY: The descriptor is borrowed, and null siginfo with zero flags uses kernel signal data.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result < 0 {
            Err(Errno::last())
        } else {
            Ok(())
        }
    };

    // Keep the executor PID reserved until fixture teardown has sent its signals.
    let wait_options = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    let before = read_links().expect("observe host links before address acquisition");
    let mut temporary_links = Vec::new();
    let mut owned_helpers = Vec::new();
    let mut executor: Option<Child> = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let created = Command::new("/usr/bin/timeout")
            .args(["--kill-after=1", "120", "lxc-create"])
            .args([
                "-n", name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a", LXC_ARCH,
            ])
            .output()
            .expect("create addressless container");
        if !created.status.success() {
            panic!("addressless container fixture creation failed: {created:?}");
        }
        let located = Command::new("sh")
            .args(["-c", "command -v busybox"])
            .output()
            .expect("locate host BusyBox");
        if !located.status.success() {
            panic!("the DHCP fixture requires host BusyBox: {located:?}");
        }
        let busybox = fs::canonicalize(String::from_utf8_lossy(&located.stdout).trim())
            .expect("resolve host BusyBox");
        fs::create_dir(directory.join("original")).expect("create original BusyBox directory");
        fs::copy(&busybox, directory.join("original/busybox"))
            .expect("keep BusyBox available for non-DHCP applets");
        let gate = directory.join("busybox-gate");

        // Hold the DHCP client after its interface has been created.
        fs::write(
            &gate,
            r#"#!/bin/sh
if [ "$1" != udhcpc ]; then
    exec "$MXC_E2E_FIXTURE/original/busybox" "$@"
fi
previous=
interface=
for argument do
    if [ "$previous" = -i ] || [ "$previous" = --interface ]; then
        interface=$argument
        break
    fi
    previous=$argument
done
if [ -z "$interface" ]; then
    echo "DHCP fixture did not receive an interface" >&2
    exit 97
fi
ip -j -d link show dev "$interface" > "$MXC_E2E_FIXTURE/acquiring-link" || exit 98
printf '%s\n' "$$" > "$MXC_E2E_FIXTURE/entered"
exec /bin/sleep 300
"#,
        )
        .expect("write blocking BusyBox fixture");
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o700))
            .expect("make BusyBox fixture executable");
        let config = json!({
            "version": "0.9.0-alpha",
            "containerId": name,
            "containment": "lxc",
            "process": { "commandLine": "true" },
            "lifecycle": { "destroyOnExit": false },
            "lxc": { "distribution": "alpine", "release": "3.23" },
            "network": { "egress": { "default": "allow" } }
        });
        let output_path = directory.join("executor-output");
        let output = fs::File::create(&output_path).expect("capture executor output");
        let mut command = Command::new(wxc_e2e_tests::find_platform_exec().expect("find lxc-exec"));
        command
            .arg("--config-base64")
            .arg(STANDARD.encode(config.to_string()))
            .env("MXC_E2E_FIXTURE", &directory)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(output.try_clone().expect("capture executor stdout"))
            .stderr(output);

        // SAFETY: Only namespace and mount syscalls run in the child before exec.
        unsafe {
            command.pre_exec(move || {
                unshare(CloneFlags::CLONE_NEWNS).map_err(std::io::Error::from)?;
                mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                    None::<&str>,
                )
                .map_err(std::io::Error::from)?;
                mount(
                    Some(gate.as_path()),
                    busybox.as_path(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .map_err(std::io::Error::from)
            });
        }
        let started = Instant::now();
        executor = Some(command.spawn().expect("start gated executor"));
        let child = executor.as_mut().expect("executor was started");
        let group = Pid::from_raw(child.id() as i32);
        let client_pid = loop {
            if let Some(pid) = fs::read_to_string(&entered)
                .ok()
                .and_then(|pid| pid.trim().parse::<i32>().ok())
            {
                break Pid::from_raw(pid);
            }
            let status = waitid(Id::Pid(group), wait_options)
                .expect("observe executor before DHCP without reaping");
            if status != WaitStatus::StillAlive {
                panic!(
                    "executor exited before reaching address acquisition: {status:?}\n{}",
                    fs::read_to_string(&output_path).expect("read executor diagnostics")
                );
            }
            if started.elapsed() >= Duration::from_secs(30) {
                panic!(
                    "executor did not reach the DHCP gate within 30 seconds\n{}",
                    fs::read_to_string(&output_path).expect("read executor diagnostics")
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut ancestor = client_pid;
        let mut helpers = Vec::new();
        while ancestor != group {
            if ancestor.as_raw() <= 1 {
                panic!("gated DHCP client {client_pid} is not descended from executor {group}");
            }

            // SAFETY: A successful pidfd_open returns a new descriptor owned by this fixture.
            let pidfd = unsafe {
                let fd = libc::syscall(libc::SYS_pidfd_open, ancestor.as_raw(), 0u32);
                if fd < 0 {
                    panic!("pin DHCP helper {ancestor}: {}", Errno::last());
                }
                OwnedFd::from_raw_fd(fd as i32)
            };
            let (parent, started) = read_process(ancestor)
                .expect("observe gated DHCP client ancestry")
                .expect("gated DHCP client ancestry must still be alive");
            helpers.push((ancestor, started, pidfd));
            ancestor = parent;
        }
        let mut parent = group;
        for (pid, started, pidfd) in helpers.iter().rev() {
            let (current_parent, current_start) = read_process(*pid)
                .expect("verify pinned DHCP helper ancestry")
                .expect("pinned DHCP helper must still be alive");
            if current_parent != parent || current_start != *started {
                panic!("DHCP helper {pid} changed identity or ancestry while pinning ownership");
            }
            signal_pidfd(pidfd, 0).expect("verify pidfd still refers to the observed DHCP helper");
            parent = *pid;
        }
        owned_helpers = helpers;
        let client_links: Vec<Value> = serde_json::from_slice(
            &fs::read(directory.join("acquiring-link")).expect("read DHCP interface observation"),
        )
        .expect("decode DHCP interface observation");
        let client_link = client_links.first().expect("DHCP interface exists");
        let during = read_links().expect("observe host links during address acquisition");
        temporary_links = during
            .iter()
            .filter(|link| {
                !before.iter().any(|original| same_link(original, link))
                    && ((same_link(client_link, link) && client_link["address"] == link["address"])
                        || (!client_link["link_index"].is_null()
                            && link["ifindex"] == client_link["link_index"]
                            && link["link_index"] == client_link["ifindex"]))
            })
            .cloned()
            .collect();
        if temporary_links.is_empty() {
            panic!(
                "DHCP gate was reached without newly created host networking; \
                 client={client_link}, before={before:?}, during={during:?}"
            );
        }
        kill(group, Signal::SIGINT).expect("send Ctrl+C to executor during address acquisition");
        let status = loop {
            match waitid(Id::Pid(group), wait_options)
                .expect("observe cancellation exit without reaping")
            {
                status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break Some(status),
                WaitStatus::StillAlive => {}
                status => panic!("unexpected executor state during cancellation: {status:?}"),
            }

            // Finish before the documented one-minute startup timeout can cancel the run.
            if started.elapsed() >= Duration::from_secs(45) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let remaining_group_helpers: Vec<_> = fs::read_dir("/proc")
            .expect("observe executor group at cancellation exit")
            .map(|entry| entry.expect("read process directory entry").file_name())
            .filter_map(|name| name.to_str()?.parse::<i32>().ok())
            .map(Pid::from_raw)
            .filter(|pid| *pid != group)
            .filter(|pid| match getpgid(Some(*pid)) {
                Ok(process_group) => process_group == group,
                Err(Errno::ESRCH) => false,
                Err(error) => panic!("observe executor group member {pid}: {error}"),
            })
            .collect();
        let helpers_reaped = remaining_group_helpers.is_empty()
            && owned_helpers
                .iter()
                .all(|(_, _, pidfd)| match signal_pidfd(pidfd, 0) {
                    Err(Errno::ESRCH) => true,
                    Ok(()) => false,
                    Err(error) => panic!("observe pinned DHCP helper after cancellation: {error}"),
                });
        let after = read_links().expect("observe host links at executor exit");
        let remaining: Vec<_> = after
            .iter()
            .filter(|link| temporary_links.iter().any(|owned| same_link(owned, link)))
            .cloned()
            .collect();
        (
            status,
            helpers_reaped,
            remaining,
            format!(
                "{}\nhelpers at acquisition={owned_helpers:?}\n\
                 remaining group helpers={remaining_group_helpers:?}\n\
                 links before={before:?}\nlinks during={during:?}\nlinks after={after:?}",
                fs::read_to_string(output_path).expect("read executor output")
            ),
        )
    }));
    if let Some(child) = executor.as_ref() {
        let pid = Pid::from_raw(child.id() as i32);
        let _ = kill(pid, Signal::SIGINT);
        let cleanup_started = std::time::Instant::now();
        while matches!(
            waitid(Id::Pid(pid), wait_options),
            Ok(WaitStatus::StillAlive) | Err(Errno::EINTR)
        ) && cleanup_started.elapsed() < Duration::from_secs(180)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let mut helper_cleanup_errors = Vec::new();
    for (pid, _, pidfd) in &owned_helpers {
        if let Err(error) = signal_pidfd(pidfd, libc::SIGKILL) {
            if error != Errno::ESRCH {
                helper_cleanup_errors.push(format!("kill pinned helper {pid}: {error}"));
            }
        }
    }
    if let Some(mut child) = executor {
        let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Ok(current) = read_links() {
        for link in current
            .iter()
            .filter(|link| temporary_links.iter().any(|owned| same_link(owned, link)))
        {
            let _ = Command::new("/usr/bin/timeout")
                .args([
                    "--kill-after=1",
                    "5",
                    "ip",
                    "link",
                    "delete",
                    "dev",
                    link["ifname"].as_str().expect("observed interface name"),
                ])
                .output();
        }
    }
    let destroyed = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1", "15", "lxc-destroy", "-n", name, "-f"])
        .output();
    let cleanup_links = read_links();
    let fixture_network_removed = cleanup_links.as_ref().is_ok_and(|links| {
        !temporary_links
            .iter()
            .any(|link| links.iter().any(|current| same_link(link, current)))
    });
    if !helper_cleanup_errors.is_empty()
        || !fixture_network_removed
        || std::path::Path::new(&definition).exists()
    {
        panic!(
            "address acquisition fixture cleanup failed: helpers={helper_cleanup_errors:?}, \
             links={cleanup_links:?}, container={destroyed:?}"
        );
    }
    let (status, helpers_reaped, remaining, output) =
        outcome.expect("address acquisition cancellation fixture failed");
    let cancelled = match &status {
        Some(WaitStatus::Exited(_, code)) => *code != 0,
        Some(WaitStatus::Signaled(..)) => true,
        _ => false,
    };

    assert!(
        cancelled && helpers_reaped && remaining.is_empty(),
        "Ctrl+C during address acquisition must remove temporary host networking and reap \
         helper processes before the executor exits; exit={status:?}, \
         helpers_reaped={helpers_reaped}, remaining_links={remaining:?}\n{output}"
    );
}
