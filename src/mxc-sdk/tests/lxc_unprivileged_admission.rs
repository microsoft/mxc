// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use mxc_sdk::lxc_common::lxc_bindings::{LxcContainer, StartNetwork};

const FIXTURE_DIRECTORY: &str = "MXC_LXC_ADMISSION_DIRECTORY";
const SHIFTED_MAP: &str = "         0     100000      65536\n";
const IDENTITY_MAP: &str = "         0          0 4294967295\n";

const LXC_TOOL: &str = r#"#!/bin/sh
set -eu
tool=${0##*/}
case "$tool" in
    lxc-start)
        printf 'start\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
        if [ "$MXC_LXC_ADMISSION_CASE" = failed_start_never_attempts_inspection ]; then
            echo 'fixture start failure' >&2
            exit 1
        fi
        printf 'RUNNING\n' > "$MXC_LXC_ADMISSION_DIRECTORY/state"
        ;;
    lxc-attach)
        case "$*" in
            *"/proc/self/uid_map"*)
                printf 'inspect\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
                read -r state < "$MXC_LXC_ADMISSION_DIRECTORY/state"
                [ "$state" = RUNNING ] || exit 1
                if [ "$MXC_LXC_ADMISSION_CASE" = failed_inspection_stops_before_workload ]; then
                    echo 'fixture attach failure' >&2
                    exit 1
                fi
                ;;
            *)
                printf 'workload\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
                ;;
        esac
        while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
        [ "$#" -gt 0 ] || exit 1
        shift
        exec "$@"
        ;;
    cat)
        if [ "$#" -eq 1 ] && [ "$1" = /proc/self/uid_map ]; then
            printf '%s' "$MXC_LXC_ADMISSION_MAP"
        else
            exec /bin/cat "$@"
        fi
        ;;
    lxc-stop)
        printf 'stop\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
        if [ "$MXC_LXC_ADMISSION_CASE" = cleanup_failure_preserves_the_admission_error ]; then
            echo 'fixture stop failure' >&2
            exit 1
        fi
        printf 'STOPPED\n' > "$MXC_LXC_ADMISSION_DIRECTORY/state"
        ;;
    lxc-execute)
        printf 'start\nworkload\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
        printf 'RUNNING\n' > "$MXC_LXC_ADMISSION_DIRECTORY/state"
        while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
        [ "$#" -gt 0 ] || exit 1
        shift
        status=0
        "$@" || status=$?
        printf 'stop\n' >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
        printf 'STOPPED\n' > "$MXC_LXC_ADMISSION_DIRECTORY/state"
        exit "$status"
        ;;
    lxc-info)
        if [ -f "$MXC_LXC_ADMISSION_DIRECTORY/state" ]; then
            read -r state < "$MXC_LXC_ADMISSION_DIRECTORY/state"
        else
            state=STOPPED
        fi
        case " $* " in
            *" -H "*) printf '%s\n' "$state" ;;
            *) printf 'Name: admission-fixture\nState: %s\n' "$state" ;;
        esac
        ;;
    lxc-ls)
        printf 'metadata: %s\n' "$*" >> "$MXC_LXC_ADMISSION_DIRECTORY/events"
        case "$*" in
            *UNPRIVILEGED*|*unprivileged*) printf 'NAME UNPRIVILEGED\nadmission-fixture true\n' ;;
            *) printf 'admission-fixture\n' ;;
        esac
        ;;
    *)
        echo "unexpected fixture tool: $tool" >&2
        exit 1
        ;;
esac
"#;

fn fixture_directory() -> Option<PathBuf> {
    std::env::var_os(FIXTURE_DIRECTORY).map(PathBuf::from)
}

fn run_fixture(test: &str, uid_map: &str) {
    let directory = tempfile::Builder::new()
        .prefix("lxc-admission-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create fixture under the crate directory");
    let path = directory.path().canonicalize().expect("fixture path");
    std::os::unix::fs::symlink("/bin/sh", path.join("sh")).expect("fixture shell");
    for tool in [
        "lxc-start",
        "lxc-attach",
        "lxc-stop",
        "lxc-execute",
        "lxc-info",
        "lxc-ls",
        "cat",
    ] {
        let executable = path.join(tool);
        fs::write(&executable, LXC_TOOL).expect("write fixture executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
    }

    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture"])
        .env(FIXTURE_DIRECTORY, &path)
        .env("MXC_LXC_ADMISSION_CASE", test)
        .env("MXC_LXC_ADMISSION_MAP", uid_map)
        .env("PATH", &path)
        .output()
        .expect("run admission fixture");
    assert!(
        output.status.success(),
        "{test}, uid_map={uid_map:?}:\n{}\n{}\nevents:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(path.join("events")).unwrap_or_default()
    );
}

fn container() -> LxcContainer {
    let path = fixture_directory().expect("child fixture directory");
    LxcContainer::new(
        "admission-fixture",
        Some(path.to_str().expect("fixture path")),
    )
}

fn assert_admission_error(error: &str) {
    let lower = error.to_ascii_lowercase();
    assert!(
        ["privileg", "uid", "map", "inspect", "check"]
            .iter()
            .any(|word| lower.contains(word)),
        "admission failure did not identify a privilege or UID-map check: {error}"
    );
}

fn assert_stopped_before_workload() {
    let path = fixture_directory().expect("child fixture directory");
    let events = fs::read_to_string(path.join("events")).expect("fixture events");
    for event in ["start", "inspect", "stop"] {
        assert!(
            events.lines().any(|line| line == event),
            "admission did not {event} the container:\n{events}"
        );
    }
    assert!(
        !events.lines().any(|line| line == "workload"),
        "an unvalidated container ran the workload:\n{events}"
    );
    assert_eq!(
        fs::read_to_string(path.join("state")).expect("container state"),
        "STOPPED\n",
        "the refused container was left running:\n{events}"
    );
}

#[test]
fn shifted_root_is_admitted_after_start() {
    if let Some(path) = fixture_directory() {
        container()
            .start(StartNetwork::NoInterface)
            .expect("a valid shifted UID map must be admitted");
        let events = fs::read_to_string(path.join("events")).expect("fixture events");
        assert!(
            events.contains("inspect\n"),
            "no live UID-map inspection:\n{events}"
        );
        assert_eq!(
            fs::read_to_string(path.join("state")).expect("container state"),
            "RUNNING\n",
            "an admitted container must remain running"
        );
        return;
    }

    for uid_map in [
        SHIFTED_MAP,
        "1 200000 100\n0 100000 1\n",
        "0 4294967294 1\n",
        "0 100000 1\n4294967294 4294967294 1\n",
        "unreadable-uid-map\n0 100000 1\n",
        "0 100000 1\nunreadable-uid-map\n",
        "1 0 1\n0 100000 1\n",
        "0 100000 1\n1 0 1\n",
    ] {
        run_fixture("shifted_root_is_admitted_after_start", uid_map);
    }
}

#[test]
fn maps_without_shifted_root_are_refused_and_stopped() {
    if fixture_directory().is_some() {
        let error = container()
            .start(StartNetwork::NoInterface)
            .expect_err("a UID map without shifted root must not be admitted");
        assert_admission_error(&error);
        assert!(
            !error.contains("unreadable-uid-map"),
            "admission failure included an unreadable row: {error}"
        );
        assert_stopped_before_workload();
        return;
    }

    for uid_map in [
        IDENTITY_MAP,
        "1 100000 65536\n",
        "",
        " \t\n",
        "unreadable-uid-map\n",
        "unreadable-uid-map\n0 0 4294967295\n",
        "0 100000\n",
        "0 100000 1 extra\n",
        "root 100000 1\n",
        "0 outside 1\n",
        "0 100000 count\n",
        "-1 100000 1\n",
        "0 -1 1\n",
        "0 100000 0\n",
        "0 100000 -1\n",
        "0 18446744073709551616 1\n",
        "0 100000 18446744073709551616\n",
    ] {
        run_fixture("maps_without_shifted_root_are_refused_and_stopped", uid_map);
    }
}

#[test]
fn configured_network_does_not_bypass_admission() {
    if fixture_directory().is_some() {
        let error = container()
            .start(StartNetwork::FromContainerConfig)
            .expect_err("configured networking must not admit a privileged container");
        assert_admission_error(&error);
        assert_stopped_before_workload();
        return;
    }
    run_fixture("configured_network_does_not_bypass_admission", IDENTITY_MAP);
}

#[test]
fn failed_inspection_stops_before_workload() {
    if fixture_directory().is_some() {
        let error = container()
            .start(StartNetwork::NoInterface)
            .expect_err("failed inspection must refuse admission");
        assert_admission_error(&error);
        assert_stopped_before_workload();
        return;
    }
    run_fixture("failed_inspection_stops_before_workload", SHIFTED_MAP);
}

#[test]
fn failed_start_never_attempts_inspection() {
    if let Some(path) = fixture_directory() {
        let error = container()
            .start(StartNetwork::NoInterface)
            .expect_err("start failure must reach the caller");
        assert!(
            error.to_ascii_lowercase().contains("start"),
            "start failure lost its context: {error}"
        );
        let events = fs::read_to_string(path.join("events")).expect("fixture events");
        assert!(
            events.contains("start\n"),
            "the failing start was not attempted:\n{events}"
        );
        assert!(
            !events.lines().any(|line| line == "inspect"),
            "a failed start attempted to attach:\n{events}"
        );
        return;
    }
    run_fixture("failed_start_never_attempts_inspection", SHIFTED_MAP);
}

#[test]
fn cleanup_failure_preserves_the_admission_error() {
    if let Some(path) = fixture_directory() {
        let error = container()
            .start(StartNetwork::NoInterface)
            .expect_err("failed admission and failed cleanup must reach the caller");
        assert_admission_error(&error);
        assert!(
            error.to_ascii_lowercase().contains("stop")
                || error.to_ascii_lowercase().contains("cleanup"),
            "admission failure hid the failed stop: {error}"
        );
        let events = fs::read_to_string(path.join("events")).expect("fixture events");
        assert!(
            events.contains("stop\n"),
            "cleanup was not attempted:\n{events}"
        );
        assert!(!events.contains("workload\n"), "workload ran:\n{events}");
        return;
    }
    run_fixture(
        "cleanup_failure_preserves_the_admission_error",
        IDENTITY_MAP,
    );
}

#[test]
fn direct_execution_refuses_an_unvalidated_container() {
    if fixture_directory().is_some() {
        let error = container()
            .exec("printf WORKLOAD_OK; exit 23", "/", 1_000)
            .expect_err("direct execution must not bypass live UID-map admission");
        assert_admission_error(&error);
        assert_stopped_before_workload();
        return;
    }
    for uid_map in [IDENTITY_MAP, ""] {
        run_fixture("direct_execution_refuses_an_unvalidated_container", uid_map);
    }
}

#[test]
fn direct_execution_inspects_before_workload_and_stops_afterward() {
    if let Some(path) = fixture_directory() {
        let (code, stdout, stderr) = container()
            .exec("printf WORKLOAD_OK; exit 23", "/", 1_000)
            .expect("direct execution with a shifted UID map");
        assert_eq!(
            code, 23,
            "workload exit status was lost: {stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("WORKLOAD_OK"),
            "workload did not run: {stdout}\n{stderr}"
        );
        let events = fs::read_to_string(path.join("events")).expect("fixture events");
        let inspect = events.find("inspect\n").expect("live map inspected");
        let workload = events.find("workload\n").expect("workload executed");
        let stop = events.rfind("stop\n").expect("container stopped");
        assert!(
            inspect < workload && workload < stop,
            "direct execution did not inspect, execute, and stop in order:\n{events}"
        );
        assert_eq!(
            fs::read_to_string(path.join("state")).expect("container state"),
            "STOPPED\n",
            "direct execution left its container running"
        );
        return;
    }
    for uid_map in [
        SHIFTED_MAP,
        "unreadable-uid-map\n0 100000 1\nunreadable-uid-map\n",
    ] {
        run_fixture(
            "direct_execution_inspects_before_workload_and_stops_afterward",
            uid_map,
        );
    }
}
