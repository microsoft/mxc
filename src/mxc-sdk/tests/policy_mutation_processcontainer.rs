// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "windows")]

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use mxc_sdk::v1::configs::ProcessContainerConfig;
use mxc_sdk::v1::policy::{
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig,
    UiPolicy,
};
use mxc_sdk::v1::{ContainerRequest, Containment, FilesystemPolicy, WaitResult};
use mxc_sdk::v1_1;
use serde::Deserialize;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

const MUTATION_WARNING: &str = "Sandbox configuration updated due to IT policy";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    root: PathBuf,
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

fn mentions_path(text: &str, path: &Path) -> bool {
    text.replace("\\\\", "\\")
        .to_ascii_lowercase()
        .contains(&path.display().to_string().to_ascii_lowercase())
}

fn request(root: &Path, certificate: usize, proxy_port: u16, second: bool) -> ContainerRequest {
    let windows = std::env::var("SystemRoot").expect("Windows directory");
    let certificate_path = root.join(format!("certs\\ca-{certificate}.pem"));
    let ledger = root.join("ledger\\launches.txt");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let mut script = format!(
        "$ErrorActionPreference='Stop'; \
         [IO.File]::AppendAllText({},\"$PID`n\"); \
         if ([IO.File]::ReadAllText({}) -cne 'ca-{certificate}') {{ throw 'fresh CA grant lost' }}; \
         if ($env:HTTP_PROXY -cne '{proxy}') {{ throw 'fresh proxy endpoint lost' }}; ",
        quoted(&ledger),
        quoted(&certificate_path),
    );
    for directory in if second { vec!["a", "b"] } else { vec!["a"] } {
        let allowed = root.join(format!("{directory}\\seed.txt"));
        let denied = root.join(format!("{directory}\\denied\\seed.txt"));
        script.push_str(&format!(
            "$f=[IO.File]::Open({},[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite); $f.Dispose(); \
             foreach ($access in @([IO.FileAccess]::Read,[IO.FileAccess]::Write)) {{ \
               $opened=$false; $f=$null; \
               try {{ $f=[IO.File]::Open({},[IO.FileMode]::Open,$access); $opened=$true }} \
               catch [UnauthorizedAccessException] {{}} \
               finally {{ if ($null -ne $f) {{ $f.Dispose() }} }}; \
               if ($opened) {{ throw 'IT-policy deny was not enforced' }} \
             }}; ",
            quoted(&allowed),
            quoted(&denied),
        ));
    }
    script.push_str("[Console]::Out.WriteLine('MXC_GOVERNED_MUTATION_OK'); exit 7");
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut writable = vec![root.join("a"), root.join("ledger")];
    if second {
        writable.push(root.join("b"));
    }
    ContainerRequest {
        containment: Containment::ProcessContainer(ProcessContainerConfig::default()),
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: writable
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            readonly_paths: vec![windows.clone(), certificate_path.display().to_string()],
            denied_paths: Vec::new(),
            clear_policy_on_exit: None,
        }),
        network: Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Allow),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some(proxy),
            }),
        }),
        ui: Some(UiPolicy {
            disable: false,
            ..Default::default()
        }),
        timeout_ms: Some(20_000),
        working_directory: Some(root.join("a").display().to_string()),
        ..ContainerRequest::new(format!(
            "\"{windows}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \
             -NoProfile -NonInteractive -EncodedCommand {encoded}"
        ))
    }
}

fn launches(root: &Path) -> Vec<u32> {
    fs::read_to_string(root.join("ledger\\launches.txt"))
        .expect("independent workload-entry ledger")
        .lines()
        .map(|line| line.parse().expect("workload PID"))
        .collect()
}

#[test]
#[ignore = "requires the prepared governed-host fixture and agent-tagged SDK creator"]
fn governed_creation_policy_reuses_restrictions() {
    let fixture_path =
        std::env::var_os("MXC_POLICY_MUTATION_FIXTURE").expect("required fixture manifest");
    let fixture: Fixture =
        serde_json::from_slice(&fs::read(fixture_path).expect("fixture manifest"))
            .expect("fixture");
    assert!(fixture.root.is_absolute());
    let root = fixture.root;
    assert!(launches(&root).is_empty(), "use fresh fixture data");
    for name in ["a\\denied\\seed.txt", "b\\denied\\seed.txt"] {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(name))
            .expect("the creator must have underlying access before sandbox policy denies it");
    }
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // Record this process's birth identity for attributable timeout cleanup.
    unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    }
    .expect("SDK process creation identity");
    fs::write(
        root.join("sdk-owner.json"),
        serde_json::to_vec(&serde_json::json!({
            "pid": std::process::id(),
            "executable": std::env::current_exe().expect("SDK test executable"),
            "creationFileTime": (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
        }))
        .expect("owner metadata"),
    )
    .expect("owner receipt");

    let authored = request(&root, 1, 18081, false);
    let before = format!("{authored:?}");
    let error = mxc_sdk::v1::run(authored.clone(), Default::default())
        .expect_err("strict control must encounter real IT policy");
    let message = error.to_string();
    assert!(message.contains("Sandbox creation failed: blocked by IT policy."));
    assert!(message.contains("0x800704EC"));
    assert!(mentions_path(&message, &root.join("a\\denied")));
    assert!(!message.contains("class=filesystem ("));
    assert!(!message.contains("flags=0x"));
    assert!(
        launches(&root).is_empty(),
        "strict refusal launched a workload"
    );

    let mut options = v1_1::RunOptions::default();
    options.mutate_policy = true;
    for (index, second) in [false, false, true, true].into_iter().enumerate() {
        let current = request(&root, index + 1, 18081 + index as u16, second);
        let original = format!("{current:?}");
        let output = if index == 2 {
            let mut spawn_options = v1_1::SpawnOptions::default();
            spawn_options.mutate_policy = true;
            v1_1::spawn(current.clone(), spawn_options)
                .expect("opted-in live creation")
                .wait_with_output()
                .expect("live workload completion")
        } else {
            v1_1::run(current.clone(), options).expect("opted-in captured execution")
        };
        assert_eq!(format!("{current:?}"), original, "caller request changed");
        assert_eq!(
            output.outcome,
            WaitResult::Exited(7),
            "{}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "MXC_GOVERNED_MUTATION_OK"
        );
        assert_eq!(launches(&root).len(), index + 1, "workload replay");
        let changes: Vec<_> = output
            .warnings
            .iter()
            .filter(|warning| warning.starts_with(MUTATION_WARNING))
            .collect();
        match index {
            0 => assert!(changes
                .iter()
                .any(|warning| mentions_path(warning, &root.join("a\\denied")))),
            2 => {
                assert_eq!(
                    changes.len(),
                    1,
                    "only the new deny-list correction is reported"
                );
                assert!(changes
                    .iter()
                    .any(|warning| mentions_path(warning, &root.join("b\\denied"))));
                let before = format!(
                    "filesystem.deniedpaths: [\"{}\"] ->",
                    root.join("a\\denied")
                        .display()
                        .to_string()
                        .to_ascii_lowercase()
                );
                assert!(
                    changes[0]
                        .replace("\\\\", "\\")
                        .to_ascii_lowercase()
                        .contains(&before),
                    "the cached restriction must precede the newly negotiated change"
                );
            }
            _ => assert!(changes.is_empty(), "warm cache hit emitted {changes:?}"),
        }
    }
    let error = v1_1::run(request(&root, 4, 18084, false), Default::default())
        .expect_err("strict invocation must not use cached restrictions");
    assert!(mentions_path(&error.to_string(), &root.join("a\\denied")));
    assert_eq!(launches(&root).len(), 4);
    assert_eq!(format!("{authored:?}"), before);
    fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "sdkProcessId": std::process::id(),
            "workloadProcessIds": launches(&root),
            "strictControls": 2,
            "successfulCreations": 4,
            "coldCorrection": true,
            "quietReuse": true,
            "freshCertificateAndProxy": true,
            "additionalRestriction": true,
            "quietUpdatedReuse": true,
        }))
        .expect("result serialization"),
    )
    .expect("result receipt");
}
