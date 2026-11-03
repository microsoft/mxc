// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use crate::lxc_common::lxc_bindings::LxcContainer;
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{ContainerPolicy, NetworkAction, NetworkEgressPolicy};

#[test]
fn filtered_hook_preserves_user_settings_on_quoted_paths() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("lxc network's ")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let container_directory = directory.path().join("sandbox");
    fs::create_dir(&container_directory)?;
    let config_path = container_directory.join("config");
    let original = "\
lxc.uts.name = user-sandbox
lxc.hook.version = 0
lxc.hook.start-host = /usr/local/lib/user-start first second
lxc.mount.entry = /srv/input input none bind,ro,create=dir 0 0
lxc.net.0.type = veth
lxc.net.0.link = user-bridge
";
    fs::write(&config_path, original)?;
    let policy = ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        }),
        ..Default::default()
    };
    let container = LxcContainer::new("sandbox", directory.path().to_str());
    let mut logger = Logger::new(Mode::Buffer);
    container
        .set_network_policy(&policy, &mut logger)
        .unwrap_or_else(|error| panic!("filtered policy rejected for {config_path:?}: {error}"));

    let saved = fs::read_to_string(&config_path)?;
    let settings: Vec<_> = saved
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    for (key, value) in original
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
    {
        assert!(
            settings.contains(&(key, value)),
            "filtered policy changed user setting {key} = {value} in {config_path:?}\n{saved}"
        );
    }
    let hooks: Vec<_> = settings
        .iter()
        .filter_map(|(key, value)| {
            (*key == "lxc.hook.start-host" && *value != "/usr/local/lib/user-start first second")
                .then_some(*value)
        })
        .collect();
    assert_eq!(
        hooks.len(),
        1,
        "filtered policy must register one managed start-host hook in {config_path:?}\n{saved}"
    );
    let hook_path = fs::read_dir(&container_directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|path| {
            fs::read_to_string(path).is_ok_and(|contents| contents.starts_with("#!/bin/sh"))
        })
        .unwrap_or_else(|| panic!("no /bin/sh hook artifact beside {config_path:?}\n{saved}"));
    assert_ne!(
        fs::metadata(&hook_path)?.permissions().mode() & 0o111,
        0,
        "saved start-host hook is not executable: {hook_path:?}"
    );

    fs::write(&hook_path, "#!/bin/sh\nprintf '%s\\n' hook-invoked\n")?;
    let output = Command::new("/bin/sh").arg("-c").arg(hooks[0]).output()?;
    assert!(
        output.status.success(),
        "saved hook command {:?} cannot run from {config_path:?}: {}",
        hooks[0],
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, b"hook-invoked\n",
        "saved hook command {:?} did not invoke the artifact at {hook_path:?}",
        hooks[0]
    );
    Ok(())
}

#[test]
fn no_network_clears_then_restores_user_interfaces() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("lxc-network-roundtrip-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let container_directory = directory.path().join("sandbox");
    fs::create_dir(&container_directory)?;
    let config_path = container_directory.join("config");
    let include_path = directory.path().join("included-network.conf");
    fs::write(&include_path, "lxc.net.2.type = veth\n")?;
    let original = format!(
        "\
lxc.net.0.type = veth
lxc.net.0.link = original-bridge
lxc.net.1.type = phys
lxc.net.1.link = original-interface
lxc.include = {}
lxc.hook.start-host = /usr/local/lib/user-start
lxc.mount.entry = /srv/cache cache none bind,create=dir 0 0
",
        include_path.display()
    );
    fs::write(&config_path, &original)?;
    let filtered = ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);
    LxcContainer::new("sandbox", directory.path().to_str())
        .set_network_policy(&filtered, &mut logger)
        .unwrap_or_else(|error| panic!("filtered policy rejected for {config_path:?}: {error}"));
    LxcContainer::new("sandbox", directory.path().to_str())
        .set_network_policy(&ContainerPolicy::default(), &mut logger)
        .unwrap_or_else(|error| panic!("no-network policy rejected for {config_path:?}: {error}"));

    let isolated = fs::read_to_string(&config_path)?;
    let settings: Vec<_> = isolated
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    let reset = settings
        .iter()
        .position(|setting| *setting == ("lxc.net", ""))
        .unwrap_or_else(|| {
            panic!("no interface-clearing assignment in {config_path:?}\n{isolated}")
        });
    let include = settings
        .iter()
        .position(|(key, value)| *key == "lxc.include" && *value == include_path.to_str().unwrap())
        .unwrap_or_else(|| panic!("user include was removed from {config_path:?}\n{isolated}"));
    assert!(
        reset > include,
        "included interfaces must be cleared after their declarations in {config_path:?}\n{isolated}"
    );
    let remaining_network: Vec<_> = settings[reset + 1..]
        .iter()
        .copied()
        .filter(|(key, _)| *key == "lxc.net" || key.starts_with("lxc.net."))
        .collect();
    assert_eq!(
        remaining_network,
        [("lxc.net.0.type", "empty"), ("lxc.net.0.flags", "up")],
        "no-network policy leaves usable interfaces after its reset in {config_path:?}\n{isolated}"
    );
    let hooks: Vec<_> = settings
        .iter()
        .copied()
        .filter(|(key, _)| *key == "lxc.hook.start-host")
        .collect();
    assert_eq!(
        hooks,
        [("lxc.hook.start-host", "/usr/local/lib/user-start")],
        "no-network policy must remove only MXC's start-host hook in {config_path:?}\n{isolated}"
    );
    assert!(
        settings.contains(&(
            "lxc.mount.entry",
            "/srv/cache cache none bind,create=dir 0 0"
        )),
        "no-network policy changed the user mount in {config_path:?}\n{isolated}"
    );

    LxcContainer::new("sandbox", directory.path().to_str())
        .set_network_policy(&filtered, &mut logger)
        .unwrap_or_else(|error| {
            panic!("restored filtered policy rejected for {config_path:?}: {error}")
        });
    let restored = fs::read_to_string(&config_path)?;
    let restored_network: Vec<_> = restored
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .filter(|(key, _)| *key == "lxc.net" || key.starts_with("lxc.net."))
        .collect();
    assert_eq!(
        restored_network,
        [
            ("lxc.net.0.type", "veth"),
            ("lxc.net.0.link", "original-bridge"),
            ("lxc.net.1.type", "phys"),
            ("lxc.net.1.link", "original-interface")
        ],
        "filtered policy did not restore the original user interfaces in {config_path:?}\n{restored}"
    );
    assert_eq!(
        restored
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(key, _)| key.trim() == "lxc.hook.start-host")
            .count(),
        2,
        "restored filtered policy must retain the user hook and register MXC's hook in {config_path:?}\n{restored}"
    );
    Ok(())
}

#[test]
fn repeated_saves_do_not_accumulate_hook_artifacts() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("lxc-network-replacement-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let container_directory = directory.path().join("sandbox");
    fs::create_dir(&container_directory)?;
    let config_path = container_directory.join("config");
    fs::write(&config_path, "lxc.net.0.type = veth\n")?;
    let policy = ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);
    for replacement in 0..3 {
        LxcContainer::new("sandbox", directory.path().to_str())
            .set_network_policy(&policy, &mut logger)
            .unwrap_or_else(|error| {
                panic!("filtered save {replacement} rejected for {config_path:?}: {error}")
            });
        let saved = fs::read_to_string(&config_path)?;
        assert_eq!(
            saved
                .lines()
                .filter_map(|line| line.split_once('='))
                .filter(|(key, _)| key.trim() == "lxc.hook.start-host")
                .count(),
            1,
            "filtered save {replacement} duplicated the managed hook in {config_path:?}\n{saved}"
        );
        let hooks: Vec<_> = fs::read_dir(&container_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|path| {
                fs::read_to_string(path).is_ok_and(|contents| contents.starts_with("#!/bin/sh"))
            })
            .collect();
        assert_eq!(
            hooks.len(),
            1,
            "filtered save {replacement} left missing or superseded hook artifacts beside {config_path:?}: {hooks:?}"
        );
    }
    Ok(())
}

#[test]
fn missing_or_unreadable_config_is_not_replaced() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("lxc-network-invalid-config-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let container_directory = directory.path().join("sandbox");
    fs::create_dir(&container_directory)?;
    let config_path = container_directory.join("config");
    let container = LxcContainer::new("sandbox", directory.path().to_str());
    let mut logger = Logger::new(Mode::Buffer);
    let policy = ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        container.set_network_policy(&policy, &mut logger).is_err(),
        "filtered policy accepted missing config {config_path:?}"
    );
    assert!(
        !config_path.exists(),
        "failed policy save created a config at {config_path:?}"
    );

    fs::create_dir(&config_path)?;
    let sentinel_path = config_path.join("untouched");
    fs::write(&sentinel_path, b"original contents")?;
    assert!(
        container.set_network_policy(&policy, &mut logger).is_err(),
        "filtered policy accepted unreadable config directory {config_path:?}"
    );
    assert_eq!(
        fs::read(&sentinel_path)?,
        b"original contents",
        "failed policy save changed the existing config directory {config_path:?}"
    );
    Ok(())
}
