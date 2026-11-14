// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Path;

use super::lxc_bindings::LxcContainer;

pub(crate) fn configure(container: &LxcContainer, configuration: &Path) -> Result<(), String> {
    let resolver = std::fs::read_to_string(configuration)
        .map_err(|error| format!("Failed to read LXC DHCP resolver settings: {error}"))?;
    let command = format!(
        "set -eu; if [ -L /etc/resolv.conf ]; then rm /etc/resolv.conf; fi; \
         printf '%s' {} > /etc/resolv.conf; chmod 644 /etc/resolv.conf",
        super::network_startup::quote_shell_arg(&resolver)
    );
    let (code, _, stderr) = container.attach_capture(
        &command,
        "/",
        &[],
        true,
        Some(std::time::Duration::from_secs(10)),
    )?;
    if code != 0 {
        return Err(format!(
            "Failed to configure container DNS: {}",
            stderr.trim()
        ));
    }

    Ok(())
}
