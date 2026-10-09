// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use clap::Parser;
use mxc_sdk::mxc_common::config_parser::load_one_shot_request;
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::ExecutionRequest;
use std::process;

#[derive(Parser)]
#[command(name = "lxc-exec", about = "Linux Container Executor")]
pub struct LinuxExecutorArguments {
    /// Path to config JSON file (positional)
    #[arg(value_name = "CONFIG_PATH")]
    config_path: Option<String>,

    /// Path to config JSON file
    #[arg(long = "config")]
    config: Option<String>,

    /// Base64-encoded JSON config
    #[arg(long = "config-base64")]
    config_base64: Option<String>,

    /// Enable debug/console output
    #[arg(long)]
    debug: bool,

    /// Delete container mode
    #[arg(long)]
    delete: bool,

    /// Container name (required with --delete)
    #[arg(long = "containername")]
    containername: Option<String>,

    /// Enable experimental features
    #[arg(long)]
    experimental: bool,

    /// Report host backend availability as JSON and exit
    #[arg(long = "available-backends")]
    available_backends: bool,

    /// Parse and validate config then exit without executing
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Path to diagnostic log file (appends, creates if missing)
    #[arg(long = "log-file")]
    log_file: Option<String>,

    /// Install the warmed Hyperlight snapshot and exit, for the default
    /// runtime (`agent`) or the comma-separated runtimes given with `=`:
    /// `--setup-hyperlight=python,node`. Names are `agent`, `python`,
    /// `python-shell`, `node`, `bash` and `dotnet-jit`. For each, pulls the
    /// published rootfs from GHCR unless the image home already holds it,
    /// boots it once, and writes the snapshot into the default user data
    /// dir (~/.local/share/mxc-hyperlight on Linux,
    /// %LOCALAPPDATA%\mxc-hyperlight on Windows). $MXC_HYPERLIGHT_HOME
    /// overrides the destination if set. Intended for tool install hooks
    /// so first-run has zero warmup cost.
    #[arg(
        long = "setup-hyperlight",
        value_name = "RUNTIMES",
        num_args = 0..=1,
        require_equals = true,
        value_delimiter = ','
    )]
    setup_hyperlight: Option<Vec<String>>,

    /// Rebuild the snapshot even if one already exists.
    #[arg(long, requires = "setup_hyperlight")]
    force: bool,
}

impl LinuxExecutorArguments {
    pub fn get_log_path(&self) -> Option<String> {
        self.log_file.clone()
    }

    pub fn should_run_in_debug(&self) -> bool {
        self.debug
    }

    pub fn should_display_avalible_backends(&self) -> bool {
        self.available_backends
    }

    pub fn parse_and_validate(&self) -> bool {
        self.dry_run
    }

    pub fn get_request(&self) -> ExecutionRequest {
        let (config_data, is_base64) = if let Some(ref b64) = self.config_base64 {
            (b64.clone(), true)
        } else if let Some(ref path) = self.config {
            (path.clone(), false)
        } else if let Some(ref path) = self.config_path {
            (path.clone(), false)
        } else {
            eprintln!(
                "Error: No config provided. Use a positional path, --config, or --config-base64"
            );
            process::exit(1);
        };

        let mut logger = Logger::new(if self.debug {
            Mode::Console
        } else {
            Mode::Buffer
        });

        let mut request = match load_one_shot_request(&config_data, &mut logger, is_base64) {
            Ok(r) => r,
            Err(_) => {
                eprint!("Request error\n{}", logger.get_buffer());
                process::exit(1);
            }
        };

        request.experimental_enabled = self.experimental;
        request.dry_run = self.dry_run;

        request
    }

    pub fn does_user_want_hyperlight_setup(&self) -> bool {
        self.setup_hyperlight.is_some()
    }

    pub fn setup_hyperlight(&self) -> Result<String, String> {
        if let Some(config_path) = &self.config_path {
            return Err(format!(
                "Error: --setup-hyperlight takes no config path; name runtimes with \
                 --setup-hyperlight={config_path}"
            ));
        }

        #[cfg(not(all(feature = "hyperlight", target_arch = "x86_64")))]
        {
            return Err(
                "Error: --setup-hyperlight requires x86_64 (Hyperlight needs KVM or WHP)"
                    .to_string(),
            );
        }

        #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
        {
            // WHP is delay-loaded; check before setup boots a VM.
            #[cfg(target_os = "windows")]
            if !mxc_sdk::hyperlight_common::is_whp_available() {
                return Err(
                    "Error: --setup-hyperlight requires Windows Hypervisor Platform (WHP). \
                     Enable the HypervisorPlatform optional feature and reboot."
                        .to_string(),
                );
            }

            //KVM is checked before anything is pulled.
            #[cfg(target_os = "linux")]
            if !mxc_sdk::hyperlight_common::is_kvm_available() {
                return Err(
                    "Error: --setup-hyperlight requires KVM: /dev/kvm must be readable and \
                     writable by this user."
                        .to_string(),
                );
            }

            // Setup is an interactive install: the pull and the warm-up
            // report progress as they go.
            let runtimes =
                mxc_sdk::hyperlight_common::parse_runtimes(&self.setup_hyperlight.clone().unwrap())
                    .map_err(|message| format!("Error: {message}"))?;

            let mut logger = mxc_sdk::mxc_common::logger::Logger::new(
                mxc_sdk::mxc_common::logger::Mode::Console,
            );
            match mxc_sdk::hyperlight_common::setup(self.force, &runtimes, &mut logger) {
                Ok(home) => Ok(format!("hyperlight setup: image home ready at {home:?}")),
                Err(msg) => Err(format!("hyperlight setup failed: {msg}")),
            }
        }
    }

    pub fn does_user_want_to_delete_a_container(&self) -> bool {
        self.delete
    }

    pub fn delete_container(&self) -> Result<String, String> {
        let name = match self.containername {
            Some(ref n) => n,
            None => return Err("Error: --containername is required with --delete".to_string()),
        };

        Self::delete_lxc_container(name)
    }

    fn delete_lxc_container(name: &str) -> Result<String, String> {
        use mxc_sdk::lxc_common::lxc_bindings::LxcContainer;

        let container = LxcContainer::new(name, None);

        if !container.is_defined() {
            return Err(format!("Container '{}' does not exist.", name));
        }

        match container.destroy() {
            Ok(()) => Ok(format!("Deleted LXC container: {}", name)),
            Err(e) => Err(format!("Failed to delete LXC container '{}': {}", name, e)),
        }
    }
}
