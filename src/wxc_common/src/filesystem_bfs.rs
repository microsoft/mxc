use std::process::{Command, Stdio};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::ContainerPolicy;

const BFSCFG_EXE: &str = "bfscfg.exe";
const UNABLE_TO_PERFORM: &str = "Unable to perform policy operation";

pub struct FileSystemBfsManager {
    app_container_name: String,
    configured: bool,
}

impl FileSystemBfsManager {
    pub fn new(app_container_name: String) -> Self {
        Self {
            app_container_name,
            configured: false,
        }
    }

    pub fn configured(&self) -> bool {
        self.configured
    }

    pub fn configure(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if policy.readwrite_paths.is_empty() && policy.readonly_paths.is_empty() {
            logger.log_line("No BFS paths to configure.");
            return Ok(());
        }

        for path in &policy.readwrite_paths {
            let inherit = test_for_root_path(path);
            if let Err(e) = self.add_bfs_path(path, inherit, logger) {
                self.remove_configuration(logger);
                return Err(e);
            }
            self.configured = true;
        }

        for path in &policy.readonly_paths {
            let inherit = test_for_root_path(path);
            if let Err(e) = self.add_readonly_bfs_path(path, inherit, logger) {
                self.remove_configuration(logger);
                return Err(e);
            }
            self.configured = true;
        }

        Ok(())
    }

    pub fn remove_configuration(&mut self, logger: &mut Logger) -> bool {
        if self.configured {
            if self.remove_configuration_inner(logger).is_ok() {
                self.configured = false;
            }
        }
        !self.configured
    }

    fn remove_configuration_inner(&self, logger: &mut Logger) -> Result<(), WxcError> {
        let args = vec!["--clearpolicy", "--appid", &self.app_container_name];
        let description = format!(
            "Failed to remove BFS configuration for AppContainer {}",
            self.app_container_name
        );
        self.execute_bfscfg_operation(&args, &description, logger)
    }

    fn add_bfs_path(
        &self,
        path: &str,
        inherit: bool,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        let mut args = vec![
            "--addpolicy",
            "--policybroker",
            "--filename",
            path,
            "--appid",
            &self.app_container_name,
        ];
        if inherit {
            args.push("--containerinherit");
        }
        let description = format!(
            "Failed to add BFS path {} for AppContainer {}",
            path, self.app_container_name
        );
        self.execute_bfscfg_operation(&args, &description, logger)
    }

    fn add_readonly_bfs_path(
        &self,
        path: &str,
        inherit: bool,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        let mut args = vec![
            "--addpolicy",
            "--policybrokerreadonly",
            "--filename",
            path,
            "--appid",
            &self.app_container_name,
        ];
        if inherit {
            args.push("--containerinherit");
        }
        let description = format!(
            "Failed to add read-only BFS path {} for AppContainer {}",
            path, self.app_container_name
        );
        self.execute_bfscfg_operation(&args, &description, logger)
    }

    fn execute_bfscfg_operation(
        &self,
        args: &[&str],
        operation_description: &str,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        let output = self.run_bfscfg(args)?;

        if output.contains(UNABLE_TO_PERFORM) {
            return Err(WxcError::FilesystemPolicy(
                operation_description.to_string(),
            ));
        }

        if !output.is_empty() {
            logger.log_line(&format!("Output from bfscfg.exe:\n{}", output));
        }

        Ok(())
    }

    fn run_bfscfg(&self, args: &[&str]) -> Result<String, WxcError> {
        let output = Command::new(BFSCFG_EXE)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| {
                WxcError::FilesystemPolicy(format!("Failed to run {}: {}", BFSCFG_EXE, e))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut combined = stdout.into_owned();
        if !stderr.is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(&stderr);
        }

        Ok(combined)
    }
}

/// Returns `false` for `C:\` (no inheritance), `true` for all other paths.
fn test_for_root_path(path: &str) -> bool {
    path != "C:\\"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_root_path_c_drive() {
        assert!(!test_for_root_path("C:\\"));
    }

    #[test]
    fn test_for_root_path_subdir() {
        assert!(test_for_root_path("C:\\Users"));
        assert!(test_for_root_path("D:\\"));
        assert!(test_for_root_path("C:\\Windows\\System32"));
    }

    #[test]
    fn test_new_manager() {
        let mgr = FileSystemBfsManager::new("test_container".to_string());
        assert!(!mgr.configured());
    }
}
