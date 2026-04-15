// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::ContainerPolicy;
use crate::process_util;

const BFSCFG_EXE: &str = "bfscfg.exe";
const UNABLE_TO_PERFORM: &str = "Unable to perform policy operation";
const BFSCFG_TIMEOUT_MS: u32 = 10_000;

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
        if self.configured && self.remove_configuration_inner(logger).is_ok() {
            self.configured = false;
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

    fn add_bfs_path(&self, path: &str, inherit: bool, logger: &mut Logger) -> Result<(), WxcError> {
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
        let cmd_line = build_bfscfg_cmd_line(args);

        let output = process_util::run_process_with_captured_output(&cmd_line, BFSCFG_TIMEOUT_MS)?;

        let stdout = output.stdout;
        let stderr = output.stderr;

        // Only include stderr if the process failed (non-zero exit code)
        if output.exit_code != 0 {
            let mut combined = stdout;
            if !stderr.is_empty() {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&stderr);
            }
            return Ok(combined);
        }

        Ok(stdout)
    }
}

/// Returns `false` for `C:\` (no inheritance), `true` for all other paths.
fn test_for_root_path(path: &str) -> bool {
    path != "C:\\"
}

// We control the arguments and ensure they are properly quoted, so this simple implementation
// is sufficient for our needs. Arguments are only quoted when they contain spaces. When quoting
// is needed, trailing backslashes are doubled to prevent them from escaping the closing quote
// (e.g. `C:\My Folder\` becomes `"C:\My Folder\\"` so bfscfg sees the path correctly).
fn build_bfscfg_cmd_line(args: &[&str]) -> String {
    let mut cmd_line = BFSCFG_EXE.to_string();
    for arg in args {
        if arg.contains(' ') {
            // Double any trailing backslashes so they don't escape the closing quote
            let escaped = if arg.ends_with('\\') {
                format!("{}\\", arg)
            } else {
                arg.to_string()
            };
            cmd_line.push_str(&format!(" \"{escaped}\""));
        } else {
            cmd_line.push(' ');
            cmd_line.push_str(arg);
        }
    }
    cmd_line
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

    #[test]
    fn test_build_cmd_line_quotes_args_with_spaces() {
        let cmd = build_bfscfg_cmd_line(&[
            "--addpolicy",
            "--filename",
            r"C:\Program Files\PowerShell\7",
            "--appid",
            "test_container",
        ]);
        assert_eq!(
            cmd,
            r#"bfscfg.exe --addpolicy --filename "C:\Program Files\PowerShell\7" --appid test_container"#
        );
    }

    #[test]
    fn test_build_cmd_line_no_quotes_without_spaces() {
        let cmd = build_bfscfg_cmd_line(&[
            "--addpolicy",
            "--policybrokerreadonly",
            "--filename",
            r"C:\Users",
            "--appid",
            "test",
        ]);
        assert_eq!(
            cmd,
            r"bfscfg.exe --addpolicy --policybrokerreadonly --filename C:\Users --appid test"
        );
    }

    #[test]
    fn test_build_cmd_line_trailing_backslash() {
        let cmd = build_bfscfg_cmd_line(&[
            "--addpolicy",
            "--policybrokerreadonly",
            "--filename",
            r"C:\",
            "--appid",
            "test",
        ]);
        // C:\ has no spaces, so no quoting needed — trailing backslash is safe
        assert_eq!(
            cmd,
            r"bfscfg.exe --addpolicy --policybrokerreadonly --filename C:\ --appid test"
        );
    }

    #[test]
    fn test_build_cmd_line_path_with_spaces_and_trailing_backslash() {
        let cmd = build_bfscfg_cmd_line(&[
            "--addpolicy",
            "--filename",
            r"C:\My Folder\",
            "--appid",
            "test",
        ]);
        // Trailing backslash is doubled inside quotes to prevent escaping the quote
        assert_eq!(
            cmd,
            r#"bfscfg.exe --addpolicy --filename "C:\My Folder\\" --appid test"#
        );
    }
}
