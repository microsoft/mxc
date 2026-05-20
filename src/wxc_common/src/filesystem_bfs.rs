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

    /// Unconditionally clear BFS policy entries for an AppContainer identity.
    ///
    /// Unlike `remove_configuration`, this does not check whether `configure()`
    /// was called first -- it always runs `bfscfg.exe --clearpolicy`. Use this
    /// for cleanup of externally-created sandboxes (e.g., BaseContainer profiles
    /// created by the OS via `CreateProcessInSandbox`).
    pub fn clear_policy(app_container_name: &str, logger: &mut Logger) {
        let mut mgr = Self::new(app_container_name.to_string());
        mgr.configured = true;
        mgr.remove_configuration(logger);
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
            if is_denied(path, &policy.denied_paths) {
                logger.log_line(&format!(
                    "Skipping readwrite path {:?} — overridden by deniedPaths",
                    path
                ));
                continue;
            }
            let mut inherit = test_for_root_path(path);
            if inherit && has_denied_children(path, &policy.denied_paths) {
                logger.log_line(&format!(
                    "Warning: readwrite path {:?} has denied sub-paths; \
                     disabling inheritance to limit scope. \
                     BFS cannot deny individual sub-paths under a granted parent.",
                    path
                ));
                inherit = false;
            }
            if let Err(e) = self.add_bfs_path(path, inherit, logger) {
                self.remove_configuration(logger);
                return Err(e);
            }
            self.configured = true;
        }

        for path in &policy.readonly_paths {
            if is_denied(path, &policy.denied_paths) {
                logger.log_line(&format!(
                    "Skipping readonly path {:?} — overridden by deniedPaths",
                    path
                ));
                continue;
            }
            let mut inherit = test_for_root_path(path);
            if inherit && has_denied_children(path, &policy.denied_paths) {
                logger.log_line(&format!(
                    "Warning: readonly path {:?} has denied sub-paths; \
                     disabling inheritance to limit scope. \
                     BFS cannot deny individual sub-paths under a granted parent.",
                    path
                ));
                inherit = false;
            }
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

/// Returns `true` if `path` is equal to, or is a child of, any entry in
/// `denied_paths`. Comparison is case-insensitive and separator-normalized
/// to match Windows filesystem semantics.
fn is_denied(path: &str, denied_paths: &[String]) -> bool {
    let normalized = normalize_for_comparison(path);
    denied_paths.iter().any(|denied| {
        let denied_norm = normalize_for_comparison(denied);
        // Exact match
        if normalized == denied_norm {
            return true;
        }
        // Child path: `path` starts with `denied` + separator
        let prefix = format!("{}\\", denied_norm);
        normalized.starts_with(&prefix)
    })
}

/// Returns `true` if any entry in `denied_paths` is a child of `path`.
/// This detects the case where BFS would grant broad access (e.g. `C:\Users`
/// with inheritance) that covers a denied sub-path (e.g. `C:\Users\secret`).
/// BFS has no deny primitive, so we cannot selectively exclude sub-paths
/// once a parent is granted.
fn has_denied_children(path: &str, denied_paths: &[String]) -> bool {
    let normalized = normalize_for_comparison(path);
    let prefix = format!("{}\\", normalized);
    denied_paths.iter().any(|denied| {
        let denied_norm = normalize_for_comparison(denied);
        denied_norm.starts_with(&prefix)
    })
}

/// Lowercase, normalize separators to `\`, and strip trailing separator
/// for consistent comparison.
fn normalize_for_comparison(path: &str) -> String {
    let lower = path.to_lowercase().replace('/', "\\");
    lower.trim_end_matches('\\').to_string()
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

    #[test]
    fn is_denied_exact_match() {
        let denied = vec![r"C:\temp".to_string()];
        assert!(is_denied(r"C:\temp", &denied));
    }

    #[test]
    fn is_denied_case_insensitive() {
        let denied = vec![r"C:\Temp".to_string()];
        assert!(is_denied(r"C:\temp", &denied));
        assert!(is_denied(r"C:\TEMP", &denied));
    }

    #[test]
    fn is_denied_child_path() {
        let denied = vec![r"C:\temp".to_string()];
        assert!(is_denied(r"C:\temp\subdir", &denied));
        assert!(is_denied(r"C:\temp\file.txt", &denied));
    }

    #[test]
    fn is_denied_not_prefix_of_different_path() {
        let denied = vec![r"C:\temp".to_string()];
        // "C:\temporary" should NOT be denied — it's not under "C:\temp\"
        assert!(!is_denied(r"C:\temporary", &denied));
    }

    #[test]
    fn is_denied_no_match() {
        let denied = vec![r"C:\secrets".to_string()];
        assert!(!is_denied(r"C:\temp", &denied));
        assert!(!is_denied(r"C:\Users", &denied));
    }

    #[test]
    fn is_denied_trailing_separator() {
        let denied = vec![r"C:\temp\".to_string()];
        assert!(is_denied(r"C:\temp", &denied));
        assert!(is_denied(r"C:\temp\file.txt", &denied));
    }

    #[test]
    fn is_denied_mixed_separators() {
        let denied = vec!["C:/temp".to_string()];
        assert!(is_denied(r"C:\temp", &denied));
        assert!(is_denied(r"C:\temp\subdir", &denied));

        let denied2 = vec![r"C:\temp".to_string()];
        assert!(is_denied("C:/temp", &denied2));
        assert!(is_denied("C:/temp/subdir", &denied2));
    }

    #[test]
    fn has_denied_children_detects_sub_path() {
        let denied = vec![r"C:\Users\secret".to_string()];
        assert!(has_denied_children(r"C:\Users", &denied));
    }

    #[test]
    fn has_denied_children_no_match() {
        let denied = vec![r"C:\secrets".to_string()];
        assert!(!has_denied_children(r"C:\Users", &denied));
    }

    #[test]
    fn has_denied_children_exact_match_is_not_child() {
        let denied = vec![r"C:\Users".to_string()];
        // Exact match is not a "child" — it's handled by is_denied
        assert!(!has_denied_children(r"C:\Users", &denied));
    }
}
