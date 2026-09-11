// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::ContainerPolicy;
#[cfg(feature = "tier2_bfs")]
use wxc_common::process_util;

#[cfg(feature = "tier2_bfs")]
pub(crate) const BFSCFG_EXE: &str = "bfscfg.exe";
const UNABLE_TO_PERFORM: &str = "Unable to perform policy operation";
#[cfg(feature = "tier2_bfs")]
const BFSCFG_TIMEOUT_MS: u32 = 10_000;

/// Manages the BFS (Brokered File System) policy for an AppContainer.
///
/// `bfscfg_path` is the **absolute path** of `bfscfg.exe` resolved at
/// detector probe time (see
/// [`crate::fallback_detector::find_bfscfg_exe`]). It is passed verbatim
/// as `lpApplicationName` to `CreateProcessW` so probe and execution
/// agree on the binary, defeating executable-search-order hijacking.
///
/// `bfscfg_path` may be `None` when the caller has not yet resolved a
/// path — e.g. cleanup paths that need to be able to delete an
/// AppContainer profile even when the BFS broker is not available on
/// this host. In that case [`Self::configure`] returns an error when the
/// policy actually requires BFS; [`Self::remove_configuration`] is a
/// no-op when nothing was configured.
pub struct FileSystemBfsManager {
    app_container_name: String,
    bfscfg_path: Option<PathBuf>,
    configured: bool,
}

impl FileSystemBfsManager {
    pub fn new(app_container_name: String, bfscfg_path: Option<PathBuf>) -> Self {
        Self {
            app_container_name,
            bfscfg_path,
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
        let bfscfg_path = crate::fallback_detector::find_bfscfg_exe().unwrap_or(None);
        let mut mgr = Self::new(app_container_name.to_string(), bfscfg_path);
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

        if self.bfscfg_path.is_none() {
            return Err(WxcError::BfsNotAvailable);
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
        // Defence-in-depth gate. The primary safety guarantee is in
        // `fallback_detector::find_bfscfg_exe`, which returns `Ok(None)`
        // when the `tier2_bfs` feature is off — so `configure()` errors
        // out before reaching this method. The gate here ensures no
        // future caller can reach the spawn site without flipping the
        // feature.
        #[cfg(not(feature = "tier2_bfs"))]
        {
            let _ = (self, args);
            Err(WxcError::FilesystemPolicy(
                "bfscfg.exe invocation refused: tier2_bfs feature is not enabled".to_string(),
            ))
        }
        #[cfg(feature = "tier2_bfs")]
        {
            // Resolved at probe time; `configure` errors before we get here
            // when this is `None`. The `remove_configuration` path also
            // requires it via `configured = true`, which only flips after a
            // successful `configure` (i.e. after a successful resolve).
            let bfscfg_path = self.bfscfg_path.as_ref().ok_or_else(|| {
                WxcError::FilesystemPolicy(
                    "bfscfg.exe path not resolved; refusing to invoke by bare name".to_string(),
                )
            })?;
            let bfscfg_path_str = bfscfg_path.to_str().ok_or_else(|| {
                WxcError::FilesystemPolicy(format!(
                    "bfscfg.exe path is not valid UTF-8: {}",
                    bfscfg_path.display()
                ))
            })?;
            let cmd_line = build_bfscfg_cmd_line(bfscfg_path_str, args);

            // Pass `lpApplicationName = Some(bfscfg_path_str)` so Windows
            // loads exactly this binary, bypassing the executable search
            // order. This is the security-critical half of the absolute-
            // path execution policy; the command-line argv[0] is purely
            // cosmetic for the child.
            let output = process_util::run_process_with_captured_output(
                Some(bfscfg_path_str),
                &cmd_line,
                BFSCFG_TIMEOUT_MS,
            )?;

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
}

/// Returns `false` for `C:\` (no inheritance), `true` for all other paths.
fn test_for_root_path(path: &str) -> bool {
    path != "C:\\"
}

// We control the arguments and ensure they are properly quoted, so this simple implementation
// is sufficient for our needs. Arguments are only quoted when they contain spaces. When quoting
// is needed, trailing backslashes are doubled to prevent them from escaping the closing quote
// (e.g. `C:\My Folder\` becomes `"C:\My Folder\\"` so bfscfg sees the path correctly).
//
// `exe_path` is the absolute path of `bfscfg.exe` and becomes argv[0]. It's quoted whenever it
// contains a space, which covers the unusual case of Windows installed under a path with spaces.
// Note that `lpApplicationName` (passed separately to `CreateProcessW`) is the authoritative
// source for *which* binary executes; this command line is only what the child sees as its
// argv. We still include the full absolute path here for tools that scrape it from logs.
#[cfg(feature = "tier2_bfs")]
fn build_bfscfg_cmd_line(exe_path: &str, args: &[&str]) -> String {
    let mut cmd_line = if exe_path.contains(' ') {
        let escaped = if exe_path.ends_with('\\') {
            format!("{}\\", exe_path)
        } else {
            exe_path.to_string()
        };
        format!("\"{escaped}\"")
    } else {
        exe_path.to_string()
    };
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
        let mgr = FileSystemBfsManager::new("test_container".to_string(), None);
        assert!(!mgr.configured());
    }

    // `build_bfscfg_cmd_line` only exists when the `tier2_bfs` feature
    // is compiled in; its tests must be gated the same way.
    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn test_build_cmd_line_quotes_args_with_spaces() {
        let cmd = build_bfscfg_cmd_line(
            r"C:\Windows\System32\bfscfg.exe",
            &[
                "--addpolicy",
                "--filename",
                r"C:\Program Files\PowerShell\7",
                "--appid",
                "test_container",
            ],
        );
        assert_eq!(
            cmd,
            r#"C:\Windows\System32\bfscfg.exe --addpolicy --filename "C:\Program Files\PowerShell\7" --appid test_container"#
        );
    }

    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn test_build_cmd_line_no_quotes_without_spaces() {
        let cmd = build_bfscfg_cmd_line(
            r"C:\Windows\System32\bfscfg.exe",
            &[
                "--addpolicy",
                "--policybrokerreadonly",
                "--filename",
                r"C:\Users",
                "--appid",
                "test",
            ],
        );
        assert_eq!(
            cmd,
            r"C:\Windows\System32\bfscfg.exe --addpolicy --policybrokerreadonly --filename C:\Users --appid test"
        );
    }

    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn test_build_cmd_line_trailing_backslash() {
        let cmd = build_bfscfg_cmd_line(
            r"C:\Windows\System32\bfscfg.exe",
            &[
                "--addpolicy",
                "--policybrokerreadonly",
                "--filename",
                r"C:\",
                "--appid",
                "test",
            ],
        );
        // C:\ has no spaces, so no quoting needed — trailing backslash is safe
        assert_eq!(
            cmd,
            r"C:\Windows\System32\bfscfg.exe --addpolicy --policybrokerreadonly --filename C:\ --appid test"
        );
    }

    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn test_build_cmd_line_path_with_spaces_and_trailing_backslash() {
        let cmd = build_bfscfg_cmd_line(
            r"C:\Windows\System32\bfscfg.exe",
            &[
                "--addpolicy",
                "--filename",
                r"C:\My Folder\",
                "--appid",
                "test",
            ],
        );
        // Trailing backslash is doubled inside quotes to prevent escaping the quote
        assert_eq!(
            cmd,
            r#"C:\Windows\System32\bfscfg.exe --addpolicy --filename "C:\My Folder\\" --appid test"#
        );
    }

    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn test_build_cmd_line_quotes_exe_path_with_spaces() {
        // Unusual but legal: Windows installed under a path with spaces.
        // The exe path itself must be quoted.
        let cmd = build_bfscfg_cmd_line(
            r"C:\My Windows\System32\bfscfg.exe",
            &["--clearpolicy", "--appid", "test"],
        );
        assert_eq!(
            cmd,
            r#""C:\My Windows\System32\bfscfg.exe" --clearpolicy --appid test"#
        );
    }
}
