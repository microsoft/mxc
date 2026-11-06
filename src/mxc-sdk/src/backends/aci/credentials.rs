// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Resource Manager (ARM) access tokens for the ACI backend.
//!
//! A pre-acquired token in [`ARM_TOKEN_ENV`] takes precedence, which suits
//! automation that signs in with a workload identity. Otherwise the Azure CLI
//! supplies a token for the account signed in with `az login`.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::mxc_common::mxc_error::MxcError;

/// Environment variable holding a pre-acquired ARM access token.
pub(super) const ARM_TOKEN_ENV: &str = "MXC_ACI_ARM_TOKEN";
const ARM_RESOURCE: &str = "https://management.azure.com/";
const CLI_TIMEOUT: Duration = Duration::from_secs(120);
const CLI_POLL: Duration = Duration::from_millis(50);
const CLI_ERROR_LIMIT: usize = 1024;

/// A bearer token or connection secret that must never be logged.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Secret(String);

impl Secret {
    /// Accepts a token that can be sent in an HTTP `Authorization` header.
    pub fn new(value: String, what: &str) -> Result<Self, MxcError> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(MxcError::backend_error(format!(
                "ACI {what} is empty or contains characters that cannot be sent in an HTTP header"
            )));
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

/// An ARM access token for `subscription`.
pub(super) fn arm_token(subscription: &str) -> Result<Secret, MxcError> {
    if let Some(token) = std::env::var_os(ARM_TOKEN_ENV).filter(|token| !token.is_empty()) {
        let token = token.into_string().map_err(|_| {
            MxcError::backend_unavailable(format!("{ARM_TOKEN_ENV} is not valid Unicode"))
        })?;
        return Secret::new(token, &format!("token in {ARM_TOKEN_ENV}"))
            .map_err(|error| MxcError::backend_unavailable(error.message));
    }
    let cli = find_azure_cli().ok_or_else(|| {
        MxcError::backend_unavailable(format!(
            "ACI needs Azure credentials: install the Azure CLI and run `az login`, or set \
             {ARM_TOKEN_ENV} to an access token for {ARM_RESOURCE}"
        ))
    })?;
    azure_cli_token(&cli, subscription)
}

fn azure_cli_token(cli: &Path, subscription: &str) -> Result<Secret, MxcError> {
    let mut child = Command::new(cli)
        .args([
            "account",
            "get-access-token",
            "--resource",
            ARM_RESOURCE,
            "--subscription",
            subscription,
            "--output",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot run the Azure CLI at {}: {error}",
                cli.display()
            ))
        })?;
    // Drain both pipes while waiting so a chatty CLI cannot block on a full pipe.
    let mut stdout = child.stdout.take().map(read_in_background);
    let mut stderr = child.stderr.take().map(read_in_background);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < CLI_TIMEOUT => std::thread::sleep(CLI_POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MxcError::backend_unavailable(format!(
                    "the Azure CLI did not return an access token within {} s",
                    CLI_TIMEOUT.as_secs()
                )));
            }
            Err(error) => {
                return Err(MxcError::backend_unavailable(format!(
                    "cannot wait for the Azure CLI: {error}"
                )));
            }
        }
    };
    let stdout = stdout.take().map(join_reader).unwrap_or_default();
    let stderr = stderr.take().map(join_reader).unwrap_or_default();
    if !status.success() {
        return Err(MxcError::backend_unavailable(format!(
            "the Azure CLI could not get an access token for subscription {subscription} \
             ({status}); run `az login` with an account that can use the sandbox group: {}",
            bounded(&String::from_utf8_lossy(&stderr))
        )));
    }
    parse_cli_token(&stdout)
}

fn parse_cli_token(stdout: &[u8]) -> Result<Secret, MxcError> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CliToken {
        access_token: String,
    }
    let token: CliToken = serde_json::from_slice(stdout).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "the Azure CLI returned an unexpected access-token response: {error}"
        ))
    })?;
    Secret::new(token.access_token, "access token from the Azure CLI")
        .map_err(|error| MxcError::backend_unavailable(error.message))
}

fn read_in_background(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}

fn join_reader(handle: std::thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

fn bounded(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(CLI_ERROR_LIMIT) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

/// The Azure CLI launcher on `PATH`. On Windows the CLI is the batch file
/// `az.cmd`, which `Command` cannot find by its bare name.
fn find_azure_cli() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["az.cmd", "az.exe"]
    } else {
        &["az"]
    };
    find_on_path(std::env::var_os("PATH")?.as_os_str(), names)
}

fn find_on_path(path: &std::ffi::OsStr, names: &[&str]) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn secrets_are_redacted_and_must_fit_an_http_header() {
        let secret = Secret::new("eyJ0.eyJ1.sig".to_owned(), "token").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(secret.expose(), "eyJ0.eyJ1.sig");
        for value in ["", "has space", "line\nbreak", "caf\u{e9}"] {
            let error = Secret::new(value.to_owned(), "token").unwrap_err();
            assert!(
                !error.message.contains(value) || value.is_empty(),
                "{error}"
            );
        }
    }

    #[test]
    fn cli_token_parsing_reads_only_the_access_token() {
        let token = parse_cli_token(
            br#"{"accessToken":"eyJ0.eyJ1.sig","expiresOn":"2026-11-06 19:00:00.000000","subscription":"s","tenant":"t","tokenType":"Bearer"}"#,
        )
        .unwrap();
        assert_eq!(token.expose(), "eyJ0.eyJ1.sig");
        for output in [
            &b"not json"[..],
            br#"{"token":"x"}"#,
            br#"{"accessToken":""}"#,
        ] {
            let error = parse_cli_token(output).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        }
    }

    #[test]
    fn cli_lookup_ignores_relative_path_entries() {
        let directory = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) { "az.cmd" } else { "az" };
        std::fs::write(directory.path().join(name), "").unwrap();
        let path =
            std::env::join_paths([PathBuf::from("relative"), directory.path().to_path_buf()])
                .unwrap();
        assert_eq!(
            find_on_path(&path, &[name]),
            Some(directory.path().join(name))
        );
        let relative_only = std::env::join_paths([PathBuf::from(".")]).unwrap();
        assert_eq!(find_on_path(&relative_only, &[name]), None);
    }

    #[test]
    fn cli_errors_are_bounded() {
        assert_eq!(bounded("  short  "), "short");
        let long = "x".repeat(CLI_ERROR_LIMIT + 10);
        assert_eq!(bounded(&long).len(), CLI_ERROR_LIMIT + 3);
    }
}
