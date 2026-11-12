// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::frame::{encode_frame, FrameType, MAX_FRAME_PAYLOAD};
use crate::mxc_common::{models::ExecutionRequest, mxc_error::MxcError};
use std::collections::BTreeMap;

pub(crate) struct ExecStartPayload {
    frame: Vec<u8>,
    pub(super) client_budget: std::time::Duration,
}

impl ExecStartPayload {
    pub(super) fn from_request(request: &ExecutionRequest) -> Result<Self, MxcError> {
        if request.script_code.trim().is_empty()
            || request.script_code.contains('\0')
            || request.working_directory.contains('\0')
        {
            return Err(MxcError::policy_validation(
                "W365 exec requires a nonblank Windows executable command line and NUL-free cwd",
            ));
        }
        if request.env.is_some() && !request.inherit_default_env {
            return Err(MxcError::policy_validation("W365 exec cannot replace the guest environment; supplied env requires inheritDefaultEnv: true"));
        }
        let mut env = BTreeMap::new();
        for entry in request.env.iter().flatten() {
            let (key, value) = entry.split_once('=').unwrap_or((entry, ""));
            if key.is_empty() || key.contains('\0') || value.contains('\0') {
                return Err(MxcError::policy_validation(
                    "W365 env requires nonempty NUL-free names and NUL-free values",
                ));
            }
            env.insert(key, value);
        }
        let mut payload = serde_json::json!({
            "command": request.script_code,
            // MXC commandLine launches an executable; do not invoke an implicit shell.
            "shell": "raw", "mode": "pipe", "timeoutMs": request.script_timeout,
        });
        if !request.working_directory.is_empty() {
            payload["cwd"] = serde_json::json!(request.working_directory);
        }
        if request.env.is_some() {
            payload["env"] = serde_json::json!(env);
        }
        let bytes = serde_json::to_vec(&payload)
            .map_err(|_| MxcError::backend_error("cannot encode W365 ExecStart"))?;
        if bytes.len() > MAX_FRAME_PAYLOAD {
            return Err(MxcError::policy_validation(
                "W365 ExecStart exceeds 65536 bytes; nothing was sent",
            ));
        }
        // Zero selects the released server's default, not unlimited execution.
        let timeout = if request.script_timeout == 0 {
            300_000
        } else {
            u64::from(request.script_timeout)
        };
        Ok(Self {
            frame: encode_frame(FrameType::ExecStart, &bytes),
            client_budget: std::time::Duration::from_millis(timeout + 30_000),
        })
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, MxcError> {
        Ok(self.frame.clone())
    }
}

#[derive(serde::Deserialize)]
pub(super) struct ExitPayload {
    #[serde(rename = "code")]
    pub exit_code: i32,
}

#[derive(serde::Deserialize)]
pub(super) struct ErrorPayload {
    pub code: String,
    pub message: String,
}

pub(super) fn parse_exit(bytes: &[u8]) -> Result<ExitPayload, MxcError> {
    serde_json::from_slice(bytes).map_err(|_| MxcError::backend_error("invalid Exit payload"))
}

pub(super) fn parse_error(bytes: &[u8]) -> Result<ErrorPayload, MxcError> {
    serde_json::from_slice(bytes).map_err(|_| MxcError::backend_error("invalid Error payload"))
}

pub(super) fn parse_started(bytes: &[u8]) -> Result<(), MxcError> {
    #[derive(serde::Deserialize)]
    struct Started {
        pid: u32,
    }
    let started: Started = serde_json::from_slice(bytes)
        .map_err(|_| MxcError::backend_error("invalid Started payload"))?;
    if started.pid == 0 {
        return Err(MxcError::backend_error("invalid Started pid"));
    }
    Ok(())
}
