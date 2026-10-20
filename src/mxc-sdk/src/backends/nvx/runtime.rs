// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};

use aci_edge_sandboxes::agent::AgentConfig;
use aci_edge_sandboxes::AciEdgeSandbox;
use aci_edge_sandboxes::{ImageSource, SandboxSpec};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

pub(super) fn create_client(state_root: &Path) -> Result<AciEdgeSandbox, MxcError> {
    let config = AgentConfig::bundled(state_root).map_err(map_nvx_error)?;
    AciEdgeSandbox::agent(config).map_err(map_nvx_error)
}

pub(super) fn lifecycle_state_root() -> Result<PathBuf, MxcError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        MxcError::backend_unavailable(
            "cannot resolve LOCALAPPDATA for the persistent NVX lifecycle state",
        )
    })?;
    let state_root = PathBuf::from(local_app_data)
        .join("Microsoft")
        .join("MXC")
        .join("nvx");
    admit_persistent_state_root(&state_root)?;
    Ok(state_root)
}

fn admit_persistent_state_root(state_root: &Path) -> Result<(), MxcError> {
    let parent = state_root.parent().ok_or_else(|| {
        MxcError::backend_unavailable("persistent NVX lifecycle state path has no parent")
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "cannot create the persistent NVX lifecycle state parent '{}': {error}",
            parent.display()
        ))
    })?;

    match crate::mxc_common::filesystem_dacl::create_owner_only_directory(state_root, true)
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot create persistent NVX lifecycle state root '{}': {error}",
                state_root.display()
            ))
        })? {
        crate::mxc_common::filesystem_dacl::CreateDirectoryDisposition::Created => {
            if let Err(error) = validate_private_state_root(state_root, "new ") {
                let _ = std::fs::remove_dir(state_root);
                return Err(error);
            }
        }
        crate::mxc_common::filesystem_dacl::CreateDirectoryDisposition::AlreadyExists => {
            validate_private_state_root(state_root, "")?;
        }
    }
    Ok(())
}

fn validate_private_state_root(state_root: &Path, prefix: &str) -> Result<(), MxcError> {
    let metadata = std::fs::symlink_metadata(state_root).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "cannot inspect {prefix}persistent NVX lifecycle state root '{}': {error}",
            state_root.display()
        ))
    })?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(MxcError::backend_unavailable(format!(
            "refusing {prefix}persistent NVX lifecycle state root '{}': expected a directory without a reparse point",
            state_root.display()
        )));
    }
    let secure = crate::mxc_common::filesystem_dacl::validate_owner_only_directory(state_root)
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot validate {prefix}persistent NVX lifecycle state root '{}': {error}",
                state_root.display()
            ))
        })?;
    if !secure {
        return Err(MxcError::backend_unavailable(format!(
            "refusing {prefix}persistent NVX lifecycle state root '{}': owner or ACL is not private",
            state_root.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT.0
        != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) fn sandbox_spec(image: &str) -> Result<SandboxSpec, MxcError> {
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(SandboxSpec::new().with_image(ImageSource::Reference(image.to_owned())))
}

pub(super) fn map_nvx_error(error: aci_edge_sandboxes::Error) -> MxcError {
    let code = match error.code() {
        aci_edge_sandboxes::ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        aci_edge_sandboxes::ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        aci_edge_sandboxes::ErrorCode::StaleId => MxcErrorCode::StaleId,
        aci_edge_sandboxes::ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        aci_edge_sandboxes::ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        aci_edge_sandboxes::ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        _ => MxcErrorCode::BackendError,
    };
    MxcError::new(
        code,
        format!("NVX signed bundled agent: {}", error.message()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn persistent_state_admission_creates_private_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nvx");

        admit_persistent_state_root(&root).unwrap();

        assert!(crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap());
    }

    #[test]
    fn persistent_state_admission_rejects_permissive_existing_root_without_repair() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nvx");
        std::fs::create_dir(&root).unwrap();
        assert!(
            !crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap(),
            "test root unexpectedly inherited the exact private MXC DACL"
        );

        let error = admit_persistent_state_root(&root).unwrap_err();

        assert!(error.message.contains("owner or ACL is not private"));
        assert!(
            !crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap(),
            "admission must not repair an existing permissive root"
        );
    }

    #[test]
    fn persistent_state_admission_rejects_junction() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        let root = parent.path().join("nvx");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                root.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mklink /J failed ({status}); junction creation needs no elevation"
        );

        let error = admit_persistent_state_root(&root).unwrap_err();

        assert!(error.message.contains("without a reparse point"));
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn persistent_state_admission_is_race_safe_for_concurrent_initialization() {
        let parent = tempfile::tempdir().unwrap();
        let root = Arc::new(parent.path().join("nvx"));
        let workers = 8usize;
        let barrier = Arc::new(Barrier::new(workers));
        let mut joins = Vec::with_capacity(workers);

        for _ in 0..workers {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                admit_persistent_state_root(root.as_path())
            }));
        }

        for join in joins {
            join.join()
                .expect("worker thread panicked")
                .expect("concurrent admission call failed");
        }

        assert!(
            crate::mxc_common::filesystem_dacl::validate_owner_only_directory(root.as_path())
                .expect("validate final root ACL")
        );
    }
}
