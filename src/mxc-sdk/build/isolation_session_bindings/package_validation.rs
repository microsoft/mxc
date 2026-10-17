// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const APP_DLL: &str = "IsoSessionApp.dll";
const RUNTIME_MANIFEST: &str = "IsoSession.manifest";
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub(super) fn package_file_name(package_id: &str, package_version: &str) -> String {
    format!(
        "{}.{}.nupkg",
        package_id.to_ascii_lowercase(),
        package_version
    )
}

pub(super) fn package_runtime_instance(package_version: &str) -> Result<String, String> {
    let mut parts = package_version.split('.');
    let prefix = parts.next();
    let release = parts.next();
    let patch = parts.next();
    if prefix != Some("0")
        || parts.next().is_some()
        || !patch.is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        || !release.is_some_and(|value| {
            value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(format!(
            "IsolationSession SDK package version must use 0.YYYYMM.patch, got {package_version:?}"
        ));
    }

    let release = release.unwrap();
    Ok(format!("{}.{}", &release[..4], &release[4..]))
}

pub(super) fn validate_runtime_manifest(manifest: &[u8], instance: &str) -> Result<(), String> {
    let content = std::str::from_utf8(manifest)
        .map_err(|e| format!("{RUNTIME_MANIFEST} is not valid UTF-8: {e}"))?;
    for required in [
        "<assemblyIdentity name=\"IsoSession.Runtime\"",
        "<file name=\"IsoSessionApp.dll\"",
    ] {
        if !content.contains(required) {
            return Err(format!("{RUNTIME_MANIFEST} is missing {required:?}"));
        }
    }

    let expected_instance = format!("name=\"{instance}\"");
    if !content.contains(&expected_instance) {
        return Err(format!(
            "{RUNTIME_MANIFEST} does not identify runtime instance {instance:?}"
        ));
    }
    Ok(())
}

pub(super) fn validate_runtime_architecture(
    binary: &[u8],
    target_arch: &str,
) -> Result<(), String> {
    if target_arch != "x86_64" {
        return Err(format!(
            "IsolationSession lifted runtime supports only target architecture \"x86_64\"; \
             the pinned SDK package contains one AMD64 {APP_DLL}, so {target_arch:?} cannot be \
             built until an architecture-specific payload is published"
        ));
    }

    if binary.len() < 0x40 || &binary[..2] != b"MZ" {
        return Err(format!("{APP_DLL} is not a valid PE image"));
    }
    let pe_offset = u32::from_le_bytes(
        binary[0x3c..0x40]
            .try_into()
            .expect("slice length is checked"),
    ) as usize;
    let machine_end = pe_offset
        .checked_add(6)
        .ok_or_else(|| format!("{APP_DLL} has an invalid PE header offset"))?;
    if machine_end > binary.len() || &binary[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(format!("{APP_DLL} has an invalid PE header"));
    }

    let actual_machine = u16::from_le_bytes(
        binary[pe_offset + 4..machine_end]
            .try_into()
            .expect("slice length is checked"),
    );
    if actual_machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!(
            "{APP_DLL} machine type 0x{actual_machine:04X} does not match Cargo target \
             architecture \"x86_64\" (expected 0x{IMAGE_FILE_MACHINE_AMD64:04X})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        package_file_name, package_runtime_instance, validate_runtime_architecture,
        validate_runtime_manifest, IMAGE_FILE_MACHINE_AMD64,
    };

    const MANIFEST: &str = "\
<assembly>
  <assemblyIdentity name=\"IsoSession.Runtime\" />
  <file name=\"IsoSessionApp.dll\" />
  <iso:instance name=\"2026.10\" />
</assembly>";

    #[test]
    fn package_version_maps_to_runtime_instance() {
        assert_eq!(
            package_runtime_instance("0.202610.5").unwrap(),
            "2026.10"
        );
    }

    #[test]
    fn package_file_name_uses_nuget_packages_layout() {
        assert_eq!(
            package_file_name("Microsoft.AI.IsolationSession.SDK", "0.202610.5"),
            "microsoft.ai.isolationsession.sdk.0.202610.5.nupkg"
        );
    }

    #[test]
    fn completed_runtime_manifest_is_accepted() {
        validate_runtime_manifest(MANIFEST.as_bytes(), "2026.10").unwrap();
    }

    #[test]
    fn mismatched_runtime_manifest_is_rejected() {
        let error = validate_runtime_manifest(MANIFEST.as_bytes(), "2026.11").unwrap_err();
        assert!(error.contains("does not identify runtime instance"));
    }

    fn pe_image(machine: u16) -> Vec<u8> {
        let mut image = vec![0; 0x80];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        image[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        image
    }

    #[test]
    fn runtime_architecture_accepts_amd64_for_x86_64() {
        validate_runtime_architecture(&pe_image(IMAGE_FILE_MACHINE_AMD64), "x86_64").unwrap();
    }

    #[test]
    fn runtime_architecture_rejects_non_amd64_payload() {
        let error = validate_runtime_architecture(&pe_image(0xAA64), "x86_64").unwrap_err();
        assert!(error.contains("does not match Cargo target architecture"));
    }

    #[test]
    fn runtime_architecture_rejects_unsupported_target() {
        let error =
            validate_runtime_architecture(&pe_image(IMAGE_FILE_MACHINE_AMD64), "aarch64")
                .unwrap_err();
        assert!(error.contains("supports only target architecture"));
    }

    #[test]
    fn runtime_architecture_rejects_invalid_pe() {
        let error = validate_runtime_architecture(b"not a PE", "x86_64").unwrap_err();
        assert!(error.contains("not a valid PE image"));
    }

    #[test]
    fn runtime_architecture_rejects_truncated_pe_header() {
        let mut image = pe_image(IMAGE_FILE_MACHINE_AMD64);
        image.truncate(0x44);

        let error = validate_runtime_architecture(&image, "x86_64").unwrap_err();
        assert!(error.contains("invalid PE header"));
    }
}
