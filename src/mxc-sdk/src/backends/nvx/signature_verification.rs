// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME, CertFreeCertificateChain, CertGetCertificateChain,
    CertGetNameStringW, CERT_CHAIN_PARA, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    CRYPT_PROVIDER_SGNR, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

const MICROSOFT: &str = "Microsoft Corporation";
const BINARIES: [&str; 3] = ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"];
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Keeps the checked files from being overwritten or deleted while the runtime uses them.
#[derive(Debug)]
pub(crate) struct VerifiedBundle {
    _files: [File; 3],
    _directories: [File; 2],
}

pub(crate) fn verify_bundle(directory: &Path) -> io::Result<VerifiedBundle> {
    let directory = directory.canonicalize()?;
    let root = lock_directory(&directory)?;
    let bin = lock_directory(&directory.join("bin"))?;
    let [agent, vmm, images] = BINARIES.map(|name| directory.join("bin").join(name));
    Ok(VerifiedBundle {
        _files: [
            verify_file(&agent)?,
            verify_file(&vmm)?,
            verify_file(&images)?,
        ],
        _directories: [bin, root],
    })
}

fn lock_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    reject_reparse_point(&directory, path)?;
    Ok(directory)
}

fn reject_reparse_point(file: &File, path: &Path) -> io::Result<()> {
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(format!(
            "NVX signature verification refuses a reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn verify_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot open NVX binary {} for signature verification: {error}",
                    path.display()
                ),
            )
        })?;
    reject_reparse_point(&file, path)?;
    let path = path.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot resolve NVX signature path {}: {error}",
                path.display()
            ),
        )
    })?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut information = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE(file.as_raw_handle()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut information,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // The path, information and file stay alive through verification and state cleanup.
    let status = unsafe {
        WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let verified = if status == 0 {
        verified_publisher(&data)
    } else {
        Err(io::Error::other(format!(
            "Authenticode trust verification failed (0x{:08X}); certificate trust and revocation must be verifiable",
            status as u32
        )))
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // Every VERIFY call must be paired with CLOSE, including failed verification.
    let close_status = unsafe {
        WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if let Err(error) = verified {
        let cleanup = if close_status == 0 {
            String::new()
        } else {
            format!(
                "; verification-state cleanup failed (0x{:08X})",
                close_status as u32
            )
        };
        return Err(io::Error::other(format!(
            "NVX signature rejected for {}: {error}{cleanup}",
            path.display()
        )));
    }
    if close_status != 0 {
        return Err(io::Error::other(format!(
            "cannot close signature verification state for {} (0x{:08X})",
            path.display(),
            close_status as u32
        )));
    }
    Ok(file)
}

fn verified_publisher(data: &WINTRUST_DATA) -> io::Result<()> {
    // These pointers belong to the successfully verified WinTrust state, not a separately
    // parsed certificate or timestamp signer. They are used only before STATEACTION_CLOSE.
    unsafe {
        let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if provider.is_null() {
            return Err(io::Error::other(
                "WinTrust returned no verified signer state",
            ));
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        let signer = signer
            .as_ref()
            .ok_or_else(|| io::Error::other("WinTrust returned no verified signer"))?;
        verify_signer_chains(signer, &mut |signer| {
            verify_certificate_chain(signer_certificate(signer)?, &signer.sftVerifyAsOf)
        })?;
        let certificate = signer_certificate(signer)?;
        let common_name = certificate_attribute(certificate, szOID_COMMON_NAME)?;
        let organization = certificate_attribute(certificate, szOID_ORGANIZATION_NAME)?;
        if common_name != MICROSOFT || organization != MICROSOFT {
            return Err(io::Error::other(format!(
                "expected Microsoft Corporation publisher, got CN={common_name}, O={organization}"
            )));
        }
    }
    Ok(())
}

unsafe fn signer_certificate(signer: &CRYPT_PROVIDER_SGNR) -> io::Result<*const CERT_CONTEXT> {
    if signer.dwError != 0 || signer.csCertChain == 0 || signer.pasCertChain.is_null() {
        return Err(io::Error::other(format!(
            "WinTrust returned an invalid signer chain (0x{:08X})",
            signer.dwError
        )));
    }
    let certificate = unsafe { (*signer.pasCertChain).pCert };
    if certificate.is_null() {
        return Err(io::Error::other("WinTrust returned no signer certificate"));
    }
    Ok(certificate)
}

unsafe fn verify_signer_chains(
    signer: &CRYPT_PROVIDER_SGNR,
    verify: &mut impl FnMut(&CRYPT_PROVIDER_SGNR) -> io::Result<()>,
) -> io::Result<()> {
    // Counter-signers, including timestamp authorities, share the live WinTrust state.
    // They need trusted chains, but are not required to be Microsoft publishers.
    let mut pending = vec![(signer, false)];
    while let Some((signer, timestamp)) = pending.pop() {
        verify(signer).map_err(|error| {
            if timestamp {
                io::Error::other(format!("timestamp signer verification failed: {error}"))
            } else {
                error
            }
        })?;
        if signer.csCounterSigners != 0 && signer.pasCounterSigners.is_null() {
            return Err(io::Error::other(
                "WinTrust returned no timestamp signer data",
            ));
        }
        for index in (0..signer.csCounterSigners).rev() {
            let counter = unsafe { &*signer.pasCounterSigners.add(index as usize) };
            pending.push((counter, true));
        }
    }
    Ok(())
}

unsafe fn verify_certificate_chain(
    certificate: *const CERT_CONTEXT,
    verified_time: &FILETIME,
) -> io::Result<()> {
    let parameters = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain = std::ptr::null_mut();
    // Inspect raw chain errors independently of Authenticode's optional offline policy.
    unsafe {
        CertGetCertificateChain(
            None,
            certificate,
            Some(verified_time),
            Some((*certificate).hCertStore),
            &parameters,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            None,
            &mut chain,
        )
    }
    .map_err(|error| {
        io::Error::other(format!("cannot verify signer certificate chain: {error}"))
    })?;
    let chain = std::ptr::NonNull::new(chain)
        .ok_or_else(|| io::Error::other("no verified signer certificate chain"))?;
    // WinTrust supplies the current time or its validated signing timestamp.
    // Revocation and root trust still use current Windows trust data.
    // SAFETY: the successful call allocated this non-null context; release follows the read.
    let status = unsafe { chain.as_ref().TrustStatus.dwErrorStatus };
    unsafe { CertFreeCertificateChain(chain.as_ptr()) };
    require_trusted_chain(status)
}

fn require_trusted_chain(status: u32) -> io::Result<()> {
    if status != 0 {
        return Err(io::Error::other(format!(
            "signer certificate chain trust or revocation is not verified (0x{status:08X})"
        )));
    }
    Ok(())
}

unsafe fn certificate_attribute(
    certificate: *const CERT_CONTEXT,
    attribute: PCSTR,
) -> io::Result<String> {
    // The certificate is owned by live, successfully verified WinTrust state.
    let length = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            Some(attribute.as_ptr().cast()),
            None,
        )
    };
    if length <= 1 {
        return Err(io::Error::other(
            "verified signer has no publisher attribute",
        ));
    }
    let mut buffer = vec![0; length as usize];
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            Some(attribute.as_ptr().cast()),
            Some(&mut buffer),
        )
    };
    if written != length {
        return Err(io::Error::other("cannot read verified publisher attribute"));
    }
    String::from_utf16(&buffer[..buffer.len() - 1])
        .map_err(|error| io::Error::other(format!("invalid publisher name: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_chain_error_fails_closed_including_unknown_revocation() {
        assert!(require_trusted_chain(0).is_ok());
        for bit in 0..32 {
            let status = 1u32 << bit;
            let error = require_trusted_chain(status).unwrap_err();
            assert!(
                error.to_string().contains(&format!("0x{status:08X}")),
                "{error}"
            );
        }
    }

    #[test]
    fn primary_success_cannot_mask_an_unverified_timestamp_chain() {
        for status in [0x40, 0x0100_0000, 0x4, 0x20] {
            let mut timestamp = CRYPT_PROVIDER_SGNR {
                dwError: status,
                ..Default::default()
            };
            let signer = CRYPT_PROVIDER_SGNR {
                csCounterSigners: 1,
                pasCounterSigners: &mut timestamp,
                ..Default::default()
            };
            let mut visited = Vec::new();
            let error = unsafe {
                verify_signer_chains(&signer, &mut |chain| {
                    visited.push(chain.dwError);
                    require_trusted_chain(chain.dwError)
                })
            }
            .unwrap_err();
            assert_eq!(visited, [0, status]);
            assert!(error.to_string().contains("timestamp signer"), "{error}");
        }
        let signer = CRYPT_PROVIDER_SGNR {
            csCounterSigners: 1,
            ..Default::default()
        };
        let error = unsafe { verify_signer_chains(&signer, &mut |_| Ok(())) }.unwrap_err();
        assert!(
            error.to_string().contains("no timestamp signer data"),
            "{error}"
        );
    }
}
