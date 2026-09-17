// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimum host Windows version for the WSL Container backend.
//!
//! The floors are WSL 2's own documented system requirements, which differ by
//! processor architecture:
//! <https://learn.microsoft.com/windows/wsl/install-manual#step-2---check-requirements-for-running-wsl-2>
//!
//! They describe the in-box WSL 2 component; the lifted WSL package WSLC needs
//! installs only on build 19041 and later, which the SDK's own component probe
//! enforces.

use std::mem::size_of;
use std::sync::OnceLock;

use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
    PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

/// Windows 10 version 1903, the oldest build WSL 2 supports on x64.
const BUILD_1903: u32 = 18362;

/// Windows 10 version 1909.
const BUILD_1909: u32 = 18363;

/// Update build revision that brought WSL 2 to 1903 and 1909.
const MIN_UBR_1903_1909: u32 = 1049;

/// Windows 10 version 2004, the oldest build WSL 2 supports on ARM64.
const BUILD_2004: u32 = 19041;

const CURRENT_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

type RtlGetVersionFn = unsafe extern "system" fn(version_info: *mut OSVERSIONINFOW) -> NTSTATUS;

static OS_BUILD_NUMBER: OnceLock<u32> = OnceLock::new();
static OS_UPDATE_BUILD_REVISION: OnceLock<u32> = OnceLock::new();
static HOST_ARCHITECTURE: OnceLock<HostArchitecture> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostArchitecture {
    X64,
    Arm64,

    /// Any other architecture, and a host whose architecture could not be read.
    Other,
}

/// Reports whether this host meets the WSLC backend's minimum Windows version.
pub fn check_windows_version() -> Result<(), String> {
    let architecture = host_architecture();
    let build = os_build_number();
    let update_build_revision = os_update_build_revision();
    if meets_minimum(architecture, build, update_build_revision) {
        return Ok(());
    }

    let requirement = match architecture {
        HostArchitecture::Arm64 => {
            format!("Windows 10 version 2004 (build {BUILD_2004}) or later on ARM64")
        }
        _ => format!("Windows 10 version 1903 (build {BUILD_1903}.{MIN_UBR_1903_1909}) or later"),
    };
    Err(format!(
        "WSLc requires {requirement}; this host is build {}",
        format_build(build, update_build_revision)
    ))
}

/// An unreadable build or revision arrives here as `u32::MAX` and passes, so a
/// failed probe never withholds a backend the host may well support.
fn meets_minimum(architecture: HostArchitecture, build: u32, update_build_revision: u32) -> bool {
    match architecture {
        HostArchitecture::Arm64 => build >= BUILD_2004,
        _ => match build {
            BUILD_1903 | BUILD_1909 => update_build_revision >= MIN_UBR_1903_1909,
            _ => build > BUILD_1909,
        },
    }
}

fn format_build(build: u32, update_build_revision: u32) -> String {
    if update_build_revision == u32::MAX {
        build.to_string()
    } else {
        format!("{build}.{update_build_revision}")
    }
}

fn os_build_number() -> u32 {
    *OS_BUILD_NUMBER.get_or_init(read_build_number)
}

fn os_update_build_revision() -> u32 {
    *OS_UPDATE_BUILD_REVISION.get_or_init(read_update_build_revision)
}

fn host_architecture() -> HostArchitecture {
    *HOST_ARCHITECTURE.get_or_init(read_host_architecture)
}

/// Reads the build number from `RtlGetVersion`, which — unlike
/// `GetVersionExW` — is not capped by the compatibility shim.
fn read_build_number() -> u32 {
    // SAFETY: ntdll.dll is always loaded in every Windows process, and
    // `GetModuleHandleW` returns the existing module handle without
    // incrementing a reference count.
    unsafe {
        let module = match GetModuleHandleW(windows::core::w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return u32::MAX,
        };
        let proc = match GetProcAddress(module, windows::core::s!("RtlGetVersion")) {
            Some(p) => p,
            None => return u32::MAX,
        };
        let rtl_get_version: RtlGetVersionFn = std::mem::transmute(proc);
        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        if rtl_get_version(&mut info).is_ok() {
            info.dwBuildNumber
        } else {
            u32::MAX
        }
    }
}

/// Reads the fourth component of `<major>.<minor>.<build>.<ubr>`, which
/// `RtlGetVersion` does not report.
fn read_update_build_revision() -> u32 {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(CURRENT_VERSION_KEY)
        .and_then(|key| key.get_value::<u32, _>("UBR"))
        .unwrap_or(u32::MAX)
}

/// Reads the architecture of the host, which differs from this binary's target
/// architecture when the process runs under emulation.
fn read_host_architecture() -> HostArchitecture {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `GetNativeSystemInfo` only writes into the struct it is handed,
    // and reading `wProcessorArchitecture` reads the union member the OS just
    // wrote.
    let architecture = unsafe {
        GetNativeSystemInfo(&mut info);
        info.Anonymous.Anonymous.wProcessorArchitecture
    };
    if architecture == PROCESSOR_ARCHITECTURE_ARM64 {
        HostArchitecture::Arm64
    } else if architecture == PROCESSOR_ARCHITECTURE_AMD64 {
        HostArchitecture::X64
    } else {
        HostArchitecture::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64_accepts_1903_and_1909_only_at_the_serviced_revision() {
        for build in [BUILD_1903, BUILD_1909] {
            assert!(!meets_minimum(HostArchitecture::X64, build, 1048));
            assert!(meets_minimum(
                HostArchitecture::X64,
                build,
                MIN_UBR_1903_1909
            ));
        }
    }

    #[test]
    fn x64_rejects_everything_below_1903() {
        assert!(!meets_minimum(HostArchitecture::X64, 17763, u32::MAX));
        assert!(!meets_minimum(
            HostArchitecture::X64,
            BUILD_1903 - 1,
            u32::MAX
        ));
    }

    #[test]
    fn x64_accepts_2004_and_later_without_a_revision_floor() {
        assert!(meets_minimum(HostArchitecture::X64, BUILD_2004, 0));
        assert!(meets_minimum(HostArchitecture::X64, 26100, 0));
    }

    #[test]
    fn arm64_holds_the_higher_floor_through_1909() {
        assert!(!meets_minimum(
            HostArchitecture::Arm64,
            BUILD_1909,
            MIN_UBR_1903_1909
        ));
        assert!(meets_minimum(HostArchitecture::Arm64, BUILD_2004, 0));
    }

    #[test]
    fn an_unidentified_architecture_takes_the_x64_floor() {
        assert!(
            meets_minimum(HostArchitecture::Other, BUILD_1903, MIN_UBR_1903_1909),
            "an unrecognized host must not be refused on the ARM64 rule"
        );
    }

    #[test]
    fn an_indeterminate_probe_passes() {
        assert!(meets_minimum(HostArchitecture::X64, u32::MAX, u32::MAX));
        assert!(meets_minimum(HostArchitecture::Arm64, u32::MAX, u32::MAX));
        assert!(meets_minimum(HostArchitecture::X64, BUILD_1903, u32::MAX));
    }

    #[test]
    fn format_build_drops_an_unreadable_revision() {
        assert_eq!(format_build(19041, 1288), "19041.1288");
        assert_eq!(format_build(19041, u32::MAX), "19041");
    }

    #[test]
    fn the_host_probes_agree_with_a_shipped_target() {
        assert!(matches!(
            host_architecture(),
            HostArchitecture::X64 | HostArchitecture::Arm64
        ));
        let build = os_build_number();
        assert!(
            build >= 10240 || build == u32::MAX,
            "unexpected build number: {build}"
        );
    }

    #[test]
    fn the_message_names_the_requirement_and_the_host() {
        // The live host decides whether this returns an error at all, so the
        // wording is asserted only when it does.
        if let Err(message) = check_windows_version() {
            assert!(message.contains("WSLc requires Windows 10"), "{message}");
            assert!(message.contains("this host is build"), "{message}");
        }
    }
}
