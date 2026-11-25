// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A store admits one live session, so anything recorded for a store when a
//! session opens it was left by an earlier session.

use std::ffi::{CStr, OsStr};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::ptr;

use sha2::{Digest, Sha256};

use crate::mxc_common::filesystem_security::{
    lock_owner_only_directory_path, set_current_user_owner, LockedDirectoryPath,
};
use crate::mxc_common::models::ScriptResponse;
use crate::mxc_common::string_util::CoTaskMemPWSTR;
use crate::wslc_common::error::{sdk_api_failure, WslcError, WslcStepError};
use crate::wslc_common::wslc_bindings::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Container,
    Network,
}

pub(crate) trait OwnedNames: Sized {
    const RECORD_SUFFIX: &'static str;

    fn from_key(key: String) -> Self;

    fn key(&self) -> &str;

    /// In delete order: a network can't be deleted while a container is attached.
    fn resources(&self) -> Vec<(Kind, &CStr)>;

    fn all(&self) -> Vec<String> {
        self.resources()
            .iter()
            .map(|(_, name)| name.to_string_lossy().into_owned())
            .collect()
    }
}

pub(crate) fn fingerprint(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn is_fingerprint(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) const SUBNET_PREFIX_LENGTH: u8 = 24;

// The built-in proxy always denies this range, so no egress rule can reach
// these networks.
const SUBNET_RANGE: Ipv4Addr = Ipv4Addr::new(10, 231, 0, 0);
const SUBNET_RANGE_PREFIX_LENGTH: u8 = 16;

pub(crate) fn first_free_subnet(used: &[(Ipv4Addr, u8)]) -> Option<Ipv4Addr> {
    let bounds = |address: Ipv4Addr, prefix_length: u8| {
        let mask = u32::MAX
            .checked_shl(32u32.saturating_sub(u32::from(prefix_length)))
            .unwrap_or(0);
        let first = u32::from(address) & mask;
        (first, first | !mask)
    };
    let used: Vec<(u32, u32)> = used
        .iter()
        .map(|&(address, prefix_length)| bounds(address, prefix_length))
        .collect();
    let (pool_first, pool_last) = bounds(SUBNET_RANGE, SUBNET_RANGE_PREFIX_LENGTH);
    let step = 1u32 << (32 - SUBNET_PREFIX_LENGTH);
    (pool_first..=pool_last)
        .step_by(step as usize)
        .map(|first| (first, first + step - 1))
        .find(|&(first, last)| used.iter().all(|&(a, b)| last < a || b < first))
        .map(|(first, _)| Ipv4Addr::from(first))
}

pub(crate) const fn in_addr_of(ip: Ipv4Addr) -> IN_ADDR {
    let [s_b1, s_b2, s_b3, s_b4] = ip.octets();
    in_addr {
        S_un: in_addr__bindgen_ty_1 {
            S_un_b: in_addr__bindgen_ty_1__bindgen_ty_1 {
                s_b1,
                s_b2,
                s_b3,
                s_b4,
            },
        },
    }
}

fn ip_of(address: &IN_ADDR) -> Ipv4Addr {
    // SAFETY: every view of the union is four plain bytes.
    let bytes = unsafe { address.S_un.S_un_b };
    Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
}

/// A null `address` lets the runtime pick one.
pub(crate) fn network(name: &CStr, address: *const IN_ADDR) -> WslcContainerNetwork {
    WslcContainerNetwork {
        name: name.as_ptr(),
        aliases: ptr::null(),
        aliasCount: 0,
        ipv4Address: address,
        ipv6Address: ptr::null(),
    }
}

/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn create_network(
    sdk: &WslcSdk,
    session: WslcSession,
    name: &CStr,
    subnet: Ipv4Addr,
    internal: bool,
) -> Result<(), WslcError> {
    let mut settings = std::mem::zeroed::<WslcNetworkSettings>();
    settings.name = name.as_ptr();
    settings.flags = WslcNetworkFlags::WSLC_NETWORK_FLAG_ENABLE_IPV4;
    if internal {
        settings.flags |= WslcNetworkFlags::WSLC_NETWORK_FLAG_INTERNAL;
    }
    settings.ipv4PrefixLength = SUBNET_PREFIX_LENGTH;
    settings.ipv4Subnet = in_addr_of(subnet);
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr =
        sdk.WslcCreateSessionNetwork(session, &settings, ptr::null_mut(), err_msg.as_mut_ptr());
    if hr != S_OK {
        return Err(WslcError::sdk(
            format!("Could not create network {}", name.to_string_lossy()),
            hr,
            err_msg.to_string_lossy(),
        ));
    }
    Ok(())
}

pub(crate) struct SessionNetwork {
    pub(crate) name: String,
    pub(crate) ipv4_subnet: Option<(Ipv4Addr, u8)>,
}

/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn list_networks(
    sdk: &WslcSdk,
    session: WslcSession,
) -> Result<Vec<SessionNetwork>, WslcError> {
    let mut networks: *mut WslcNetworkInfo = ptr::null_mut();
    let mut count: u32 = 0;
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcListSessionNetworks(session, &mut networks, &mut count, err_msg.as_mut_ptr());
    if hr != S_OK {
        return Err(WslcError::sdk(
            "could not list networks",
            hr,
            err_msg.to_string_lossy(),
        ));
    }
    if networks.is_null() {
        return Ok(Vec::new());
    }
    let listed = std::slice::from_raw_parts(networks, count as usize)
        .iter()
        .map(|info| {
            let bytes =
                std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            SessionNetwork {
                name: String::from_utf8_lossy(&bytes[..end]).into_owned(),
                ipv4_subnet: (info.ipv4PrefixLength != 0)
                    .then(|| (ip_of(&info.ipv4Subnet), info.ipv4PrefixLength)),
            }
        })
        .collect();
    windows::Win32::System::Com::CoTaskMemFree(Some(networks as *const std::ffi::c_void));
    Ok(listed)
}

/// Returns whether anything was deleted.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn remove_all_recorded<N: OwnedNames>(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
) -> Result<bool, String> {
    let mut removed = false;
    let mut errors = Vec::new();
    for key in records.keys::<N>()? {
        match remove_recorded(sdk, session, records, &N::from_key(key)) {
            Ok(deleted) => removed |= deleted,
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join(" "))
    }
}

#[derive(Debug, Default, PartialEq)]
struct Removal {
    removed: bool,
    remaining: Vec<String>,
    errors: Vec<String>,
}

fn remove_each(
    resources: &[(Kind, &CStr)],
    owned: &[String],
    mut delete: impl FnMut(Kind, &CStr) -> Result<bool, String>,
) -> Removal {
    let mut removal = Removal::default();
    for &(kind, name) in resources {
        let name_text = name.to_string_lossy();
        if !owned.iter().any(|owned| *owned == name_text) {
            continue;
        }
        match delete(kind, name) {
            Ok(deleted) => removal.removed |= deleted,
            Err(e) => {
                removal.remaining.push(name_text.into_owned());
                removal.errors.push(e);
            }
        }
    }
    removal
}

/// Returns whether anything was deleted; what can't be deleted stays recorded.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn remove_recorded<N: OwnedNames>(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
    names: &N,
) -> Result<bool, String> {
    let owned = records.read(names)?;
    let removal = remove_each(&names.resources(), &owned, |kind, name| {
        delete_resource(sdk, session, kind, name)
    });
    let mut errors = removal.errors;
    if let Err(e) = records.write(names, &removal.remaining) {
        errors.push(e);
    }
    if errors.is_empty() {
        return Ok(removal.removed);
    }
    Err(format!(
        "{}. {}",
        errors.join("; "),
        records.manual_cleanup(names, &removal.remaining)
    ))
}

unsafe fn delete_resource(
    sdk: &WslcSdk,
    session: WslcSession,
    kind: Kind,
    name: &CStr,
) -> Result<bool, String> {
    let mut err_msg = CoTaskMemPWSTR::null();
    match kind {
        Kind::Container => {
            let Some(container) = open_container(sdk, session, name)? else {
                return Ok(false);
            };
            let hr = sdk.WslcDeleteContainer(
                container.as_raw(),
                WslcDeleteContainerFlags::WSLC_DELETE_CONTAINER_FLAG_FORCE,
                err_msg.as_mut_ptr(),
            );
            match hr {
                S_OK => Ok(true),
                WSLC_E_CONTAINER_NOT_FOUND => Ok(false),
                _ => Err(failure("delete container", name, hr, &err_msg)),
            }
        }
        Kind::Network => {
            let hr = sdk.WslcDeleteSessionNetwork(session, name.as_ptr(), err_msg.as_mut_ptr());
            match hr {
                S_OK => Ok(true),
                WSLC_E_NETWORK_NOT_FOUND => Ok(false),
                _ => Err(failure("delete network", name, hr, &err_msg)),
            }
        }
    }
}

pub(crate) unsafe fn open_container(
    sdk: &WslcSdk,
    session: WslcSession,
    name: &CStr,
) -> Result<Option<WslcContainerGuard>, String> {
    let mut container: WslcContainer = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcOpenContainer(session, name.as_ptr(), &mut container, err_msg.as_mut_ptr());
    match hr {
        S_OK => Ok(Some(WslcContainerGuard::from_raw(
            container,
            sdk.release_container_fn(),
        ))),
        WSLC_E_CONTAINER_NOT_FOUND => Ok(None),
        _ => Err(failure("open container", name, hr, &err_msg)),
    }
}

fn failure(action: &str, name: &CStr, hr: HRESULT, err_msg: &CoTaskMemPWSTR) -> String {
    format!(
        "could not {action} {}: {} (HRESULT 0x{:08X})",
        name.to_string_lossy(),
        err_msg.to_string_lossy(),
        hr as u32
    )
}

pub(crate) fn host_error(message: String) -> ScriptResponse {
    WslcError::Host(message).into_response()
}

pub(crate) fn session_network_failure(
    error: WslcError,
    operation: &str,
    feature: &str,
) -> WslcStepError {
    let WslcError::Sdk { hr, .. } = error else {
        return error.into_step_error();
    };
    let failure = sdk_api_failure(operation, hr);
    if hr == WSLC_E_RUNTIME_UPDATE_NEEDED {
        return WslcError::Unavailable(format!(
            "WSLc: {feature} needs WSL 3.0.5 or later. Run `wsl --update`"
        ))
        .into_step_error()
        .with_api_failure(failure);
    }
    error.into_step_error().with_api_failure(failure)
}

pub(crate) struct StoreRecords {
    store: String,
    dir: Option<LockedDirectoryPath>,
}

impl Drop for StoreRecords {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let path = dir.path().to_path_buf();
            drop(dir);
            // Fails, leaving it in place, while any record remains.
            let _ = std::fs::remove_dir(path);
        }
    }
}

impl StoreRecords {
    fn dir(&self) -> &Path {
        self.dir.as_ref().expect("set until drop").path()
    }

    pub(crate) fn open(store_path: &str) -> Result<Self, String> {
        let store = std::fs::canonicalize(store_path)
            .map_err(|e| format!("could not resolve the image store path {store_path}: {e}"))?;
        let store_key = fingerprint(&store.to_string_lossy().to_lowercase());

        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|dir| !dir.is_empty())
            .map_or_else(std::env::temp_dir, PathBuf::from);
        let components = ["Microsoft", "MXC", "wslc", "stores", &store_key];
        let dir_path: PathBuf = components.iter().fold(base.clone(), |p, c| p.join(c));
        let failed = |e: &dyn std::fmt::Display| {
            format!(
                "could not open MXC's ownership records in {}: {e}",
                dir_path.display()
            )
        };
        let dir = lock_owner_only_directory_path(&base, &components.map(OsStr::new), 2)
            .map_err(|e| failed(&e))?;
        // An elevated run would otherwise leave them owned by Administrators,
        // which the user's other runs reject.
        for private in dir.path().ancestors().take(3) {
            set_current_user_owner(private).map_err(|e| failed(&e))?;
        }
        Ok(Self {
            store: store_path.to_string(),
            dir: Some(dir),
        })
    }

    pub(crate) fn store(&self) -> &str {
        &self.store
    }

    pub(crate) fn path<N: OwnedNames>(&self, names: &N) -> PathBuf {
        self.dir()
            .join(format!("{}{}", names.key(), N::RECORD_SUFFIX))
    }

    pub(crate) fn keys<N: OwnedNames>(&self) -> Result<Vec<String>, String> {
        let failed = |e: std::io::Error| format!("could not list {}: {e}", self.dir().display());
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(self.dir()).map_err(failed)? {
            let file_name = entry.map_err(failed)?.file_name();
            if let Some(key) = file_name.to_str().and_then(record_key::<N>) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub(crate) fn all_recorded<N: OwnedNames>(&self) -> Result<Vec<String>, String> {
        let mut recorded = Vec::new();
        for key in self.keys::<N>()? {
            recorded.extend(self.read(&N::from_key(key))?);
        }
        Ok(recorded)
    }

    pub(crate) fn read<N: OwnedNames>(&self, names: &N) -> Result<Vec<String>, String> {
        let path = self.path(names);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(format!(
                    "could not read {}: {e}. {}",
                    path.display(),
                    self.manual_cleanup(names, &names.all())
                ))
            }
        };
        recorded_names(&text, names).map_err(|e| {
            format!(
                "{} is not a valid ownership record ({e}). {}",
                path.display(),
                self.manual_cleanup(names, &names.all())
            )
        })
    }

    /// Record `remaining`, or delete the record once nothing remains.
    pub(crate) fn write<N: OwnedNames>(
        &self,
        names: &N,
        remaining: &[String],
    ) -> Result<(), String> {
        let path = self.path(names);
        let failed =
            |e: &dyn std::fmt::Display| format!("could not update {}: {e}", path.display());
        if remaining.is_empty() {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(failed(&e)),
                _ => Ok(()),
            };
        }
        let mut file = tempfile::NamedTempFile::new_in(self.dir()).map_err(|e| failed(&e))?;
        serde_json::to_writer(&mut file, remaining).map_err(|e| failed(&e))?;
        file.persist(&path).map_err(|e| failed(&e))?;
        Ok(())
    }

    pub(crate) fn manual_cleanup<N: OwnedNames>(&self, names: &N, remaining: &[String]) -> String {
        let record = self.path(names);
        if remaining.is_empty() {
            return format!("To clean up by hand, delete {}", record.display());
        }
        format!(
            "To clean up by hand, delete {} from the image store at {}, then delete {}",
            remaining.join(", "),
            self.store,
            record.display()
        )
    }
}

pub(crate) fn record_key<N: OwnedNames>(file_name: &str) -> Option<&str> {
    file_name
        .strip_suffix(N::RECORD_SUFFIX)
        .filter(|key| is_fingerprint(key))
}

/// A record can't make MXC delete a name its owner doesn't own.
fn recorded_names<N: OwnedNames>(text: &str, names: &N) -> Result<Vec<String>, serde_json::Error> {
    let recorded: Vec<String> = serde_json::from_str(text)?;
    Ok(names
        .all()
        .into_iter()
        .filter(|name| recorded.contains(name))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    struct Pair {
        key: String,
        container: CString,
        network: CString,
    }

    impl OwnedNames for Pair {
        const RECORD_SUFFIX: &'static str = ".pair.json";

        fn from_key(key: String) -> Self {
            Self {
                container: CString::new(format!("test-{key}-container")).unwrap(),
                network: CString::new(format!("test-{key}-network")).unwrap(),
                key,
            }
        }

        fn key(&self) -> &str {
            &self.key
        }

        fn resources(&self) -> Vec<(Kind, &CStr)> {
            vec![
                (Kind::Container, self.container.as_c_str()),
                (Kind::Network, self.network.as_c_str()),
            ]
        }
    }

    #[test]
    fn cleanup_tries_every_owned_resource_after_a_failure() {
        let names = Pair::from_key(fingerprint("owner"));
        let owned = names.all();
        let mut attempted = Vec::new();
        let removal = remove_each(&names.resources(), &owned, |kind, name| {
            attempted.push(name.to_string_lossy().into_owned());
            match kind {
                Kind::Container => Err("busy".to_string()),
                Kind::Network => Ok(true),
            }
        });
        assert_eq!(attempted, owned);
        assert_eq!(
            removal,
            Removal {
                removed: true,
                remaining: vec![owned[0].clone()],
                errors: vec!["busy".to_string()],
            }
        );
    }

    #[test]
    fn records_honor_only_that_owners_names() {
        let names = Pair::from_key(fingerprint("owner"));
        let other = Pair::from_key(fingerprint("other owner"));
        assert!(is_fingerprint(names.key()));
        assert_ne!(names.key(), other.key());

        let text = serde_json::to_string(&[
            names.all()[1].clone(),
            other.all()[0].clone(),
            "unrelated".to_string(),
            names.all()[0].clone(),
        ])
        .unwrap();
        assert_eq!(recorded_names(&text, &names).unwrap(), names.all());
        assert!(recorded_names("not json", &names).is_err());
        assert!(!is_fingerprint("0123456789ABCDEF"));
        assert!(!is_fingerprint("0123456789abcde"));
    }

    #[test]
    fn subnets_are_allocated_lowest_first_around_used_ones() {
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        assert_eq!(first_free_subnet(&[]), Some(ip("10.231.0.0")));

        let outside = [(ip("172.17.0.0"), 16), (ip("10.230.255.0"), 24)];
        assert_eq!(
            first_free_subnet(&outside),
            Some(ip("10.231.0.0")),
            "networks outside the range don't count"
        );

        let used = [
            (ip("10.231.0.0"), 24),
            (ip("10.231.1.128"), 25),
            (ip("10.231.3.0"), 24),
        ];
        assert_eq!(first_free_subnet(&used), Some(ip("10.231.2.0")));

        assert_eq!(
            first_free_subnet(&[(ip("10.231.0.0"), 22)]),
            Some(ip("10.231.4.0")),
            "a /22 blocks every /24 it covers"
        );
        assert_eq!(first_free_subnet(&[(ip("10.0.0.0"), 8)]), None);
        assert_eq!(
            first_free_subnet(&[(ip("10.231.0.7"), 40)]),
            Some(ip("10.231.1.0")),
            "an out-of-range prefix length blocks only its own address"
        );

        let full: Vec<(Ipv4Addr, u8)> = (0..=255u8)
            .map(|third| (Ipv4Addr::new(10, 231, third, 0), 24))
            .collect();
        assert_eq!(first_free_subnet(&full), None);
        assert_eq!(
            first_free_subnet(&full[1..]),
            Some(ip("10.231.0.0")),
            "a freed subnet is reused"
        );
    }

    #[test]
    fn allocated_subnets_stay_inside_the_range_the_gateway_denies() {
        use crate::wslc_gateway_policy::{Cidr, GATEWAY_SUBNETS};
        let mut used = Vec::new();
        while let Some(subnet) = first_free_subnet(&used) {
            assert!(GATEWAY_SUBNETS.contains_network(&Cidr::new(subnet, SUBNET_PREFIX_LENGTH)));
            used.push((subnet, SUBNET_PREFIX_LENGTH));
        }
        assert_eq!(used.len(), 256);
    }

    #[test]
    fn an_older_wsl_without_session_networks_is_unavailable() {
        use crate::mxc_common::models::FailurePhase;
        let failure = |hr| {
            session_network_failure(
                WslcError::sdk("could not list networks", hr, ""),
                "WslcListSessionNetworks",
                "the built-in proxy",
            )
        };

        let old_wsl = failure(WSLC_E_RUNTIME_UPDATE_NEEDED);
        assert_eq!(old_wsl.failure_phase, FailurePhase::BackendUnavailable);
        assert_eq!(
            old_wsl.error_message,
            "WSLc: the built-in proxy needs WSL 3.0.5 or later. Run `wsl --update`"
        );
        assert_eq!(
            old_wsl.api_failure.as_deref(),
            Some(&sdk_api_failure(
                "WslcListSessionNetworks",
                WSLC_E_RUNTIME_UPDATE_NEEDED
            ))
        );

        let other = failure(E_FAIL);
        assert_eq!(other.failure_phase, FailurePhase::LaunchFailed);
        assert_eq!(
            other.api_failure.as_deref(),
            Some(&sdk_api_failure("WslcListSessionNetworks", E_FAIL))
        );
    }
}
