// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Built-in proxy for create-and-run containers.
//!
//! WSLc networking is either none or unfiltered NAT, so to filter egress the
//! workload joins an internal network whose only way out is a gateway
//! container. The gateway runs `mxc-wslc-gateway`, which serves DNS and an
//! HTTP proxy that applies the egress rules, and reaches out through its own
//! NAT network.
//!
//! Each proxy's networks and containers are named from its session name. MXC
//! records the names before creating them, and when a session opens a store
//! it deletes everything recorded there: a store admits one live session, so
//! those were left by a run that ended without cleanup. Unrecorded names are
//! never deleted.

use std::ffi::{CStr, CString, OsStr};
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::mxc_common::filesystem_security::{
    lock_owner_only_directory_path, set_current_user_owner, LockedDirectoryPath,
};
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::ScriptResponse;
use crate::mxc_common::proxy_env;
use crate::mxc_common::string_util::CoTaskMemPWSTR;
use crate::wslc_common::container_steps::{self, cstr_bytes, sdk_error, ProcessSettings};
use crate::wslc_common::error::WslcError;
use crate::wslc_common::image;
use crate::wslc_common::policy::ProxiedEgress;
use crate::wslc_common::policy_mapping::VolumeMount;
use crate::wslc_common::process_env::EnvScope;
use crate::wslc_common::wslc_bindings::*;
use crate::wslc_gateway_policy as gateway;

const NAME_PREFIX: &str = "mxc-wslc-gw-";
const LEFTOVERS_REMOVED: &str = "Removed the built-in proxy left by an earlier run";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Container,
    Network,
}

/// One proxy's container and network names: `mxc-wslc-gw-<key>-<role>`,
/// where the key is a fingerprint of the session name.
pub(crate) struct ProxyNames {
    key: String,
    workload: CString,
    gateway: CString,
    internal: CString,
    egress: CString,
}

impl ProxyNames {
    fn for_session(session_name: &str) -> Self {
        Self::from_key(fingerprint(session_name))
    }

    fn from_key(key: String) -> Self {
        let name = |role: &str| {
            CString::new(format!("{NAME_PREFIX}{key}-{role}")).expect("the key is hex")
        };
        Self {
            workload: name("workload"),
            gateway: name("gateway"),
            internal: name("internal"),
            egress: name("egress"),
            key,
        }
    }

    /// In delete order: a network can't be deleted while a container is attached.
    fn resources(&self) -> [(Kind, &CStr); 4] {
        [
            (Kind::Container, self.workload.as_c_str()),
            (Kind::Container, self.gateway.as_c_str()),
            (Kind::Network, self.internal.as_c_str()),
            (Kind::Network, self.egress.as_c_str()),
        ]
    }

    fn all(&self) -> Vec<String> {
        self.resources()
            .iter()
            .map(|(_, name)| name.to_string_lossy().into_owned())
            .collect()
    }
}

/// 16 hex digits of SHA-256.
fn fingerprint(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn is_fingerprint(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const EGRESS_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 231, 0, 0);
const INTERNAL_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 231, 1, 0);
const SUBNET_PREFIX_LENGTH: u8 = 24;
const GATEWAY_EGRESS_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 231, 0, 2);
const GATEWAY_WORKLOAD_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 231, 1, 254);
const PROXY_PORT: u16 = 3128;
const NODE_USE_ENV_PROXY: &str = "NODE_USE_ENV_PROXY";

// The SDK reads these through pointers when the container is created.
static GATEWAY_EGRESS_IN_ADDR: IN_ADDR = in_addr_of(GATEWAY_EGRESS_ADDRESS);
static GATEWAY_WORKLOAD_IN_ADDR: IN_ADDR = in_addr_of(GATEWAY_WORKLOAD_ADDRESS);

const IMAGE_ID: &str = env!("MXC_WSLC_GATEWAY_IMAGE_ID");
const IMAGE_TAR: &str = "mxc-wslc-gateway.tar";
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// A running gateway and the networks it serves. Torn down on drop.
pub(crate) struct Gateway {
    sdk: &'static WslcSdk,
    /// Owned by the caller, which must drop this before ending the session.
    session: WslcSession,
    // Releasing the handle stops the output callbacks.
    _container: WslcContainerGuard,
    process: ProcessSettings,
    resolv_conf: tempfile::TempPath,
    records: StoreRecords,
    names: ProxyNames,
    torn_down: AtomicBool,
}

impl Gateway {
    /// Create this session's networks and start its gateway. Call
    /// [`sweep_leftovers`] on the session first.
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers, `session` must outlive the
    /// returned value, and COM must be initialized on the calling thread.
    pub(crate) unsafe fn start(
        sdk: &'static WslcSdk,
        session: WslcSession,
        store_path: &str,
        session_name: &str,
        egress: &ProxiedEgress,
        logger: &mut Logger,
    ) -> Result<Self, ScriptResponse> {
        let records = StoreRecords::open(store_path).map_err(host_error)?;
        let names = ProxyNames::for_session(session_name);
        refuse_unrecorded(sdk, session, &records, &names)?;
        records.write(&names, &names.all()).map_err(host_error)?;
        match Self::start_inner(sdk, session, &names, egress, logger) {
            Ok((container, process, resolv_conf)) => Ok(Self {
                sdk,
                session,
                _container: container,
                process,
                resolv_conf,
                records,
                names,
                torn_down: AtomicBool::new(false),
            }),
            Err(mut e) => {
                if let Err(cleanup) = remove_recorded(sdk, session, &records, &names) {
                    e.error_message =
                        format!("{}; cleanup also failed: {cleanup}", e.error_message);
                }
                Err(e)
            }
        }
    }

    unsafe fn start_inner(
        sdk: &'static WslcSdk,
        session: WslcSession,
        names: &ProxyNames,
        egress: &ProxiedEgress,
        logger: &mut Logger,
    ) -> Result<(WslcContainerGuard, ProcessSettings, tempfile::TempPath), ScriptResponse> {
        create_network(sdk, session, &names.egress, EGRESS_SUBNET, false)?;
        create_network(sdk, session, &names.internal, INTERNAL_SUBNET, true)?;

        let tag = image_tag();
        ensure_image(sdk, session, &tag, logger)?;
        let tag_c = cstr_bytes("gateway image", &tag)?;
        let mut settings = std::mem::zeroed::<WslcContainerSettings>();
        let hr = sdk.WslcInitContainerSettings(tag_c.as_ptr() as PCSTR, &mut settings);
        if hr != S_OK {
            return Err(sdk_error("WslcInitContainerSettings failed", hr, ""));
        }
        let hr = sdk.WslcSetContainerSettingsName(&mut settings, names.gateway.as_ptr());
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsName failed", hr, ""));
        }
        // The first network is primary, so the default route leaves through NAT.
        let networks = [
            network(&names.egress, &GATEWAY_EGRESS_IN_ADDR),
            network(&names.internal, &GATEWAY_WORKLOAD_IN_ADDR),
        ];
        let hr = sdk.WslcSetContainerSettingsNetworks(
            &mut settings,
            networks.as_ptr(),
            networks.len() as u32,
        );
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsNetworks failed", hr, ""));
        }

        let policy = serde_json::to_string(&render_policy(egress)).map_err(|e| {
            WslcError::Host(format!("could not render the built-in proxy policy: {e}"))
                .into_response()
        })?;
        let mut process = ProcessSettings::build_argv(
            sdk,
            &["/gateway".to_string()],
            &[format!("{}={policy}", gateway::POLICY_ENV)],
        )?;
        let hr = sdk.WslcSetContainerSettingsInitProcess(&mut settings, process.raw_mut());
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetContainerSettingsInitProcess failed",
                hr,
                "",
            ));
        }

        let mut container: WslcContainer = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcCreateContainer(session, &settings, &mut container, err_msg.as_mut_ptr());
        if hr != S_OK {
            return Err(sdk_error(
                "Could not create the built-in proxy's container",
                hr,
                &err_msg.to_string_lossy(),
            ));
        }
        let container = WslcContainerGuard::from_raw(container, sdk.release_container_fn());
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcStartContainer(
            container.as_raw(),
            WslcContainerStartFlags::WSLC_CONTAINER_START_FLAG_ATTACH,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            return Err(sdk_error(
                "Could not start the built-in proxy's container",
                hr,
                &err_msg.to_string_lossy(),
            ));
        }
        process.mark_process_created();

        if let Err(e) = await_ready(&process) {
            return Err(WslcError::Host(format!(
                "the built-in proxy did not start: {e}. Output:\n{}",
                String::from_utf8_lossy(&lock(&process.io_ctx().stdout))
            ))
            .into_response());
        }

        let resolv_conf = write_resolv_conf().map_err(|e| {
            WslcError::Host(format!(
                "could not write the built-in proxy's resolv.conf: {e}"
            ))
            .into_response()
        })?;
        let _ = writeln!(logger, "[WSLC] Built-in proxy ready at {}", proxy_url());
        Ok((container, process, resolv_conf))
    }

    /// The workload's mount of the gateway's DNS settings.
    pub(crate) fn resolv_conf_mount(&self) -> VolumeMount {
        VolumeMount {
            windows_path: self.resolv_conf.to_string_lossy().into_owned(),
            container_path: RESOLV_CONF.to_string(),
            read_only: true,
        }
    }

    pub(crate) fn workload_name(&self) -> &CStr {
        &self.names.workload
    }

    /// The workload's only network. The SDK reads it when the container is
    /// created.
    pub(crate) fn workload_networks(&self) -> [WslcContainerNetwork; 1] {
        [network(&self.names.internal, ptr::null())]
    }

    /// Delete the gateway, the workload, and their networks, then log the
    /// gateway's output. Call after the workload has stopped.
    pub(crate) fn teardown(&self, logger: &mut Logger) -> Result<(), String> {
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        let _com = ComApartment::enter()?;
        // SAFETY: `session` outlives `self`, and `sdk` is valid while it lives.
        let removed =
            unsafe { remove_recorded(self.sdk, self.session, &self.records, &self.names) };

        let io = self.process.io_ctx();
        let (exited, signal) = &*io.exited;
        let _ = signal.wait_timeout_while(lock(exited), EXIT_TIMEOUT, |done| !*done);
        let output = std::mem::take(&mut *lock(&io.stdout));
        for line in String::from_utf8_lossy(&output).lines() {
            let _ = writeln!(logger, "[WSLC][gateway] {line}");
        }

        match removed {
            Ok(_) => {
                self.torn_down.store(true, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(format!("could not remove the built-in proxy: {e}")),
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.teardown(&mut Logger::new(Mode::Buffer));
    }
}

/// The proxy URL the workload is pointed at.
pub(crate) fn proxy_url() -> String {
    format!("http://{GATEWAY_WORKLOAD_ADDRESS}:{PROXY_PORT}")
}

/// The workload's environment: the caller's, pointed at the proxy.
pub(crate) fn workload_env(caller_env: &[String], scope: EnvScope) -> Vec<String> {
    let mut env = proxy_env::apply_cooperative_proxy_env(caller_env, &proxy_url());
    // Node.js ignores HTTP(S)_PROXY unless this is set. It joins the default
    // environment, so a replacing request doesn't get it.
    if scope == EnvScope::Merge
        && !caller_env
            .iter()
            .any(|entry| entry.split('=').next() == Some(NODE_USE_ENV_PROXY))
    {
        env.push(format!("{NODE_USE_ENV_PROXY}=1"));
    }
    env
}

fn render_policy(egress: &ProxiedEgress) -> gateway::Policy {
    let egress = egress.egress.clone();
    gateway::Policy {
        workload_address: GATEWAY_WORKLOAD_ADDRESS,
        egress_address: GATEWAY_EGRESS_ADDRESS,
        proxy_port: PROXY_PORT,
        forward_dns: egress.default == gateway::Action::Allow || !egress.allow.is_empty(),
        egress,
        host_loopback: None,
        custom_proxy: None,
        port_mappings: Vec::new(),
    }
}

const fn in_addr_of(ip: Ipv4Addr) -> IN_ADDR {
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

fn network(name: &CStr, address: *const IN_ADDR) -> WslcContainerNetwork {
    WslcContainerNetwork {
        name: name.as_ptr(),
        aliases: ptr::null(),
        aliasCount: 0,
        ipv4Address: address,
        ipv6Address: ptr::null(),
    }
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn image_tag() -> String {
    let hex = IMAGE_ID.trim_start_matches("sha256:");
    format!("mxc-wslc-gateway:{}", &hex[..12])
}

/// The gateway image ships beside the native module, like `wslcsdk.dll`.
fn image_tar_path() -> Result<PathBuf, String> {
    Ok(
        crate::mxc_common::process_util::module_path_for_address(image_tar_path as *const ())?
            .parent()
            .ok_or("could not determine the MXC native module directory")?
            .join(IMAGE_TAR),
    )
}

unsafe fn ensure_image(
    sdk: &WslcSdk,
    session: WslcSession,
    tag: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    if image_present(sdk, session, tag)? {
        return Ok(());
    }
    let tar = image_tar_path().map_err(|e| WslcError::Host(e).into_response())?;
    if !tar.is_file() {
        return Err(WslcError::Host(format!(
            "the built-in proxy image {} is missing; reinstall MXC",
            tar.display()
        ))
        .into_response());
    }
    image::import_image_from_tar(sdk, session, tag, &tar.to_string_lossy(), logger)?;
    if !image_present(sdk, session, tag)? {
        return Err(WslcError::Host(format!(
            "the built-in proxy image {} is not the one this MXC build expects ({IMAGE_ID}); \
             reinstall MXC",
            tar.display()
        ))
        .into_response());
    }
    Ok(())
}

unsafe fn image_present(
    sdk: &WslcSdk,
    session: WslcSession,
    tag: &str,
) -> Result<bool, ScriptResponse> {
    let id = IMAGE_ID.trim_start_matches("sha256:");
    let stored = container_steps::list_stored_images(sdk, session)
        .map_err(|hr| sdk_error("WslcListSessionImages failed", hr, ""))?;
    Ok(stored.iter().any(|image| {
        image.name == tag
            && image
                .sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                == id
    }))
}

unsafe fn create_network(
    sdk: &WslcSdk,
    session: WslcSession,
    name: &CStr,
    subnet: Ipv4Addr,
    internal: bool,
) -> Result<(), ScriptResponse> {
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
        return Err(sdk_error(
            &format!("Could not create network {}", name.to_string_lossy()),
            hr,
            &err_msg.to_string_lossy(),
        ));
    }
    Ok(())
}

/// Delete every proxy recorded for the store. Call once a session has
/// opened the store and before starting a proxy: a store admits one live
/// session, so anything recorded then was left by a run that ended without
/// cleanup.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn sweep_leftovers(
    sdk: &WslcSdk,
    session: WslcSession,
    store_path: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let records = StoreRecords::open(store_path).map_err(host_error)?;
    let mut removed = false;
    let mut errors = Vec::new();
    for key in records.keys().map_err(host_error)? {
        match remove_recorded(sdk, session, &records, &ProxyNames::from_key(key)) {
            Ok(deleted) => removed |= deleted,
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        return Err(host_error(format!(
            "could not remove the built-in proxy left by an earlier run: {}",
            errors.join(" ")
        )));
    }
    if removed {
        let _ = writeln!(logger, "[WSLC] {LEFTOVERS_REMOVED}");
        logger.warning_line(&format!("WARNING: WSLc: {LEFTOVERS_REMOVED}"));
    }
    Ok(())
}

/// Cleanup outcome: whether anything was deleted, and what failed.
#[derive(Debug, Default, PartialEq)]
struct Removal {
    removed: bool,
    remaining: Vec<String>,
    errors: Vec<String>,
}

/// Try every owned resource, even after a failure, so one stuck resource
/// doesn't strand the rest.
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

/// Delete what the proxy's record lists, keeping any failures recorded.
/// Returns whether anything was deleted.
unsafe fn remove_recorded(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
    names: &ProxyNames,
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

/// Refuse proxy names that exist without a record. They're from a lost
/// record or another tool, so MXC can neither reuse nor delete them.
unsafe fn refuse_unrecorded(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
    names: &ProxyNames,
) -> Result<(), ScriptResponse> {
    let record = records.path(names);
    if record.exists() {
        return Err(host_error(format!(
            "the image store at {} already has a built-in proxy for this session, \
             recorded in {}",
            records.store,
            record.display()
        )));
    }
    let recorded = records.all_recorded().map_err(host_error)?;
    let unrecorded = |kind: &str, name: &str| {
        host_error(format!(
            "the image store at {} has a {kind} named {name} that MXC can't prove it created \
             (no ownership record lists it), so MXC won't delete it; delete it from the store \
             by hand or set a different wslc.storagePath",
            records.store
        ))
    };
    for network in network_names(sdk, session).map_err(host_error)? {
        if network.starts_with(NAME_PREFIX) && !recorded.contains(&network) {
            return Err(unrecorded("network", &network));
        }
    }
    for (kind, name) in names.resources() {
        if kind == Kind::Container
            && open_container(sdk, session, name)
                .map_err(host_error)?
                .is_some()
        {
            return Err(unrecorded("container", &name.to_string_lossy()));
        }
    }
    Ok(())
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

unsafe fn network_names(sdk: &WslcSdk, session: WslcSession) -> Result<Vec<String>, String> {
    let mut networks: *mut WslcNetworkInfo = ptr::null_mut();
    let mut count: u32 = 0;
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcListSessionNetworks(session, &mut networks, &mut count, err_msg.as_mut_ptr());
    if hr != S_OK {
        return Err(format!(
            "could not list networks: {} (HRESULT 0x{:08X})",
            err_msg.to_string_lossy(),
            hr as u32
        ));
    }
    if networks.is_null() {
        return Ok(Vec::new());
    }
    let names = std::slice::from_raw_parts(networks, count as usize)
        .iter()
        .map(|info| {
            let bytes =
                std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        })
        .collect();
    windows::Win32::System::Com::CoTaskMemFree(Some(networks as *const std::ffi::c_void));
    Ok(names)
}

/// The proxies MXC created in one image store, recorded under
/// `%LOCALAPPDATA%\Microsoft\MXC\wslc\stores\<store fingerprint>`. Each
/// `<key>.json` lists the names one proxy created.
struct StoreRecords {
    /// As configured, for messages.
    store: String,
    /// `None` only while dropping.
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

    fn open(store_path: &str) -> Result<Self, String> {
        // Different spellings of one store must share its records.
        let store = std::fs::canonicalize(store_path)
            .map_err(|e| format!("could not resolve the image store path {store_path}: {e}"))?;
        let store_key = fingerprint(&store.to_string_lossy().to_lowercase());
        let local_app_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(
            "could not find the built-in proxy's ownership records: LOCALAPPDATA is not set",
        )?);
        let components = ["Microsoft", "MXC", "wslc", "stores", &store_key];
        let dir_path: PathBuf = components
            .iter()
            .fold(local_app_data.clone(), |p, c| p.join(c));
        let failed = |e: &dyn std::fmt::Display| {
            format!(
                "could not open the built-in proxy's ownership records in {}: {e}",
                dir_path.display()
            )
        };
        let dir = lock_owner_only_directory_path(&local_app_data, &components.map(OsStr::new), 2)
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

    fn path(&self, names: &ProxyNames) -> PathBuf {
        self.dir().join(format!("{}.json", names.key))
    }

    /// The keys of the proxies recorded in this store.
    fn keys(&self) -> Result<Vec<String>, String> {
        let failed = |e: std::io::Error| format!("could not list {}: {e}", self.dir().display());
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(self.dir()).map_err(failed)? {
            let file_name = entry.map_err(failed)?.file_name();
            if let Some(key) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .filter(|key| is_fingerprint(key))
            {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        Ok(keys)
    }

    fn all_recorded(&self) -> Result<Vec<String>, String> {
        let mut recorded = Vec::new();
        for key in self.keys()? {
            recorded.extend(self.read(&ProxyNames::from_key(key))?);
        }
        Ok(recorded)
    }

    fn read(&self, names: &ProxyNames) -> Result<Vec<String>, String> {
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
    fn write(&self, names: &ProxyNames, remaining: &[String]) -> Result<(), String> {
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

    /// How to finish by hand a cleanup MXC couldn't.
    fn manual_cleanup(&self, names: &ProxyNames, remaining: &[String]) -> String {
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

/// The recorded names that belong to `names`. Anything else is never deleted.
fn recorded_names(text: &str, names: &ProxyNames) -> Result<Vec<String>, serde_json::Error> {
    let recorded: Vec<String> = serde_json::from_str(text)?;
    Ok(names
        .all()
        .into_iter()
        .filter(|name| recorded.contains(name))
        .collect())
}

fn host_error(message: String) -> ScriptResponse {
    WslcError::Host(message).into_response()
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

fn await_ready(process: &ProcessSettings) -> Result<(), String> {
    let io = process.io_ctx();
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let output = String::from_utf8_lossy(&lock(&io.stdout)).into_owned();
        for line in output.lines() {
            if line == "READY" {
                return Ok(());
            }
            if let Some(reason) = line.strip_prefix("FATAL ") {
                return Err(reason.to_string());
            }
        }
        let (exited, signal) = &*io.exited;
        let exited = lock(exited);
        if *exited {
            return Err("it exited".to_string());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!("not ready within {}s", READY_TIMEOUT.as_secs()));
        }
        let wait = (deadline - now).min(Duration::from_millis(50));
        let _ = signal.wait_timeout(exited, wait);
    }
}

fn write_resolv_conf() -> std::io::Result<tempfile::TempPath> {
    let mut file = tempfile::Builder::new()
        .prefix("mxc-wslc-gw-")
        .suffix("-resolv.conf")
        .tempfile()?;
    std::io::Write::write_all(
        &mut file,
        format!("nameserver {GATEWAY_WORKLOAD_ADDRESS}\noptions ndots:0\n").as_bytes(),
    )?;
    Ok(file.into_temp_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_is_forwarded_only_when_some_egress_is_allowed() {
        let egress = |default, allow: Vec<gateway::Rule>| ProxiedEgress {
            egress: gateway::Egress {
                default,
                allow,
                deny: Vec::new(),
            },
            warnings: Vec::new(),
        };
        let rule = gateway::Rule {
            to: vec![gateway::Target {
                cidr: "20.0.0.0/8".parse().unwrap(),
                except: Vec::new(),
            }],
            ports: None,
        };

        let policy = render_policy(&egress(gateway::Action::Deny, vec![rule]));
        assert!(policy.forward_dns);
        assert_eq!(policy.workload_address, GATEWAY_WORKLOAD_ADDRESS);
        assert_eq!(proxy_url(), "http://10.231.1.254:3128");
        assert!(render_policy(&egress(gateway::Action::Allow, Vec::new())).forward_dns);
        assert!(!render_policy(&egress(gateway::Action::Deny, Vec::new())).forward_dns);
    }

    #[test]
    fn workload_env_adds_node_proxy_to_the_default_environment() {
        let env = workload_env(&["HTTPS_PROXY=http://other:1".to_string()], EnvScope::Merge);
        assert!(env.contains(&"HTTPS_PROXY=http://10.231.1.254:3128".to_string()));
        assert!(env.contains(&"NODE_USE_ENV_PROXY=1".to_string()));

        let env = workload_env(&[], EnvScope::Replace);
        assert!(env.contains(&"HTTPS_PROXY=http://10.231.1.254:3128".to_string()));
        assert!(!env.iter().any(|e| e.starts_with("NODE_USE_ENV_PROXY=")));

        let env = workload_env(&["NODE_USE_ENV_PROXY=0".to_string()], EnvScope::Merge);
        assert_eq!(
            env.iter()
                .filter(|e| e.starts_with("NODE_USE_ENV_PROXY="))
                .collect::<Vec<_>>(),
            ["NODE_USE_ENV_PROXY=0"]
        );
    }

    #[test]
    fn cleanup_tries_every_owned_resource_after_a_failure() {
        let names = ProxyNames::for_session("session");
        let owned = [&names.workload, &names.internal, &names.egress]
            .map(|name| name.to_string_lossy().into_owned());
        let mut attempted = Vec::new();
        let removal = remove_each(&names.resources(), &owned, |kind, name| {
            attempted.push(name.to_string_lossy().into_owned());
            match kind {
                Kind::Container => Err("busy".to_string()),
                Kind::Network => Ok(name == names.egress.as_c_str()),
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
    fn records_honor_only_that_proxys_names() {
        let names = ProxyNames::for_session("session");
        let other = ProxyNames::for_session("other session");
        assert!(is_fingerprint(&names.key));
        assert_ne!(names.key, other.key);
        assert!(names
            .all()
            .iter()
            .all(|name| name.starts_with(&format!("{NAME_PREFIX}{}-", names.key))));

        let text = serde_json::to_string(&[
            names.all()[3].clone(),
            other.all()[0].clone(),
            "unrelated".to_string(),
            names.all()[0].clone(),
        ])
        .unwrap();
        assert_eq!(
            recorded_names(&text, &names).unwrap(),
            [names.all()[0].clone(), names.all()[3].clone()]
        );
        assert!(recorded_names("not json", &names).is_err());
        assert!(!is_fingerprint("0123456789ABCDEF"));
        assert!(!is_fingerprint("0123456789abcde"));
    }
}
