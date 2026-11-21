// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Built-in proxy for WSLc containers.
//!
//! WSLc networking is either none or unfiltered NAT, so to filter egress the
//! workload joins an internal network whose only way out is a gateway
//! container. The gateway runs `mxc-wslc-gateway`, which serves DNS and an
//! HTTP proxy that applies the egress rules, and reaches out through its own
//! NAT network.
//!
//! Each proxy's networks and containers are named from its owner (the session
//! name for create-and-run, the sandbox id for container lifecycle operations)
//! and recorded in [`session_resources`] before they are created, and a
//! session that opens a store deletes the proxies recorded there.

use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{PortMapping, ScriptResponse};
use crate::mxc_common::proxy_env;
use crate::mxc_common::string_util::CoTaskMemPWSTR;
use crate::wslc_common::container_steps::{
    self, cstr_bytes, sdk_error, ContainerNetworking, ProcessSettings,
};
use crate::wslc_common::error::{WslcError, WslcStepError};
use crate::wslc_common::image;
use crate::wslc_common::policy::{self, CustomProxy, CustomProxyHost, ProxiedEgress};
use crate::wslc_common::policy_mapping::VolumeMount;
use crate::wslc_common::process_env::{self, EnvScope};
use crate::wslc_common::sandbox_network;
use crate::wslc_common::session_resources::{
    self, create_network, fingerprint, host_error, in_addr_of, network, open_container,
    remove_recorded, Kind, OwnedNames, SessionNetwork, StoreRecords, SUBNET_PREFIX_LENGTH,
};
use crate::wslc_common::wslc_bindings::*;
use crate::wslc_gateway_policy as gateway;

const NAME_PREFIX: &str = "mxc-wslc-gw-";
const LEFTOVERS_REMOVED: &str = "Removed the built-in proxy left by an earlier run";

/// One proxy's container and network names: `mxc-wslc-gw-<key>-<role>`,
/// where the key is a fingerprint of the proxy's owner.
pub(crate) struct ProxyNames {
    key: String,
    workload: CString,
    gateway: CString,
    internal: CString,
    egress: CString,
}

impl ProxyNames {
    fn for_owner(owner: &str) -> Self {
        Self::from_key(fingerprint(owner))
    }
}

impl OwnedNames for ProxyNames {
    const RECORD_SUFFIX: &'static str = ".json";

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

    fn key(&self) -> &str {
        &self.key
    }

    fn resources(&self) -> Vec<(Kind, &CStr)> {
        vec![
            (Kind::Container, self.workload.as_c_str()),
            (Kind::Container, self.gateway.as_c_str()),
            (Kind::Network, self.internal.as_c_str()),
            (Kind::Network, self.egress.as_c_str()),
        ]
    }
}

const PROXY_PORT: u16 = 3128;
const NODE_USE_ENV_PROXY: &str = "NODE_USE_ENV_PROXY";

const IMAGE_ID: &str = env!("MXC_WSLC_GATEWAY_IMAGE_ID");
const IMAGE_TAR: &str = "mxc-wslc-gateway.tar";
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// One proxy's two networks, each a free /24 of the session's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Subnets {
    egress: Ipv4Addr,
    internal: Ipv4Addr,
}

impl Subnets {
    fn allocate(networks: &[SessionNetwork]) -> Result<Self, ScriptResponse> {
        let mut used: Vec<_> = networks.iter().filter_map(|n| n.ipv4_subnet).collect();
        let mut next = || {
            let subnet = session_resources::first_free_subnet(&used)?;
            used.push((subnet, SUBNET_PREFIX_LENGTH));
            Some(subnet)
        };
        match (next(), next()) {
            (Some(egress), Some(internal)) => Ok(Self { egress, internal }),
            _ => Err(host_error(format!(
                "this session has no two free subnets in {} left for another built-in proxy; \
                 deprovision a sandbox in it, or place this one in a session of its own",
                gateway::GATEWAY_SUBNETS
            ))),
        }
    }

    fn gateway_egress(&self) -> Ipv4Addr {
        with_host(self.egress, 2)
    }

    fn gateway_workload(&self) -> Ipv4Addr {
        with_host(self.internal, 254)
    }

    /// Pinned so the gateway knows where to relay port mappings.
    fn workload(&self) -> Ipv4Addr {
        with_host(self.internal, 2)
    }

    /// The address the workload reaches Windows loopback through.
    fn host_loopback_relay(&self) -> Ipv4Addr {
        with_host(self.internal, 3)
    }
}

fn with_host(subnet: Ipv4Addr, host: u8) -> Ipv4Addr {
    let [a, b, c, _] = subnet.octets();
    Ipv4Addr::new(a, b, c, host)
}

/// A running gateway and the networks it serves. Torn down on drop.
pub struct Gateway {
    sdk: *const WslcSdk,
    /// Owned by the caller, which must drop this before ending the session.
    session: WslcSession,
    // Releasing the handle stops the output callbacks.
    _container: WslcContainerGuard,
    process: ProcessSettings,
    resolv_conf: tempfile::TempPath,
    records: StoreRecords,
    names: ProxyNames,
    subnets: Subnets,
    proxy_url: String,
    host_loopback: bool,
    torn_down: AtomicBool,
}

impl Gateway {
    /// Create the networks and start the gateway for `owner`. Call
    /// [`sweep_leftovers`] on the session first, and pass the custom proxy
    /// from [`resolve_custom_proxy`].
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers, `sdk` and `session` must
    /// outlive the returned value, and COM must be initialized on the calling
    /// thread.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn start(
        sdk: *const WslcSdk,
        session: WslcSession,
        store_path: &str,
        owner: &str,
        egress: &ProxiedEgress,
        custom_proxy: Option<gateway::CustomProxy>,
        port_mappings: &[PortMapping],
        logger: &mut Logger,
    ) -> Result<Self, ScriptResponse> {
        let sdk_ref = &*sdk;
        let records = StoreRecords::open(store_path).map_err(host_error)?;
        let names = ProxyNames::for_owner(owner);
        let networks = session_resources::list_networks(sdk_ref, session)
            .map_err(|e| host_error(e.to_string()))?;
        refuse_unrecorded(sdk_ref, session, &records, &names, &networks)?;
        let subnets = Subnets::allocate(&networks)?;

        let proxy_url =
            workload_proxy_url(egress.custom_proxy.as_ref(), subnets).map_err(host_error)?;
        let policy = render_policy(egress, custom_proxy, port_mappings, subnets);

        records.write(&names, &names.all()).map_err(host_error)?;
        match Self::start_inner(
            sdk_ref,
            session,
            &names,
            subnets,
            &policy,
            port_mappings,
            logger,
        ) {
            Ok((container, process, resolv_conf)) => {
                let _ = writeln!(
                    logger,
                    "[WSLC] Built-in proxy ready at {}",
                    proxy_env::redact_proxy_url(&proxy_url)
                );
                Ok(Self {
                    sdk,
                    session,
                    _container: container,
                    process,
                    resolv_conf,
                    records,
                    names,
                    subnets,
                    proxy_url,
                    host_loopback: egress.host_loopback,
                    torn_down: AtomicBool::new(false),
                })
            }
            Err(mut e) => {
                if let Err(cleanup) = remove_recorded(sdk_ref, session, &records, &names) {
                    e.error_message =
                        format!("{}; cleanup also failed: {cleanup}", e.error_message);
                }
                Err(e)
            }
        }
    }

    unsafe fn start_inner(
        sdk: &WslcSdk,
        session: WslcSession,
        names: &ProxyNames,
        subnets: Subnets,
        policy: &gateway::Policy,
        port_mappings: &[PortMapping],
        logger: &mut Logger,
    ) -> Result<(WslcContainerGuard, ProcessSettings, tempfile::TempPath), ScriptResponse> {
        create_network(sdk, session, &names.egress, subnets.egress, false)?;
        create_network(sdk, session, &names.internal, subnets.internal, true)?;

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
        // The SDK reads the addresses when the container is created.
        let egress_address = in_addr_of(subnets.gateway_egress());
        let workload_address = in_addr_of(subnets.gateway_workload());
        let networks = [
            network(&names.egress, &egress_address),
            network(&names.internal, &workload_address),
        ];
        let hr = sdk.WslcSetContainerSettingsNetworks(
            &mut settings,
            networks.as_ptr(),
            networks.len() as u32,
        );
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsNetworks failed", hr, ""));
        }
        // Only the host loopback relay changes the gateway's own network.
        let net_admin = [c"NET_ADMIN".as_ptr()];
        if policy.host_loopback.is_some() {
            let hr = sdk.WslcSetContainerSettingsCapabilityAdditions(
                &mut settings,
                net_admin.as_ptr(),
                net_admin.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetContainerSettingsCapabilityAdditions failed",
                    hr,
                    "",
                ));
            }
        }
        // Published ports reach only a container with a non-internal network,
        // so the gateway takes the workload's mappings and relays them.
        let mappings = container_steps::sdk_port_mappings(port_mappings);
        if !mappings.is_empty() {
            let hr = sdk.WslcSetContainerSettingsPortMappings(
                &mut settings,
                mappings.as_ptr(),
                mappings.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetContainerSettingsPortMappings failed",
                    hr,
                    "",
                ));
            }
        }

        let policy = serde_json::to_string(policy).map_err(|e| {
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
            return Err(create_container_error(hr, &err_msg.to_string_lossy()).into_response());
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

        let resolv_conf = write_resolv_conf(subnets).map_err(|e| {
            WslcError::Host(format!(
                "could not write the built-in proxy's resolv.conf: {e}"
            ))
            .into_response()
        })?;
        Ok((container, process, resolv_conf))
    }

    /// The workload's mount of the gateway's DNS settings.
    pub fn resolv_conf_mount(&self) -> VolumeMount {
        VolumeMount {
            windows_path: self.resolv_conf.to_string_lossy().into_owned(),
            container_path: RESOLV_CONF.to_string(),
            read_only: true,
        }
    }

    pub fn workload_networking(&self) -> ContainerNetworking<'_> {
        ContainerNetworking::Proxied {
            name: &self.names.workload,
            network: &self.names.internal,
            address: self.subnets.workload(),
        }
    }

    /// Delete the gateway, the workload, and their networks, then log the
    /// gateway's output. Call after the workload has stopped.
    pub fn teardown(&self, logger: &mut Logger) -> Result<(), String> {
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        let _com = ComApartment::enter()?;
        // SAFETY: `sdk` and `session` outlive `self`.
        let removed =
            unsafe { remove_recorded(&*self.sdk, self.session, &self.records, &self.names) };

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

    /// The workload's environment: the caller's, pointed at the proxy.
    pub fn workload_env(&self, caller_env: &[String], scope: EnvScope) -> Vec<String> {
        workload_env(caller_env, scope, &self.proxy_url, self.host_loopback)
    }
}

fn workload_env(
    caller_env: &[String],
    scope: EnvScope,
    proxy_url: &str,
    host_loopback: bool,
) -> Vec<String> {
    let mut env = process_env::with_proxy(caller_env, proxy_url, host_loopback);
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

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.teardown(&mut Logger::new(Mode::Buffer));
    }
}

/// The proxy URL the workload is pointed at. A custom proxy's IP or loopback
/// host is unreachable from the workload, so it becomes the gateway's address.
fn workload_proxy_url(custom: Option<&CustomProxy>, subnets: Subnets) -> Result<String, String> {
    let gateway = subnets.gateway_workload();
    let Some(custom) = custom else {
        return Ok(format!("http://{gateway}:{PROXY_PORT}"));
    };
    if let CustomProxyHost::Name(_) = custom.host {
        return Ok(custom.url.clone());
    }
    let mut url = url::Url::parse(&custom.url)
        .map_err(|_| "runtimeConfig.networkProxy is not a valid URL".to_string())?;
    url.set_host(Some(&gateway.to_string())).map_err(|e| {
        format!("could not point runtimeConfig.networkProxy at the built-in proxy: {e}")
    })?;
    Ok(url.into())
}

/// Resolves a custom proxy hostname on Windows and checks the address it
/// resolves to, so the gateway never resolves it. Each call looks the name up
/// and checks it again.
pub fn resolve_custom_proxy(
    egress: &ProxiedEgress,
) -> Result<Option<gateway::CustomProxy>, WslcStepError> {
    egress
        .custom_proxy
        .as_ref()
        .map(|proxy| {
            resolve_custom_proxy_with_lookup(proxy, |host, port| (host, port).to_socket_addrs())
                .map_err(WslcError::into_step_error)
        })
        .transpose()
}

fn resolve_custom_proxy_with_lookup(
    custom: &CustomProxy,
    lookup: impl FnOnce(&str, u16) -> std::io::Result<std::vec::IntoIter<SocketAddr>>,
) -> Result<gateway::CustomProxy, WslcError> {
    let (name, address) = match &custom.host {
        CustomProxyHost::Name(name) => {
            let ip = lookup(name, custom.port)
                .map_err(|e| {
                    WslcError::Unavailable(format!(
                        "WSLc: could not resolve runtimeConfig.networkProxy host '{name}' on \
                         Windows: {e}"
                    ))
                })?
                .find_map(|a| match a.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .ok_or_else(|| {
                    WslcError::Rejected(format!(
                        "WSLc: runtimeConfig.networkProxy host '{name}' has no IPv4 address on Windows"
                    ))
                })?;
            let address = policy::relayed_proxy_address(ip).map_err(|e| {
                WslcError::Rejected(format!("{} (resolved from '{name}')", e.message))
            })?;
            if address.is_none() {
                return Err(WslcError::Rejected(format!(
                    "WSLc: runtimeConfig.networkProxy host '{name}' resolves to Windows loopback; \
                     use http://127.0.0.1:{} instead",
                    custom.port
                )));
            }
            (Some(name.clone()), address)
        }
        CustomProxyHost::Address(address) => (None, *address),
    };
    Ok(gateway::CustomProxy {
        name,
        address,
        port: custom.port,
    })
}

fn render_policy(
    egress: &ProxiedEgress,
    custom_proxy: Option<gateway::CustomProxy>,
    port_mappings: &[PortMapping],
    subnets: Subnets,
) -> gateway::Policy {
    let host_loopback = egress.host_loopback;
    let egress = egress.egress.clone();
    let mut relayed: Vec<gateway::PortMapping> = Vec::new();
    for mapping in port_mappings {
        if relayed
            .iter()
            .all(|r| r.listen_port != mapping.container_port)
        {
            relayed.push(gateway::PortMapping {
                listen_port: mapping.container_port,
                workload_address: subnets.workload(),
                workload_port: mapping.container_port,
            });
        }
    }
    gateway::Policy {
        workload_address: subnets.gateway_workload(),
        egress_address: subnets.gateway_egress(),
        // The workload keeps the custom proxy's port.
        proxy_port: custom_proxy.as_ref().map_or(PROXY_PORT, |proxy| proxy.port),
        forward_dns: egress.default == gateway::Action::Allow || !egress.allow.is_empty(),
        egress,
        host_loopback: host_loopback.then_some(gateway::HostLoopback {
            relay_address: subnets.host_loopback_relay(),
            prefix_length: SUBNET_PREFIX_LENGTH,
        }),
        custom_proxy,
        port_mappings: relayed,
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

/// Delete every proxy and sandbox network recorded for the store. Call once
/// a session has opened the store and before creating either: a store admits
/// one live session, so anything recorded then was left by a run that ended
/// without cleanup.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub unsafe fn sweep_leftovers(
    sdk: &WslcSdk,
    session: WslcSession,
    store_path: &str,
    logger: &mut Logger,
) -> Result<(), String> {
    let records = StoreRecords::open(store_path)?;
    let removed = session_resources::remove_all_recorded::<ProxyNames>(sdk, session, &records)
        .map_err(|e| format!("could not remove the built-in proxy left by an earlier run: {e}"))?;
    if removed {
        let _ = writeln!(logger, "[WSLC] {LEFTOVERS_REMOVED}");
        logger.warning_line(&format!("WARNING: WSLc: {LEFTOVERS_REMOVED}"));
    }
    sandbox_network::remove_leftovers(sdk, session, &records, logger).map_err(|e| {
        format!("could not remove the sandbox networks left by an earlier daemon: {e}")
    })
}

/// Refuse proxy names that exist without a record. They're from a lost
/// record or another tool, so MXC can neither reuse nor delete them.
unsafe fn refuse_unrecorded(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
    names: &ProxyNames,
    networks: &[SessionNetwork],
) -> Result<(), ScriptResponse> {
    let record = records.path(names);
    if record.exists() {
        return Err(host_error(format!(
            "the image store at {} already has a built-in proxy with these names, \
             recorded in {}",
            records.store(),
            record.display()
        )));
    }
    let recorded = records.all_recorded::<ProxyNames>().map_err(host_error)?;
    let unrecorded = |kind: &str, name: &str| {
        host_error(format!(
            "the image store at {} has a {kind} named {name} that MXC can't prove it created \
             (no ownership record lists it), so MXC won't delete it; delete it from the store \
             by hand or set a different wslc.storagePath",
            records.store()
        ))
    };
    for network in networks {
        if network.name.starts_with(NAME_PREFIX) && !recorded.contains(&network.name) {
            return Err(unrecorded("network", &network.name));
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

fn create_container_error(hr: HRESULT, sdk_msg: &str) -> WslcError {
    if hr == WSLC_E_CAPABILITY_ADDITIONS_DISABLED {
        return WslcError::Unavailable(
            "WSLc: network.ingress.hostLoopback 'allow' needs the built-in proxy to add \
             NET_ADMIN, which the AllowWSLContainerPrivileged policy forbids on this host"
                .to_string(),
        );
    }
    WslcError::sdk(
        "Could not create the built-in proxy's container",
        hr,
        sdk_msg,
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

fn write_resolv_conf(subnets: Subnets) -> std::io::Result<tempfile::TempPath> {
    let mut file = tempfile::Builder::new()
        .prefix("mxc-wslc-gw-")
        .suffix("-resolv.conf")
        .tempfile()?;
    std::io::Write::write_all(
        &mut file,
        format!(
            "nameserver {}\noptions ndots:0\n",
            subnets.gateway_workload()
        )
        .as_bytes(),
    )?;
    Ok(file.into_temp_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBNETS: Subnets = Subnets {
        egress: Ipv4Addr::new(10, 231, 0, 0),
        internal: Ipv4Addr::new(10, 231, 1, 0),
    };

    #[test]
    fn dns_is_forwarded_only_when_some_egress_is_allowed() {
        let egress = |default, allow: Vec<gateway::Rule>| ProxiedEgress {
            egress: gateway::Egress {
                default,
                allow,
                deny: Vec::new(),
            },
            host_loopback: false,
            custom_proxy: None,
            warnings: Vec::new(),
        };
        let rule = gateway::Rule {
            to: vec![gateway::Target {
                cidr: "20.0.0.0/8".parse().unwrap(),
                except: Vec::new(),
            }],
            ports: None,
        };

        let policy = render_policy(
            &egress(gateway::Action::Deny, vec![rule]),
            None,
            &[],
            SUBNETS,
        );
        assert!(policy.forward_dns);
        assert_eq!(policy.workload_address, Ipv4Addr::new(10, 231, 1, 254));
        assert_eq!(policy.proxy_port, PROXY_PORT);
        assert_eq!(
            workload_proxy_url(None, SUBNETS).unwrap(),
            "http://10.231.1.254:3128"
        );
        assert!(
            render_policy(
                &egress(gateway::Action::Allow, Vec::new()),
                None,
                &[],
                SUBNETS
            )
            .forward_dns
        );
        assert!(
            !render_policy(
                &egress(gateway::Action::Deny, Vec::new()),
                None,
                &[],
                SUBNETS
            )
            .forward_dns
        );
    }

    fn custom(url: &str, host: CustomProxyHost, port: u16) -> CustomProxy {
        CustomProxy {
            url: url.to_string(),
            host,
            port,
        }
    }

    fn resolves_to(
        addrs: &[&str],
    ) -> impl FnOnce(&str, u16) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        let addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        move |_, _| Ok(addrs.into_iter())
    }

    #[test]
    fn a_custom_proxy_is_relayed_on_its_own_port_without_dns_forwarding() {
        let egress = ProxiedEgress {
            egress: gateway::Egress {
                default: gateway::Action::Deny,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            host_loopback: false,
            custom_proxy: None,
            warnings: Vec::new(),
        };
        let relayed = gateway::CustomProxy {
            name: None,
            address: Some(Ipv4Addr::new(1, 1, 1, 1)),
            port: 8080,
        };
        let policy = render_policy(&egress, Some(relayed.clone()), &[], SUBNETS);
        assert_eq!(policy.proxy_port, 8080);
        assert!(!policy.forward_dns);
        assert_eq!(policy.custom_proxy, Some(relayed));
    }

    #[test]
    fn a_custom_proxy_hostname_is_resolved_to_its_first_ipv4_address() {
        let proxy = custom(
            "http://proxy.example:8080",
            CustomProxyHost::Name("proxy.example".to_string()),
            8080,
        );
        let relayed = resolve_custom_proxy_with_lookup(
            &proxy,
            resolves_to(&["[2001:db8::1]:8080", "1.2.3.4:8080"]),
        )
        .unwrap();
        assert_eq!(relayed.name.as_deref(), Some("proxy.example"));
        assert_eq!(relayed.address, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(relayed.port, 8080);

        for addrs in [
            ["[2001:db8::1]:8080"],
            ["127.0.0.1:8080"],
            ["10.231.1.9:8080"],
            ["169.254.169.254:8080"],
        ] {
            assert!(matches!(
                resolve_custom_proxy_with_lookup(&proxy, resolves_to(&addrs)),
                Err(WslcError::Rejected(_))
            ));
        }
        let failed = resolve_custom_proxy_with_lookup(&proxy, |_, _| {
            Err(std::io::ErrorKind::NotFound.into())
        });
        assert!(
            matches!(failed, Err(WslcError::Unavailable(m)) if m.contains("could not resolve"))
        );
    }

    #[test]
    fn a_capability_policy_refusal_reports_the_host_unavailable() {
        assert!(matches!(
            create_container_error(WSLC_E_CAPABILITY_ADDITIONS_DISABLED, ""),
            WslcError::Unavailable(m) if m.contains("AllowWSLContainerPrivileged")
        ));
        assert!(matches!(
            create_container_error(E_FAIL, "boom"),
            WslcError::Sdk { hr: E_FAIL, .. }
        ));
    }

    #[test]
    fn the_workload_reaches_a_custom_proxy_ip_through_the_gateway() {
        let ip = |url: &str, port| {
            custom(
                url,
                CustomProxyHost::Address(Some(Ipv4Addr::new(1, 1, 1, 1))),
                port,
            )
        };
        assert_eq!(
            workload_proxy_url(Some(&ip("http://user:pw@1.1.1.1:8080", 8080)), SUBNETS).unwrap(),
            "http://user:pw@10.231.1.254:8080/"
        );
        assert_eq!(
            workload_proxy_url(Some(&ip("socks5://1.1.1.1:1080", 1080)), SUBNETS).unwrap(),
            "socks5://10.231.1.254:1080"
        );
        let named = custom(
            "https://proxy.example:443",
            CustomProxyHost::Name("proxy.example".to_string()),
            443,
        );
        assert_eq!(
            workload_proxy_url(Some(&named), SUBNETS).unwrap(),
            "https://proxy.example:443"
        );
    }

    #[test]
    fn each_mapped_container_port_is_relayed_once_to_the_workload() {
        let mapping = |windows_port, container_port| PortMapping {
            windows_port,
            container_port,
            protocol: "tcp".to_string(),
        };
        let egress = ProxiedEgress {
            egress: gateway::Egress {
                default: gateway::Action::Deny,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            host_loopback: false,
            custom_proxy: None,
            warnings: Vec::new(),
        };
        let policy = render_policy(
            &egress,
            None,
            &[
                mapping(18080, 8080),
                mapping(18081, 8080),
                mapping(2222, 22),
            ],
            SUBNETS,
        );
        assert!(!policy.forward_dns);
        assert_eq!(
            policy.port_mappings,
            [8080, 22].map(|port| gateway::PortMapping {
                listen_port: port,
                workload_address: Ipv4Addr::new(10, 231, 1, 2),
                workload_port: port,
            })
        );
    }

    #[test]
    fn workload_env_adds_node_proxy_to_the_default_environment() {
        let url = "http://10.231.1.254:3128";
        let env = workload_env(
            &["HTTPS_PROXY=http://other:1".to_string()],
            EnvScope::Merge,
            url,
            false,
        );
        assert!(env.contains(&"HTTPS_PROXY=http://10.231.1.254:3128".to_string()));
        assert!(env.contains(&"NODE_USE_ENV_PROXY=1".to_string()));

        let env = workload_env(&[], EnvScope::Replace, url, false);
        assert!(env.contains(&"HTTPS_PROXY=http://10.231.1.254:3128".to_string()));
        assert!(!env.iter().any(|e| e.starts_with("NODE_USE_ENV_PROXY=")));

        let env = workload_env(
            &["NODE_USE_ENV_PROXY=0".to_string()],
            EnvScope::Merge,
            url,
            false,
        );
        assert_eq!(
            env.iter()
                .filter(|e| e.starts_with("NODE_USE_ENV_PROXY="))
                .collect::<Vec<_>>(),
            ["NODE_USE_ENV_PROXY=0"]
        );
    }

    #[test]
    fn host_loopback_is_relayed_at_its_own_address_and_bypasses_the_proxy() {
        let egress = |host_loopback| ProxiedEgress {
            egress: gateway::Egress {
                default: gateway::Action::Deny,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            host_loopback,
            custom_proxy: None,
            warnings: Vec::new(),
        };
        assert_eq!(
            render_policy(&egress(true), None, &[], SUBNETS).host_loopback,
            Some(gateway::HostLoopback {
                relay_address: Ipv4Addr::new(10, 231, 1, 3),
                prefix_length: 24,
            })
        );
        assert_eq!(
            render_policy(&egress(false), None, &[], SUBNETS).host_loopback,
            None
        );

        let caller = ["NO_PROXY=*".to_string()];
        let no_proxy = |host_loopback| {
            workload_env(
                &caller,
                EnvScope::Merge,
                "http://10.231.1.254:3128",
                host_loopback,
            )
            .into_iter()
            .filter(|e| e.to_ascii_uppercase().starts_with("NO_PROXY="))
            .collect::<Vec<_>>()
        };
        assert_eq!(
            no_proxy(true),
            ["NO_PROXY=host.wslc.internal", "no_proxy=host.wslc.internal"]
        );
        assert_eq!(no_proxy(false), ["NO_PROXY=", "no_proxy="]);
    }

    #[test]
    fn proxy_names_share_the_prefix_and_the_owner_key() {
        let names = ProxyNames::for_owner("wslc:one");
        let other = ProxyNames::for_owner("wslc:two");
        assert!(session_resources::is_fingerprint(&names.key));
        assert_ne!(names.key, other.key);
        assert!(names
            .all()
            .iter()
            .all(|name| name.starts_with(&format!("{NAME_PREFIX}{}-", names.key))));
    }

    #[test]
    fn each_proxy_takes_two_subnets_no_other_network_holds() {
        let held = |name: &str, subnet: [u8; 4]| SessionNetwork {
            name: name.to_string(),
            ipv4_subnet: Some((Ipv4Addr::from(subnet), 24)),
        };
        let subnets = Subnets::allocate(&[
            held("bridge", [172, 17, 0, 0]),
            held("a", [10, 231, 0, 0]),
            held("b", [10, 231, 2, 0]),
        ])
        .unwrap();
        assert_eq!(subnets.egress, Ipv4Addr::new(10, 231, 1, 0));
        assert_eq!(subnets.internal, Ipv4Addr::new(10, 231, 3, 0));
        assert_eq!(subnets.workload(), Ipv4Addr::new(10, 231, 3, 2));

        let full: Vec<_> = (0..=255).map(|c| held("n", [10, 231, c, 0])).collect();
        assert!(Subnets::allocate(&full[1..]).is_err());
    }
}
