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
//! A store admits one live session, so the networks and containers have fixed
//! names, and each run first removes anything a crashed run left behind.

use std::ffi::CStr;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

const EGRESS_NETWORK: &CStr = c"mxc-wslc-gw-0-egress";
const INTERNAL_NETWORK: &CStr = c"mxc-wslc-gw-0-internal";
const GATEWAY_CONTAINER: &CStr = c"mxc-wslc-gw-0-gateway";
/// Name of the workload container on the internal network.
pub(crate) const WORKLOAD_CONTAINER: &CStr = c"mxc-wslc-gw-0-workload";

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
    torn_down: AtomicBool,
}

impl Gateway {
    /// Remove leftovers, create the networks, and start the gateway.
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers, `session` must outlive the
    /// returned value, and COM must be initialized on the calling thread.
    pub(crate) unsafe fn start(
        sdk: &'static WslcSdk,
        session: WslcSession,
        egress: &ProxiedEgress,
        logger: &mut Logger,
    ) -> Result<Self, ScriptResponse> {
        refuse_running_gateway(sdk, session)?;
        let removed = remove_by_name(sdk, session).map_err(|e| {
            WslcError::Host(format!(
                "could not remove the built-in proxy left by an earlier run: {e}"
            ))
            .into_response()
        })?;
        if removed {
            let _ = writeln!(
                logger,
                "[WSLC] Removed the built-in proxy left by an earlier run"
            );
        }
        match Self::start_inner(sdk, session, egress, logger) {
            Ok(gateway) => Ok(gateway),
            Err(e) => {
                let _ = remove_by_name(sdk, session);
                Err(e)
            }
        }
    }

    unsafe fn start_inner(
        sdk: &'static WslcSdk,
        session: WslcSession,
        egress: &ProxiedEgress,
        logger: &mut Logger,
    ) -> Result<Self, ScriptResponse> {
        create_network(sdk, session, EGRESS_NETWORK, EGRESS_SUBNET, false)?;
        create_network(sdk, session, INTERNAL_NETWORK, INTERNAL_SUBNET, true)?;

        let tag = image_tag();
        ensure_image(sdk, session, &tag, logger)?;
        let tag_c = cstr_bytes("gateway image", &tag)?;
        let mut settings = std::mem::zeroed::<WslcContainerSettings>();
        let hr = sdk.WslcInitContainerSettings(tag_c.as_ptr() as PCSTR, &mut settings);
        if hr != S_OK {
            return Err(sdk_error("WslcInitContainerSettings failed", hr, ""));
        }
        let hr = sdk.WslcSetContainerSettingsName(&mut settings, GATEWAY_CONTAINER.as_ptr());
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsName failed", hr, ""));
        }
        // The first network is primary, so the default route leaves through NAT.
        let networks = [
            network(EGRESS_NETWORK, &GATEWAY_EGRESS_IN_ADDR),
            network(INTERNAL_NETWORK, &GATEWAY_WORKLOAD_IN_ADDR),
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
        Ok(Self {
            sdk,
            session,
            _container: container,
            process,
            resolv_conf,
            torn_down: AtomicBool::new(false),
        })
    }

    /// The workload's mount of the gateway's DNS settings.
    pub(crate) fn resolv_conf_mount(&self) -> VolumeMount {
        VolumeMount {
            windows_path: self.resolv_conf.to_string_lossy().into_owned(),
            container_path: RESOLV_CONF.to_string(),
            read_only: true,
        }
    }

    /// Delete the gateway, the workload, and their networks, then log the
    /// gateway's output. Call after the workload has stopped.
    pub(crate) fn teardown(&self, logger: &mut Logger) -> Result<(), String> {
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        let _com = ComApartment::enter()?;
        // SAFETY: `session` outlives `self`, and `sdk` is valid while it lives.
        let removed = unsafe { remove_by_name(self.sdk, self.session) };

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

/// The workload's only network. The SDK reads it when the container is
/// created.
pub(crate) fn workload_networks() -> [WslcContainerNetwork; 1] {
    [WslcContainerNetwork {
        name: INTERNAL_NETWORK.as_ptr(),
        aliases: ptr::null(),
        aliasCount: 0,
        ipv4Address: ptr::null(),
        ipv6Address: ptr::null(),
    }]
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

fn network(name: &'static CStr, address: &'static IN_ADDR) -> WslcContainerNetwork {
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

/// Refuse to touch a gateway that is still serving another run.
unsafe fn refuse_running_gateway(
    sdk: &WslcSdk,
    session: WslcSession,
) -> Result<(), ScriptResponse> {
    let Some(container) = open_container(sdk, session, GATEWAY_CONTAINER)
        .map_err(|e| WslcError::Host(e).into_response())?
    else {
        return Ok(());
    };
    let mut state = WslcContainerState(0);
    let hr = sdk.WslcGetContainerState(container.as_raw(), &mut state);
    if hr != S_OK {
        return Err(sdk_error(
            "Could not read the state of the built-in proxy container",
            hr,
            "",
        ));
    }
    if state == WslcContainerState::WSLC_CONTAINER_STATE_RUNNING {
        return Err(WslcError::Host(
            "the built-in proxy is already running in this image store for another run".to_string(),
        )
        .into_response());
    }
    Ok(())
}

/// Delete the containers, then their networks. Missing ones are skipped.
/// Returns whether anything was deleted.
unsafe fn remove_by_name(sdk: &WslcSdk, session: WslcSession) -> Result<bool, String> {
    let mut removed = false;
    for name in [WORKLOAD_CONTAINER, GATEWAY_CONTAINER] {
        let Some(container) = open_container(sdk, session, name)? else {
            continue;
        };
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcDeleteContainer(
            container.as_raw(),
            WslcDeleteContainerFlags::WSLC_DELETE_CONTAINER_FLAG_FORCE,
            err_msg.as_mut_ptr(),
        );
        match hr {
            S_OK => removed = true,
            WSLC_E_CONTAINER_NOT_FOUND => {}
            _ => return Err(failure("delete container", name, hr, &err_msg)),
        }
    }
    for name in [INTERNAL_NETWORK, EGRESS_NETWORK] {
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcDeleteSessionNetwork(session, name.as_ptr(), err_msg.as_mut_ptr());
        match hr {
            S_OK => removed = true,
            WSLC_E_NETWORK_NOT_FOUND => {}
            _ => return Err(failure("delete network", name, hr, &err_msg)),
        }
    }
    Ok(removed)
}

unsafe fn open_container(
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
}
