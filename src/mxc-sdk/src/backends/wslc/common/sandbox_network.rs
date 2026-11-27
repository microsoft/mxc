// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The network of its own that each bridged container lifecycle sandbox joins,
//! so a sandbox can't connect to another sandbox's container address in the
//! same session VM.

use std::ffi::{CStr, CString};
use std::fmt::Write as _;

use crate::mxc_common::logger::Logger;
use crate::wslc_common::error::{WslcError, WslcStepError};
use crate::wslc_common::session_resources::{
    self, fingerprint, Kind, OwnedNames, StoreRecords, SUBNET_PREFIX_LENGTH,
};
use crate::wslc_common::wslc_bindings::*;

const NAME_PREFIX: &str = "mxc-wslc-net-";

struct NetworkName {
    key: String,
    network: CString,
}

impl OwnedNames for NetworkName {
    const RECORD_SUFFIX: &'static str = ".network.json";

    fn from_key(key: String) -> Self {
        Self {
            network: CString::new(format!("{NAME_PREFIX}{key}")).expect("the key is hex"),
            key,
        }
    }

    fn key(&self) -> &str {
        &self.key
    }

    fn resources(&self) -> Vec<(Kind, &CStr)> {
        vec![(Kind::Network, self.network.as_c_str())]
    }
}

pub struct SandboxNetwork {
    name: NetworkName,
    store: String,
}

impl SandboxNetwork {
    pub fn named(sandbox_id: &str, store_path: &str) -> Self {
        Self {
            name: NetworkName::from_key(fingerprint(sandbox_id)),
            store: store_path.to_string(),
        }
    }

    /// # Safety
    /// `sdk` must hold valid function pointers, `session` must be live, and COM
    /// must be initialized on the calling thread.
    pub unsafe fn create(
        sdk: &WslcSdk,
        session: WslcSession,
        store_path: &str,
        sandbox_id: &str,
        logger: &mut Logger,
    ) -> Result<Self, WslcStepError> {
        let network = Self::named(sandbox_id, store_path);
        let name = &network.name;
        let networks = session_resources::list_networks(sdk, session)
            .map_err(|e| sdk_failure(e, "WslcListSessionNetworks"))?;

        // Cleanup deletes by name, so it must never adopt a network it didn't create.
        if networks
            .iter()
            .any(|listed| listed.name.as_bytes() == name.network.to_bytes())
        {
            return Err(host(format!(
                "WSLc: the session already has a network named {}, which MXC didn't create for \
                 this sandbox",
                name.network.to_string_lossy()
            )));
        }
        let used: Vec<_> = networks
            .iter()
            .filter_map(|network| network.ipv4_subnet)
            .collect();
        let subnet = session_resources::first_free_subnet(&used).ok_or_else(|| {
            host(
                "WSLc: this session has no free subnet left for another bridged sandbox; \
                 deprovision a bridged sandbox in it, or place this one in a session of its own \
                 with provision-session (contract 1.1.0-alpha)"
                    .to_string(),
            )
        })?;
        let records = StoreRecords::open(store_path).map_err(host)?;
        records.write(name, &name.all()).map_err(host)?;
        if let Err(e) =
            session_resources::create_network(sdk, session, &name.network, subnet, false)
        {
            let mut error = sdk_failure(e, "WslcCreateSessionNetwork");
            if let Err(cleanup) = session_resources::remove_recorded(sdk, session, &records, name) {
                error.error_message =
                    format!("{}; cleanup also failed: {cleanup}", error.error_message);
            }
            return Err(error);
        }
        let _ = writeln!(
            logger,
            "[WSLC][daemon] Network {} created on {subnet}/{SUBNET_PREFIX_LENGTH}",
            name.network.to_string_lossy()
        );
        Ok(network)
    }

    pub fn name(&self) -> &CStr {
        &self.name.network
    }

    /// Call once no container is attached to the network.
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers, `session` must be the live
    /// session the network was created in, and COM must be initialized on the
    /// calling thread.
    pub unsafe fn delete(
        &self,
        sdk: &WslcSdk,
        session: WslcSession,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let records = StoreRecords::open(&self.store)?;
        session_resources::remove_recorded(sdk, session, &records, &self.name)?;
        let _ = writeln!(
            logger,
            "[WSLC][daemon] Network {} deleted",
            self.name.network.to_string_lossy()
        );
        Ok(())
    }
}

/// Delete every sandbox network recorded for the store.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be live, and COM
/// must be initialized on the calling thread.
pub(crate) unsafe fn remove_leftovers(
    sdk: &WslcSdk,
    session: WslcSession,
    records: &StoreRecords,
    logger: &mut Logger,
) -> Result<(), String> {
    if session_resources::remove_all_recorded::<NetworkName>(sdk, session, records)? {
        let _ = writeln!(
            logger,
            "[WSLC] Removed sandbox networks left by an earlier daemon"
        );
    }
    Ok(())
}

fn host(message: String) -> WslcStepError {
    WslcError::Host(message).into_step_error()
}

fn sdk_failure(error: WslcError, operation: &str) -> WslcStepError {
    session_resources::session_network_failure(
        error,
        operation,
        "bridged networking for container lifecycle operations",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wslc_common::egress_gateway::ProxyNames;
    use crate::wslc_common::session_resources::record_key;

    #[test]
    fn proxy_and_sandbox_network_records_never_sweep_each_other() {
        let key = fingerprint("wslc:0123456789abcdef0123456789abcdef");
        let network_record = format!("{key}{}", NetworkName::RECORD_SUFFIX);
        let proxy_record = format!("{key}{}", ProxyNames::RECORD_SUFFIX);

        assert_eq!(
            record_key::<NetworkName>(&network_record),
            Some(key.as_str())
        );
        assert_eq!(record_key::<ProxyNames>(&proxy_record), Some(key.as_str()));
        assert_eq!(record_key::<ProxyNames>(&network_record), None);
        assert_eq!(record_key::<NetworkName>(&proxy_record), None);
    }
}
