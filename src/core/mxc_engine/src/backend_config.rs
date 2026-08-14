// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Debug;

/// A typed containment backend configuration accepted by the SDK request
/// builder.
///
/// This trait is sealed: callers can use concrete backend configurations
/// directly or store them behind `Box<dyn BackendConfig>`, while wire-format
/// construction remains an engine implementation detail.
pub trait BackendConfig: private::BackendConfigImpl + Debug {}

impl<T> BackendConfig for T where T: private::BackendConfigImpl + Debug + ?Sized {}

pub(crate) use private::{BackendConfigContext, BackendConfigImpl};

mod private {
    use serde_json::Value;
    use wxc_common::mxc_error::MxcError;

    use crate::policy::SandboxPolicy;

    /// Context shared by backend-specific wire configuration builders.
    pub struct BackendConfigContext<'a> {
        pub policy: &'a SandboxPolicy,
        pub container_id: &'a str,
    }

    /// Backend-specific policy-to-wire behavior.
    pub trait BackendConfigImpl {
        fn accepts_host_rules_without_outbound(&self) -> bool;

        fn apply(
            &self,
            config: &mut Value,
            context: &BackendConfigContext<'_>,
        ) -> Result<(), MxcError>;
    }
}
