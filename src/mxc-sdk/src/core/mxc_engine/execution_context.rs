// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::execution_context::{ContextInput, ExecutionContext};
#[cfg(target_os = "windows")]
use crate::mxc_common::models::ContainmentBackend;
use crate::{Error, ErrorCode};

pub(crate) fn describe(input: ContextInput) -> Result<ExecutionContext, Error> {
    match input.backend {
        #[cfg(target_os = "windows")]
        ContainmentBackend::ProcessContainer => Ok(
            crate::backend_modules::process_container::common::execution_context::describe(input),
        ),
        _ => Err(Error::new(
            ErrorCode::UnsupportedContainment,
            "execution context is currently implemented only for ProcessContainer",
        )),
    }
}
