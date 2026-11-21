// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::execution_context::{ContextInput, ExecutionContext};

pub(crate) fn describe(mut input: ContextInput) -> ExecutionContext {
    input.filesystem.notes.extend([
        "Windows ACLs can supply additional access, including ALL_APPLICATION_PACKAGES grants; that access is not inventoried here.".to_string(),
        "An applicable equal-path denial wins; a more-specific explicit child grant can reopen access beneath a denied parent.".to_string(),
        "Enumeration-only access does not permit reading file contents.".to_string(),
    ]);
    if input.capture_allows_access {
        input.filesystem.notes.push(
            "captureDenials allow mode is configured: ungranted accesses can be allowed while recording; this is not a strict deny-by-default run.".to_string(),
        );
    }
    input
        .network
        .egress_default
        .get_or_insert("deny".to_string());
    input
        .network
        .ingress_default
        .get_or_insert("deny".to_string());
    input
        .network
        .host_loopback
        .get_or_insert("deny".to_string());
    input.network.notes.push(
        "Configured network access does not guarantee reachability. Native launch validation remains authoritative.".to_string(),
    );
    if input.network.proxy_configured == Some(true) {
        input.network.notes.push(
            "A runtime proxy is configured; its URL and credentials are omitted. Consult the proxy policy for destination filtering.".to_string(),
        );
    }
    if input.process.working_directory.is_none() {
        input.process.notes.push(
            "Omitted cwd selects the first existing writable policy directory, then a readable policy directory, then the system drive root; no directory was probed here.".to_string(),
        );
    }
    input.process.notes.push(
        "Environment replacement must satisfy Windows requirements; native PSEC can replace LOCALAPPDATA with a container-profile path. An omitted or zero timeout imposes no MXC workload timeout.".to_string(),
    );
    ExecutionContext {
        backend: "processcontainer".to_string(),
        filesystem: input.filesystem,
        network: input.network,
        process: input.process,
        limitations: vec![
            "Configured policy only, not a list of every accessible file. Path existence, aliases, host capabilities and OS permissions are not checked.".to_string(),
            "This context applies only to processes using this MXC request; it does not describe unrelated tools or grant permission.".to_string(),
        ],
    }
}
