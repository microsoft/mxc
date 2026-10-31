# API proposal: WSLC built-in egress proxy

> **Audience:** MXC developers

- **Issue:** [#1462](https://github.com/microsoft/mxc/issues/1462)
- **Feature design spec:** [`README.md`](README.md)

No public API changes. WSLC accepts network values through the existing v1
types that it rejects today.

## Caller scenario

- See the [usage examples](README.md#problem-and-scope). Both use the same
  calls; only the request values differ, so one example per SDK is shown.
- The examples run example 2 from the design spec: egress denied,
  `hostLoopback: allow`, and one port mapping. Create-and-run cleans up the
  controller and networks when the run ends; the caller releases nothing extra.

Rust (`mxc_sdk::v1`):

```rust
use mxc_sdk::v1::{
    self, configs::WslcConfig, Containment, ContainerRequest, NetworkAction,
    NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy,
};

let request = ContainerRequest {
    containment: Containment::Wslc(WslcConfig {
        image: "python:3.12-alpine".into(),
        port_mappings: vec![(18080, 8080)],
        ..Default::default()
    }),
    network: Some(NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Allow),
        }),
        ..Default::default()
    }),
    ..ContainerRequest::new("python3 /app/server.py")
};
let output = v1::run(request, Default::default())?;
```

.NET (`Microsoft.Mxc.Sdk.V1`):

```csharp
using Microsoft.Mxc.Sdk.V1;

var request = new ContainerRequest("python3 /app/server.py")
{
    Containment = new Containment.Wslc
    {
        Image = "python:3.12-alpine",
        PortMappings = { new WslcPortMapping(18080, 8080) },
    },
    Network = new NetworkPolicy
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
        Ingress = new NetworkIngressPolicy
        {
            Default = NetworkAction.Deny,
            HostLoopback = NetworkAction.Allow,
        },
    },
};
ExecutionResult output = await MxcContainer.RunAsync(request);
```

Node (`@microsoft/mxc-sdk/v1`):

```typescript
import { run } from '@microsoft/mxc-sdk/v1';

const output = await run({
  command: 'python3 /app/server.py',
  containment: {
    type: 'wslc',
    config: {
      image: 'python:3.12-alpine',
      portMappings: [{ windowsPort: 18080, containerPort: 8080 }],
    },
  },
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'deny', hostLoopback: 'allow' },
  },
});
```

Example 1 (CIDR allow-list) sets `egress.allow` with the existing
`NetworkRulePolicy` / `NetworkRuleConfig` types.

For container lifecycle operations, the same network policy goes on the
provision request (Rust `ProvisionRequest::set_network`, .NET
`WslcProvisionRequest.Network`, Node provision `network`). Provision-time
port mappings require the `1.1.0-alpha` development contract and are not
available in v1 SDKs; use [MXC request JSON](../../../../schema.md#mxc-request-json).

## Proposed signatures and types

- **Rust:** `mxc_sdk::v1`. Fits the existing version; no new or changed
  declarations.
- **.NET:** `Microsoft.Mxc.Sdk.V1`. Fits the existing version; no new or
  changed declarations.
- **Node:** `@microsoft/mxc-sdk/v1`. Fits the existing version; no new or
  changed declarations.

Existing types used: `NetworkPolicy`, `NetworkEgressPolicy` /
`NetworkEgressConfig`, `NetworkIngressPolicy` / `NetworkIngressConfig`,
`NetworkRulePolicy` / `NetworkRuleConfig`, `NetworkPeerPolicy` /
`NetworkPeerConfig`, `NetworkPortPolicy` / `NetworkPortConfig`,
`NetworkRuntimeConfig`, and the WSLC port mapping types. Sync/async behavior
and cancellation are unchanged.

## Inputs, results, and SDK differences

- **Inputs:** no new inputs. Allowed values, defaults and rejections are in
  the design spec's [proposed behavior](README.md#proposed-behavior). Omitted
  optional fields stay omitted, as today.

- **Results:** unchanged. Errors for the new rejections (proposed):

  | Case | Error code |
  |---|---|
  | Non-TCP allow rule, `networkProxy` plus egress rules, overlapping CIDR | `PolicyValidation` / `policy_validation` |
  | WSL older than 3.0.5 for any proxied config | `BackendUnavailable` / `backend_unavailable` |
  | `AllowWSLContainerPrivileged=0` with proxied `hostLoopback: allow` | `BackendUnavailable` / `backend_unavailable` |

  Rust returns `v1::Error`, .NET throws `MxcException`, Node rejects with its
  error type; each carries the code and a message naming the WSL version or
  admin policy.

- **Caller-owned resources:** none added. The controller and networks belong
  to the container and are released by create-and-run cleanup or
  `deprovision`.

- **Discovery:** unchanged; see [Open questions](#open-questions).

- **SDK differences:** one existing difference matters here. Rust and .NET
  provision requests carry `NetworkPolicy.runtime_config` / `RuntimeConfig`;
  Node's provision `DirectionalNetworkConfig` has none. WSLC rejects a proxy
  at provision today. The resolution is design spec
  [open question 1](README.md#open-questions).

## Compatibility and request mapping

- Existing callers compile and behave the same, except for the
  [runtime behavior changes](README.md#contracts-apis-and-compatibility):
  previously rejected requests now run, and `BRIDGED` containers may gain
  Windows loopback access.

- Request mapping is unchanged (contract `1.0.0`):

  | SDK input | MXC request field |
  |---|---|
  | Network `egress` (default, allow, deny) | `network.egress` |
  | Network `ingress` (default, hostLoopback) | `network.ingress` |
  | Network runtime config `networkProxy` | `runtimeConfig.networkProxy` |
  | WSLC port mappings | `wslc.portMappings` (`protocol: tcp`) |

- Optional-field presence is preserved as today.

- Backend and execution-mode support: see the design spec's
  [backend table](README.md#backend-applicability-and-availability).

## Validation and documentation

- Functional scenarios: see the design spec's
  [validation plan](README.md#acceptance-criteria-and-validation-plan).

- SDK tests:
  - Rust `src/mxc-sdk/src/api_tests.rs`: WSLC request with egress rules and
    mixed defaults maps to the expected request fields.
  - Node `sdk/node/tests/unit/policy.test.ts` and
    `sdk/node/tests/integration/wslc-e2e.test.ts`: mapping, plus one proxied
    run.
  - .NET `MxcContainerWslcE2ETests.cs` and `MxcLifecycleWslcE2ETests.cs`: one
    proxied create-and-run and one lifecycle run.
  - Error-code conversion for the new rejections in each SDK.

- References: no signature changes to `docs/api-reference/{rust,dotnet,node}/v1/`.
  Update the WSLC notes in the Rust, .NET and Node SDK READMEs if they
  describe WSLC networking as all-or-nothing.

## Open questions

1. **Discovery capability:** should `BackendCapability` gain a value for WSLC
   egress rules or host loopback, so callers can detect support before
   running? Without one, unsupported hosts fail at run time with
   `backend_unavailable`. Adding a value is non-breaking: the enum is
   `#[non_exhaustive]` in Rust and has an `Unknown` value in .NET. Owners:
   `@theelliotm` and SDK maintainers.

2. **Error codes:** confirm the proposed codes above. Owners: SDK maintainers.

## Review checklist

- [ ] Examples demonstrate a useful caller task and correct ownership.
- [ ] Concrete versioned entry points are named; any new API version is justified.
- [ ] Defaults, optional values, errors, and cancellation are explicit.
- [ ] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [ ] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [ ] Backend and execution-mode support decisions are linked; SDK discovery results and errors reflect them.
- [ ] Compatibility and request mapping are addressed; breaking changes are prominent.
- [ ] Public API validation and consumer documentation updates are planned.
- [ ] Answers and examples are concise; shared design details are linked, not repeated.
