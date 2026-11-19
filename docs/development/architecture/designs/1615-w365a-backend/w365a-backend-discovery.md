# W365A backend discovery and routing

> **Audience:** MXC developers

This extension to the [original proposal](README.md) makes pool selection
optional and replaces per-call endpoint configuration with private routing
records. It changes only the experimental backend; published contracts,
SDK signatures and the opaque `w365:{poolId}:{sessionId}` format stay unchanged.
Token acquisition and remote reservation ownership remain outside MXC.

## Provisioning

`w365Agents.provision.poolId` becomes optional; explicit null or invalid GUIDs
remain invalid. `userObjectId` remains required and non-nil by the backend.
`W365A_GRAPH_ENVIRONMENT` selects a fixed Graph base:

| Value | Graph base |
| --- | --- |
| Omitted or `public` | `https://graph.microsoft.com/beta` |
| `canary` | `https://canary.graph.microsoft.com/testprodbeta_cpc_sh` |

1. With a pool ID, fetch its resource directly. Otherwise list
   `{base}/me/cloudPcPools`, validate pagination and IDs, and try pools in list
   order. An empty list is an error.

2. Fetch `{base}/deviceManagement/virtualEndpoint/cloudPcPools/{poolId}`.
   Require a matching `id`.
   Read `sessionUsage.availableSessionsCount` as Int32 and skip nonpositive
   counts without checkout. Missing or malformed usage is an error. If all
   selected pools lack capacity, return `no_available_sessions`; an explicit
   pool never switches to another pool.
   For a pool with capacity, read `poolUrl` from this resource, not the list.
   Use Graph's checkout destination, path and query directly, appending
   `api-version=3.0`; retain HTTPS/443 and credential/fragment checks without
   imposing a service host or path pattern. Do not rewrite pool IDs or regions.
   Missing or invalid metadata and Graph errors fail explicitly; no endpoint
   environment fallback exists.

3. Use API 3.0 JSON checkout, completing `Created` with the same session ID;
   release remains API 2.0. Without an explicit pool, advance only after an
   HTTP 4xx rejection other than 408, with `possiblySucceeded=false` and no
   allocated ID. All other failures stop. If all pools reject checkout, return
   the last error with per-pool attempt details.

4. Validate checkout's `computerUrl`, save routing, and return the full opaque
   ID. This is a computer-resource URL, not an origin or MCP endpoint. Construct
   readiness/Exec paths without duplicating its resource path or query. Missing
   or invalid `computerUrl` fails; never derive DP routing from a region or
   `W365A_DP_SUFFIX`.

Graph, CP and DP tokens are separate, caller-supplied credentials; none is
acquired, refreshed or stored. Provision needs Graph and CP tokens, not DP.
Listing has a 30-second budget across pages; each resource fetch has 30 seconds
and each checkout has 45 seconds. Supported URL shapes and environment settings
are specified in the [backend guide](../../../../backends/w365agents/w365agents-backend.md).

## Routing and recovery

Preflight storage before discovery. Store bounded, versioned records keyed by
canonical pool/session GUIDs, containing validated destination hostnames and CP
source, never credentials, tickets or complete responses. Use private per-user
storage on Windows/Linux/macOS, owner and link checks, locks and atomic writes.
Identical publication is allowed; conflicting records fail.

Later lifecycle calls require the matching local record and ignore endpoint
variables. They do not query Graph: start/exec use caller-supplied DP credentials;
stop/deprovision use CP credentials. Missing, foreign or corrupt records fail,
including old or cross-machine IDs. No implicit import or rediscovery is added.

After allocation, preserve the cleanup ID and CP routing even when DP validation
fails. Publication failure must report the known ID and CP destination, never
success or another allocation. If no valid record can be saved, direct the caller
to service-operator reconciliation; ordinary MXC cleanup requires that record.

Retain routing after failed, uncertain or accepted release for explicit retries.
Records do not establish reservation status, readiness or completed reset.
No automatic release, pruning, replacement or daemon is introduced.

## Validation

Use the existing native, .NET and Node loopback fixtures on supported hosts for
discovery/failover, fresh-process lifecycle routing and storage/recovery failures.
Scenario coverage is maintained in the
[backend guide](../../../../backends/w365agents/w365agents-backend.md#offline-functional-fixtures).
Offline fixtures, documented `poolUrl` examples and observed API 2.0 URLs do not
verify deployed Graph permissions or API 3.0 routing compatibility. Live
validation requires separate authorization.
