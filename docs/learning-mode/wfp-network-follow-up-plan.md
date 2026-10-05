# WFP Learning Mode follow-up plan

## Current validated state

The MVP diagnostic path works end to end:

1. ProcessModel installs per-AppContainer WFP filters.
2. WFP records a denied network operation.
3. AppInfo receives the event through `FwpmNetEventSubscribe4`.
4. AppInfo emits `Microsoft-Windows-LearningMode-NetworkDecision` event ID 1.
5. The event is routed into the matching managed Learning Mode ETL.
6. MXC decodes the event and places it in either canonical denials or verbose
   diagnostics.

MXC starts native capture with `StartLearningModeTraceWithOptions`, requesting
both `ACCESS` and `NETWORK`. AppInfo owns WFP startup, rollback, draining, and
cleanup; MXC does not coordinate with WFP directly. If the combined start
fails, MXC fails the trace rather than collecting partial access-only data.

VM validation used an outbound TCP connection to `1.1.1.1:445`. The managed
ETL contained one `NetworkDecisionV1` event with the expected package, endpoint,
protocol, direction, Tessera provider, and Tessera sublayer.

## Completed OS.2020 contract: Tessera denial reasons

ProcessModel stores a two-byte `WfpFilterReason` header followed by the exact
user SID in `FWPM_FILTER0.providerData` when
`Feature_Tessera_WfpPolicyTagging` is enabled. AppInfo validates that private
format and copies only a valid non-`None` reason into the existing
`NetworkDecisionV1.Reason` field:

```text
0   = no actionable denial reason
100 = direct default deny
101 = explicit deny rule
102 = allow-rule exclusion
103 = proxy-containment baseline
```

Malformed, unsupported, disabled-feature, and `None` metadata leave the public
reason at `65535` (unknown/unavailable). MXC does not parse WFP provider data.

The unshipped detailed attribution fields were removed. `NetworkDecisionV1`
retains its original event ID/version `1` and 24-field shape, ending with
`CapabilityId`. MXC maps reasons `100`-`103` directly and does not require
`TagVersion`, `PolicyModel`, `RuleKind`, or `RuleOrdinal`.

## Remaining MXC work: schema 0.8 policy regeneration

Once a direct default-deny event becomes a canonical network denial,
MXC can report it through `captureDenials`. The compatibility adjusted-config
generator does not yet consume it:

- `src/host/plm/src/analysis.rs::legacy_config_inputs` handles file and
  capability denials only;
- `ResourceType::Network` is intentionally ignored;
- therefore an actionable network denial does not yet update an adjusted
  schema 0.8 policy.

Implement network regeneration as schema-aware logic rather than extending the
legacy file/capability event format:

1. Read `DenialDetails::Network` from canonical denials.
2. Accept only `Tessera` + `DirectDefaultDeny`.
3. Convert IPv4 destinations to `/32` and IPv6 destinations to `/128`.
4. Preserve the protocol and destination port when present.
5. Add the resulting selector to `network.egress.allow`.
6. Deduplicate equivalent CIDR/protocol/port selectors.
7. Preserve existing deny rules and deny precedence.
8. Do not generate direct allows for explicit denies, allow exclusions, proxy
   containment, unknown reasons, or incomplete endpoints.
9. Reject or skip regeneration when the source policy selects the proxy model,
   because a direct allow would bypass its required egress path.
10. Add schema 0.8 adjusted-config tests for IPv4, IPv6, portless protocols,
    duplicates, existing rules, deny conflicts, and proxy policies.

## Completion criteria

For a direct default-deny TCP connection to `1.1.1.1:445`:

1. The managed ETL contains `Reason=100` in the original 24-field
   `NetworkDecisionV1` payload.
2. MXC emits a canonical network denial for `tcp://1.1.1.1:445`.
3. Policy regeneration adds an egress allow selector equivalent to:

```json
{
  "to": [{ "cidr": "1.1.1.1/32" }],
  "ports": [{ "protocol": "tcp", "port": 445 }]
}
```

4. Re-running with the adjusted policy permits that endpoint while preserving
   all unrelated network restrictions.
