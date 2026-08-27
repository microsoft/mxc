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

VM validation used an outbound TCP connection to `1.1.1.1:445`. The managed
ETL contained one `NetworkDecisionV1` event with the expected package, endpoint,
protocol, direction, Tessera provider, and Tessera sublayer.

## Remaining OS.2020 work: Tessera filter tags

The ProcessModel/Tessera network-filtering code must set
`FWPM_FILTER0.rawContext` when each filter is installed:

```text
bits 63-48: magic        0x4D58
bits 47-40: version      1
bits 39-32: policy model
bits 31-24: rule kind
bits 23-0:  rule ordinal
```

Policy models:

```text
1 = direct
2 = proxy
```

Rule kinds:

```text
1 = default-deny baseline
2 = explicit deny
3 = allow-rule exclusion
4 = proxy-containment baseline
```

Without this tag, AppInfo emits reason `65535` with zero-valued tag fields.
MXC retains that event as `unknownNetworkReason` in verbose diagnostics because
the endpoint and runtime filter ID do not prove whether the denial represents
missing policy, an explicit deny, an exclusion, or proxy containment.

The ProcessModel owner must add and test these tags in the OS.2020
`processmodel\lib\networkFiltering\` filter-construction path. A direct
default-deny filter must produce reason `100`, tag version `1`, policy model
`1`, and rule kind `1`.

## Remaining MXC work: schema 0.8 policy regeneration

Once a tagged direct default-deny event becomes a canonical network denial,
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

1. The managed ETL contains `Reason=100`, `TagVersion=1`, `PolicyModel=1`, and
   `RuleKind=1`.
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
