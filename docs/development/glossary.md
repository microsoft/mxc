# MXC developer glossary and wording guide

> **Audience:** MXC developers

Use the preferred wording in consumer prose; keep code identifiers unchanged.
Shared terms: [consumer glossary](../glossary.md).

## Implementation terminology

| Existing term | Preferred wording | Specific meaning or example |
|---|---|---|
| State-aware / stateful API | Container lifecycle operations | Provision, start, exec, stop, deprovision; implemented by `StatefulSandboxBackend`. Use "manual lifecycle operations" when emphasizing caller-managed calls and cleanup. |
| One-shot | Create-and-run execution | Make container, run workload, clean up. |
| Exact contract / exact registered contract | Contract | Versioned request rules in `mxc_contract`; identify the version, operation, and provision backend. A schema describes the contract. |
| Wire format / wire contract | Interface-specific format / contract | Name the format: ["MXC request JSON"](../schema.md#mxc-request-json) or daemon binary frames. |
| Wire type / DTO (data transfer object) | Serialization type | Name the exchanged-data type and namespace, not just its role. |
| Closed type / closed enum / closed union | Fixed set of types or values | Enumerated choices; host availability is checked independently. |
| Closed request root / recursively closed schema | Unknown-field rejection | Applies to the top-level request / nested objects too. Name the version and operation. |
| Request root | Top-level request type | Creation or lifecycle input in JSON schema, not a filesystem root. |
| Discriminator | Variant-selecting field | Lifecycle "MXC request JSON" uses `phase`. |
| Binding / checked binding | Checked backend-config conversion | Preserve absent versus present-empty configuration. |
| Backend-neutral | Shared across backends | `mxc_common` models, not backend execution or enforcement. |
| Operation-neutral | Shared across named operations | Name the operations, type, and shared responsibility. |
| Surface / authoring surface | Named API, type, or field | Example: `Microsoft.Mxc.Sdk.V1.ContainerRequest`. |
| Pinned version / hash | Required version / expected checksum | Dependency selection or verification, not log-output assertions. |
| Pinned logging / pin logger output in corpus | Record and assert expected logs | Name the log fields, test inputs, and comparison test. |
| Hosts-file pin / pinned proxy endpoint | Address mapping / address restriction | Name the hosts-file entry or permitted proxy address. |

## Avoid ambiguous shorthand

These are wording examples, not feature names.

| Wording to avoid | Write instead |
|---|---|
| The request / the config / change policy configuration | Name the actual type, namespace, and field, e.g. `mxc_sdk::v1::ContainerRequest`. |
| Unqualified `ExecutionRequest` | SDK input: `mxc_sdk::v1::ExecutionRequest`. Runtime model: `mxc_common::models::ExecutionRequest`. |
| Closed exclusion | Specify field rejection, a predefined diagnostic reason, or denied access. |
| Closes over policy | Specify callback capture, contained policy fields, or validation. |
| Pin output | Record expected output and assert it in a named test. |
| Operation-neutral configuration | Name the shared type and operations. |
| Raw JSON / "Native request" / "SDK request JSON" | Use ["MXC request JSON"](../schema.md#mxc-request-json); typed SDK callers do not author JSON. |

## Documentation editing rules

Keep edits local. Name types and fields; define unfamiliar terms.
Use "contract," not "exact contract"; reserve "schema" for its JSON description.
Quote JSON format names and link their definitions on first use.
Keep API names, signatures, paths, and commands unchanged.
