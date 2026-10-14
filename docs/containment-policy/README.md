# Containment policy language

MXC request JSON selects an exact, versioned containment policy contract. Choose
the document for the `version` in your request; the documents are self-contained
and cover both create-and-run execution and container lifecycle operations.

| Request `version` | Contract | Status |
|---|---|---|
| `0.9.0-alpha` | [0.9.0-alpha](0.9.0/policy.md) | Published; minimum supported |
| `1.0.0` | [1.0.0](1.0.0/policy.md) | Published; current stable |
| `1.1.0-alpha` | [Development](dev/policy.md) | Mutable; may change before publication |

The version is an exact string, not a range or product version. A missing,
retired, or unregistered version is rejected. Schema validation establishes the
request's shape; the selected backend also validates whether it can enforce the
requested policy on the host.
