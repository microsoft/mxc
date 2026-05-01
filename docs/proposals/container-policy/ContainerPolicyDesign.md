# Container Policy Design: Intent, Composition, and Binding

This document defines the policy architecture for sandboxed code execution
across platforms. It introduces **intent policy** — a single declarative
language used by four different policy authors — and describes how their
independent policy statements compose into a concrete, enforceable runtime
configuration.

A companion document, *Container Sandboxing Mechanisms: A Cross-Platform
Survey*, covers the underlying isolation mechanisms (namespaces, AppContainer,
Seatbelt, etc.) that enforce the policies described here.

---

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1 The Problem](#11-the-problem)
  - [1.2 One Language, Four Authors](#12-one-language-four-authors)
  - [1.3 Document Road Map](#13-document-road-map)
- [2. Intent Policy: The Universal Format](#2-intent-policy-the-universal-format)
  - [2.1 Design Principles](#21-design-principles)
  - [2.2 The Four Sections](#22-the-four-sections)
  - [2.3 Storage Classes](#23-storage-classes)
  - [2.4 Network Service References](#24-network-service-references)
  - [2.5 Process, IPC, and Device Declarations](#25-process-ipc-and-device-declarations)
  - [2.6 Constraints](#26-constraints)
  - [2.7 Claims](#27-claims)
- [3. The Code Author](#3-the-code-author)
  - [3.1 What the Code Author Declares](#31-what-the-code-author-declares)
  - [3.2 Worked Examples](#32-worked-examples)
  - [3.3 Agentic Authoring](#33-agentic-authoring)
- [4. The User](#4-the-user)
  - [4.1 What the User Expresses](#41-what-the-user-expresses)
  - [4.2 Consent Models](#42-consent-models)
  - [4.3 Granularity and Revocability](#43-granularity-and-revocability)
  - [4.4 The user_selected Storage Class](#44-the-user_selected-storage-class)
  - [4.5 Agentic Delegation](#45-agentic-delegation)
- [5. The IT Administrator](#5-the-it-administrator)
  - [5.1 What the Administrator Expresses](#51-what-the-administrator-expresses)
  - [5.2 Deny-Overlays and Allow-Ceilings](#52-deny-overlays-and-allow-ceilings)
  - [5.3 Service Catalogs](#53-service-catalogs)
  - [5.4 Distribution and Management](#54-distribution-and-management)
  - [5.5 Worked Example](#55-worked-example)
- [6. The System](#6-the-system)
  - [6.1 What the Operating System Expresses](#61-what-the-operating-system-expresses)
  - [6.2 Platform Invariants as Intent](#62-platform-invariants-as-intent)
  - [6.3 Compile-Time and Runtime Enforcement](#63-compile-time-and-runtime-enforcement)
  - [6.4 Worked Examples](#64-worked-examples)
- [7. Composition: How Four Policies Become One](#7-composition-how-four-policies-become-one)
  - [7.1 The Intersection Rule](#71-the-intersection-rule)
  - [7.2 Formal Semantics](#72-formal-semantics)
  - [7.3 Conflict and Failure](#73-conflict-and-failure)
  - [7.4 Audit Trail](#74-audit-trail)
  - [7.5 Worked Example: End-to-End Composition](#75-worked-example-end-to-end-composition)
- [8. Binding: From Intent to Execution](#8-binding-from-intent-to-execution)
  - [8.1 What the Binder Does](#81-what-the-binder-does)
  - [8.2 Resolution Steps](#82-resolution-steps)
  - [8.3 Backend Feasibility Validation](#83-backend-feasibility-validation)
  - [8.4 Worked Example: Intent to Bound Policy](#84-worked-example-intent-to-bound-policy)
- [9. Bound Policy Format](#9-bound-policy-format)
  - [9.1 Structure Overview](#91-structure-overview)
  - [9.2 Filesystem Rules](#92-filesystem-rules)
  - [9.3 Network Rules](#93-network-rules)
  - [9.4 Resources, Environment, and Platform](#94-resources-environment-and-platform)
- [10. Versioning](#10-versioning)
  - [10.1 Version Axes](#101-version-axes)
  - [10.2 The Binder as Version Bridge](#102-the-binder-as-version-bridge)
  - [10.3 Intent Policy Versioning](#103-intent-policy-versioning)
  - [10.4 Per-Layer Version Checks](#104-per-layer-version-checks)
  - [10.5 Capability Profile Versioning](#105-capability-profile-versioning)
  - [10.6 Bound Policy and Runtime Versioning](#106-bound-policy-and-runtime-versioning)
  - [10.7 Caller Migration Scenarios](#107-caller-migration-scenarios)
  - [10.8 Relationship to Existing MXC Versioning](#108-relationship-to-existing-mxc-versioning)
- [Appendix A: Intent Policy Schema Reference](#appendix-a-intent-policy-schema-reference)
- [Appendix B: Bound Policy Schema Reference](#appendix-b-bound-policy-schema-reference)
- [Appendix C: Worked Examples — Intent to Bound Transformations](#appendix-c-worked-examples--intent-to-bound-transformations)
- [Appendix D: Open Questions and Abstraction Gaps](#appendix-d-open-questions-and-abstraction-gaps)
  - [D.1 Constraints Blur the Line Between Intent and Configuration](#d1-constraints-blur-the-line-between-intent-and-configuration)
  - [D.2 Network Operations Are Advisory-Only](#d2-network-operations-are-advisory-only)
  - [D.3 Claims Lack a Verification Story](#d3-claims-lack-a-verification-story)
  - [D.4 Service Catalog Resolution Is Underspecified](#d4-service-catalog-resolution-is-underspecified)
  - [D.5 Network Scope Narrowing Semantics Are Underspecified](#d5-network-scope-narrowing-semantics-are-underspecified)
  - [D.6 Wall-Time Enforcement Is Universally User-Space](#d6-wall-time-enforcement-is-universally-user-space)
  - [D.7 IPC and Device Models Are Underdeveloped](#d7-ipc-and-device-models-are-underdeveloped)
  - [D.8 Exec Whitelisting for Interpreted Languages](#d8-exec-whitelisting-for-interpreted-languages)
  - [D.9 Multi-Sandbox Orchestration](#d9-multi-sandbox-orchestration)

---

## 1. Introduction

### 1.1 The Problem

Modern software increasingly runs code whose provenance, behavior, and
trustworthiness are uncertain. AI agents generate code on the fly. CLI tools
download and execute plugins. Language model "claws" (CLI + LLM agent
workflows) chain tool invocations that no human has reviewed. Even traditional
applications run third-party dependencies that receive far less scrutiny than
the application code itself.

Containing this code — running it in a sandbox that limits what it can access
and what damage it can do — requires *policy*. But policy authored by whom?

Consider a scenario: an AI coding agent generates a Python script to analyze
a CSV file. The script needs to read the input file, write an output report,
and use pandas. It does not need network access, it does not need to read
`~/.ssh`, and it certainly does not need to modify operating system binaries.

At least four parties have something to say about what this script should be
allowed to do:

1. **The code author** (or the agent that generated the code) knows what
   resources the code needs to function.
2. **The user** who initiated the task knows which specific files to analyze
   and what level of access they are comfortable granting.
3. **The IT administrator** may have organizational rules — no sandbox gets
   network access to external hosts, all executions are memory-capped at 2 GB,
   only signed runtimes are permitted.
4. **The operating system** enforces invariants that no other party can
   override — system binaries are read-only, kernel memory is inaccessible,
   code signing requirements apply.

Today, these four perspectives are typically expressed in completely different
formats, at different times, through different mechanisms, if they are
expressed at all. The result is that sandboxing is either too permissive
(broad defaults that don't reflect actual needs) or too brittle (hand-crafted
configurations that break when anything changes).

### 1.2 One Language, Four Authors

This document proposes a different approach: **a single declarative policy
language — intent policy — that all four parties use.** The same schema, the
same vocabulary of storage classes, network service references, constraints,
and capability declarations. The four policy statements are then
*composed* — intersected so that each can only further restrict, never
broaden — into a single effective policy. That effective policy is then
*bound* to the target platform, resolving abstract declarations into concrete
paths, hostnames, and mechanism configurations.

```
Code Author Intent ──┐
                      │
User Intent ──────────┤
                      ├──→ Compose (intersect) ──→ Effective Intent ──→ Bind ──→ Bound Policy
IT Admin Intent ──────┤
                      │
System Intent ────────┘
```

This design has several properties:

- **Composable by construction.** Because all four policies use the same
  language, intersection is a well-defined operation on matching fields.
  There is no impedance mismatch between "what the admin says" and "what the
  developer says."

- **Auditable.** Every restriction in the final bound policy is traceable to
  a specific policy author. When a sandbox denies an operation, the system can
  report *which* policy layer caused the denial.

- **Portable.** Intent policies contain no platform-specific paths, hostnames,
  or mechanism details. The same intent policy works on Linux, macOS, and
  Windows. Platform specifics enter only at the binding step.

- **Agentic-friendly.** AI agents can generate intent policies using abstract
  vocabulary ("I need read access to `input_data` and write access to
  `output_data`") without knowing whether they are running on Ubuntu or
  Windows 11. The binding step handles platform resolution.

### 1.3 Document Road Map

- **Section 2** defines the intent policy format — the universal schema that
  all four authors use.
- **Sections 3–6** describe each policy author: what they express, why, and
  with what trust model.
- **Section 7** defines composition — how the four policies are intersected
  into a single effective policy.
- **Section 8** describes binding — how abstract intent is resolved to a
  concrete, platform-specific runtime configuration.
- **Section 9** defines the bound policy format — the JSON schema that the
  binder produces and the sandbox runtime consumes.
- **Appendices** provide schema references and worked examples.

The companion survey document covers the platform-specific isolation
mechanisms (AppContainer, namespaces, Seatbelt, BFS, etc.) that enforce
bound policies at runtime. This document is concerned with *what gets
expressed and how it composes*, not with the enforcement machinery.

A future companion document will cover backend capability profiles — formal
descriptions of what each platform's sandboxing primitives can enforce — and
"blessed" policy compositions that guarantee specific security properties.
See §8.3 for the profile model and `examples/capability_profiles/` for
concrete primitive and composition profiles.

---

## 2. Intent Policy: The Universal Format

Intent policy is a declarative, platform-agnostic JSON format for expressing
what a sandboxed workload needs, what constraints apply, and what behavioral
properties the author asserts. It is the common language shared by all four
policy sources.

### 2.1 Design Principles

1. **No platform-specific paths, ports, or mechanism details.** An intent
   policy never names `/usr/bin/python3` or `C:\Python310\python.exe`. It
   says `"language": "python"`. The binder resolves the rest.

2. **Logical data domains, not OS layout.** Storage is described by semantic
   class — `workspace`, `input_data`, `temp` — not by filesystem path. This
   makes intent portable across platforms and across different deployment
   environments on the same platform.

3. **Named service references, not hostnames.** Network access is expressed
   as `"service": "weather-api"`, not `"host": "api.weatherapi.com"`. The
   mapping from logical service name to concrete endpoint is maintained in a
   service catalog owned by the IT administrator or operating system.

4. **Machine-resolvable.** Every field in an intent policy can be mechanically
   resolved by the binder without human judgment. If a field requires
   human interpretation, the schema is wrong.

5. **Composable via intersection.** The schema is designed so that combining
   two intent policies always produces a valid, more-restrictive intent
   policy. There are no fields where composition is ambiguous.

### 2.2 The Four Sections

An intent policy document has four top-level sections:

| Section | Purpose | Trust Model |
|---|---|---|
| `requires` | What the workload needs to function | Validated by the binder — unresolvable requirements fail the bind |
| `constraints` | Hard runtime limits the author commits to | Enforced by the sandbox — violation terminates the workload |
| `claims` | Behavioral properties the author asserts | Informational — future work (see §2.7) |
| `metadata` | Identity, versioning, description | Informational |

```jsonc
{
  "manifest_version": "1.0",

  "metadata": {
    "name": "example-workload",
    "version": "1.0.0",
    "description": "A short description of what this workload does"
  },

  "requires": {
    "runtime":     { /* language, version, packages */ },
    "storage":     [ /* storage class declarations */ ],
    "network":     [ /* service references and capabilities */ ],
    "process":     { /* spawn, exec, signals */ },
    "tools":       [ /* named tool references */ ],
    "credentials": [ /* named credential references */ ],
    "ipc":         "none",
    "devices":     "none"
  },

  "constraints": {
    "max_memory_mb": 1024,
    "max_cpu_cores": 2,
    "max_wall_time_seconds": 120,
    /* ... */
  },

  "claims": {
    "deterministic": true,
    /* ... */
  }
}
```

When used by different policy authors, not all sections are equally relevant.
A code author's intent policy will have rich `requires` declarations. A system
policy will primarily express constraints and restricted-capability
declarations. But the schema is the same — and that uniformity is what makes
composition work.

### 2.3 Storage Classes

Storage classes are the heart of filesystem policy. Rather than naming
platform-specific paths, intent policies declare *logical data domains* with
access modes:

| Class | Typical Access | Semantics |
|---|---|---|
| `workspace` | read-write | Working directory for the workload |
| `input_data` | read | Caller-supplied input files |
| `output_data` | write | Where the workload writes its results |
| `temp` | read-write | Scratch space, discarded after execution |
| `cache` | read-write | Persists across invocations, evictable |
| `config` | read | Application configuration, read-only |
| `secrets` | read | Credentials and keys, injected at runtime, never on disk |
| `app_code` | read | The workload's own code bundle |
| `user_selected` | varies | Files/folders chosen by the user at runtime (see §4.4) |

**What is NOT in this list:** `system_libraries`, `runtime_libraries`, or
platform-specific directories. The binder derives those from the `runtime`
declaration — if the workload needs Python 3.10, the binder knows where
Python's standard library lives on the target platform and grants read access
to it automatically.

A storage declaration in intent policy:

```jsonc
"storage": [
  { "class": "input_data", "access": "read",
    "description": "CSV files to analyze" },
  { "class": "output_data", "access": "write",
    "description": "Analysis report (JSON)" },
  { "class": "workspace", "access": "read-write",
    "description": "Working directory for intermediate results" },
  { "class": "temp", "access": "read-write",
    "persistence": "ephemeral" }
]
```

The `persistence` field indicates whether the storage survives across
invocations:

| Value | Meaning |
|---|---|
| `ephemeral` | Discarded after each execution |
| `discardable` | May survive across invocations but can be evicted |
| (omitted) | Persistence determined by the storage class default |

### 2.4 Network Service References

Network access is expressed as named service references, not as hostnames and
ports:

```jsonc
"network": [
  {
    "service": "weather-api",
    "protocol": "https",
    "operations": ["query"],
    "auth": "injected-token",
    "description": "Weather data provider"
  },
  { "capability": "dns" }
]
```

Each service reference names a logical service. The service catalog (§5.3)
maps logical names to concrete endpoints. The `operations` field is advisory —
it documents what the code does with the service (query, download, upload) but
does not currently affect enforcement. The `auth` field describes how
credentials are delivered:

| Value | Meaning |
|---|---|
| `injected-token` | A credential is injected into the sandbox at a well-known path (see `credentials`) |
| `none` | No authentication required |
| (omitted) | No authentication or auth is handled within the app |

Generic network capabilities (`dns`, `ntp`, `localhost`) are declared
separately from named services because they don't map to a specific host:

```jsonc
{ "capability": "dns" }       // DNS resolution needed
{ "capability": "localhost" }  // Localhost communication needed
```

An empty `network` array means no network access at all — the strongest
network isolation possible.

### 2.5 Process, IPC, and Device Declarations

**Process:**

```jsonc
"process": {
  "spawn": true,         // Can the workload create child processes?
  "max_children": 16,    // Upper bound on child process count
  "exec": ["cargo", "rustc", "cc", "ld"],  // Named executables (resolved by binder)
  "signals": "self"      // Signal scope: "self" (own process tree only)
}
```

**Tools** are a separate declaration for named executables the workload needs:

```jsonc
"tools": [
  { "name": "curl", "access": "execute" },
  { "name": "jq", "access": "execute" }
]
```

The binder resolves tool names to platform-specific executable paths.

**IPC and Devices** use simple capability declarations:

```jsonc
"ipc": "none",      // No inter-process communication needed
"devices": "none"   // No device access needed
```

More granular IPC and device declarations are possible (e.g., specific named
pipes, specific device capabilities) but the common case for contained code
is `"none"`.

### 2.6 Constraints

Constraints are hard, enforceable limits that the sandbox runtime must
respect. Unlike requirements (which declare what the workload *needs*),
constraints declare ceilings (what the workload *must not exceed*):

```jsonc
"constraints": {
  "max_memory_mb": 1024,
  "max_cpu_cores": 2,
  "max_wall_time_seconds": 120,
  "max_processes": 1,
  "max_open_files": 256,
  "max_output_bytes": 10485760,
  "persistent_storage": "forbidden",
  "privilege_escalation": "forbidden",
  "inbound_network": "forbidden"
}
```

| Field | Type | Meaning |
|---|---|---|
| `max_memory_mb` | integer | Memory ceiling in megabytes |
| `max_cpu_cores` | integer | CPU core count limit |
| `max_wall_time_seconds` | integer | Wall-clock execution time limit |
| `max_processes` | integer | Maximum concurrent processes |
| `max_open_files` | integer | Maximum open file descriptors |
| `max_output_bytes` | integer | Maximum bytes written to output |
| `persistent_storage` | `"forbidden"` | Workload may not write to persistent storage |
| `privilege_escalation` | `"forbidden"` | Workload may not escalate privileges |
| `inbound_network` | `"forbidden"` | Workload may not accept inbound connections |

Constraints compose naturally via intersection: when two policies both
declare `max_memory_mb`, the effective constraint is `min(a, b)`. When one
policy declares `privilege_escalation: "forbidden"` and another is silent, the
forbidden constraint wins — silence is not permission.

### 2.7 Claims

Claims are self-asserted behavioral properties:

```jsonc
"claims": {
  "deterministic": true,
  "idempotent": true,
  "no_side_effects_beyond_output": true,
  "no_credential_exfiltration": true
}
```

Claims are **not enforced** by the sandbox runtime. A claim of
`"deterministic": true` does not cause the sandbox to verify determinism.
Claims exist to inform trust decisions, audit posture, and future tooling
that may validate them.

The role of claims in the broader policy architecture is future work. They
are included in the schema for forward compatibility but are not developed
further in this document.

---

## 3. The Code Author

The code author — a human developer, an AI agent, or a code generation
pipeline — is the first policy voice. Their intent policy declares what
resources the code needs to function correctly.

### 3.1 What the Code Author Declares

The code author's primary contribution is the `requires` section: a
least-privilege declaration of capabilities. The principle is simple:
**declare exactly what you need, nothing more.**

The code author also sets initial `constraints` — self-imposed limits that
reflect the expected resource envelope of the workload. These are not
aspirational; they are hard limits that the sandbox will enforce. A code
author who sets `max_memory_mb: 512` is asserting that the code should be
terminated if it exceeds 512 MB, because that would indicate a bug or
unexpected behavior.

The code author's intent policy is a **complete, self-contained document.**
It should be possible to read a code author's intent policy and understand:

- What language and runtime the code needs
- What data it reads and writes (by storage class)
- What external services it communicates with (by name)
- What system tools it invokes
- What credentials it requires
- What resource limits apply
- What behavioral properties the author asserts

### 3.2 Worked Examples

**Example: Offline computation (no network, no credentials)**

A Python data analysis script that reads CSV files, processes them with
pandas, and writes a JSON report:

```jsonc
{
  "manifest_version": "1.0",
  "metadata": {
    "name": "csv-data-analyzer",
    "version": "1.0.0",
    "description": "Reads CSV input, performs statistical analysis with pandas,
                    writes summary report"
  },
  "requires": {
    "runtime": {
      "language": "python",
      "min_version": "3.10",
      "packages": ["pandas", "numpy"]
    },
    "storage": [
      { "class": "input_data", "access": "read",
        "description": "CSV files to analyze" },
      { "class": "output_data", "access": "write",
        "description": "Analysis report (JSON)" },
      { "class": "workspace", "access": "read-write",
        "description": "Working directory for intermediate results" },
      { "class": "temp", "access": "read-write", "persistence": "ephemeral" }
    ],
    "network": [],
    "process": { "spawn": false },
    "ipc": "none",
    "devices": "none",
    "credentials": []
  },
  "constraints": {
    "max_memory_mb": 1024,
    "max_cpu_cores": 2,
    "max_wall_time_seconds": 120,
    "max_processes": 1,
    "max_output_bytes": 10485760,
    "persistent_storage": "forbidden",
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden"
  },
  "claims": {
    "deterministic": true,
    "idempotent": true,
    "no_side_effects_beyond_output": true
  }
}
```

Key observations:

- `"network": []` — the strongest possible network declaration. The code
  needs no network access at all.
- `"process": { "spawn": false }` — no child processes. The sandbox can
  block `fork()` entirely.
- `"credentials": []` — no secrets needed. The sandbox need not inject any
  credential material.
- The constraints reinforce the intent: `max_processes: 1` is consistent
  with `spawn: false`, and `inbound_network: "forbidden"` is consistent with
  an empty network array.

**Example: Network services with credentials**

A Node.js API aggregator that queries two external services:

```jsonc
{
  "manifest_version": "1.0",
  "metadata": {
    "name": "multi-api-aggregator",
    "version": "2.1.0",
    "description": "Queries weather and geocoding APIs, aggregates results"
  },
  "requires": {
    "runtime": {
      "language": "node",
      "min_version": "20.0",
      "packages": ["axios", "zod"]
    },
    "storage": [
      { "class": "workspace", "access": "read-write" },
      { "class": "output_data", "access": "write" },
      { "class": "temp", "access": "read-write", "persistence": "ephemeral" },
      { "class": "config", "access": "read",
        "description": "Query parameters and API config" }
    ],
    "network": [
      { "service": "weather-api", "protocol": "https",
        "operations": ["query"], "auth": "injected-token" },
      { "service": "geocoding-api", "protocol": "https",
        "operations": ["query"], "auth": "injected-token" },
      { "capability": "dns" }
    ],
    "process": { "spawn": false },
    "ipc": "none",
    "devices": "none",
    "credentials": [
      { "name": "WEATHER_API_KEY", "type": "api-key" },
      { "name": "GEOCODING_API_KEY", "type": "api-key" }
    ]
  },
  "constraints": {
    "max_memory_mb": 256,
    "max_cpu_cores": 1,
    "max_wall_time_seconds": 60,
    "max_processes": 1,
    "max_output_bytes": 1048576,
    "persistent_storage": "forbidden",
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden"
  },
  "claims": {
    "deterministic": false,
    "idempotent": true,
    "no_credential_exfiltration": true,
    "no_side_effects_beyond_output": true
  }
}
```

Key observations:

- Network access is declared by *service name*, not by hostname. The code
  author does not know (or need to know) that `weather-api` resolves to
  `api.weatherapi.com`.
- Credentials are declared by name and type. The code author knows the
  credential exists but does not embed its value. The credential is injected
  into the sandbox at a well-known path determined by the binder.
- `auth: "injected-token"` connects the network service to the credential:
  the sandbox must make `WEATHER_API_KEY` available for the code to use when
  calling the weather service.

**Example: Tool execution with process spawning**

An infrastructure health check that invokes system tools:

```jsonc
{
  "manifest_version": "1.0",
  "metadata": {
    "name": "infra-health-check",
    "version": "2.0.0",
    "description": "Shell-based health checker: HTTP endpoints, TLS certs, DB"
  },
  "requires": {
    "runtime": { "language": "bash", "min_version": "5.0" },
    "tools": [
      { "name": "curl", "access": "execute" },
      { "name": "openssl", "access": "execute" },
      { "name": "psql", "access": "execute" },
      { "name": "jq", "access": "execute" }
    ],
    "storage": [
      { "class": "output_data", "access": "write" },
      { "class": "workspace", "access": "read-write" },
      { "class": "config", "access": "read" },
      { "class": "temp", "access": "read-write", "persistence": "ephemeral" }
    ],
    "network": [
      { "service": "internal-api-gateway", "protocol": "https",
        "operations": ["health-check"] },
      { "service": "internal-auth-service", "protocol": "https",
        "operations": ["health-check"] },
      { "service": "primary-database", "protocol": "tcp",
        "operations": ["query"], "auth": "injected-token" },
      { "capability": "dns" }
    ],
    "process": {
      "spawn": true,
      "max_children": 8,
      "exec": ["curl", "openssl", "psql", "jq", "bash"],
      "signals": "self"
    },
    "ipc": "none",
    "devices": "none",
    "credentials": [
      { "name": "DB_CONNECTION_STRING", "type": "connection-string" }
    ]
  },
  "constraints": {
    "max_memory_mb": 256,
    "max_cpu_cores": 1,
    "max_wall_time_seconds": 120,
    "max_processes": 16,
    "max_output_bytes": 1048576,
    "persistent_storage": "forbidden",
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden"
  },
  "claims": {
    "deterministic": false,
    "idempotent": true,
    "no_credential_exfiltration": true,
    "no_side_effects_beyond_output": true
  }
}
```

This example shows richer process control: `spawn: true` with a named
`exec` list. The sandbox allows child processes but only for the listed
executables — an arbitrary binary cannot be spawned. The binder resolves
tool names like `"curl"` to platform-specific paths (`/usr/bin/curl` on
Linux, `C:\Windows\System32\curl.exe` on Windows).

### 3.3 Agentic Authoring

In agentic workflows — where an AI agent generates both code and the intent
policy that accompanies it — the abstract nature of intent policy is
especially important.

**Why agents cannot write platform-specific policy:**

An AI agent generating a Python script does not know:
- Whether the target machine runs Linux, macOS, or Windows
- Where Python is installed (`/usr/bin/python3.10`?
  `/opt/homebrew/bin/python3`? `C:\Python312\python.exe`?)
- What the filesystem layout looks like
- What network endpoints correspond to logical services
- What isolation mechanisms are available

Asking agents to produce platform-specific bound policies would require them
to have system administration knowledge that is both error-prone and
unnecessary. Intent policy solves this by letting agents express requirements
in portable, abstract terms:

```jsonc
// Agent says: "I need Python with pandas, some files to read, a place to
// write output, and no network access."
{
  "requires": {
    "runtime": { "language": "python", "min_version": "3.10",
                 "packages": ["pandas"] },
    "storage": [
      { "class": "input_data", "access": "read" },
      { "class": "output_data", "access": "write" }
    ],
    "network": []
  }
}
```

The binder handles everything else.

**Agent-generated policy is not automatically trusted.** An agent's intent
policy is treated the same as any other code author's intent — it passes
through user consent (§4), admin policy (§5), and system constraints (§6)
before anything executes. An agent that requests `"service": "public-web"`
with wildcard access will have that request narrowed or denied by admin
policy if the organization restricts external network access.

**Auditability is critical for agentic scenarios.** When an agent generates
an intent policy, the policy document itself serves as an audit record of what
the agent requested. Because the language is abstract and human-readable
("the agent requested read access to `input_data` and write access to
`output_data`"), audit review is feasible even when the agent generates
thousands of workloads. This is dramatically harder if the audit trail
consists of platform-specific bound policies with concrete paths and IP
addresses.

---

## 4. The User

The user — the human who initiates or approves the execution of sandboxed
code — is the second policy voice. Their intent policy narrows the code
author's requirements to reflect what the user actually consents to for this
specific invocation.

### 4.1 What the User Expresses

The user's policy answers the question: **"Of the things this code says it
needs, which am I willing to grant right now?"**

Consider an AI agent that declares it needs `"service": "public-web"` for
research. The user might:

- **Grant fully:** "Yes, access the web."
- **Grant partially:** "Yes, but only `*.wikipedia.org`."
- **Deny:** "No, run this offline."

The user's policy is expressed in the same intent format:

```jsonc
// User's intent: "I consent to network access, but only to Wikipedia"
{
  "requires": {
    "network": [
      { "service": "public-web", "protocol": "https",
        "scope": "*.wikipedia.org" }
    ]
  }
}
```

When composed with the code author's broader request for `"public-web"`, the
intersection narrows to Wikipedia only.

### 4.2 Consent Models

User consent can be obtained through several models, depending on the
deployment context:

**Pre-approved (policy file):** The user provides an intent policy file
before execution. This is suitable for automation pipelines where a human
reviews and approves the policy once, and subsequent invocations reuse it.

```jsonc
// user-policy.jsonc — reviewed and saved by the user
{
  "requires": {
    "storage": [
      { "class": "input_data", "access": "read" },
      { "class": "output_data", "access": "write" }
    ],
    "network": []
  },
  "constraints": {
    "max_memory_mb": 512,
    "max_wall_time_seconds": 60
  }
}
```

**Interactive (runtime prompts):** The sandbox runtime presents the code
author's requirements to the user and asks for approval. This is the model
used by macOS TCC (Transparency, Consent, and Control) dialogs, Android
runtime permissions, and Windows BFS consent prompting. The user sees
something like:

```
"csv-data-analyzer" requests:
  ✓ Read access to input files
  ✓ Write access to output directory
  ✗ No network access requested
  ✗ No credential access requested

  Memory limit: 1024 MB
  Time limit: 120 seconds

  [Allow] [Allow Once] [Deny]
```

The user's response is captured as an intent policy and composed with the
code author's intent.

**Delegated (trust the code author):** In some contexts, the user trusts the
code author entirely and does not want to be prompted. The user's policy is
effectively "allow whatever the code author requests":

```jsonc
// User delegates fully — no narrowing
{
  "requires": {},
  "constraints": {}
}
```

An empty intent policy imposes no additional restrictions. The effective
policy is determined by the code author, IT admin, and system layers.

### 4.3 Granularity and Revocability

User consent operates at several granularity levels:

| Granularity | Example | Persistence |
|---|---|---|
| **Per-invocation** | "Allow this one execution" | Not stored |
| **Per-session** | "Allow for the duration of this agent session" | Session-scoped |
| **Per-workload** | "Always allow csv-data-analyzer with these settings" | Stored in user preferences |
| **Per-author** | "Trust all workloads from this code author" | Stored in user preferences |

Crucially, user consent is **revocable**. Unlike sandbox restrictions (which
are applied once at container creation and cannot be lifted), user consent
can be withdrawn at any time:

- A per-session consent expires when the session ends
- A per-workload consent can be revoked in user preferences
- A per-author trust delegation can be rescinded

Revocation does not affect currently-running workloads (the sandbox is
already configured), but it prevents future invocations from inheriting the
previously granted consent.

### 4.4 The user_selected Storage Class

The `user_selected` storage class represents files or directories chosen by
the user at runtime — the "Open File" or "Save As" dialog pattern:

```jsonc
// Code author's intent: "I may need access to a user-chosen file"
"storage": [
  { "class": "user_selected", "access": "read",
    "description": "File chosen by the user to analyze" }
]
```

This class is unique because its binding depends entirely on user action:

1. The code author declares that user-selected files may be needed
2. At runtime, the sandbox presents a file picker (or folder picker)
3. The user selects specific files or directories
4. The binder creates filesystem rules for exactly those paths
5. Only the user-selected paths are accessible — nothing else

This pattern is already well-established:
- **macOS:** Powerbox file dialogs grant per-file access to sandboxed apps
- **Windows:** BFS consent prompting brokers access to specific files
- **Linux:** XDG Desktop Portals provide file chooser dialogs that return
  file descriptors to sandboxed apps

The `user_selected` class bridges the gap between the code author's abstract
need ("I will process a file the user chooses") and the user's concrete
consent ("I choose this specific file").

### 4.5 Agentic Delegation

When an AI agent invokes sandboxed code, the question of "who is the user?"
becomes nuanced:

**Direct invocation:** A human runs an agent that generates and executes
code. The human is the user. Consent may be interactive ("the agent wants to
analyze your spreadsheet — allow?") or pre-approved ("I trust this agent
to access my Documents folder").

**Chained invocation:** An agent invokes another agent, which generates code.
The original human may be several levels removed. In this case, the consent
model must support delegation:

```
Human ──trusts──→ Agent A ──invokes──→ Agent B ──generates──→ Code
         ↑                                                        ↓
         └──────── consent applies to entire chain ──────────────┘
```

The key principle is that **the human's consent is the ceiling.** Agent A
cannot grant Agent B more access than the human granted Agent A. Each
delegation step can only narrow, never broaden — the same intersection
semantics that govern the four policy layers.

Detailed delegation chain semantics (maximum delegation depth, consent
inheritance across agent boundaries, revocation propagation) are an active
area of design and are not fully specified in this document.

---

## 5. The IT Administrator

The IT administrator — or more broadly, the organizational policy authority —
is the third policy voice. Their intent policy expresses what the
organization permits, regardless of what individual code authors or users
request.

### 5.1 What the Administrator Expresses

The administrator's policy answers the question: **"What are our
organization's rules for sandboxed code execution?"**

Administrator policy typically expresses restrictions:
- Network boundaries ("no external network access outside `*.corp.example.com`")
- Resource ceilings ("no sandbox gets more than 2 GB memory")
- Execution constraints ("only signed runtimes are permitted")
- Data handling rules ("no persistent storage for agent-generated code")

### 5.2 Deny-Overlays and Allow-Ceilings

Administrator intent policy uses the same format as code author intent, but
serves a different purpose. Where a code author's `requires` section says
"I need these capabilities," an administrator's `requires` section says
"these are the capabilities our organization permits." Where a code author's
`constraints` section says "I should not exceed these limits," an
administrator's `constraints` section says "nobody may exceed these limits."

**Example: Organization restricts network and memory**

```jsonc
{
  "manifest_version": "1.0",
  "metadata": {
    "name": "corp-sandbox-policy",
    "version": "1.0.0",
    "description": "Corporate policy for all sandboxed workloads"
  },
  "requires": {
    "network": [
      { "service": "*", "protocol": "https",
        "scope": "*.corp.example.com",
        "description": "Only internal corporate endpoints allowed" }
    ]
  },
  "constraints": {
    "max_memory_mb": 2048,
    "max_wall_time_seconds": 600,
    "max_processes": 32,
    "persistent_storage": "forbidden",
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden"
  }
}
```

When this admin policy is composed with a code author's intent that requests
`"service": "public-web"` (arbitrary internet access), the intersection
denies it — the admin policy allows only `*.corp.example.com`, and
`public-web` falls outside that scope. The bind step fails with an auditable
explanation: "code author requires `public-web`, denied by admin policy
`corp-sandbox-policy` which restricts network to `*.corp.example.com`."

### 5.3 Service Catalogs

The IT administrator (or the operating system, for system-level services)
maintains the **service catalog** — the mapping from logical service names
to concrete network endpoints:

```jsonc
{
  "catalog_version": "1.0",
  "services": {
    "weather-api": {
      "hosts": ["api.weatherapi.com"],
      "port": 443,
      "protocol": "https",
      "auth_method": "bearer-token",
      "credential_ref": "WEATHER_API_KEY"
    },
    "geocoding-api": {
      "hosts": ["api.opencagedata.com"],
      "port": 443,
      "protocol": "https",
      "auth_method": "bearer-token",
      "credential_ref": "GEOCODING_API_KEY"
    },
    "internal-api-gateway": {
      "hosts": ["gateway.corp.example.com"],
      "port": 443,
      "protocol": "https"
    },
    "primary-database": {
      "hosts": ["db-primary.corp.example.com"],
      "port": 5432,
      "protocol": "tcp",
      "auth_method": "connection-string",
      "credential_ref": "DB_CONNECTION_STRING"
    },
    "llm-api": {
      "hosts": ["api.anthropic.com"],
      "port": 443,
      "protocol": "https",
      "auth_method": "bearer-token",
      "credential_ref": "LLM_API_KEY"
    }
  }
}
```

The service catalog is the single point of truth for "what does service name X
mean in our environment?" This separation provides several benefits:

- **Code authors don't embed infrastructure knowledge.** The intent policy
  says `"service": "llm-api"`, and the catalog resolves it. If the
  organization switches LLM providers, only the catalog changes — not every
  intent policy that references the service.

- **Administrators control what services exist.** If a service name is not in
  the catalog, it cannot be resolved, and the bind step fails. This gives
  administrators an implicit allowlist over available services.

- **Credential binding is centralized.** The catalog's `credential_ref`
  field connects service names to credential names, which the binder uses to
  inject the right secrets into the sandbox.

### 5.4 Distribution and Management

Administrator intent policies and service catalogs are distributed through
standard enterprise management channels:

| Platform | Distribution Mechanism |
|---|---|
| Windows | Group Policy Objects (GPO), Microsoft Intune (MDM) |
| macOS | MDM profiles (Jamf, Workspace ONE) |
| Linux | Configuration management (Ansible, Puppet, Chef), package managers |
| Cross-platform | Environment variables, well-known config paths, API endpoints |

The specific distribution mechanism is outside the scope of this document,
but the format is not — administrator policy is expressed in the same intent
policy JSON format, distributed to endpoints, and consumed by the binder at
bind time.

### 5.5 Worked Example

**Scenario:** An organization allows internal services but blocks external
internet access. An AI agent generates code that requests `llm-api` access.

**Admin policy:**
```jsonc
{
  "requires": {
    "network": [
      { "service": "*", "scope": "*.corp.example.com" }
    ]
  }
}
```

**Code author intent (agent-generated):**
```jsonc
{
  "requires": {
    "network": [
      { "service": "llm-api", "protocol": "https",
        "auth": "injected-token" }
    ]
  }
}
```

**Service catalog entry:**
```jsonc
"llm-api": {
  "hosts": ["api.anthropic.com"],
  "port": 443
}
```

**Composition result:** The admin policy restricts network to
`*.corp.example.com`. The `llm-api` service resolves to
`api.anthropic.com`, which is outside the allowed scope.

**Outcome:** Bind fails. The error message is: *"Network service 'llm-api'
resolves to 'api.anthropic.com', which is not permitted by admin policy
'corp-sandbox-policy' (network scope: '*.corp.example.com')."*

If the organization later deploys an internal LLM gateway at
`llm.corp.example.com`, only the catalog changes:

```jsonc
"llm-api": {
  "hosts": ["llm.corp.example.com"],
  "port": 443
}
```

Now the bind succeeds. No intent policies change — neither the agent's nor
the admin's.

---

## 6. The System

The operating system — the platform itself — is the fourth and final policy
voice. System intent policy expresses invariants that hold regardless of what
any code author, user, or administrator requests. It is the security floor
that cannot be lowered.

### 6.1 What the Operating System Expresses

The system's policy answers the question: **"What does this platform
guarantee, unconditionally?"**

Every operating system enforces certain security properties that are not
negotiable:

- Operating system code cannot be modified by applications
- Kernel memory is not accessible to user-mode processes
- Code pages cannot be simultaneously writable and executable (W^X)
- Certain system services and daemons are protected from termination
- Code signing requirements apply to specific contexts

These are not "policies" in the sense that someone chose them for a
particular deployment. They are structural properties of the platform —
invariants that the OS kernel enforces regardless of any policy layer above.

### 6.2 Platform Invariants as Intent

The key insight is that system invariants can be expressed in the same intent
policy format:

```jsonc
{
  "manifest_version": "1.0",
  "metadata": {
    "name": "windows-system-policy",
    "version": "10.0",
    "description": "Windows platform security invariants"
  },
  "requires": {
    "storage": [
      { "class": "system_binaries", "access": "read",
        "description": "OS binaries are read-only; modification is forbidden" },
      { "class": "system_config", "access": "read",
        "description": "System configuration (registry hives, etc.) is read-only" }
    ]
  },
  "constraints": {
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden",
    "kernel_memory_access": "forbidden",
    "modify_system_binaries": "forbidden",
    "disable_aslr": "forbidden",
    "writable_executable_pages": "forbidden"
  }
}
```

By expressing these invariants in intent policy format:

- **Composition works mechanically.** The system policy intersects with
  the other three layers using the same rules. A code author who requests
  write access to a storage class that the system has declared read-only
  will have that request denied at composition time.

- **Failure messages are clear.** "Write access to `system_binaries` denied
  by system policy `windows-system-policy`" is an actionable error message.

- **The binder knows what to enforce.** When system policy declares
  `system_binaries` as read-only, the binder maps this to platform-specific
  paths (`C:\Windows\System32` on Windows, `/usr/lib` on Linux, `/usr/bin`
  on macOS) and generates the appropriate filesystem rules in the bound
  policy.

### 6.3 Compile-Time and Runtime Enforcement

System policy operates at two enforcement points:

**Compile-time (static validation):** When the binder produces a bound
policy, it checks the result against system policy. Any bound policy that
would grant access forbidden by system policy is rejected before any code
runs. This catches misconfigurations early.

**Runtime (dynamic enforcement):** Even if a bound policy somehow permits
something that system policy forbids (e.g., due to a binder bug), the
operating system's own enforcement mechanisms provide a backstop:

| Platform | Runtime Enforcement |
|---|---|
| **Windows** | Integrity levels prevent write-up; PPL protects system processes; KMCS enforces kernel code signing; AppContainer SIDs exclude system paths |
| **macOS** | SIP (System Integrity Protection) protects system volumes; code signing requirements enforced by the kernel; TCC controls access to protected resources |
| **Linux** | SELinux/AppArmor mandatory access control; mount namespaces hide system paths; seccomp-BPF filters dangerous syscalls; kernel `STRICT_DEVMEM` protects `/dev/mem` |

System policy in intent format is a *declaration* of these existing
enforcement mechanisms. It does not create new enforcement — it makes
existing platform guarantees visible and composable with the other policy
layers.

### 6.4 Worked Examples

**"Operating system code cannot be modified"**

Intent (system policy):
```jsonc
{
  "requires": {
    "storage": [
      { "class": "system_binaries", "access": "read" }
    ]
  },
  "constraints": {
    "modify_system_binaries": "forbidden"
  }
}
```

Bound on Windows:
```jsonc
"filesystem": {
  "rules": [
    { "path": "C:\\Windows\\System32", "scope": "subtree",
      "allow": ["read", "execute"] },
    { "path": "C:\\Windows\\SysWOW64", "scope": "subtree",
      "allow": ["read", "execute"] },
    { "path": "C:\\Program Files\\WindowsApps", "scope": "subtree",
      "allow": ["read"] }
  ]
}
```

Bound on Linux:
```jsonc
"filesystem": {
  "rules": [
    { "path": "/usr/bin", "scope": "subtree",
      "allow": ["read", "execute"] },
    { "path": "/usr/lib", "scope": "subtree",
      "allow": ["read", "execute"] },
    { "path": "/usr/sbin", "scope": "subtree",
      "allow": ["read", "execute"] }
  ]
}
```

The intent is the same — "system binaries are read-only" — but the bound
paths are platform-specific.

**"No access to user credentials"**

Intent (system policy):
```jsonc
{
  "requires": {
    "storage": []  // no storage classes that include credential stores
  },
  "constraints": {
    "access_credential_stores": "forbidden"
  }
}
```

Bound on Windows:
```jsonc
"filesystem": {
  "mask": [
    "%USERPROFILE%\\.ssh",
    "%USERPROFILE%\\.aws",
    "%USERPROFILE%\\.azure",
    "%APPDATA%\\Microsoft\\Credentials"
  ]
}
```

Bound on Linux:
```jsonc
"filesystem": {
  "mask": [
    "/home/*/.ssh",
    "/home/*/.aws",
    "/home/*/.gnupg",
    "/home/*/.config/gcloud"
  ]
}
```

---

## 7. Composition: How Four Policies Become One

The four intent policies — code author, user, IT admin, system — are
composed into a single **effective intent policy** before binding. Composition
is the central operation of the policy architecture.

### 7.1 The Intersection Rule

The fundamental composition rule is: **each policy layer can only further
restrict, never broaden.** The effective policy is the intersection of all
four input policies.

This means:
- If the code author requests network access and the admin forbids it, the
  effective policy has no network access.
- If the code author requests 4 GB memory and the admin caps at 2 GB, the
  effective limit is 2 GB.
- If the user denies access to a storage class the code author requested,
  that storage class is removed from the effective policy.
- If the system declares certain paths read-only, no other layer can grant
  write access to those paths.

The beauty of intersection is that it is **unambiguous**. There is no
priority ordering to debate, no conflict resolution heuristic. The most
restrictive statement always wins because every layer can only remove
capabilities, not add them.

### 7.2 Formal Semantics

For each field type in the intent policy schema, composition follows specific
rules:

**Capability sets (storage, network, tools, credentials):** Intersection.
A capability must be present in *all* policies that mention it, or it is
excluded from the effective policy. A policy that is silent on a capability
set (e.g., admin policy does not mention `storage`) imposes no restriction on
that set — silence is not denial.

```
effective.storage = author.storage ∩ user.storage ∩ admin.storage ∩ system.storage
```

Where `∩` means: retain only storage classes that appear in all policies
that declare a `storage` section.

**Numeric constraints:** Minimum. The effective value is `min(a, b, c, d)`
across all policies that declare the constraint.

```
effective.max_memory_mb = min(
  author.max_memory_mb,
  user.max_memory_mb,     // if declared
  admin.max_memory_mb,    // if declared
  system.max_memory_mb    // if declared
)
```

**Forbidden constraints:** Union. If *any* policy declares something
forbidden, it is forbidden in the effective policy.

```
effective.privilege_escalation = "forbidden"
  if any(author, user, admin, system).privilege_escalation == "forbidden"
```

**Access modes:** Intersection. If the code author requests `read-write` for
a storage class and the system declares `read` only, the effective access is
`read`.

```
effective.access = author.access ∩ system.access
// "read-write" ∩ "read" = "read"
```

**Network service scopes:** Intersection. If the code author requests
`"public-web"` (any host) and the admin restricts to `"*.corp.example.com"`,
the effective scope is `"*.corp.example.com"` (or empty, if `public-web`
hosts fall outside that scope).

### 7.3 Conflict and Failure

When composition produces an effective policy that cannot satisfy the code
author's requirements, the bind step **fails explicitly** rather than
silently degrading. This is a critical design choice.

**Why fail-closed?**

A code author who declares `"network": [{ "service": "llm-api" }]` is
saying: "my code needs LLM API access to function." If admin policy denies
network access to the LLM endpoint, there is no useful degraded behavior —
the code will fail at runtime anyway, but in a confusing way (timeout,
connection refused, cryptic error). Failing at bind time with a clear message
is better:

```
Bind failed: code author requires network service 'llm-api',
  but admin policy 'corp-sandbox-policy' restricts network scope
  to '*.corp.example.com' and 'llm-api' resolves to
  'api.anthropic.com' (outside permitted scope).
```

**Distinguishing required from optional capabilities** is a potential future
extension. A code author might mark some requirements as "preferred but not
essential" — the bind could then succeed with a warning when an optional
capability is denied. This is not currently part of the schema.

### 7.4 Audit Trail

Because all four policies use the same format, and composition is a
deterministic operation, every restriction in the effective policy is
**attributable to a specific policy layer:**

| Restriction | Source |
|---|---|
| Read-only access to system binaries | System policy |
| No external network | Admin policy |
| Memory capped at 512 MB | Code author (self-imposed) |
| No access to Documents folder | User (denied consent) |
| Credential injection path | Service catalog (admin) |

The binder can produce an **attribution report** alongside the bound policy,
documenting the provenance of every rule. This is essential for:

- **Debugging:** "Why can't the workload access the network?" →
  "Admin policy restricts network to `*.corp.example.com`."
- **Compliance:** "Who authorized this workload's access to the database?" →
  "Code author requested `primary-database`; admin catalog resolved it to
  `db-primary.corp.example.com:5432`; user consented at 2024-01-15T10:30Z."
- **Agentic audit:** "What did the agent request, and what was it actually
  granted?" → The intent policy (request) and effective policy (grant) are
  both human-readable JSON documents.

### 7.5 Worked Example: End-to-End Composition

**Scenario:** An AI agent generates a research tool that needs LLM access
and web browsing. The user approves with restrictions. The organization has
a network policy. The OS enforces its invariants.

**Code author intent (agent-generated):**
```jsonc
{
  "requires": {
    "runtime": { "language": "python", "min_version": "3.11",
                 "packages": ["httpx", "beautifulsoup4"] },
    "storage": [
      { "class": "workspace", "access": "read-write" },
      { "class": "output_data", "access": "write" },
      { "class": "temp", "access": "read-write", "persistence": "ephemeral" },
      { "class": "cache", "access": "read-write",
        "persistence": "discardable" }
    ],
    "network": [
      { "service": "llm-api", "protocol": "https",
        "auth": "injected-token" },
      { "service": "public-web", "protocol": "https" },
      { "capability": "dns" }
    ],
    "credentials": [
      { "name": "LLM_API_KEY", "type": "api-key" }
    ]
  },
  "constraints": {
    "max_memory_mb": 1024,
    "max_wall_time_seconds": 600,
    "privilege_escalation": "forbidden"
  }
}
```

**User intent (interactive consent):**
```jsonc
{
  "requires": {
    "network": [
      { "service": "llm-api" },
      { "service": "public-web", "scope": "*.wikipedia.org" },
      { "capability": "dns" }
    ]
  },
  "constraints": {
    "max_wall_time_seconds": 300
  }
}
```

The user approves LLM access but restricts web browsing to Wikipedia, and
lowers the time limit.

**Admin intent (organizational policy):**
```jsonc
{
  "requires": {
    "network": [
      { "service": "*", "scope": "*.corp.example.com" },
      { "service": "llm-api" }
    ]
  },
  "constraints": {
    "max_memory_mb": 2048,
    "persistent_storage": "forbidden",
    "inbound_network": "forbidden"
  }
}
```

The admin allows internal endpoints and the LLM API (explicitly
whitelisted), but blocks other external access.

**System intent (OS invariants):**
```jsonc
{
  "constraints": {
    "privilege_escalation": "forbidden",
    "modify_system_binaries": "forbidden",
    "kernel_memory_access": "forbidden"
  }
}
```

**Composition:**

| Capability | Author | User | Admin | System | Effective |
|---|---|---|---|---|---|
| `llm-api` | ✓ | ✓ | ✓ (whitelisted) | — | ✓ |
| `public-web` | ✓ (any) | ✓ (`*.wikipedia.org`) | ✗ (not in scope) | — | **✗ denied** |
| `dns` | ✓ | ✓ | — | — | ✓ |
| `max_memory_mb` | 1024 | — | 2048 | — | **1024** (min) |
| `max_wall_time_seconds` | 600 | 300 | — | — | **300** (min) |
| `persistent_storage` | — | — | forbidden | — | **forbidden** |
| `privilege_escalation` | forbidden | — | — | forbidden | **forbidden** |

**Effective intent policy after composition:**
```jsonc
{
  "requires": {
    "runtime": { "language": "python", "min_version": "3.11",
                 "packages": ["httpx", "beautifulsoup4"] },
    "storage": [
      { "class": "workspace", "access": "read-write" },
      { "class": "output_data", "access": "write" },
      { "class": "temp", "access": "read-write", "persistence": "ephemeral" },
      { "class": "cache", "access": "read-write",
        "persistence": "discardable" }
    ],
    "network": [
      { "service": "llm-api", "protocol": "https",
        "auth": "injected-token" },
      { "capability": "dns" }
    ],
    "credentials": [
      { "name": "LLM_API_KEY", "type": "api-key" }
    ]
  },
  "constraints": {
    "max_memory_mb": 1024,
    "max_wall_time_seconds": 300,
    "persistent_storage": "forbidden",
    "privilege_escalation": "forbidden",
    "inbound_network": "forbidden"
  }
}
```

Note: `public-web` was removed entirely — the admin policy did not permit
it, even though the user narrowed it to Wikipedia. The intersection of
"only Wikipedia" and "only *.corp.example.com" is empty.

This effective intent is then passed to the binder for resolution to a
platform-specific bound policy.

---

## 8. Binding: From Intent to Execution

Binding is the step that transforms an effective intent policy (abstract,
portable) into a bound policy (concrete, platform-specific). The binder is
the single component that has platform knowledge — where Python is installed,
what filesystem paths correspond to storage classes, what hostnames
correspond to service names.

### 8.1 What the Binder Does

The binder takes three inputs:

1. **Effective intent policy** — the composed result from §7
2. **Service catalog** — the IT admin / OS mapping of service names to
   endpoints (§5.3)
3. **Platform context** — OS type, architecture, installed runtimes, available
   isolation mechanisms

And produces one output:

- **Bound policy** — a concrete JSON document with platform-specific paths,
  hostnames, ports, and mechanism configurations

```
Effective Intent + Service Catalog + Platform Context ──→ Binder ──→ Bound Policy
```

The bound policy is the document that the sandbox runtime consumes. It
contains no abstract references — every path is a real filesystem path, every
host is a resolvable DNS name, every mechanism is a concrete platform
feature.

### 8.2 Resolution Steps

The binder performs the following resolutions in order:

**1. Runtime resolution.** The intent's `runtime` declaration is resolved to
concrete executable and library paths:

```
Intent: { "language": "python", "min_version": "3.10", "packages": ["pandas"] }

Linux: /usr/bin/python3.10, /usr/lib/python3.10/**, /usr/local/lib/python3.10/dist-packages/**
Windows: C:\Python310\python.exe, C:\Python310\Lib\**, C:\Python310\Lib\site-packages\**
```

**2. Storage class resolution.** Each storage class maps to a
platform-specific directory:

| Class | Linux Path | Windows Path |
|---|---|---|
| `workspace` | `/workspace` | `C:\Sandbox\Workspace` |
| `input_data` | `/input` | `C:\Sandbox\Input` |
| `output_data` | `/output` | `C:\Sandbox\Output` |
| `temp` | `/tmp` | `C:\Sandbox\Temp` |
| `cache` | `/cache` | `C:\Sandbox\Cache` |
| `config` | `/config` | `C:\Sandbox\Config` |
| `secrets` | `/run/secrets` | `C:\Sandbox\Secrets` |
| `app_code` | `/app` | `C:\Sandbox\App` |

**3. Service name resolution.** Each network service reference is resolved
via the service catalog:

```
Intent: { "service": "weather-api", "protocol": "https" }
Catalog: { "hosts": ["api.weatherapi.com"], "port": 443 }
Bound: { "host": "api.weatherapi.com", "port": 443, "protocol": "tcp", "direction": "outbound" }
```

**4. Tool resolution.** Named tools are resolved to platform-specific
executable paths:

```
Intent: { "name": "curl", "access": "execute" }
Linux: /usr/bin/curl
Windows: C:\Windows\System32\curl.exe
```

**5. Credential resolution.** Named credentials are mapped to injection
paths and environment variables:

```
Intent: { "name": "WEATHER_API_KEY", "type": "api-key" }
Linux: /run/secrets/WEATHER_API_KEY (file), WEATHER_API_KEY_FILE env var
Windows: C:\Sandbox\Secrets\WEATHER_API_KEY (file), WEATHER_API_KEY_FILE env var
```

**6. Platform mechanism selection.** Based on the OS and available isolation
primitives, the binder populates the `platform` section of the bound policy:

- **Linux:** Namespace configuration, seccomp-BPF rules, Landlock rules
- **Windows:** AppContainer capabilities, BFS configuration, Job Object limits
- **macOS:** Seatbelt profile generation

### 8.3 Backend Feasibility Validation

Before producing the bound policy, the binder validates that the target
platform can actually enforce the effective intent policy. Each platform's
sandboxing primitives have specific capabilities and limitations — for
example, a platform without Landlock support cannot enforce per-directory
filesystem rules at the kernel level, and macOS lacks cgroups so process
count limits cannot be expressed as a cap (only as all-or-nothing fork
denial).

The binder checks policy requirements against a three-layer capability
model:

#### 8.3.1 Primitive Profiles

Each isolation mechanism has its own **primitive profile** — a formal
description of what it can enforce, at what granularity, and at what
enforcement level. Capabilities are organized by policy dimension
(filesystem, network, process, resources, IPC, credentials, privilege).

For each capability the profile declares:

- **supported** — whether the primitive can enforce this at all
- **granularity** — the finest unit of control (`per-file`, `per-host-port`,
  `all-or-nothing`, etc.)
- **enforcement** — the enforcement level (`kernel`, `user-space`,
  `advisory`)
- **mechanism** — how enforcement works (e.g., "LSM hooks on path-based
  operations" or "Job object memory limits")
- **limitations** — caveats that affect real-world enforcement

Separate profiles exist for each distinct primitive and version. For
example, `landlock_v4` is a separate profile from a hypothetical
`landlock_v2` because v4 adds network filtering that v2 lacks.

See `examples/capability_profiles/primitives/` for concrete profiles
covering AppContainer, BFS, WFP, Landlock v4, seccomp-bpf, cgroups v2,
Linux namespaces, and macOS Seatbelt.

#### 8.3.2 Blessed Compositions

Real sandbox environments combine multiple primitives into a **stack**.
A blessed composition is a named, validated combination of primitives
whose combined capabilities and **security guarantees** have been
verified. Each composition declares:

- **primitives** — the set of primitives in the stack, each with its role
- **effective_capabilities** — the union of individual primitive
  capabilities, resolved for overlaps (noting which primitive provides
  each capability via `"via"` attribution)
- **guarantees** — security properties the composition provides when
  correctly configured (e.g., `no-filesystem-escape`,
  `no-network-escape`, `no-privilege-escalation`), each with enforcement
  level and caveats
- **known_gaps** — capabilities the composition *cannot* enforce, with
  workarounds where available

The binder can match intent policy claims against composition guarantees.
For example, if the effective intent includes
`"no_credential_exfiltration": true`, the binder verifies the target
composition has a `no-credential-access` guarantee.

See `examples/capability_profiles/compositions/` for the three platform
stacks:

| Composition | Primitives | Guarantees |
|---|---|---|
| `windows_appcontainer_stack` | AppContainer + BFS + WFP | 5 (filesystem, network, privilege, credentials, process containment) |
| `linux_namespace_stack` | Namespaces + Landlock v4 + seccomp + cgroups v2 | 7 (adds resource-bounded, exec-restricted) |
| `macos_seatbelt_stack` | Seatbelt + POSIX rlimits + host timer | 6 (adds exec-restricted, IPC-isolated; weaker resource story) |

#### 8.3.3 Validation and Enforcement Reporting

The binder walks each requirement in the effective intent policy and
checks it against the target composition's effective capabilities:

1. **Requirement satisfied at kernel level** — the bound policy rule is
   emitted and tagged with its enforcement level.
2. **Requirement satisfied at user-space level** — the bound policy rule
   is emitted with an `"enforcement": "user-space"` annotation.
3. **Requirement cannot be satisfied** — a gap is identified.

For gaps, the **caller decides** the disposition — not the binder. The
binder reports gaps with full attribution (which requirement, which
primitive was checked, what the gap is). The caller or system-level
policy then determines whether the gap is:

- **Fatal** — bind fails with an error (e.g., "network host filtering
  required but target platform only supports all-or-nothing")
- **Warning** — bind succeeds but the bound policy includes an advisory
  annotation (e.g., "wall_time enforcement is user-space only")
- **Acceptable** — the gap is known and accepted by policy (e.g., an
  admin intent might declare `"accept_user_space_wall_time": true`)

This separation ensures the binder is a pure function (intent +
composition → bound policy + gap report) while enforcement policy
decisions remain with the appropriate authority.

### 8.4 Worked Example: Intent to Bound Policy

Starting from the effective intent produced in §7.5, here is the bound
policy the binder produces for Linux:

```jsonc
{
  "version": "1.0",
  "name": "research-agent-tool",

  "filesystem": {
    "rules": [
      // Runtime (resolved from "language": "python")
      { "path": "/usr/bin/python3.11",       "scope": "exact",
        "allow": ["read", "execute"] },
      { "path": "/usr/lib/python3.11",       "scope": "subtree",
        "allow": ["read"] },
      { "path": "/usr/local/lib/python3.11/dist-packages",
        "scope": "subtree", "allow": ["read"] },
      { "path": "/usr/lib/x86_64-linux-gnu", "scope": "subtree",
        "allow": ["read", "execute"] },
      { "path": "/etc/ssl/certs",            "scope": "subtree",
        "allow": ["read"] },

      // Storage classes (resolved from abstract classes)
      { "path": "/workspace",  "scope": "subtree",
        "allow": ["read", "write", "create"], "ephemeral": true },
      { "path": "/output",     "scope": "subtree",
        "allow": ["write", "create"], "ephemeral": true },
      { "path": "/tmp",        "scope": "subtree",
        "allow": ["read", "write", "create", "delete"],
        "ephemeral": true },
      { "path": "/cache",      "scope": "subtree",
        "allow": ["read", "write", "create"] },

      // Credentials (resolved from named credentials)
      { "path": "/run/secrets/LLM_API_KEY", "scope": "exact",
        "allow": ["read"], "ephemeral": true }
    ],
    "synthetic": {
      "/dev": "minimal",
      "/proc": "sandboxed",
      "/tmp": "ephemeral"
    }
  },

  "network": {
    "mode": "rules",
    "rules": [
      // Service resolution (llm-api from catalog)
      { "direction": "outbound", "action": "connect", "protocol": "tcp",
        "host": "api.anthropic.com", "port": 443 }
    ],
    "allow_dns": true,
    "allow_localhost": false
  },

  "resources": {
    "max_memory_mb": 1024,
    "max_wall_time_seconds": 300,
    "max_processes": 8,
    "max_open_files": 256
  },

  "environment": {
    "mode": "clean",
    "set": {
      "PATH": "/usr/bin:/usr/local/bin",
      "HOME": "/workspace",
      "LLM_API_KEY_FILE": "/run/secrets/LLM_API_KEY"
    }
  },

  "platform": {
    "linux": {
      "namespaces": {
        "user": true, "mount": true, "pid": true,
        "net": true, "ipc": true, "uts": true, "cgroup": true
      }
    }
  }
}
```

Every abstract reference has been resolved: `"language": "python"` became
specific paths to the Python interpreter and libraries;
`"service": "llm-api"` became `api.anthropic.com:443`;
`"class": "workspace"` became `/workspace`; `"name": "LLM_API_KEY"` became
`/run/secrets/LLM_API_KEY`. Note that `public-web` is absent — it was
removed during composition (§7.5).

---

## 9. Bound Policy Format

The bound policy is the concrete, platform-specific JSON document that the
sandbox runtime consumes. It is produced by the binder (§8) and is never
hand-authored. This section documents its structure.

### 9.1 Structure Overview

```jsonc
{
  "version": "1.0",         // Schema version
  "name": "workload-name",  // From intent metadata
  "description": "...",     // Traceability to intent

  "filesystem": { /* §9.2 */ },
  "network":    { /* §9.3 */ },
  "resources":  { /* §9.4 */ },
  "environment": { /* §9.4 */ },
  "platform":   { /* §9.4 */ }
}
```

### 9.2 Filesystem Rules

The filesystem section is typically the largest part of the bound policy. It
contains three subsections:

**Rules** — explicit allow-list entries:

```jsonc
"filesystem": {
  "rules": [
    {
      "path": "/usr/bin/python3.11",
      "scope": "exact",        // exact | subtree
      "allow": ["read", "execute"],
      "ephemeral": false       // true if content is discarded after execution
    },
    {
      "path": "/workspace",
      "scope": "subtree",
      "allow": ["read", "write", "create"],
      "ephemeral": true
    }
  ]
}
```

| Field | Values | Meaning |
|---|---|---|
| `scope` | `exact` | Rule applies to this path only |
| | `subtree` | Rule applies to this path and all descendants |
| `allow` | `read`, `write`, `create`, `delete`, `execute` | Permitted operations |
| `ephemeral` | `true` / `false` | Whether content is discarded after execution |

**Masks** — explicit deny-list paths (deny trumps allow):

```jsonc
"mask": [
  "%USERPROFILE%\\.ssh",
  "%USERPROFILE%\\.aws"
]
```

Masked paths are inaccessible even if a broader `subtree` rule would
otherwise grant access.

**Synthetic mounts** (Linux-specific) — special filesystem entries:

```jsonc
"synthetic": {
  "/dev": "minimal",     // Only /dev/null, /dev/zero, /dev/urandom
  "/proc": "sandboxed",  // Filtered /proc with limited process visibility
  "/tmp": "ephemeral"    // tmpfs, discarded after execution
}
```

### 9.3 Network Rules

```jsonc
"network": {
  "mode": "none",         // none | rules | full
  "rules": [              // Only when mode is "rules"
    {
      "direction": "outbound",
      "action": "connect",
      "protocol": "tcp",
      "host": "api.weatherapi.com",
      "port": 443
    }
  ],
  "allow_dns": true,      // Whether DNS resolution is permitted
  "allow_localhost": false // Whether localhost communication is permitted
}
```

| Mode | Meaning |
|---|---|
| `none` | No network access at all — strongest isolation |
| `rules` | Only connections matching explicit rules are permitted |
| `full` | Unrestricted network access (rare; typically restricted by admin policy) |

### 9.4 Resources, Environment, and Platform

**Resources** — hard enforcement limits (mapped directly from constraints):

```jsonc
"resources": {
  "max_memory_mb": 1024,
  "max_cpu_percent": 200,     // 200 = 2 cores
  "max_processes": 8,
  "max_wall_time_seconds": 300,
  "max_open_files": 256
}
```

**Environment** — environment variables for the sandboxed process:

```jsonc
"environment": {
  "mode": "clean",    // clean: no inherited env vars; inherit: pass through parent
  "set": {
    "PATH": "/usr/bin:/usr/local/bin",
    "HOME": "/workspace",
    "LLM_API_KEY_FILE": "/run/secrets/LLM_API_KEY"
  }
}
```

**Platform** — mechanism-specific configuration:

Linux:
```jsonc
"platform": {
  "linux": {
    "namespaces": {
      "user": true, "mount": true, "pid": true,
      "net": true, "ipc": true, "uts": true, "cgroup": true
    }
  }
}
```

Windows:
```jsonc
"platform": {
  "windows": {
    "appcontainer": {
      "capabilities": ["internetClient"]
    },
    "bfs": {
      "enabled": true,
      "policy_broker": true
    }
  }
}
```

The platform section is the only part of the bound policy that is
platform-specific by design. It bridges the gap between the
platform-agnostic policy dimensions (filesystem, network, resources) and the
platform-specific enforcement mechanisms described in the companion survey
document.

---

## 10. Versioning

The intent policy architecture introduces multiple versioned artifacts that
evolve independently. This section defines the versioning strategy, how
versions interact across layers, and how the binder bridges between them.

### 10.1 Version Axes

Five artifacts carry independent version numbers:

| Artifact | Version Field | Changes When | Owner |
|---|---|---|---|
| Intent policy schema | `manifest_version` | New intent concepts added (storage classes, constraint types, service reference formats) | Policy design team |
| Capability profiles | `profile_version` | OS adds capabilities, new backends, new primitives | Platform team |
| Bound policy / config | `version` | Runtime gains new enforcement features | Runtime team |
| SDK API | npm semver | `SandboxPolicy` / `IntentPolicy` types change | SDK team |
| Runtime binary | `SUPPORTED_VERSION` | Binary gains new config handling | Runtime team |

These version axes are **independent**: a new intent concept does not
necessarily require a new runtime, and a new runtime feature does not
necessarily require a new intent schema. The binder bridges between them.

### 10.2 The Binder as Version Bridge

The binder (currently in the SDK layer, potentially a standalone
component in future) sits between intent policy and bound policy. It must
understand versions in both directions:

- **Input side:** "I can read `manifest_version` 1.0 through 1.3"
- **Output side:** "I can produce `config version` 0.4 through 0.6"
- **Cross-version mapping:** "Intent 1.2 feature `requires.gpu` maps to
  a device section that only exists in config 0.6. If the runtime
  supports 0.5, this is a gap."

The binder carries an internal **compatibility matrix** that maps intent
features to the minimum config version required to express them:

```
intent 1.0                          → config 0.4+
intent 1.1 (adds storage "secrets") → config 0.4+ (maps to filesystem rules)
intent 1.2 (adds requires.gpu)      → config 0.6+ (needs device section)
```

When a new intent feature maps entirely to existing bound policy
constructs (e.g., a new storage class is just new filesystem rules), the
config version does not change. When a new intent feature needs runtime
support that does not exist yet, the binder reports a gap — using the
same mechanism as capability profile gaps in §8.3.3.

The binder targets the **highest config version the runtime supports**
that can express the effective intent. This ensures callers get the best
available enforcement without pinning to a specific config version.

### 10.3 Intent Policy Versioning

Intent policies use semantic versioning (`MAJOR.MINOR.PATCH`) in the
`manifest_version` field. The rules are:

**Major version (breaking changes):**
- Restructuring of existing fields (e.g., `requires.network` changes
  shape)
- Removal of previously defined fields
- Semantic changes that alter the meaning of existing fields

**Minor version (additive changes):**
- New fields in `requires`, `constraints`, or `claims`
- New storage classes, new network service reference types
- New constraint types or forbidden flags

**Patch version:**
- Clarifications, documentation corrections, schema metadata updates
- No behavioral change

**Version compatibility rules:**

| Binder knows | Policy declares | Result |
|---|---|---|
| 1.x | 1.0 | ✓ Accept — backward compatible |
| 1.1 | 1.1 | ✓ Accept — exact match |
| 1.1 | 1.3 | ⚠ Accept with gaps — unrecognized 1.3 fields reported as unenforced |
| 1.x | 2.0 | ✗ Reject — "upgrade MXC to support manifest_version 2.x" |

The critical rule: **if the major version is greater than the binder
knows about, the binder must fail.** A v2.0 intent policy may have
restructured security-critical fields. A v1.x binder that ignores those
fields could silently drop security constraints.

For minor version gaps, the binder **must report** unrecognized fields as
unenforced gaps. The caller decides whether those gaps are acceptable,
using the same disposition mechanism as §8.3.3. This is strictly better
than silent ignoring — the caller always knows what the binder could not
process.

### 10.4 Per-Layer Version Checks

The four policy layers (code author, user, IT admin, system) are
deployed independently and may be at different `manifest_version` levels:

| Layer | Deployed By | Version Risk |
|---|---|---|
| Code author intent | Shipped with the application/agent | Low — typically aligned with the SDK |
| User intent | Generated by the SDK's consent UI | Low — aligned with the SDK |
| Admin intent | Deployed via MDM / group policy | **Medium** — may be authored with a newer policy schema |
| System intent | Deployed via OS update | **Medium** — may use features from a newer policy schema |

The binder must check `manifest_version` **on each policy layer
independently** during the composition step:

1. Read developer intent → check `manifest_version` against binder's
   supported range
2. Read user intent → same check
3. Read admin intent → same check (**may be newer**)
4. Read system intent → same check (**may be newer**)

If any layer has a major version ahead of the binder, composition fails
with a clear error attributing the failure to the specific layer: "Admin
policy `corp-sandbox-policy` uses `manifest_version: 2.0`, but this
binder only supports 1.x. Upgrade MXC."

If a layer has a minor version ahead, the binder proceeds but reports
which fields from that layer it could not process. This report is
included in the composition audit trail (§7.4) so that administrators
can see when their policies are not being fully enforced on specific
machines.

**Practical implication for IT administrators:** When deploying an admin
intent policy that uses `manifest_version` 1.3 features, the
administrator should know that machines running a binder that only
understands 1.1 will report gaps for the 1.3-specific fields. MDM
deployments are typically version-targeted, so this can be managed by
deploying the MXC update before or alongside the policy update.

### 10.5 Capability Profile Versioning

Capability profiles use `profile_version` in their top-level metadata.
Profiles are typically deployed alongside the MXC installation but may
also be updated by OS updates (e.g., a Windows update ships a new
`appcontainer` profile reflecting new OS capabilities).

The binder must handle profile version mismatches:

| Binder knows | Profile declares | Result |
|---|---|---|
| 1.x | 1.0 | ✓ Accept — backward compatible |
| 1.0 | 1.2 | ⚠ Accept — unknown capabilities ignored (conservative: binder assumes it cannot enforce what it doesn't recognize) |
| 1.x | 2.0 | ✗ Reject — "upgrade MXC to support profile_version 2.x" |

The key difference from intent versioning: for profiles, ignoring
unknown capabilities is **safe** because it is conservative. The binder
simply doesn't know the platform can enforce something, which means it
may report a false gap — but it will never claim enforcement it cannot
verify. For intents, ignoring unknown fields is **unsafe** because the
field may express a security constraint the binder is silently dropping.

### 10.6 Bound Policy and Runtime Versioning

Bound policies carry the existing `version` field (currently
`0.4.0-alpha`). This version represents the configuration schema that
the runtime binary (wxc-exec, lxc-exec) consumes. The versioning rules
follow the existing MXC convention documented in `docs/versioning.md`:

- Runtime checks `version` major.minor against its `SUPPORTED_VERSION`
- Reject if config major.minor > binary major.minor
- Accept if equal or older (backward compatible)
- Patch and prerelease labels are ignored for comparison

The binder produces bound policies at the highest config version the
target runtime supports. Since bound policies are never hand-authored
(§8), the version is always set by the binder based on what it knows
about the target runtime.

The bound policy version determines what enforcement features are
available. The binder's compatibility matrix (§10.2) maps intent features
to minimum config versions. If the intent requires features beyond what
the runtime's config version can express, the binder reports a gap.

### 10.7 Caller Migration Scenarios

This section illustrates how version changes propagate through the
system.

#### Scenario 1: New Intent Field, No Runtime Change

A new storage class `"model_weights"` is added in `manifest_version`
1.1. The binder maps it to a filesystem path — no new config feature
needed. The config version stays at 0.4.

- **Developer:** Updates intent to use `"class": "model_weights"`
- **Binder:** Recognizes 1.1, resolves `model_weights` to a platform
  path, produces config 0.4
- **Runtime:** Unchanged — sees the same filesystem rules it always has
- **Machines with old binder (1.0):** Report unrecognized field
  `model_weights` as a gap. Bind may fail if the developer's `requires`
  section cannot be satisfied without it.

#### Scenario 2: New Runtime Capability, No Intent Change

The runtime adds a new seccomp notification mode (config 0.5). The binder
can now produce better enforcement for existing intent policies.

- **Developer:** No change — same `manifest_version` 1.0 intent
- **Binder:** Updated to produce config 0.5 when targeting the new
  runtime. Existing intents automatically get improved enforcement.
- **Runtime:** Accepts config 0.5, applies new enforcement mode
- **Machines with old runtime (0.4):** Binder detects runtime supports
  0.4, produces config 0.4 instead — graceful fallback

#### Scenario 3: New Intent Feature Requires New Runtime

Intent 1.2 adds `requires.gpu`. The binder maps this to a device section
that only exists in config 0.6.

- **Developer:** Updates intent to `manifest_version` 1.2 with
  `requires.gpu`
- **Binder:** Knows `requires.gpu` needs config 0.6
- **Runtime at 0.6:** Binder produces config 0.6 with device section ✓
- **Runtime at 0.5:** Binder reports gap: "requires.gpu needs config
  0.6, but runtime supports 0.5. Upgrade the runtime."

#### Scenario 4: Admin Policy Uses Newer Schema

An IT administrator deploys an admin intent at `manifest_version` 1.3 to
machines running a binder that understands 1.1.

- **Composition:** Binder reads admin intent, notes `manifest_version`
  1.3 > 1.1, identifies fields it doesn't recognize
- **Gap report:** "Admin policy `corp-2025-q2` declares
  `constraints.max_gpu_memory_mb: 4096` (manifest_version 1.3 field).
  This binder (1.1) cannot enforce this constraint."
- **Caller decides:** If the unrecognized constraint is defense-in-depth
  (the runtime doesn't even expose GPU), the caller may accept the gap.
  If the constraint is security-critical, the caller rejects and
  requires an MXC upgrade.

#### Scenario 5: Breaking Schema Change

Intent schema v2.0 restructures `requires.network` (breaking change).
The binder is updated to support both v1.x and v2.x on the input side.

- **Old intents (1.x):** Continue to work — binder routes to v1 parser
- **New intents (2.x):** Use the new structure — binder routes to v2
  parser
- **Old binder (1.x only):** Rejects v2.0 intents with "upgrade MXC"
- **Migration window:** Both formats coexist until v1.x is deprecated.
  The binder logs a deprecation warning when processing v1.x intents.

### 10.8 Relationship to Existing MXC Versioning

The existing MXC versioning system (documented in `docs/versioning.md`)
covers the config schema version (`0.4.0-alpha`), the experimental
feature lifecycle, and the SDK's `SandboxPolicy.version` field. The
intent policy architecture extends this system rather than replacing it:

| Existing Concept | Intent Policy Equivalent |
|---|---|
| `SandboxPolicy.version` | Will carry `manifest_version` as intent becomes the SDK input format |
| `ContainerConfig.version` | Bound policy `version` — unchanged |
| `SUPPORTED_VERSION` (Rust) | Unchanged — validates bound policy version |
| `SUPPORTED_VERSION` (SDK) | Extends to also validate `manifest_version` |
| Experimental feature gate (`--experimental`) | Could gate experimental intent features (e.g., new `requires` types) |
| Dev schema (`schemas/dev/`) | May gain an intent schema variant with experimental intent fields |

The `SandboxPolicy` type is the natural evolution point. Today it
accepts concrete paths and boolean flags. As it evolves toward the intent
format, it gains `requires`, `constraints`, and `claims` sections. The
`version` field transitions from config schema version to
`manifest_version`. During the transition period, the SDK can accept
both formats: a legacy `SandboxPolicy` (routed through the existing
`buildSandboxPayload()` path) and a new `IntentPolicy` (routed through
the compose → bind pipeline).

The experimental feature lifecycle applies at the intent layer as well.
New intent features (e.g., `requires.gpu`) can be introduced under an
`experimental` section of the intent schema, gated behind
`--experimental`, and promoted to the stable schema when mature —
following the same pattern described in `docs/versioning.md` for config
features.

---

## Appendix A: Intent Policy Schema Reference

This appendix provides the complete field reference for intent policy
documents. All four policy authors (code author, user, IT admin, system) use
this schema.

### Top-Level Structure

| Field | Type | Required | Description |
|---|---|---|---|
| `manifest_version` | string | Yes | Schema version (currently `"1.0"`) |
| `metadata` | object | Yes | Identity and description |
| `requires` | object | Yes | Capability declarations |
| `constraints` | object | No | Hard enforceable limits |
| `claims` | object | No | Self-asserted behavioral properties |

### metadata

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Workload or policy name |
| `version` | string | Yes | Semantic version |
| `description` | string | No | Human-readable description |
| `author` | string | No | Author identity (email, agent ID) |

### requires.runtime

| Field | Type | Required | Description |
|---|---|---|---|
| `language` | string | Yes | Runtime language (`python`, `node`, `rust`, `dotnet`, `bash`, etc.) |
| `min_version` | string | No | Minimum version required |
| `packages` | string[] | No | Required packages/libraries |

### requires.storage[]

| Field | Type | Required | Description |
|---|---|---|---|
| `class` | string | Yes | Storage class name (see §2.3) |
| `access` | string | Yes | `read`, `write`, `read-write` |
| `description` | string | No | Human-readable purpose |
| `persistence` | string | No | `ephemeral`, `discardable` |

### requires.network[]

Service reference form:

| Field | Type | Required | Description |
|---|---|---|---|
| `service` | string | Yes | Logical service name |
| `protocol` | string | No | `https`, `tcp`, etc. |
| `operations` | string[] | No | Advisory: `query`, `download`, `upload` |
| `auth` | string | No | `injected-token`, `none` |
| `scope` | string | No | Host pattern restriction (e.g., `*.example.com`) |
| `description` | string | No | Human-readable purpose |

Capability form:

| Field | Type | Required | Description |
|---|---|---|---|
| `capability` | string | Yes | `dns`, `localhost`, `ntp` |

### requires.tools[]

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Tool name (resolved by binder) |
| `access` | string | Yes | `execute` |

### requires.credentials[]

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Credential name (used as env var prefix) |
| `type` | string | Yes | `api-key`, `connection-string`, `bearer-token`, etc. |
| `description` | string | No | Human-readable purpose |

### requires.process

| Field | Type | Required | Description |
|---|---|---|---|
| `spawn` | boolean | Yes | Whether child processes are allowed |
| `max_children` | integer | No | Maximum child process count |
| `exec` | string[] | No | Allowed executable names (resolved by binder) |
| `signals` | string | No | `self` (own process tree only) |

### requires.ipc / requires.devices

String values: `"none"` (most common), or an object with granular
declarations (future extension).

### constraints

| Field | Type | Description |
|---|---|---|
| `max_memory_mb` | integer | Memory ceiling |
| `max_cpu_cores` | integer | CPU core limit |
| `max_wall_time_seconds` | integer | Execution time limit |
| `max_processes` | integer | Concurrent process limit |
| `max_open_files` | integer | Open file descriptor limit |
| `max_output_bytes` | integer | Output size limit |
| `persistent_storage` | `"forbidden"` | No persistent writes |
| `privilege_escalation` | `"forbidden"` | No privilege elevation |
| `inbound_network` | `"forbidden"` | No inbound connections |

### claims

| Field | Type | Description |
|---|---|---|
| `deterministic` | boolean | Same input always produces same output |
| `idempotent` | boolean | Repeated execution is safe |
| `no_side_effects_beyond_output` | boolean | Only `output_data` is modified |
| `no_credential_exfiltration` | boolean | Credentials are not leaked |

---

## Appendix B: Bound Policy Schema Reference

This appendix provides the complete field reference for bound policy
documents produced by the binder.

### Top-Level Structure

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | string | Yes | Schema version |
| `name` | string | Yes | From intent metadata |
| `description` | string | No | Traceability to intent |
| `filesystem` | object | Yes | Filesystem access rules |
| `network` | object | Yes | Network access rules |
| `resources` | object | Yes | Resource limits |
| `environment` | object | Yes | Environment variable configuration |
| `platform` | object | Yes | Platform-specific mechanism config |

### filesystem

| Field | Type | Description |
|---|---|---|
| `rules[]` | array | Explicit allow-list rules |
| `rules[].path` | string | Concrete filesystem path |
| `rules[].scope` | string | `exact` or `subtree` |
| `rules[].allow` | string[] | `read`, `write`, `create`, `delete`, `execute` |
| `rules[].ephemeral` | boolean | Content discarded after execution |
| `mask[]` | string[] | Paths that are always denied |
| `synthetic` | object | Special filesystem entries (Linux: `/dev`, `/proc`, `/tmp`) |

### network

| Field | Type | Description |
|---|---|---|
| `mode` | string | `none`, `rules`, or `full` |
| `rules[]` | array | Per-connection rules (when mode is `rules`) |
| `rules[].direction` | string | `outbound` (inbound is typically forbidden) |
| `rules[].action` | string | `connect` |
| `rules[].protocol` | string | `tcp`, `udp` |
| `rules[].host` | string | Concrete hostname or IP |
| `rules[].port` | integer | Port number |
| `allow_dns` | boolean | DNS resolution permitted |
| `allow_localhost` | boolean | Localhost communication permitted |

### resources

| Field | Type | Description |
|---|---|---|
| `max_memory_mb` | integer | Memory ceiling |
| `max_cpu_percent` | integer | CPU limit (100 = 1 core) |
| `max_processes` | integer | Process count limit |
| `max_wall_time_seconds` | integer | Execution time limit |
| `max_open_files` | integer | File descriptor limit |

### environment

| Field | Type | Description |
|---|---|---|
| `mode` | string | `clean` (no inheritance) or `inherit` |
| `set` | object | Key-value pairs of environment variables |

### platform.linux

| Field | Type | Description |
|---|---|---|
| `namespaces.user` | boolean | User namespace isolation |
| `namespaces.mount` | boolean | Mount namespace isolation |
| `namespaces.pid` | boolean | PID namespace isolation |
| `namespaces.net` | boolean | Network namespace isolation |
| `namespaces.ipc` | boolean | IPC namespace isolation |
| `namespaces.uts` | boolean | UTS namespace isolation |
| `namespaces.cgroup` | boolean | Cgroup namespace isolation |

### platform.windows

| Field | Type | Description |
|---|---|---|
| `appcontainer.capabilities` | string[] | AppContainer capability names |
| `bfs.enabled` | boolean | BFS filesystem brokering |
| `bfs.policy_broker` | boolean | Policy-based access brokering |

---

## Appendix C: Worked Examples — Intent to Bound Transformations

This appendix shows complete intent-to-bound transformations for
representative workload patterns. Each example shows the code author's
intent manifest and the resulting bound policies for Linux and Windows.

The full set of examples is available in the repository:

- Intent manifests: `examples/intent_manifests/`
- Bound policies (Linux): `examples/bound_policies/linux/`
- Bound policies (Windows): `examples/bound_policies/windows/`

### C.1 Offline Computation: Python Data Analysis

**Pattern:** No network, no credentials, no process spawning. Maximum
isolation.

**Intent:** `examples/intent_manifests/01_python_data_analysis.jsonc`

Key characteristics:
- `"network": []` — no network access
- `"credentials": []` — no secrets
- `"process": { "spawn": false }` — single process
- Claims: deterministic, idempotent, no side effects

**Binding transformations:**

| Intent | Linux Bound | Windows Bound |
|---|---|---|
| `runtime: python 3.10` | `/usr/bin/python3.10`, `/usr/lib/python3.10/**` | `C:\Python310\python.exe`, `C:\Python310\Lib\**` |
| `storage: input_data` | `/input` (read, subtree) | `C:\Sandbox\Input` (read, subtree) |
| `storage: output_data` | `/output` (write+create, subtree, ephemeral) | `C:\Sandbox\Output` (write+create, subtree, ephemeral) |
| `storage: workspace` | `/workspace` (read-write, subtree, ephemeral) | `C:\Sandbox\Workspace` (read-write, subtree, ephemeral) |
| `storage: temp` | `/tmp` (full access, ephemeral) | `C:\Sandbox\Temp` (full access, ephemeral) |
| `network: []` | `"mode": "none"` | `"mode": "none"` |
| platform config | All namespaces enabled | AppContainer (no capabilities), BFS enabled |

### C.2 Network Services: Node.js API Aggregator

**Pattern:** Named service references with injected credentials. Moderate
network access.

**Intent:** `examples/intent_manifests/02_node_api_aggregator.jsonc`

Key characteristics:
- Two named services (`weather-api`, `geocoding-api`) with injected tokens
- DNS capability required
- Two API key credentials
- Claims: not deterministic (network calls), idempotent, no credential
  exfiltration

**Binding transformations:**

| Intent | Linux Bound | Windows Bound |
|---|---|---|
| `service: weather-api` | `api.weatherapi.com:443` (outbound TCP) | `api.weatherapi.com:443` (outbound TCP) |
| `service: geocoding-api` | `api.opencagedata.com:443` (outbound TCP) | `api.opencagedata.com:443` (outbound TCP) |
| `capability: dns` | `allow_dns: true` | `allow_dns: true` |
| `credential: WEATHER_API_KEY` | `/run/secrets/WEATHER_API_KEY` + env var | `C:\Sandbox\Secrets\WEATHER_API_KEY` + env var |
| `credential: GEOCODING_API_KEY` | `/run/secrets/GEOCODING_API_KEY` + env var | `C:\Sandbox\Secrets\GEOCODING_API_KEY` + env var |
| platform config | All namespaces | AppContainer (`internetClient`), BFS |

Note how the service catalog resolves abstract names to concrete endpoints,
and credential injection follows a consistent pattern: file at a well-known
path, environment variable `{NAME}_FILE` pointing to that path.

### C.3 Tool Execution: Rust Snippet Runner

**Pattern:** Process spawning with a named exec-list, network access for
dependency downloads, persistent cache.

**Intent:** `examples/intent_manifests/03_rust_snippet_runner.jsonc`

Key characteristics:
- `spawn: true` with `max_children: 16` and named executables
  (`cargo`, `rustc`, `cc`, `ld`)
- Network services for crate downloads
- `cache` storage class with `persistence: "discardable"` — survives across
  invocations
- High resource limits (4 GB memory, 4 cores, 32 processes) for compilation

### C.4 Agentic Workload: LLM Research Tool

**Pattern:** AI agent tool with LLM access, web browsing, and credential
injection. Represents the agentic use case that motivates much of this
design.

**Intent:** `examples/intent_manifests/04_llm_research_tool.jsonc`

Key characteristics:
- `service: "llm-api"` with injected token — the LLM provider
- `service: "public-web"` — arbitrary HTTPS access for research
- `service: "public-web"` is the capability most likely to be narrowed or
  denied by user consent (§4) or admin policy (§5)
- Claim: `no_credential_exfiltration` — the agent asserts it won't leak the
  LLM API key through the web browsing channel

### C.5 Offline Processing: .NET Image Processor

**Pattern:** Similar to C.1 but with process spawning for parallel
processing and a separate `app_code` storage class.

**Intent:** `examples/intent_manifests/05_dotnet_image_processor.jsonc`

### C.6 Infrastructure: Bash Health Check

**Pattern:** System administration tool using standard Unix utilities.
Multiple internal services with one database credential.

**Intent:** `examples/intent_manifests/06_bash_infra_health_check.jsonc`

Key characteristics:
- Named tools (`curl`, `openssl`, `psql`, `jq`) resolved to platform paths
- Internal service names (`internal-api-gateway`, `internal-auth-service`,
  `primary-database`) — these are resolved via the organization's service
  catalog, not public DNS
- Database credential with `type: "connection-string"` — more complex than
  a simple API key
- This workload is most likely to appear in an IT admin context where the
  service catalog is well-populated and the admin policy is permissive for
  internal services

---

## Appendix D: Open Questions and Abstraction Gaps

This appendix catalogs areas where the current design is incomplete,
where abstractions are weaker than they might appear, or where future
work is needed. These are recorded here to guide ongoing design rather
than to invalidate the current model — every policy system has
boundaries, and it is better to name them explicitly.

### D.1 Constraints Blur the Line Between Intent and Configuration

The `constraints` section (§2.6) contains concrete numeric values
(`max_memory_mb: 1024`, `max_wall_time_seconds: 120`) that pass through
composition and binding essentially unchanged. Unlike `requires` — where
the binder resolves abstract storage classes to concrete paths, or
logical service names to concrete endpoints — constraints undergo no
transformation. `max_memory_mb: 1024` in the intent becomes
`max_memory_mb: 1024` in the bound policy verbatim.

This raises the question: are constraints truly *intent*, or are they
already *configuration*?

A more intent-flavored approach might use abstract resource tiers:

```jsonc
"resources": "lightweight"    // resolved to concrete limits per-platform
"resources": "compute-heavy"  // binder picks appropriate limits
```

Or relative expressions:

```jsonc
"max_memory": "2x runtime baseline"
```

The current concrete-number approach has the advantage of being
unambiguous, composable (via `min()`), and auditable. But it requires
every policy author to reason in megabytes and seconds, which is a
configuration-level concern rather than an intent-level one.

**Open question:** Should the intent layer support abstract resource
tiers that the binder resolves to concrete limits? If so, how do tiers
compose across policy layers? `min(lightweight, compute-heavy)` is not
well-defined without a total ordering on tiers.

### D.2 Network Operations Are Advisory-Only

The `operations` field in network service references (§2.4) documents
what the code does with a service — `["query"]`, `["download"]`,
`["completions"]` — but does not affect enforcement. The sandbox cannot
verify that a process connecting to `weather-api` on port 443 is
performing a query rather than an upload.

This creates an honesty gap: the field *looks* like a policy constraint
but is currently a documentation annotation. An administrator reading
`"operations": ["query"]` might reasonably believe uploads are blocked,
when in fact only the network connection itself is controlled.

**Options:**
1. Remove `operations` from the schema to avoid false confidence
2. Keep as documentation but clearly label as `"advisory_operations"`
3. Define a future enforcement path (e.g., HTTP-aware proxy that
   inspects methods, or protocol-specific middleware)

### D.3 Claims Lack a Verification Story

Claims (§2.7) are self-asserted behavioral properties:
`deterministic: true`, `no_credential_exfiltration: true`,
`no_side_effects_beyond_output: true`. The document explicitly notes
that claims are not enforced by the sandbox runtime.

This is appropriate for a v1 design, but the gap between assertion and
verification is significant. A code author claiming
`no_credential_exfiltration` provides no more assurance than a pinky
promise unless some verification mechanism exists.

**Possible verification approaches:**
- **Static analysis** — inspect code for patterns that violate claims
  (e.g., code that reads credential files and writes to network)
- **Runtime monitoring** — observe sandbox behavior and flag violations
  post-hoc (e.g., data flow tracking between credential reads and
  network writes)
- **Formal attestation** — third-party auditor signs a claim after
  review, and the signature is included in the policy
- **Sandbox-enforced proxies** — for specific claims like
  `no_credential_exfiltration`, route all network traffic through an
  egress proxy that blocks content matching credential patterns

Each approach has different cost, coverage, and false-positive
characteristics. The right answer likely varies by claim type and
deployment context.

### D.4 Service Catalog Resolution Is Underspecified

The service catalog (§5.3) maps logical service names to concrete
endpoints, but several aspects of the resolution process are not yet
defined:

- **Catalog versioning:** When the catalog changes (a service moves to a
  new host), do existing bound policies become stale? Is re-binding
  required?
- **Conflict resolution:** What happens when an admin-defined catalog and
  a system-defined catalog both define the same service name with
  different endpoints?
- **Resolution timing:** Is the catalog consulted at compose time, bind
  time, or runtime? Each has different freshness vs. reproducibility
  tradeoffs.
- **Catalog discovery:** How does the binder locate the relevant catalog?
  Is it embedded in the admin intent, referenced by URL, or discovered
  via a well-known path?
- **Catalog scope:** Can a code author reference a service name that
  doesn't exist in any catalog? Should the binder fail, warn, or assume
  the admin will define it later?

### D.5 Network Scope Narrowing Semantics Are Underspecified

The user consent model (§4) allows narrowing a network service's scope.
For example, a code author requests `"service": "public-web"` and a user
restricts it to `"scope": "*.wikipedia.org,*.arxiv.org"`. The
composition rule intersects these.

But the semantics of scope intersection are not rigorously defined:

- **Pattern language:** Is `*.example.com` a glob? A regex? A DNS suffix
  match? Does it match `sub.sub.example.com`?
- **Intersection rules:** What does intersecting `*.example.com` with
  `api.example.com` produce? Is it `api.example.com` (the more specific
  pattern)? What about `*.example.com` ∩ `*.api.example.com`?
- **Disjunction:** Scopes use comma-separated lists
  (`*.wikipedia.org,*.arxiv.org`). Intersection of two comma-separated
  lists requires pairwise pattern comparison.
- **Negation:** Can a scope express "everything except"? If so, how does
  negation interact with intersection?

A formal scope algebra — probably based on DNS suffix matching with
explicit rules for wildcard depth — is needed before this feature can be
implemented reliably.

### D.6 Wall-Time Enforcement Is Universally User-Space

All three blessed compositions (Windows, Linux, macOS) report wall-time
enforcement as `"user-space"` — a host-side timer that sends
SIGKILL/TerminateProcess when the deadline expires. No current operating
system provides a kernel-enforced wall-time deadline for a process group.

This is a systemic gap rather than a per-platform one. For most
workloads it is acceptable — the host timer is reliable and the latency
between deadline and termination is small. But it means:

- A compromised host process could fail to enforce the deadline
- The guarantee is only as strong as the host-side monitor
- There is a small window between deadline expiry and process termination

**Open question:** Should the document explicitly classify wall-time as
a "best-effort" resource constraint rather than a hard guarantee? Should
compositions that list wall_time enforcement as user-space not include it
in their security guarantees?

### D.7 IPC and Device Models Are Underdeveloped

The current model defaults to `"ipc": "none"` and `"devices": "none"`
(§2.5), with a brief mention that "more granular" declarations are
possible. This is adequate for the common case of isolated code
execution, but several real-world scenarios need more:

- **Mach IPC on macOS** — many system services are accessed via Mach
  ports. The Seatbelt profile can filter `mach-lookup` by service name,
  but the intent policy has no way to express "I need access to Mach
  service `com.apple.securityd`."
- **D-Bus on Linux** — desktop Linux applications use D-Bus for
  inter-process communication. Sandboxed processes that need to interact
  with system services (e.g., NetworkManager) would need D-Bus policy.
- **Named pipes on Windows** — BFS can redirect named pipe access, but
  the intent policy has no way to declare named pipe requirements.
- **GPU/accelerator access** — ML workloads may need access to
  `/dev/nvidia*` or Metal devices. `"devices": "none"` is too coarse;
  `"devices": "gpu"` is too vague for security policy.

A future revision should define an IPC declaration model that names
specific IPC channels or device classes, similar to how network services
are named today.

### D.8 Exec Whitelisting for Interpreted Languages

The Linux blessed composition includes an `exec-restricted` guarantee:
"Only explicitly whitelisted executables can be exec'd." But this
guarantee operates at the binary level — Landlock's
`LANDLOCK_ACCESS_FS_EXECUTE` controls which files can be passed to
`execve()`.

For interpreted languages, this means:

- Whitelisting `/usr/bin/python3` allows execution of **any** Python
  code, including code that the workload downloads at runtime
- The exec whitelist prevents launching unexpected *binaries* but says
  nothing about what *scripts* those binaries execute
- A Rust snippet runner has a meaningful exec whitelist (only `cargo`,
  `rustc`, `cc`, `ld`), but a Python workload's whitelist is
  effectively just "Python is allowed"

This is not a bug — it is an inherent limitation of binary-level exec
control. But it means the `exec-restricted` guarantee is weaker for
interpreted workloads than the name suggests.

**Possible mitigations:**
- Filesystem rules that restrict what the interpreter can *read*
  (preventing it from loading unexpected scripts)
- `--isolated` or equivalent interpreter flags that disable import hooks
  and restrict module search paths
- Content-hash verification of script files before execution

### D.9 Multi-Sandbox Orchestration

This document covers policy for a single sandbox instance. But agentic
systems frequently involve multiple sandboxes that collaborate:

- A coordinator agent that dispatches work to specialized tool sandboxes
- A pipeline of sandboxes where one sandbox's output feeds the next
- A supervisor sandbox that monitors and restarts worker sandboxes

These patterns raise policy questions not addressed in the current model:

- **Inter-sandbox communication:** If sandbox A needs to send data to
  sandbox B, what policy governs the channel? Is it expressed in A's
  intent, B's intent, or a separate orchestration policy?
- **Transitive trust:** If a user trusts coordinator sandbox A, and A
  spawns worker sandbox B, does the user's trust extend to B? Under what
  conditions?
- **Aggregate resource limits:** Six worker sandboxes each with
  `max_memory_mb: 1024` consume 6 GB total. Should there be an
  aggregate ceiling for the orchestration as a whole?
- **Data provenance:** When sandbox B processes data that originated in
  sandbox A, do A's data handling constraints (e.g.,
  `persistent_storage: "forbidden"`) propagate?
- **Shared credentials:** If the coordinator has an API key, can it
  delegate access to workers? The current model injects credentials per-
  sandbox with no delegation mechanism.

A future orchestration layer would need to define policy composition
across sandbox boundaries, not just within a single sandbox.

## Appendix E: Rubric-Based Self-Evaluation

This appendix applies the sandbox evaluation rubric (see
[SandboxEvaluationRubric.md](SandboxEvaluationRubric.md)) to the intent
policy system described in this document. The rubric defines six axes for
evaluating sandboxing and container technologies; here we evaluate the
*policy framework itself* rather than any single platform primitive it
targets.

**Technology kind.** The intent policy system does not fit neatly into the
rubric's existing categories (Primitive, Composition, Broker, Trust Anchor,
Language Sandbox). It is a **Policy Framework** — an orchestration layer that
sits above all of those and governs how compositions are selected,
configured, and validated. This category is worth adding to the rubric.

### E.1 Axis 1 — Isolation Architecture: B+

The system itself does not enforce isolation directly — it produces
configuration for enforcement mechanisms. The *architectural properties* of
the design are strong:

| Criterion | Assessment |
|-----------|-----------|
| Isolation model | Delegates to platform: Different Universe (namespaces, VMs), Guarded Doors (Seatbelt, Landlock, BFS), Reduced Credentials (AppContainer). The design is model-agnostic, which is correct. |
| Deny-by-default | **Yes, by construction.** Empty `requires` means no access. Silence is never permission. Deeply embedded in the design. |
| Monotonic restriction | **Yes, by construction.** The intersection rule (§7.1) means each layer can only further restrict. The single most important architectural property. |
| Inherited by children | Delegates to platform. The design does not explicitly address whether bound policy applies to child processes. |
| Enforcement point | Kernel (via delegation). Bound policy targets kernel-enforced mechanisms. But binder and composition steps are user-space — a compromised binder could produce a permissive policy. |
| Fail-closed on unenforceable policy | **Yes, explicitly.** §7.3 and §8.3.3 define fail-closed behavior with attribution. Gaps are reported; caller decides disposition. |
| Gap attribution | **Excellent.** The binder reports exactly which requirement failed, which primitive was checked, and why. The audit trail (§7.4) attributes every restriction to a specific policy author. |

**What prevents an A:** The design delegates enforcement entirely. It has no
mechanism to verify that the underlying platform *actually enforced* what the
bound policy specified. A correct bound policy plus a buggy runtime equals a
false sense of security. There is no runtime attestation or enforcement
verification loop.

### E.2 Axis 2 — Policy Dimension Coverage: A−

The intent schema covers more dimensions, at finer granularity, than any
single mechanism the survey documents:

| Dimension | Score | Notes |
|-----------|-------|-------|
| Filesystem | ✓ Full | Storage classes with per-operation granularity (read/write/execute/create/delete), subtree/exact scope, ephemeral/persistent semantics, masks, synthetic mounts. |
| Network | ✓ Full | Named service references, per-host/port/protocol/direction rules, DNS control, localhost control. Advisory `operations` field (D.2 acknowledges the gap). |
| Process control | ✓ Good | `spawn`, `max_children`, `exec` allowlist, `signals` scope. |
| IPC / messaging | ○ Partial | Defaults to `"none"`. §2.5 and D.7 acknowledge granular IPC (Mach ports, D-Bus, named pipes) is underdeveloped. |
| Device access | ○ Partial | Defaults to `"none"`. D.7 notes GPU/accelerator access is too coarse. No device taxonomy. |
| Privilege escalation | ✓ Full | `privilege_escalation: "forbidden"` maps to `NO_NEW_PRIVS`, integrity levels, etc. |
| Syscall filtering | ✗ Indirect | Not in the intent schema. Delegated to platform section of bound policy. No way to express "I only use these syscalls" at the intent level. |
| Resource limits | ✓ Full | `max_memory_mb`, `max_cpu_cores`, `max_wall_time_seconds`, `max_processes`, `max_open_files`, `max_output_bytes`. |
| Brokered access | ✓ Good | `user_selected` storage class (§4.4), user consent model (§4.2–4.3), admin service catalogs (§5.3). |
| Identity / code integrity | ○ Weak | Claims exist (`no_credential_exfiltration`) but are unverified (D.3). No code signing, no exec-hash verification. |

**What prevents an A:** IPC and devices are acknowledged stubs. Syscall
filtering has no intent-level expression. Claims are unverified promises.
These are flagged as open questions in Appendix D, which is honest but still
represents a gap.

### E.3 Axis 3 — Policy Language & Authoring: A

This is where the design excels. It is the core contribution of the
document.

| Criterion | Assessment |
|-----------|-----------|
| Declarative language | Yes. JSON-based, with JSONC (comments) for authoring. |
| Human-readable | Yes. Storage classes like `workspace`, `input_data` are self-documenting. |
| Machine-parseable | Yes. Standard JSON with a defined schema. |
| Schema / formal grammar | Yes. Appendix A defines the intent schema; Appendix B defines the bound policy schema. Schema versions are tracked. |
| Abstraction level | Excellent. Platform-agnostic: storage classes, named service references, named tools. No platform paths in intent. |
| Multi-author composition | Yes — four authors: code author, user, IT admin, system. The central innovation. |
| Composition algebra | Formally defined. §7.2: intersection for capability sets, `min()` for numerics, union for forbidden constraints, intersection for access modes. Deterministic and unambiguous. |
| AI/tooling authorable | Explicitly designed for this (§3.3 Agentic Authoring). Abstract vocabulary means agents need no platform knowledge. |
| Validation / dry-run | Yes. The binder validates feasibility before producing bound policy (§8.3). |
| Static conflict detection | Yes. Composition detects unsatisfiable requirements (§7.3). Fails with attribution. |
| Denial-to-rule traceability | Excellent. §7.4 defines full attribution — every restriction traceable to a specific policy author and layer. |
| Learning / discovery mode | Not in the design. The alignment doc notes MXC has ETW-based learning, but the policy design does not incorporate it. |
| Versioning | Comprehensive. §10 defines 5 independent version axes, semantic versioning, major-version-hard-fail, minor-version-with-gaps. |
| Machine-readable guarantees | Yes. Blessed compositions (§8.3.2) declare formal guarantees (`no-filesystem-escape`, `exec-restricted`). |
| Brokered / user-selected resources | Yes. §4.4 `user_selected` storage class for runtime file picking. §4.2–4.3 consent models. |

**What prevents a higher grade:** No formal grammar or BNF — the schema is
described by example and prose with JSON Schema referenced but not included
inline. Network scope algebra is explicitly underspecified (D.5). Learning /
discovery mode is absent.

### E.4 Axis 4 — Composability & Integration: B

| Criterion | Assessment |
|-----------|-----------|
| Composable with existing mechanisms | Yes, by design. Bound policy targets existing platform primitives. Capability profiles (§8.3.1) formally describe what each primitive can do. |
| Stacking is additive | Yes. The intersection rule guarantees this at the policy level. |
| Interaction semantics documented | Yes for the policy layer. Blessed compositions (§8.3.2) document primitive interactions. |
| Setup cost | Unknown. The design does not address performance. Composition + binding + validation is potentially expensive for latency-sensitive workloads. |
| Per-workload cost | Unknown. |
| Warm reuse | Not addressed. MXC's Windows Sandbox daemon has warm reuse, but the policy design does not model reuse semantics. |
| State reset | Not addressed. D.9 hints at this but defers it. |
| Teardown | Not addressed. The design concerns policy, not lifecycle. |

**Rationale:** Strong on policy composability, silent on lifecycle and
performance. As a policy framework the lifecycle concerns are somewhat out
of scope, but the rubric asks about them and the design is silent.

### E.5 Axis 5 — Operational Characteristics: B−

| Criterion | Assessment |
|-----------|-----------|
| Formal analysis / audit | No. The composition algebra is precise enough to formalize, but no formal proof or analysis has been done. |
| Known escape vectors | Not analyzed. No threat model or adversarial analysis. What happens if an attacker controls a policy layer? If the binder is compromised? |
| Defense-in-depth | Strong structurally. Blessed compositions layer multiple primitives. The intersection rule means a compromised layer can only fail to restrict, never broaden. |
| Overhead | Unknown. No performance analysis. |
| Debuggability | Strong. Attribution model (§7.4) makes policy denials traceable. The binder gap report is designed for debugging. |
| Audit trail | Excellent. Every restriction attributed. Effective intent, bound policy, and gap report form a complete audit record. |

**Rationale:** Excellent audit trail and debuggability. No threat model, no
formal analysis, no performance characterization. For a security-critical
system, the absence of adversarial analysis is notable.

### E.6 Axis 6 — Cross-Platform Policy Alignment: A

This axis is nearly tautological — the design *is* the cross-platform policy
alignment system. Evaluating honestly:

| Criterion | Assessment |
|-----------|-----------|
| Maps to `requires.storage` | Excellent. Storage classes are the core abstraction; binder resolves to platform paths. |
| Maps to `requires.network` | Good. Named services + service catalog; binder resolves to host:port. |
| Maps to `constraints` | Good. Numeric constraints pass through. Capability profiles validate enforceability. |
| Binder can generate config | Yes, by definition. Bound policy is the output format. |
| Config format stable / documented | Yes. §9 defines the bound policy schema; §10 defines versioning. |
| Capability profile writable | Yes. §8.3.1 defines the profile format with examples for all three platforms. |
| Composition role | Orchestrator. This system decides which composition to use and how to configure it. |

**What prevents a higher grade:** The design does not specify how bound
policy JSON is translated to the actual configuration format of each
mechanism (AppContainer API calls, Seatbelt S-expression profiles, LXC
container config files). The alignment doc (§5) shows MXC's current config
format diverges from the bound policy format described here.

### E.7 Summary

| Axis | Grade | Key factor |
|------|-------|------------|
| 1. Isolation Architecture | B+ | Excellent architectural properties; no enforcement verification loop |
| 2. Policy Dimension Coverage | A− | 8/10 dimensions strong; IPC, devices, syscalls are stubs |
| 3. Policy Language & Authoring | A | Standout strength: formal composition algebra, 4-author model, full attribution, comprehensive versioning |
| 4. Composability & Integration | B | Strong policy composability; silent on lifecycle and performance |
| 5. Operational Characteristics | B− | Excellent auditability; no threat model or formal analysis |
| 6. Cross-Platform Alignment | A | The raison d'être; well-designed abstraction with last-mile translation unspecified |

**Overall (Agentic workload weighting):** Isolation 25% × 3.3 + Dimensions
30% × 3.7 + Language 20% × 4.0 + Composability 10% × 3.0 + Operational 5%
× 2.7 + Cross-Platform 10% × 4.0 = **3.46 → B** (just below the 3.5
threshold for A)

### E.8 Key Observations

**Greatest strengths:**

1. **The intersection composition rule** is the single best design decision.
   It eliminates priority conflicts, makes composition deterministic, and
   guarantees monotonic restriction.
2. **The four-author model** maps directly to real-world trust
   relationships. Code author, user, admin, and system are genuinely
   distinct trust domains with distinct concerns.
3. **The abstraction level** is right — storage classes and service names,
   not paths and ports. This makes the policy genuinely portable and
   agent-authorable.

**Greatest risks:**

1. **No enforcement verification.** The system trusts that the bound policy
   is faithfully enforced. A gap between what the binder specifies and what
   the runtime enforces is invisible. The alignment doc already shows this:
   MXC's AppContainer backend silently cannot enforce per-port network
   rules, but the design has no mechanism to detect this at runtime.
2. **Complexity budget.** The full system (4 authors × intent schema ×
   composition algebra × binder × capability profiles × blessed
   compositions × bound policy × versioning) is substantial.
   PossibleSimplifications.md is evidence the design team sees this risk.
   The question is whether v1 can ship something useful that is simpler
   than the full design.
3. **The IPC/device stub.** `"ipc": "none"` and `"devices": "none"` work
   for today's agentic workloads. But GPU access for ML workloads and
   D-Bus/Mach IPC for desktop-adjacent workloads are coming. The stub will
   need to become a real taxonomy.
4. **Unverified claims.** The `claims` section is conceptually appealing but
   currently dead weight. D.3 acknowledges this. Shipping it risks users
   treating unverified claims as security assurances. The suggestion in
   PossibleSimplifications.md to drop claims from v1 (S.3) is wise.
