# Sandbox & Container Technology Evaluation Rubric

This rubric provides a systematic framework for evaluating sandboxing and
container isolation technologies — and the policy languages that govern
them — for use in cross-platform workload containment. It is derived from
the conceptual frameworks established in *Container Sandboxing Mechanisms:
A Cross-Platform Survey* (`SandboxSurvey.md`) and *Container Policy
Design: Intent, Composition, and Binding* (`ContainerPolicyDesign.md`).

The rubric is designed to be applied to any sandboxing technology,
including those not yet surveyed in this repository. Section 9 catalogs
known technologies that are **not currently covered** by the branch's
survey work.

---

## Table of Contents

- [1. How to Use This Rubric](#1-how-to-use-this-rubric)
- [2. Technology Classification](#2-technology-classification)
- [3. Axis 1 — Isolation Architecture](#3-axis-1--isolation-architecture)
- [4. Axis 2 — Policy Dimension Coverage](#4-axis-2--policy-dimension-coverage)
- [5. Axis 3 — Policy Language & Authoring](#5-axis-3--policy-language--authoring)
- [6. Axis 4 — Composability & Integration](#6-axis-4--composability--integration)
- [7. Axis 5 — Operational Characteristics](#7-axis-5--operational-characteristics)
- [8. Axis 6 — Cross-Platform Policy Alignment](#8-axis-6--cross-platform-policy-alignment)
- [9. Technologies Not Currently Covered](#9-technologies-not-currently-covered)
- [10. Applying the Rubric — Worked Example](#10-applying-the-rubric--worked-example)
- [Appendix: Blank Evaluation Scorecard](#appendix-blank-evaluation-scorecard)

---

## 1. How to Use This Rubric

For each technology (or composition of technologies), evaluate it along
six axes. Each axis contains specific criteria scored on a three-level
scale:

| Score | Meaning |
|-------|---------|
| **Full (✓)** | The technology natively supports this criterion |
| **Partial (○)** | Achievable through composition, workarounds, or with caveats |
| **None (✗)** | Not addressed; would require a separate mechanism |

Some criteria are qualitative rather than scored — these ask for a
classification (e.g., which isolation model) rather than a coverage
rating.

### Per-Axis Grading (A–F)

After completing the criteria for each axis, assign an overall letter
grade. The grade reflects how well the technology performs across that
axis's criteria **relative to its technology kind** (§2.1) — a Primitive
is not penalized for lacking lifecycle management, and a Broker is not
penalized for lacking syscall filtering.

| Grade | Meaning | Guideline |
|-------|---------|-----------|
| **A** | Excellent | Meets or exceeds all applicable criteria. Best-in-class for its kind. Few or no gaps. |
| **B** | Good | Meets most applicable criteria with minor gaps. Gaps are well-understood and can be mitigated by composition. |
| **C** | Adequate | Meets core criteria but has meaningful gaps in granularity, coverage, or maturity. Usable but requires significant complementary mechanisms. |
| **D** | Weak | Meets some criteria but has substantial gaps that limit usefulness. May require workarounds that undermine the security model. |
| **F** | Inadequate | Fails to meet the axis's core requirements, or the technology is fundamentally unsuited to this axis. |
| **N/A** | Not Applicable | The axis does not apply to this technology kind (e.g., resource limits for a Broker). |

### Overall Grade

After grading all six axes, compute an overall grade using this
procedure:

1. **Exclude N/A axes** — only grade axes that apply to the technology's
   kind.
2. **Weight by deployment context.** The rubric does not prescribe fixed
   weights because different deployment contexts value different axes.
   Three reference weighting profiles are provided below.
3. **Compute a weighted letter grade** using the mapping A=4, B=3, C=2,
   D=1, F=0, then convert back.

| Weight Profile | Use When | Axis Weights |
|----------------|----------|--------------|
| **Agentic workloads** | AI agent tool execution, code generation sandboxing | Isolation 25%, Dimensions 30%, Policy Language 20%, Composability 10%, Operational 5%, Cross-Platform 10% |
| **Enterprise / compliance** | Regulated environments, audit requirements | Isolation 20%, Dimensions 20%, Policy Language 15%, Composability 10%, Operational 10%, Cross-Platform 25% |
| **CI / build isolation** | Build systems, test runners, ephemeral containers | Isolation 15%, Dimensions 20%, Policy Language 10%, Composability 25%, Operational 25%, Cross-Platform 5% |

**Grade boundaries (weighted GPA):**

| GPA Range | Overall Grade |
|-----------|---------------|
| 3.5 – 4.0 | A |
| 2.5 – 3.4 | B |
| 1.5 – 2.4 | C |
| 0.5 – 1.4 | D |
| 0.0 – 0.4 | F |

> **Important:** The overall grade is a summary heuristic, not a
> verdict. A technology with an overall B may still be the right choice
> if its A-grade axis aligns with your highest-priority concern. Always
> read the per-axis grades and notes.

---

## 2. Technology Classification

Before evaluating, classify the technology. Different kinds of
technologies serve different roles in a sandboxing stack, and comparing
a primitive to a full composition on the same scorecard produces
misleading results.

### 2.1 Technology Kind

| Kind | Description | Examples |
|------|-------------|----------|
| **Primitive** | A single kernel or OS mechanism that enforces one or a few policy dimensions | Seccomp-BPF, Landlock, Linux namespaces, AppContainer, Integrity Levels, Job Objects |
| **Composition / Runtime** | A system that combines multiple primitives into a complete sandbox | Docker, Flatpak, Chromium sandbox, Win32 App Isolation, BubbleWrap |
| **Broker / Consent Layer** | A mechanism that mediates access to resources outside the sandbox boundary, optionally with user consent | BFS, macOS TCC, Flatpak/XDG portals, macOS Powerbox / security-scoped bookmarks |
| **Trust Anchor / Hardening** | A mechanism that establishes a trust foundation or hardens the platform, but does not sandbox per-workload | VBS/HVCI, Hardened Runtime, WDAC, Process Mitigation Policies |
| **Language / Runtime Sandbox** | Isolation provided by a language runtime or bytecode VM rather than the OS kernel | WebAssembly, Deno permissions, Java SecurityManager (deprecated) |

Mark the technology's kind first. Then:

- **Primitives** will have **N/A** on many composition-level criteria
  (lifecycle, warm reuse, multi-dimension coverage). That's expected.
- **Compositions** should be evaluated as a whole *and* by listing which
  primitives they compose.
- **Brokers** should be evaluated primarily on Axis 3 (policy language)
  and Axis 6 (cross-platform alignment), plus the brokered-access
  criteria in Axis 2.
- **Trust Anchors** are evaluated primarily on Axis 1 (enforcement
  point) and Axis 5 (security properties). Many Axis 2 dimensions will
  be N/A.
- **Language sandboxes** should be evaluated on their capability model
  and how it maps to the intent policy, understanding that OS-level
  enforcement may be absent.

### 2.2 Platform Scope

| Scope | Platforms |
|-------|-----------|
| Linux-only | |
| macOS-only | |
| Windows-only | |
| Multi-platform | List which platforms |
| Platform-agnostic | Runs anywhere (e.g., Wasm) |

---

## 3. Axis 1 — Isolation Architecture

This axis classifies the fundamental isolation strategy. Every mechanism
falls into one (or more) of the models identified in the survey (§7.1).

### 3.1 Isolation Model

Classify the technology:

| Model | Description | Information Leakage |
|-------|-------------|---------------------|
| **Different Universe** | The sandboxed process sees a constructed view of the system — unauthorized resources are invisible | Lowest — cannot even enumerate what it cannot access |
| **Guarded Doors** | The process sees the real system but access is intercepted and checked by the kernel | Medium — can discover resource existence via error codes |
| **Reduced Credentials** | The process's identity token is weakened so existing access controls deny it | Higher — interacts with real ACL system; error patterns reveal topology |
| **Kernel Filter** | An in-kernel program inspects each syscall and decides allow/deny | Varies — depends on what the filter covers |
| **Hypervisor Boundary** | The process runs in a separate VM with its own kernel | Lowest — hardware-enforced isolation |

A technology may combine models (e.g., AppContainer is Reduced
Credentials for filesystem, but Guarded Doors when combined with BFS).

### 3.2 Default Posture

| Criterion | Answer |
|-----------|--------|
| **Deny-by-default?** | Does the technology deny all access unless explicitly permitted? |
| **Monotonic restriction?** | Once privileges are dropped, can they be regained? (Answer must be "no" for serious sandboxing) |
| **Inherited by children?** | Do `fork()`/`exec()`/`CreateProcess()` carry restrictions forward? |

### 3.3 Enforcement Point

| Criterion | Answer |
|-----------|--------|
| **Where is policy enforced?** | Kernel, hypervisor, user-space runtime, or some combination? |
| **Is enforcement mandatory?** | Can the sandboxed process opt out or modify its own policy? |
| **Is enforcement complete?** | Does the mechanism cover all paths to the protected resource, or can the resource be accessed through an unchecked path? |
| **Fail-closed on unenforceable policy?** | If a policy rule cannot be enforced by this mechanism, does it fail (reject the config), warn, or silently degrade? |
| **Gap attribution?** | If enforcement is incomplete, can the system report *which* specific rules cannot be enforced and *why*? |

> **Axis 1 Grade: ___** (A–F or N/A)

---

## 4. Axis 2 — Policy Dimension Coverage

This axis evaluates which resource types the technology can govern. These
dimensions are drawn from the survey's cross-platform analysis (§3) and
the alignment document's gap analysis (§4).

For each dimension, score coverage (✓/○/✗) and note the granularity.

### 4.1 Filesystem

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Can restrict filesystem access at all** | | |
| **Per-path granularity** (file, directory, subtree, prefix, pattern) | | |
| **Per-operation granularity** (read / write / execute / create / delete / metadata / truncate) | | |
| **Hierarchy inheritance** (rules on parent apply to children) | | |
| **Deny-by-default posture** | | |
| **Supports both allowlist and denylist** | | |

### 4.2 Network

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Can restrict network access at all** | | |
| **All-or-nothing isolation** (network on/off) | | |
| **Inbound vs outbound distinction** | | |
| **Per-port filtering** | | |
| **Per-host/IP filtering** | | |
| **Per-protocol filtering** (TCP, UDP, ICMP) | | |
| **Localhost/loopback control** | | |
| **DNS control** | | |

### 4.3 Process Control

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Fork/spawn control** (can the process create children?) | | |
| **Exec control** (which executables can be launched?) | | |
| **Visibility isolation** (can the process see other processes?) | | |
| **Signal control** (can the process signal others?) | | |
| **Termination coupling** (children die with parent?) | | |

### 4.4 IPC / Messaging

| Criterion | Score | Notes |
|-----------|-------|-------|
| **IPC isolation** (shared memory, semaphores, message queues) | | |
| **Named pipe / Unix socket control** | | |
| **Platform IPC control** (Mach ports, D-Bus, COM/RPC, ALPC) | | |

### 4.5 Device Access

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Device visibility control** | | |
| **Per-device granularity** | | |
| **GPU/accelerator access control** | | |

### 4.6 Privilege Escalation Prevention

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Prevents setuid/setgid escalation** (e.g., `NO_NEW_PRIVS`) | | |
| **Prevents capability acquisition** | | |
| **Prevents token elevation** | | |

### 4.7 Syscall Filtering

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Can filter syscalls** | | |
| **Per-syscall granularity** | | |
| **Per-argument filtering** | | |
| **Architecture-aware** (handles syscall number differences) | | |

### 4.8 Resource Limits

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Memory limits** | | |
| **CPU limits** (rate, cores, time) | | |
| **Process count limits** | | |
| **Open file descriptor limits** | | |
| **Wall-time limits** | | |
| **Disk I/O limits** | | |

### 4.9 Brokered / Consent-Mediated Access

This sub-axis evaluates whether the technology supports mediated access
to resources outside the sandbox boundary — a key concept in the policy
design document (BFS on Windows, TCC on macOS, Flatpak portals on
Linux).

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Supports brokered access to host resources** | | Can the sandbox request access to specific files/services outside its boundary? |
| **Per-invocation grants** | | Can access be granted for a single operation, not persisted? |
| **Per-session grants** | | Can access be granted for the lifetime of one sandbox session? |
| **Persistent grants** | | Can grants be remembered across sessions? |
| **Revocability** | | Can previously granted access be revoked for future runs? |
| **User consent UX** | | Is there a user-facing dialog or approval mechanism? |
| **Programmatic grant API** | | Can grants be made programmatically (e.g., by an admin policy)? |

### 4.10 Identity / Code Integrity

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Code signing verification** | | Can the sandbox verify that executables/scripts are signed? |
| **Exec whitelisting** | | Can the sandbox restrict which binaries/scripts are allowed to execute? |
| **Runtime identity** | | Does the sandbox have a verifiable identity (e.g., AppContainer SID, SELinux label)? |
| **Provenance tracking** | | Can the origin of code running in the sandbox be traced? |

> **Axis 2 Grade: ___** (A–F or N/A)

---

## 5. Axis 3 — Policy Language & Authoring

This axis evaluates how policy is expressed, which directly affects
whether the technology can participate in the intent→compose→bind
pipeline described in the policy design document.

### 5.1 Policy Expression

| Criterion | Answer |
|-----------|--------|
| **Is there a declarative policy language?** | Yes (profile files, JSON schemas, etc.) / No (imperative CLI flags, API calls only) |
| **What is the policy format?** | S-expressions, JSON, YAML, XML, binary, CLI flags, kernel structs, etc. |
| **Is the policy human-readable?** | Can a security reviewer read and audit the policy? |
| **Is the policy machine-parseable?** | Can tooling programmatically generate and validate policy? |
| **Is there a schema or formal grammar?** | Is the policy language formally specified? |

### 5.2 Abstraction Level

| Criterion | Answer |
|-----------|--------|
| **Platform-specific or abstract?** | Does the policy reference platform-specific paths/ports/syscall numbers, or abstract concepts? |
| **Can express intent without mechanism details?** | Can you say "read access to input files" without naming `/home/user/data`? |
| **Supports logical names / service references?** | Can you reference `weather-api` instead of `api.weatherapi.com:443`? |
| **Supports storage classes / data domains?** | Can you reference `workspace` instead of `/tmp/sandbox-work`? |

### 5.3 Authoring Model

| Criterion | Answer |
|-----------|--------|
| **Who authors the policy?** | Developer, user, admin, OS vendor, or some combination? |
| **Is multi-author composition supported?** | Can multiple parties contribute to the final policy? |
| **Is there a composition algebra?** | How are conflicting or overlapping policies resolved? (Intersection, union, priority, undefined?) |
| **Is composition deterministic?** | Given the same inputs, does composition always produce the same output? |
| **Can policy be generated by tooling / AI agents?** | Is the format amenable to programmatic authoring? |

### 5.4 Validation & Debugging

| Criterion | Answer |
|-----------|--------|
| **Can policy be validated before enforcement?** | Is there a dry-run, lint, or compile-check mode? |
| **Static conflict detection?** | Can tooling detect conflicting rules or empty intersections before runtime? |
| **Redundancy detection?** | Can tooling identify rules that are subsumed by other rules? |
| **Are violations logged with attribution?** | When access is denied, does the log say *which rule* caused the denial? |
| **Denial-to-rule traceability?** | Can a runtime denial be traced back to a specific policy author/layer? |
| **Is there a learning/discovery mode?** | Can the system observe a workload and suggest a policy? |

### 5.5 Versioning & Compatibility

| Criterion | Answer |
|-----------|--------|
| **Is the policy format versioned?** | Schema version, ABI version, or similar? |
| **Forward compatibility behavior?** | What happens when a newer policy is loaded by an older runtime? (Fail, warn, ignore unknown fields?) |
| **Backward compatibility behavior?** | What happens when an older policy is loaded by a newer runtime? |
| **Is there a compatibility matrix?** | Documented mapping between policy features and minimum runtime versions? |

### 5.6 Guarantees & Claims

| Criterion | Answer |
|-----------|--------|
| **Can the technology express security guarantees?** | e.g., "no-filesystem-escape", "exec-restricted" |
| **Are guarantees machine-readable?** | Can tooling verify that a composition provides claimed guarantees? |
| **Can claims be validated against guarantees?** | If a policy claims `deterministic: true`, can the sandbox verify or refute it? |
| **Support for brokered/user-selected resources in policy?** | Can the policy language express "access to files the user chooses at runtime"? |

> **Axis 3 Grade: ___** (A–F or N/A)

---

## 6. Axis 4 — Composability & Integration

This axis evaluates whether the technology can be combined with others
and integrated into the MXC policy pipeline.

### 6.1 Composability with Other Mechanisms

| Criterion | Score | Notes |
|-----------|-------|-------|
| **Can be layered with other sandboxing mechanisms** | | e.g., seccomp + namespaces + Landlock |
| **Stacking is additive (more restrictive)** | | Each added layer can only further restrict |
| **No conflicts with other mechanisms** | | Adding this mechanism doesn't break another |
| **Well-defined interaction semantics** | | Is it documented how this mechanism interacts with others on the same system? |

### 6.2 Lifecycle Integration

| Criterion | Answer |
|-----------|--------|
| **Setup cost** | How expensive is initial sandbox creation? (ms, seconds, minutes) |
| **Per-workload cost** | How expensive is running a workload in an existing sandbox? |
| **Warm reuse** | Can the sandbox be reused across workloads without teardown/rebuild? |
| **State reset** | Can workload side effects be rolled back between executions? |
| **Teardown** | Is cleanup automatic? Are there resource leaks on abnormal termination? |

### 6.3 Platform Requirements

| Criterion | Answer |
|-----------|--------|
| **Required OS / kernel version** | Minimum version needed |
| **Requires root / admin / special privileges?** | Can unprivileged users create sandboxes? |
| **Requires kernel modules or drivers?** | e.g., BFS mini-filter, SELinux LSM |
| **Available on which platforms?** | Linux, macOS, Windows, or cross-platform |
| **Maturity / support status** | Production-stable, preview, deprecated, unsupported? |

> **Axis 4 Grade: ___** (A–F or N/A)

---

## 7. Axis 5 — Operational Characteristics

### 7.1 Security Properties

| Criterion | Answer |
|-----------|--------|
| **Has been formally analyzed or audited?** | Published CVEs, penetration test results, or formal verification? |
| **Known escape vectors?** | Are there documented ways to bypass the sandbox? |
| **Defense in depth contribution** | Does it add a unique layer, or does it overlap with existing mechanisms? |

### 7.2 Performance Impact

| Criterion | Answer |
|-----------|--------|
| **Syscall overhead** | Per-syscall latency added by the mechanism |
| **Startup overhead** | Time to establish the sandbox |
| **Memory overhead** | Additional memory consumed by the mechanism |
| **I/O overhead** | Impact on filesystem and network throughput |

### 7.3 Debuggability & Observability

| Criterion | Answer |
|-----------|--------|
| **Can observe what the sandboxed process is doing?** | Tracing, logging, profiling |
| **Can diagnose policy denials?** | Clear error messages when access is blocked |
| **Audit trail** | Is there a record of all policy decisions for post-hoc review? |

> **Axis 5 Grade: ___** (A–F or N/A)

---

## 8. Axis 6 — Cross-Platform Policy Alignment

This axis evaluates how well the technology fits into the
intent→compose→bind policy pipeline from the ContainerPolicyDesign
document. This is the most MXC-specific axis.

### 8.1 Intent Mapping

| Criterion | Answer |
|-----------|--------|
| **Can the technology enforce intent policy `requires.storage` declarations?** | Which storage classes map to which mechanism features? |
| **Can it enforce `requires.network` declarations?** | Service references, DNS, localhost control? |
| **Can it enforce `constraints`?** | Memory, CPU, wall-time, process count? |
| **Which dimensions require a *different* mechanism?** | What gaps must be filled by composition? |

### 8.2 Binder Integration

| Criterion | Answer |
|-----------|--------|
| **Can a binder produce configuration for this technology from bound policy?** | Is the technology's configuration format suitable for generation from abstract policy? |
| **Is the configuration format documented and stable?** | Can tooling reliably generate configurations across versions? |
| **Is there a capability profile (or could one be written)?** | Can the technology's capabilities be formally described for the binder to reason about? |

### 8.3 Composition Role

| Criterion | Answer |
|-----------|--------|
| **What role does this technology play in a full composition?** | Primary boundary? Defense-in-depth layer? Resource governor? |
| **Which other technologies does it typically compose with?** | e.g., AppContainer + BFS + Job Objects + Integrity Levels |
| **Does it duplicate another mechanism's coverage?** | Overlap is acceptable for defense-in-depth, but important to note |

> **Axis 6 Grade: ___** (A–F or N/A)
>
> **Overall Grade: ___** (weighted per §1 weight profile: _______________)

---

## 9. Technologies Not Currently Covered

The survey and design documents cover: Linux Namespaces/BubbleWrap,
Seccomp-BPF, Landlock, SELinux, macOS Seatbelt/App Sandbox, Windows
AppContainer, Restricted Tokens, Job Objects, Integrity Levels, Windows
Sandbox (Hyper-V), Win32 App Isolation, and BFS.

The following technologies are **not yet surveyed** but are relevant to
cross-platform workload sandboxing. They are grouped by technology kind
(§2.1) and then by platform.

### 9.1 Primitives — Not Covered

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **AppArmor** | Linux | The default MAC on Debian/Ubuntu (where SELinux is not). Path-based (vs SELinux's label-based). Used by Docker, LXD, Snap. Policy is more approachable than SELinux. |
| **cgroups v2** | Linux | The primary Linux mechanism for memory, CPU, I/O, and PID limits. The Linux equivalent of Windows Job Objects. Mentioned in passing in the survey but not surveyed as a mechanism. |
| **Landlock** (already surveyed but) **ABI v5–v6** | Linux | ABI v5 adds device ioctl; v6 adds Unix socket and signal scoping. The survey covers v4. |
| **eBPF / LSM-BPF** | Linux | eBPF programs attached to LSM hooks. More flexible than seccomp-BPF. Can implement custom MAC policies without kernel modules. Emerging alternative to SELinux/AppArmor for dynamic policy. |
| **io_uring restrictions** | Linux | `io_uring` bypasses traditional syscall paths, requiring separate restriction (kernel 5.17+). A gap in seccomp-only sandboxes. |
| **iptables / nftables** | Linux | The standard Linux firewall. Already used by MXC's LXC backend but not surveyed as a sandbox primitive. Important for the network policy dimension. |
| **POSIX rlimits** | Linux/macOS | `setrlimit()` for per-process resource limits (memory, file descriptors, CPU time). Simple, portable, complementary to cgroups. |
| **launchd resource controls** | macOS | macOS service manager can impose resource limits. The macOS-native path for constraining daemon resources. |
| **Windows Filtering Platform (WFP)** | Windows | The kernel-mode network filtering framework. Already used by MXC's firewall implementation but not surveyed as a primitive. Provides per-port, per-protocol, per-application network policy. |
| **Process Mitigation Policies** | Windows | Per-process flags: CFG, CIG (Code Integrity Guard), ACG (Arbitrary Code Guard), DEP. Not a sandbox per se, but directly relevant to privilege escalation prevention and code integrity. |

### 9.2 Compositions / Runtimes — Not Covered

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **Docker / OCI containers** | Linux (primarily) | Docker composes namespaces + seccomp + cgroups + AppArmor/SELinux. The most widely understood container composition. Worth surveying as a blessed composition reference. |
| **Podman** | Linux | Rootless containers by design. Demonstrates unprivileged sandboxing at the container level. |
| **Flatpak** | Linux | Full desktop sandboxing using BubbleWrap + seccomp + portals. Has its own permission model and portal-brokered access. |
| **Snap confinement** | Linux | Canonical's sandboxing for Snap packages. Uses AppArmor + seccomp + mount namespaces. Has its own interface/plug/slot permission model. |
| **systemd-nspawn** | Linux | systemd's built-in container tool. Uses namespaces + seccomp. Has a configuration format. |
| **Firejail** | Linux | User-friendly sandbox for desktop Linux apps. Uses namespaces + seccomp + Landlock. Has its own profile format. |
| **nsjail** | Linux | Google's sandboxing tool (used for CTF, build isolation). Config-file-driven namespace sandbox. |
| **Minijail** | Linux/ChromeOS | Chrome OS's sandboxing tool (also Android). Minimal, composable, production-hardened. |
| **Chromium sandbox** | Cross-platform | Multi-layer, broker-heavy, mature reference design. Uses seccomp+namespaces (Linux), Seatbelt (macOS), Restricted Tokens+Job Objects+Integrity Levels (Windows). Highly relevant as a cross-platform composition example. |
| **gVisor (runsc)** | Linux | Google's user-space kernel that intercepts syscalls. "Different Universe" without a full VM. Used by GKE Sandbox. Strong isolation model worth comparing to Hyper-V. |
| **Kata Containers** | Linux | Each container runs in its own VM (QEMU/Cloud Hypervisor/Firecracker). Similar to Windows Sandbox's Hyper-V approach for OCI containers. |
| **Firecracker** | Linux | AWS's minimal VMM. Sub-second boot. Powers Lambda and Fargate. Comparable to NanVix MicroVM. |
| **FreeBSD jails** | FreeBSD | OS-level virtualization. Relevant as a conceptual reference and because some BSD-derived ideas influence other systems. |

### 9.3 Brokers / Consent Layers — Not Covered

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **TCC (Transparency, Consent, and Control)** | macOS | The system behind "App X wants to access your Photos" dialogs. Governs camera, microphone, location, contacts, calendars. The macOS analog of Android runtime permissions. Directly relevant to user consent modeling (§4 of the policy design). |
| **Flatpak / XDG Desktop Portals** | Linux | D-Bus-based brokered access to host resources (files, printing, screenshots, camera). The Linux analog of BFS's brokered access. |
| **macOS Powerbox / security-scoped bookmarks** | macOS | File access brokering for sandboxed macOS apps. User picks files via system dialog; app receives scoped access tokens. Directly comparable to BFS and the `user_selected` storage class. |
| **XPC Services** | macOS | macOS IPC mechanism for decomposing apps into least-privilege components. Relevant to the IPC policy dimension and privilege separation. |

### 9.4 Trust Anchors / Hardening — Not Covered

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **WDAC (Windows Defender Application Control)** | Windows | Kernel-enforced controls over which executables/scripts/DLLs can run. The Windows analog of exec whitelisting. Directly relevant to the exec-control gap (Appendix D.8 of the policy design). |
| **AppLocker** | Windows | Predecessor to WDAC. Simpler but less capable. Still widely deployed in enterprises. |
| **VBS (Virtualization-Based Security)** | Windows | Uses the hypervisor to create isolated memory regions. Powers Credential Guard, HVCI. Relevant as a hardware-enforced trust anchor. |
| **HVCI (Hypervisor-enforced Code Integrity)** | Windows | Verifies code integrity using the hypervisor. Prevents unsigned kernel-mode code. Relevant to the "system intent" layer. |
| **WDAG (Windows Defender Application Guard)** | Windows | Hyper-V-based browser isolation. Similar to Windows Sandbox but purpose-built for browsing. |
| **Hardened Runtime** | macOS | Required for notarization. Prevents code injection, DYLD hijacking, unsigned code execution. Kernel-enforced, not a profile. |
| **macOS Endpoint Security framework** | macOS | Apple's supported API for monitoring process execution, file access, network activity. Potential enforcement/observability point. |
| **macOS System Extensions** | macOS | User-space replacements for kernel extensions (kexts) for network and endpoint security. Relevant for enforcement-point architecture. |

### 9.5 Language / Runtime Sandboxes — Not Covered

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **WebAssembly (Wasm)** | Cross-platform | Memory-safe, capability-based sandbox by default. No filesystem, no network, no syscalls unless explicitly provided via WASI. The purest "deny-by-default" model. |
| **WASI (WebAssembly System Interface)** | Cross-platform | The capability-based system interface for Wasm. Maps closely to the intent policy's storage class and network service model. |
| **Deno permissions model** | Cross-platform | Requires explicit `--allow-read`, `--allow-net`, etc. A runtime-level deny-by-default with per-dimension granularity. Interesting policy language comparison. |
| **Wasmtime / Wasmer / WasmEdge** | Cross-platform | Production Wasm runtimes with different capability-injection models worth comparing. |

### 9.6 Conceptual References (Other OS)

| Technology | Platform | Why It Matters |
|------------|----------|----------------|
| **Capsicum** | FreeBSD | Capability-based sandbox mode. Influenced academic work on capability systems. Chromium uses it on FreeBSD. Theoretically clean model. |
| **pledge / unveil (OpenBSD)** | OpenBSD | Process self-restriction. `pledge()` restricts syscalls by category; `unveil()` restricts filesystem paths. Influenced Landlock's design. Elegant minimal API. |

---

## 10. Applying the Rubric — Worked Example

### Example: Evaluating Landlock v4 (Linux)

**Classification**
- Technology Kind: **Primitive**
- Platform: **Linux-only**

**Axis 1 — Isolation Architecture**
- Model: **Guarded Doors** (kernel intercepts access, checks against ruleset)
- Deny-by-default: **Yes** — everything not mentioned in rules is denied
- Monotonic restriction: **Yes** — rulesets are permanent once applied
- Inherited by children: **Yes** — `fork()` and `execve()` carry restrictions
- Enforcement point: **Kernel** (LSM hook)
- Mandatory: **No** — self-restriction only (process must opt in)
- Fail-closed: **Yes** — unrecognized access types are denied by default
- Gap attribution: **No** — denials produce generic `EACCES`

> **Axis 1 Grade: A** — Strong: kernel-enforced, deny-by-default, monotonic, inherited. Loses only on the opt-in (not mandatory) and poor gap attribution.

**Axis 2 — Policy Dimension Coverage**
- Filesystem: **✓ Full** — per-path, per-operation (read/write/execute/create/delete/truncate)
- Network: **○ Partial** — TCP bind/connect only (ABI v4+); no host filtering, no UDP
- Process: **✗** — no fork/exec/visibility control
- IPC: **○ Partial** — abstract Unix socket scoping (ABI v6+)
- Devices: **○ Partial** — ioctl control (ABI v5+)
- Privilege escalation: **✓** — requires `NO_NEW_PRIVS`, irreversible
- Syscalls: **✗** — not a syscall filter (use seccomp)
- Resources: **✗** — no CPU/memory/process limits
- Brokered access: **✗** — no consent/brokering model
- Identity: **✗** — no code signing or identity model

> **Axis 2 Grade: C** — Strong filesystem, decent privilege escalation prevention, but 4 of 10 dimensions are ✗ and 3 are only partial. Requires composition for a complete sandbox.

**Axis 3 — Policy Language & Authoring**
- Declarative language: **No** — policy is expressed via C syscalls (`landlock_create_ruleset()`, `landlock_add_rule()`, `landlock_restrict_self()`)
- Machine-parseable: **Not applicable** — there is no file format; policy is programmatic
- Abstraction level: **Platform-specific** — references file descriptors and syscall constants
- Multi-author composition: **No** — single process restricts itself
- Composition algebra: **Additive only** — can stack rulesets (tighter), but no intersection/union semantics
- Versioning: **Yes** — ABI version negotiation via `landlock_create_ruleset()`
- Learning mode: **No**
- Guarantees: **No** — no machine-readable guarantee model

> **Axis 3 Grade: D** — No declarative language, no file format, no multi-author support. The ABI versioning is well-designed, but from a policy-language perspective this is a bare programmatic API.

**Axis 4 — Composability & Integration**
- Composable: **✓** — stacks cleanly with seccomp, namespaces, SELinux, AppArmor
- Stacking is additive: **✓** — additional rulesets only tighten
- Setup cost: **Negligible** — three syscalls
- Warm reuse: **N/A** — applied per-process, not per-container
- Requires root: **No** — unprivileged; requires only `NO_NEW_PRIVS`

> **Axis 4 Grade: A** — Exemplary composability. Layers cleanly with every other Linux mechanism. Zero setup cost. Unprivileged.

**Axis 5 — Operational Characteristics**
- Kernel version: **5.13+** (filesystem); **6.7+** (network)
- Overhead: **Very low** — LSM hook on each access check
- Known escapes: None published (as of this writing)
- Debuggability: **Poor** — denials produce `EACCES` with no detail

> **Axis 5 Grade: B** — Excellent performance and security posture, but poor debuggability drags it down. No audit trail for policy decisions.

**Axis 6 — Cross-Platform Policy Alignment**
- Intent mapping: Can enforce `requires.storage` (filesystem) well; `requires.network` partially (TCP only)
- Binder integration: Would need the binder to emit C code or use a helper library; no config file format to generate
- Composition role: **Defense-in-depth layer** — complements namespaces (which provide the primary "Different Universe" boundary)

> **Axis 6 Grade: C** — Good filesystem-to-intent mapping, but the lack of a config file format makes binder integration harder than mechanisms with declarative profiles. Linux-only, so no cross-platform story.
>
> **Overall Grade: B** (Agentic workloads weighting: 4+2+1+4+3+2 = weighted 2.6 → B)
> Landlock is an excellent defense-in-depth primitive with best-in-class composability, but it cannot stand alone as a sandbox and has no policy language for the binder to target.

---

## Appendix: Blank Evaluation Scorecard

Copy this template for each technology evaluation.

```
# Technology: _______________
# Platform: _______________
# Version Evaluated: _______________
# Technology Kind: Primitive | Composition | Broker | Trust Anchor | Language Sandbox

## Axis 1 — Isolation Architecture
- Isolation model:
- Deny-by-default:
- Monotonic restriction:
- Inherited by children:
- Enforcement point:
- Mandatory or opt-in:
- Enforcement completeness:
- Fail-closed on unenforceable policy:
- Gap attribution:
> **Axis 1 Grade: ___**

## Axis 2 — Policy Dimension Coverage
| Dimension             | Score | Granularity Notes |
|-----------------------|-------|-------------------|
| Filesystem            |       |                   |
| Network               |       |                   |
| Process control       |       |                   |
| IPC / messaging       |       |                   |
| Device access         |       |                   |
| Privilege escalation  |       |                   |
| Syscall filtering     |       |                   |
| Resource limits       |       |                   |
| Brokered access       |       |                   |
| Identity / code integrity |   |                   |
> **Axis 2 Grade: ___**

## Axis 3 — Policy Language & Authoring
- Declarative language:
- Policy format:
- Human-readable:
- Machine-parseable:
- Schema/formal grammar:
- Abstraction level:
- Multi-author composition:
- Composition algebra:
- Composition deterministic:
- Tooling/AI authorable:
- Validation/dry-run:
- Static conflict detection:
- Redundancy detection:
- Violation logging w/ attribution:
- Denial-to-rule traceability:
- Learning/discovery mode:
- Policy format versioned:
- Forward compatibility behavior:
- Backward compatibility behavior:
- Machine-readable guarantees:
- Claims validatable against guarantees:
- Supports brokered/user-selected resources:
> **Axis 3 Grade: ___**

## Axis 4 — Composability & Integration
- Composable with other mechanisms:
- Stacking is additive:
- Interaction semantics documented:
- Setup cost:
- Per-workload cost:
- Warm reuse:
- State reset:
- Teardown:
> **Axis 4 Grade: ___**

## Axis 5 — Operational Characteristics
- Platform requirements:
- Requires root/admin:
- Requires kernel modules/drivers:
- Maturity/support status:
- Formal analysis/audit:
- Known escape vectors:
- Defense-in-depth contribution:
- Syscall overhead:
- Startup overhead:
- Memory overhead:
- Debuggability:
- Audit trail:
> **Axis 5 Grade: ___**

## Axis 6 — Cross-Platform Policy Alignment
- Maps to intent `requires.storage`:
- Maps to intent `requires.network`:
- Maps to intent `constraints`:
- Gaps requiring other mechanisms:
- Binder can generate config:
- Config format stable/documented:
- Capability profile writable:
- Composition role:
- Typical composition partners:
- Duplicates another mechanism's coverage:
> **Axis 6 Grade: ___**

## Summary
> **Overall Grade: ___** (Weight profile: _______________)
> Brief justification:
```
