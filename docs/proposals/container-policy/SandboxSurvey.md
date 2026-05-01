# Container Sandboxing Mechanisms: A Cross-Platform Survey

This document surveys the sandboxing and container isolation mechanisms available
on Linux, macOS, and Windows. It establishes a common conceptual framework for
evaluating these mechanisms and compares them across platforms.

A companion document, *Container Policy Design*, covers the policy language,
intent manifests, binding, compilation, and runtime enforcement pipeline built on
top of these mechanisms.

---

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. The Five Questions Every Sandbox Answers](#2-the-five-questions-every-sandbox-answers)
- [3. Common Policy Dimensions](#3-common-policy-dimensions)
  - [3.1 Filesystem Access](#31-filesystem-access)
  - [3.2 Network Access](#32-network-access)
  - [3.3 Process Control](#33-process-control)
  - [3.4 Inter-Process Communication (IPC)](#34-inter-process-communication-ipc)
  - [3.5 Device Access](#35-device-access)
  - [3.6 Privilege Escalation Prevention](#36-privilege-escalation-prevention)
  - [3.7 Resource Limits](#37-resource-limits)
  - [3.8 Syscall Filtering](#38-syscall-filtering)
- [4. Linux Mechanisms](#4-linux-mechanisms)
  - [4.1 Namespaces and BubbleWrap](#41-namespaces-and-bubblewrap)
  - [4.2 Seccomp-BPF](#42-seccomp-bpf)
  - [4.3 Landlock](#43-landlock)
  - [4.4 SELinux](#44-selinux)
- [5. macOS Mechanisms](#5-macos-mechanisms)
  - [5.1 Seatbelt and App Sandbox](#51-seatbelt-and-app-sandbox)
- [6. Windows Mechanisms](#6-windows-mechanisms)
  - [6.1 AppContainer](#61-appcontainer)
  - [6.2 Restricted Tokens](#62-restricted-tokens)
  - [6.3 Job Objects](#63-job-objects)
  - [6.4 Integrity Levels](#64-integrity-levels)
  - [6.5 Windows Sandbox](#65-windows-sandbox)
  - [6.6 Win32 App Isolation](#66-win32-app-isolation)
  - [6.7 Brokered File System (BFS)](#67-brokered-file-system-bfs)
- [7. Cross-Platform Comparison](#7-cross-platform-comparison)
  - [7.1 Isolation Models](#71-isolation-models)
  - [7.2 Dimension Coverage Matrix](#72-dimension-coverage-matrix)
  - [7.3 Capability Mapping Across Platforms](#73-capability-mapping-across-platforms)
  - [7.4 Composability](#74-composability)
- [Appendix A: macOS Seatbelt Profile Language](#appendix-a-macos-seatbelt-profile-language)
- [Appendix B: Seccomp-BPF Programming Details](#appendix-b-seccomp-bpf-programming-details)
- [Appendix C: Landlock Programming Details](#appendix-c-landlock-programming-details)
- [Appendix D: SELinux Policy Language](#appendix-d-selinux-policy-language)
- [Appendix E: BFS Architecture and Programming Details](#appendix-e-bfs-architecture-and-programming-details)

---

## 1. Introduction

Running untrusted or semi-trusted code is a fundamental requirement of modern
systems — from browser tabs to CI pipelines to AI agent tool invocations. The
operating system provides the execution environment, but that environment is far
too permissive by default. A process can read arbitrary files, open network
connections, spawn children, send signals, and access devices. Sandboxing
restricts these capabilities to only what the code actually needs.

Every major operating system has evolved sandboxing mechanisms, but they differ
significantly in architecture, policy model, and granularity. Linux offers a
composable toolkit of kernel primitives (namespaces, seccomp, Landlock, SELinux).
macOS provides a kernel-enforced mandatory access control framework (Seatbelt/App
Sandbox). Windows uses a combination of restricted tokens, AppContainer SIDs,
Job Objects, and integrity levels.

Understanding these mechanisms — their capabilities, limitations, and how they
compose — is a prerequisite for designing a cross-platform sandbox policy system.
This document provides that understanding.

### What This Document Covers

- The **conceptual framework** for reasoning about sandbox policy (§2–3)
- A **survey of mechanisms** on Linux (§4), macOS (§5), and Windows (§6)
- A **cross-platform comparison** that maps mechanisms to common dimensions (§7)
- **Programming deep-dives** in appendices for implementers who need specifics

### What This Document Does Not Cover

- The design of a cross-platform policy language (see companion document)
- Intent manifests, policy binding, or policy compilation
- Container lifecycle management, warm pools, or workload cycling
- Backend capability profiles or policy evaluation algorithms

---

## 2. The Five Questions Every Sandbox Answers

Despite the diversity of mechanisms across platforms, every sandboxing system
answers the same five fundamental questions:

```
1. WHAT RESOURCES?     Files, network, IPC, devices, processes, syscalls
2. WHICH ONES?         By path, by port, by service name, by syscall number
3. WHAT OPERATIONS?    Read vs write vs execute vs create vs delete
4. DEFAULT POSTURE?    Deny-by-default (allowlist) vs allow-by-default (denylist)
5. CAN IT BE UNDONE?   No. (Always no.)
```

These five questions are the *shape* of a policy. They apply regardless of
whether the mechanism is Linux namespaces, macOS Seatbelt profiles, or Windows
AppContainer capabilities.

**Question 1: What resources?** Every mechanism governs access to some subset of
system resources. No single mechanism covers all resources — this is why
sandboxes are typically composed from multiple primitives.

**Question 2: Which ones?** Resources are identified differently across systems —
by filesystem path, by network port, by IPC service name, by syscall number, by
device node, by security label. The identification scheme determines the
granularity of policy.

**Question 3: What operations?** Read, write, and execute are the universal
triple, but systems distinguish further: create vs modify, truncate vs append,
metadata access vs data access, connect vs bind vs listen.

**Question 4: Default posture?** The most consequential architectural choice.
Deny-by-default (allowlist) means nothing works unless explicitly permitted —
secure by default, but requires complete enumeration of needs. Allow-by-default
(denylist) means everything works unless explicitly forbidden — easier to adopt,
but one missed entry is a vulnerability. Modern sandboxing systems universally
prefer deny-by-default.

**Question 5: Can it be undone?** The answer is always no. This is not a
limitation — it is a security invariant. Every serious sandboxing mechanism
enforces **monotonic restriction**: once a privilege is dropped, it cannot be
regained. Seccomp filters are immutable once loaded. Landlock rulesets are
permanent once applied. AppContainer tokens cannot be upgraded. Seatbelt profiles
cannot be weakened. This prevents a compromised process from escaping its sandbox
by modifying its own policy.

---

## 3. Common Policy Dimensions

The five questions describe the *shape* of a single policy decision. But
policies are not single decisions — they are collections of rules across
multiple **dimensions**. This section identifies the dimensions that recur
across all sandboxing systems and establishes the vocabulary used throughout
the rest of this document.

### Dimension Coverage Overview

| Policy Dimension | BubbleWrap | Seatbelt | Landlock | Seccomp | AppContainer | Restricted Tokens |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Filesystem access** | ✓ | ✓ | ✓ | ○ | ✓ | ✓ |
| **Network access** | ✓ | ✓ | ✓ | ○ | ✓ | ○ |
| **Process visibility/control** | ✓ | ✓ | ○ | ○ | ✓ | ○ |
| **IPC / messaging** | ✓ | ✓ | ✓ | ○ | ✓ | ✓ |
| **Device access** | ✓ | ✓ | ✓ | ○ | ✓ | ✓ |
| **Privilege escalation prevention** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Syscall filtering** | ○ | ✓ | — | ✓ | — | — |
| **Resource limits (CPU/mem)** | — | — | — | — | ○ | — |

✓ = native to the system | ○ = achievable by composition | — = not addressed

### 3.1 Filesystem Access

Filesystem isolation is the most common policy dimension. Every mechanism
addresses it, but through fundamentally different strategies.

#### Three Isolation Strategies

**Strategy A: "Different Universe" (Namespace/Mount-based)**

The process literally cannot *see* files that aren't explicitly mounted or
mapped into its view. The filesystem it observes is a custom-constructed tree —
a different universe from the host.

Used by: BubbleWrap (mount namespaces + bind mounts), Linux containers (overlay
filesystems).

**Strategy B: "Guarded Doors" (MAC/Filter-based)**

The process can *see* the full path namespace but is blocked at access time. The
kernel intercepts each access request and checks it against a policy. The
process knows the files exist but cannot touch them.

Used by: macOS Seatbelt profiles, Linux Landlock, SELinux type enforcement.

**Strategy C: "Reduced Credentials" (Token/ACL-based)**

The process's identity token is stripped down so that existing OS access control
lists (ACLs) deny it access. The process is who it claims to be — but it claims
to be less powerful than it was.

Used by: Windows AppContainer (unique SID), Windows Restricted Tokens (stripped
privileges), Windows Integrity Levels.

#### Common Filesystem Policy Axes

Despite the different strategies, every system expresses filesystem policy along
the same axes:

| Axis | How It Appears |
|---|---|
| **Which paths** | Specific file, directory subtree, prefix, or regex |
| **Read vs Write vs Execute** | Always distinguished; read-only is the most common restriction |
| **Direction of default** | Deny-by-default (allow specific paths) vs allow-by-default (block specific paths) |
| **Hierarchy inheritance** | "Allow read on `/usr`" implies all children |
| **Mutability vs creation** | Separate controls for writing existing files vs creating new files |

### 3.2 Network Access

Network policy varies the most in granularity across mechanisms:

| Granularity | BubbleWrap | Seatbelt | Landlock | AppContainer |
|---|---|---|---|---|
| **All-or-nothing** | ✓ | — | — | — |
| **Inbound vs outbound** | — | ✓ | ✓ | ✓ |
| **By port** | — | ✓ | ✓ | ✓ |
| **By destination host/IP** | — | ✓ | — | — |
| **By protocol (TCP/UDP)** | — | ✓ | TCP only (so far) | ✓ |
| **Localhost specifically** | — | ✓ | ✓ | ✓ |

BubbleWrap provides all-or-nothing network isolation via network namespaces —
the process either shares the host network stack or gets an empty one. Achieving
per-port or per-host filtering requires composition with iptables/nftables.

Seatbelt offers the finest granularity: per-host, per-port, per-protocol rules
expressed declaratively in the profile language.

Landlock added network support in ABI v4 (kernel 6.7) but is limited to TCP
bind/connect control — no host filtering, no UDP.

AppContainer uses capability-based network access: `internetClient` for outbound,
`internetClientServer` for inbound, with localhost control as a separate knob.

### 3.3 Process Control

Process-related policy governs spawning, visibility, and signaling:

| Capability | How It Appears |
|---|---|
| **Fork/spawn control** | Whether the process can create children at all |
| **Exec control** | Which executables the process can launch |
| **Visibility isolation** | Whether the process can see other processes on the system |
| **Signal control** | Whether the process can send signals to other processes |
| **Termination coupling** | Whether children die when the parent dies |

Linux PID namespaces provide full visibility isolation — the sandboxed process
only sees itself and its children. macOS Seatbelt can restrict `process-fork` and
`process-exec` operations. Windows Job Objects provide process grouping and
can enforce termination when the job handle closes.

### 3.4 Inter-Process Communication (IPC)

IPC mechanisms are highly OS-specific, but the *intent* of IPC policy is the
same everywhere: control which services or communication channels the sandboxed
process can access.

| System | IPC Mechanism Controlled | Policy Expression |
|---|---|---|
| BubbleWrap | Unix sockets, shared memory | `--unshare-ipc` (all-or-nothing) |
| Seatbelt | Mach ports, XPC, Unix sockets | `(allow mach-lookup (global-name "..."))` |
| Landlock | Abstract Unix sockets, signals | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI v6) |
| AppContainer | COM, RPC, named pipes, ALPC | Capability-based in manifest |

### 3.5 Device Access

Device access control prevents sandboxed code from interacting with hardware —
cameras, GPUs, USB devices, serial ports. Mechanisms range from not mounting
device nodes at all (BubbleWrap) to capability-based grants (AppContainer) to
kernel-level mediation (Seatbelt IOKit rules, Landlock `IOCTL_DEV`).

### 3.6 Privilege Escalation Prevention

Every sandbox must prevent the sandboxed process from regaining dropped
privileges. This is the monotonic restriction invariant from Question 5.

| Mechanism | How It Prevents Escalation |
|---|---|
| BubbleWrap | `PR_SET_NO_NEW_PRIVS` — setuid binaries won't elevate |
| Seatbelt | Deny-by-default + kernel enforcement — no way to load a weaker profile |
| Landlock | `PR_SET_NO_NEW_PRIVS` + restrictions are additive-only |
| Seccomp | `PR_SET_NO_NEW_PRIVS` + filters are immutable once loaded and stack |
| AppContainer | Low integrity level + unique SID — cannot access higher-integrity objects |
| Restricted Tokens | Stripped privileges + deny-only SIDs — cannot re-add removed SIDs |

The universal principle: the sandbox boundary is monotonically shrinking. Once
restricted, you cannot regain what you lost.

### 3.7 Resource Limits

Resource limits (CPU, memory, process count, open files, wall-clock time)
prevent denial-of-service attacks from within the sandbox. They are orthogonal
to access control — a process might be allowed to write to a file but not
allowed to consume unbounded memory doing so.

Most sandboxing mechanisms do not address resource limits directly:

- **Linux:** cgroups (v1 or v2) provide memory, CPU, and process count limits.
  These are a separate mechanism composed alongside namespace-based sandboxes.
- **macOS:** No built-in resource limit framework for sandboxed processes.
  `launchd` can impose some limits.
- **Windows:** Job Objects provide memory limits, CPU rate control, process
  count limits, and can enforce wall-clock timeouts.

### 3.8 Syscall Filtering

Syscall filtering restricts *which kernel operations* a process can invoke,
regardless of what resources those operations target. It is the most
fine-grained form of sandboxing — and the most mechanism-specific.

- **Linux:** seccomp-BPF runs an in-kernel BPF program on every syscall, with
  per-argument filtering capability. See §4.2 and Appendix B.
- **macOS:** Seatbelt profiles implicitly filter operations at the kernel level.
  There is no separate syscall filtering mechanism.
- **Windows:** No direct equivalent. Sandboxing relies on token-based access
  control rather than syscall interception.

---

## 4. Linux Mechanisms

Linux offers the richest set of composable sandboxing primitives. No single
mechanism provides complete isolation — they are designed to be layered.

### 4.1 Namespaces and BubbleWrap

#### Namespaces

Linux namespaces give a process an isolated view of a specific system resource.
Each namespace type isolates one dimension:

| Namespace | Isolates | Effect |
|---|---|---|
| **Mount** | Filesystem mount table | Process sees a custom filesystem tree |
| **PID** | Process ID space | Process only sees itself and its children |
| **Network** | Network stack | Process gets a separate set of interfaces, routes, iptables rules |
| **IPC** | System V IPC, POSIX message queues | Process cannot see other processes' shared memory or semaphores |
| **UTS** | Hostname and domain name | Process can have its own hostname |
| **User** | UID/GID mappings | Process can map its UID to root inside the namespace without being root outside |
| **Cgroup** | Cgroup root directory | Process sees its own cgroup as the root |

User namespaces are the key enabler for unprivileged sandboxing: they allow a
non-root process to create all other namespace types by mapping its real UID to
UID 0 inside the namespace.

#### BubbleWrap (`bwrap`)

BubbleWrap is a lightweight sandboxing tool that composes these namespaces into
a complete sandbox via command-line flags. It is a *building block*, not a
turnkey sandbox — the caller defines the exact policy.

**Policy model:** Explicit allowlist — nothing is visible unless you bind-mount
it in. There is no declarative profile language; the policy is expressed
entirely through CLI flags.

| Feature | Mechanism |
|---|---|
| Custom filesystem view | Mount namespace + bind mounts, tmpfs overlays |
| Syscall filtering | Via `--seccomp` flag (separate mechanism, composable) |
| Capability dropping | Removes Linux capabilities to prevent privilege escalation |
| `PR_SET_NO_NEW_PRIVS` | Blocks setuid escalation from within the sandbox |

**Key philosophical property:** BubbleWrap gives the sandboxed process a
*different universe* — new PID space, new mount tree, new network stack. The
process cannot see what it hasn't been explicitly shown.

**Used by:** Flatpak (as its core isolation engine), developer sandboxes, build
environments.

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ Full | "Different universe" — custom mount tree via bind mounts |
| Network | ✓ All-or-nothing | Network namespace: full isolation or shared host stack |
| Process | ✓ PID isolation | PID namespace: only sees own children |
| IPC | ✓ Full isolation | IPC namespace: `--unshare-ipc` |
| Devices | ✓ Via mount control | Only devices explicitly mounted are visible |
| Syscalls | ○ Via composition | Passes seccomp filter via `--seccomp` flag |
| Resources | ✗ Not addressed | Requires separate cgroup setup |

**Limitations:**
- Network is all-or-nothing — per-port/host filtering requires iptables composition
- No declarative policy language — policy is imperative CLI flags
- Resource limits require separate cgroup configuration

### 4.2 Seccomp-BPF

Seccomp (Secure Computing) lets a process restrict which system calls it can
make. The Linux kernel exposes ~400+ syscalls; most applications use a small
fraction. Every unused syscall is a potential attack vector.

**How it works:** A BPF (Berkeley Packet Filter) program is attached to the
process. The in-kernel BPF virtual machine inspects every syscall — its number,
architecture, and raw argument values — and returns a verdict: allow, kill,
return an error, trap, or notify a supervisor.

```
  User process calls write(fd, buf, len)
          │
          ▼
  ┌──────────────────────┐
  │   Kernel syscall      │
  │   entry point         │
  │                       │
  │  ┌─────────────────┐  │
  │  │ seccomp BPF VM  │  │  ← in-kernel virtual machine
  │  │                 │  │    executes filter program
  │  │ Input:          │  │
  │  │  .nr   = 1      │  │  (syscall number for write)
  │  │  .arch = x86_64  │  │
  │  │  .args[0..5]    │  │  (raw values, NOT dereferenced)
  │  │                 │  │
  │  │ Output: ACTION   │  │
  │  └─────────────────┘  │
  │          │             │
  │   ALLOW? → execute     │
  │   KILL?  → SIGKILL     │
  │   ERRNO? → return err  │
  │   TRAP?  → SIGSYS      │
  └──────────────────────┘
```

**Key security properties:**
1. **Immutable once loaded** — a process cannot weaken its own filter
2. **Inherited by children** — `fork()` and `execve()` carry the filter forward
3. **Stackable** — multiple filters can be layered; *all* must agree to allow
4. **No pointer dereferencing** — the BPF program sees raw argument *values*,
   not the memory they point to, preventing TOCTOU races
5. **Requires `PR_SET_NO_NEW_PRIVS`** — the process must first commit to never
   gaining new privileges

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Syscalls | ✓ Full | Per-syscall, per-argument filtering |
| Filesystem | ○ Indirect | Can block `open()`, `openat()`, etc., but cannot distinguish paths |
| Network | ○ Indirect | Can block `socket()`, `connect()`, etc. |
| All others | ✗ | Syscall-level only — no path or resource awareness |

**Used by:** Docker (default profile blocks ~44 dangerous syscalls), Chromium
(renderers limited to ~20 syscalls), systemd (`SystemCallFilter=`), Android,
Flatpak/BubbleWrap, OpenSSH.

**Limitations:**
- Cannot inspect pointed-to memory — only raw argument values (by design)
- Not a full sandbox alone — only restricts syscalls, not file paths or network
  destinations
- Architecture-dependent — syscall numbers differ across architectures
- Uses classic BPF (cBPF), not the newer eBPF

See [Appendix B](#appendix-b-seccomp-bpf-programming-details) for programming
details and code examples.

### 4.3 Landlock

Landlock is a Linux Security Module (merged in kernel 5.13) that lets a process
*restrict itself* — no root, no admin policy, no container runtime needed. A
process creates a ruleset describing what it is allowed to access, then
permanently locks itself into that ruleset.

**Where it fits in the Linux security stack:**

```
  Access Request
        │
        ▼
  DAC (Unix perms)      ← owner/group/other, rwx bits
        │ Must pass
        ▼
  LSM: SELinux/AppArmor ← admin-defined, system-wide
        │ Must pass
        ▼
  LSM: Landlock          ← process-defined, per-process, runtime
        │ Must pass
        ▼
  Access granted
```

Landlock **only restricts further** — it can never grant access that DAC or
other LSMs would deny.

**How it works (three syscalls):**

| Syscall | Purpose |
|---|---|
| `landlock_create_ruleset()` | Create a new ruleset; declare which access types to govern |
| `landlock_add_rule()` | Add rules (e.g., "allow read on this directory") |
| `landlock_restrict_self()` | Apply the ruleset — **permanent and irreversible** |

Everything NOT mentioned in the rules is **denied by default**.

**ABI evolution:**

| ABI | Kernel | Added Capabilities |
|---|---|---|
| v1 | 5.13 | Filesystem: read, write, execute, create, remove, make dirs/chars/blocks/fifos/sockets/symlinks/links |
| v2 | 5.19 | Cross-directory renames and links (`REFER`) |
| v3 | 6.2 | File truncation |
| v4 | 6.7 | **Network**: TCP bind and connect control |
| v5 | 6.10 | Device `ioctl()` control |
| v6 | 6.12 | **Unix sockets** and **signals** scoping |

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ Full | Path-hierarchy rules, per-operation control |
| Network | ✓ Partial (ABI ≥ 4) | TCP bind/connect; no host filtering, no UDP |
| IPC | ✓ Partial (ABI ≥ 6) | Abstract Unix socket scoping, signal scoping |
| Devices | ✓ Partial (ABI ≥ 5) | `ioctl()` control on device files |
| Process | ✗ | No fork/exec/visibility control |
| Resources | ✗ | No resource limits |

**Key design principles:**
1. **Self-restriction only** — can only restrict itself, never other processes
2. **Additive restrictions** — can add more rulesets (tighten), never remove
3. **Inherited by children** — `fork()` and `execve()` carry restrictions forward
4. **Composable** — stacks cleanly with seccomp, namespaces, and SELinux

The mental model: Landlock is to **files and network ports** what seccomp is to
**syscalls** — a way for a process to voluntarily shed its own power.

See [Appendix C](#appendix-c-landlock-programming-details) for programming
details, code examples, and ABI version handling.

### 4.4 SELinux

Security-Enhanced Linux (SELinux) is a **mandatory access control (MAC)
framework** built into the Linux kernel as a Linux Security Module. Originally
developed by the NSA, it is the most mature and comprehensive MAC system on
Linux.

Unlike Landlock (self-restriction) or seccomp (syscall filtering), SELinux
enforces **system-wide policy defined by an administrator**. Every process,
file, port, and IPC object is assigned a *security label* (called a *security
context*), and a central policy defines which label-to-label interactions are
allowed.

**The label system:** Everything has a security context of the form
`user:role:type:level`. The **type** is the most important part — most policy
rules are written in terms of types.

```
  Process:   system_u:system_r:httpd_t:s0
  File:      system_u:object_r:httpd_sys_content_t:s0
  Port:      system_u:object_r:http_port_t:s0
```

Labels are stored as extended attributes (`security.selinux`) on files, and in
kernel data structures for processes, sockets, and IPC objects.

**Type Enforcement:** The policy engine. Rules define what operations type A may
perform on type B:

```
allow httpd_t httpd_sys_content_t:file { read open getattr };
allow httpd_t http_port_t:tcp_socket { name_bind };
```

Everything not explicitly allowed is **denied by default**.

**Domain transitions:** When a process executes a new binary, SELinux can force
a transition to a different (usually more restricted) domain. Even if an attacker
compromises Apache (`httpd_t`), they are confined to that domain's permissions —
they cannot access files typed for `sshd_t`, `mysqld_t`, or `user_home_t`.

**Operating modes:** Enforcing (policy enforced, violations blocked and logged),
Permissive (violations logged but allowed), Disabled.

**Policy types:** Targeted (default on RHEL/Fedora — only high-risk daemons
confined), Strict (every process confined), MLS (Multi-Level Security for
classified environments).

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ Full | Label-based type enforcement on files, directories |
| Network | ✓ Per-port | Port type labels; no per-host granularity |
| Process | ✓ Domain transitions | Exec control via entrypoint rules, signal control |
| IPC | ✓ Type enforcement | Rules on IPC objects |
| Devices | ✓ Per-device | Device node type labels |
| Syscalls | ✗ | Not a syscall filter (use seccomp for that) |
| Resources | ✗ | No resource limits |

**Key design principles:**
1. **Mandatory** — enforced by the kernel, not optional per-process
2. **Deny-by-default** — everything not explicitly allowed is denied
3. **Label-based** — policy is decoupled from file paths; labels travel with
   objects (survives rename/move)
4. **Complete mediation** — every kernel access check consults SELinux
5. **Composable** — stacks with DAC, Landlock, seccomp

**Key architectural difference from path-based systems:** SELinux labels are
*attached to objects* via xattrs, so policy follows the data even when files are
moved or renamed. AppArmor (an alternative Linux MAC) matches on *path names* —
simpler, but a renamed file may escape its policy.

**Limitations:**
- Complexity — the reference policy has tens of thousands of rules
- Admin-only — unprivileged processes cannot define their own SELinux policy
- Distribution-dependent — RHEL/Fedora ship mature policies; Debian/Ubuntu
  default to AppArmor instead
- Labeling overhead — every file must be correctly labeled

See [Appendix D](#appendix-d-selinux-policy-language) for policy language
details, domain transition examples, and practical workflow.

---

## 5. macOS Mechanisms

### 5.1 Seatbelt and App Sandbox

Seatbelt is a kernel-enforced mandatory access control framework on macOS.
Processes are restricted by a *profile* — the kernel intercepts system calls and
checks them against the loaded profile.

There are two faces of the same underlying mechanism:

- **`sandbox-exec`** — a CLI tool (now deprecated by Apple) that loads an
  S-expression profile and runs a command under it. Used for custom sandboxing.
- **App Sandbox** — the supported path for Mac App Store apps, using entitlements
  (`com.apple.security.app-sandbox`) rather than hand-written profiles.

**Policy model:** Deny-by-default with declarative profiles. The kernel checks
every operation against the profile before execution.

| Feature | Mechanism |
|---|---|
| Kernel-level MAC enforcement | All syscalls filtered at kernel before execution |
| S-expression profile language | Declarative rules for file, network, Mach port, IPC, device access |
| Deny-by-default model | Everything forbidden unless the profile explicitly allows it |
| Violation logging | Blocked operations logged to system log |
| App Sandbox entitlements | App Store apps forced into sandboxing |

**Key philosophical property:** Seatbelt keeps the process in the *same
universe* but puts guards on every door. The process can *see* the filesystem
but is blocked from accessing unauthorized paths. This contrasts with
BubbleWrap's "different universe" approach where unauthorized paths are
invisible.

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ Full | Per-path rules: literal, subpath, prefix, regex |
| Network | ✓ Full | Per-host, per-port, per-protocol, inbound/outbound |
| Process | ✓ Fork/exec control | `process-fork`, `process-exec` operations |
| IPC | ✓ Mach port rules | `mach-lookup` with service name filters |
| Devices | ✓ IOKit rules | `iokit-open` for hardware device access |
| Syscalls | ✓ Built-in | Operations are implicitly syscall-level |
| Resources | ✗ | No memory/CPU limits (not built-in) |

**Caveats:**
- `sandbox-exec` is deprecated by Apple — no replacement CLI
- The profile language is undocumented — reverse-engineered from shipped `.sb`
  files
- Profiles can break across macOS upgrades as Apple renames/moves system services
- No memory or thread isolation — controls access to resources, not computation

See [Appendix A](#appendix-a-macos-seatbelt-profile-language) for the profile
language syntax, filter types, and example profiles.

---

## 6. Windows Mechanisms

Windows does not have a single equivalent to BubbleWrap or Seatbelt. Instead,
it has several complementary mechanisms that are typically composed together.

### 6.1 AppContainer

The most comprehensive Windows sandboxing mechanism. Introduced in Windows 8,
AppContainer is closest in spirit to BubbleWrap/Seatbelt for application
sandboxing.

- Process runs with a **restricted token** under a unique per-app SID
  (Security Identifier)
- **Deny-by-default** for file, registry, network, and process access
- Capabilities must be explicitly granted (e.g., `internetClient`,
  `privateNetworkClientServer`)
- Each container gets its own writable area
- Network access is granular — can separately control internet, private network,
  and localhost

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ ACL-based | Unique SID + ACLs; subtree via inheritance |
| Network | ✓ Capability-based | `internetClient`, `privateNetworkClientServer`, localhost |
| IPC | ✓ Capability-based | COM, RPC, named pipes, ALPC — controlled via capabilities |
| Devices | ✓ Capability-based | `microphone`, `webcam`, etc. |
| Process | ○ Partial | Process runs at low integrity; limited visibility |
| Resources | ✗ | No resource limits (use Job Objects) |
| Syscalls | ✗ | No syscall filtering |

**Used by:** UWP/Store apps (mandatory), Edge renderer processes, and
increasingly Win32 apps via Win32 App Isolation.

### 6.2 Restricted Tokens

A lower-level building block. A restricted token is a copy of a process token
with certain SIDs and privileges removed or converted to deny-only.

- SIDs can be converted to **deny-only** — they only match deny ACEs, not allow
  ACEs
- Privileges (like `SeDebugPrivilege`) can be stripped entirely
- The resulting token cannot be upgraded back to the original

**Dimensions covered:** Filesystem (reduced-credentials model), IPC (via token
identity). The most composable Windows primitive — used as a building block
rather than a standalone sandbox.

**Used by:** Chromium renderer processes (in combination with Job Objects,
integrity levels, and desktop isolation).

### 6.3 Job Objects

Windows Job Objects group processes and enforce resource limits. They are the
Windows analog to Linux cgroups + PID namespace.

| Capability | Notes |
|---|---|
| **Memory limits** | Per-job commit limit |
| **CPU rate control** | CPU rate limiting and hard caps |
| **Process count limits** | Maximum active processes in the job |
| **Termination control** | All processes in the job die when the job handle closes |
| **Process visibility** | Processes within a job can be enumerated together |
| **Wall-time limits** | Per-job and per-process time limits |

Job Objects do not control filesystem or network access — they are purely about
resource limits and process grouping.

### 6.4 Integrity Levels

Windows Mandatory Integrity Control assigns an integrity level to every process
and object: Untrusted, Low, Medium, High, System.

The key rule: **a process cannot write to objects at a higher integrity level.**
A Low-integrity process can read Medium-integrity files (if DAC allows) but
cannot write to them.

This is a coarse-grained mechanism — it distinguishes only four levels — but
it provides a strong baseline: sandboxed processes run at Low or Untrusted
integrity and are structurally prevented from modifying most system and user
objects.

### 6.5 Windows Sandbox

A disposable Hyper-V-based lightweight VM. Provides complete OS-level isolation
with higher overhead than process-based mechanisms. The sandbox is destroyed on
close — no persistence.

Closest analog: running a throwaway QEMU/KVM VM on Linux.

Use case: running completely untrusted code where the overhead of VM boot
(seconds) is acceptable.

### 6.6 Win32 App Isolation

Microsoft's latest effort to bring AppContainer-style isolation to traditional
Win32 desktop apps. Aims to close the gap with Linux/macOS app sandboxing for
non-Store applications. Currently in preview.

### 6.7 Brokered File System (BFS)

BFS is a kernel-mode mini-filter driver that brokers file system access for
sandboxed applications. Where AppContainer makes the sandboxed process
*invisible* to most filesystem resources by removing it from ACLs, BFS provides
the complementary mechanism: controlled, policy-governed access to specific
files and directories *outside* the sandbox boundary.

**The problem BFS solves:** AppContainer and App Silo processes are
deny-by-default — they cannot access files they do not own or that lack
explicit ACL grants. But real applications need to open user documents, read
shared configuration, and communicate over named pipes. BFS intercepts file
operations at the kernel level and makes access decisions based on per-app
policy, optionally prompting the user for consent.

**Core concepts:**

- **Mini-filter driver** registered at altitude 150,000 (FSFilter
  Virtualization group). Intercepts `IRP_MJ_CREATE` (open/create),
  `IRP_MJ_SET_INFORMATION` (rename/delete), `IRP_MJ_CLEANUP`, and
  `IRP_MJ_CREATE_NAMED_PIPE`.
- **Per-app policy** keyed by `{UserSID, PackageSID}`. Each isolated
  application has its own policy tree stored in a custom block-based filesystem
  under `%SystemRoot%\System32\config\BFS\`.
- **Four policy levels** governing how brokered access executes:
  - **AsSelf** — operation runs with the sandboxed app's own token (no
    elevation)
  - **AsUser** — operation runs with the *user's* token, granting broader
    access
  - **AsUserQueryOnly** — like AsUser but limited to read-only access
  - **AsSelfNoPrompt** — AsSelf with user prompting suppressed (used after a
    user denies consent)
- **Inheritance model** — directory policies can propagate to child entries
  via `ContainerInherit` flags, with `Protected` entries that cannot be
  overridden by parent policy.
- **Named pipe redirection** — transparent rewriting of named pipe paths so
  isolated processes can communicate with host-side services through
  per-app-mapped pipe names.
- **User consent prompting** — when an app first requests access to an
  un-policied file, BFS can RPC to a user-mode service to present a consent
  dialog. The user's decision is cached in the policy for future operations.

**Request flow (simplified):**

```
App opens file → mini-filter intercepts IRP_MJ_CREATE
  → Extract token, check if caller is AppContainer/App Silo
  → Look up {UserSID, PackageSID} in policy hash table
  → Walk policy tree for target path
  → If policy found:
      - AsSelf: allow with app's own token
      - AsUser: impersonate user's token, strip WRITE_OWNER/WRITE_DAC
  → If no policy and prompting enabled:
      - RPC to user-mode consent service
      - Cache user's decision as new policy entry
  → Post-operation: restore original security context
```

**Dimensions covered:**

| Dimension | Coverage | Notes |
|---|---|---|
| Filesystem | ✓ Policy-brokered | Per-file/directory granular policies with inheritance |
| IPC | ✓ Pipe redirection | Named pipe transparent remapping per app |
| Network | ✗ | Not in scope (handled by AppContainer capabilities) |
| Devices | ✗ | Not in scope |
| Process | ✗ | Not in scope |
| Resources | ✗ | Not in scope (use Job Objects) |
| Syscalls | ✗ | Not in scope |

**Isolation model:** BFS is a **Guarded Doors** mechanism — the file system
is not hidden (the process can see paths exist), but access is intercepted and
brokered at the kernel level. This contrasts with mount namespaces on Linux
(Different Universe) where unauthorized paths are literally invisible.

**Relationship to other Windows mechanisms:** BFS does not replace AppContainer
or integrity levels — it *complements* them. A typical Win32 App Isolation
composition is:

- AppContainer provides the deny-by-default security boundary
- BFS punches controlled holes in that boundary for specific files/directories
- Job Objects enforce resource limits
- Integrity levels prevent write-up

This is analogous to how Linux sandboxes use mount namespaces for the default
boundary and then bind-mount specific host paths into the namespace for
controlled access — except BFS does it at the access-check layer rather than
the namespace layer.

**Used by:** Win32 App Isolation (App Silo), browser isolation containers
(Edge/Chromium renderer, WebView2, JIT, Flash, DevTools), and agentic
application scenarios.

See [Appendix E](#appendix-e-bfs-architecture-and-programming-details) for
mini-filter architecture, policy storage format, IOCTL interface, and security
token handling details.

---

## 7. Cross-Platform Comparison

### 7.1 Isolation Models

Three isolation models emerge from the cross-platform analysis. Every mechanism
falls into one of these categories:

| Model | Meaning | Examples |
|---|---|---|
| **Different Universe** | The resource is *invisible* — the process literally cannot see it | Mount namespaces, PID namespaces, network namespaces |
| **Guarded Doors** | The resource is *visible* but access is intercepted and checked | SELinux, Seatbelt profiles, Landlock rules |
| **Reduced Credentials** | The process's *identity* is weakened so existing ACLs deny access | AppContainer SIDs, restricted tokens, integrity levels |

These models are ordered by isolation strength:

```
Different Universe > Guarded Doors > Reduced Credentials
```

The ordering reflects information leakage:
- **Different Universe:** the process cannot even *enumerate* what it cannot
  access. It has no knowledge of unauthorized resources.
- **Guarded Doors:** the process can *discover* that a resource exists (e.g.,
  by listing a directory) but cannot access it. The denial reveals information.
- **Reduced Credentials:** the process interacts with the real OS identity
  system. Access patterns and error messages can reveal system topology.

Additionally, syscall-level filtering uses a fourth model:

| Model | Meaning | Examples |
|---|---|---|
| **Kernel Filter** | An in-kernel program inspects each syscall and decides allow/deny | Seccomp-BPF |

### 7.2 Dimension Coverage Matrix

| Capability | Linux (BubbleWrap + kernel) | macOS (Seatbelt/App Sandbox) | Windows (AppContainer + primitives) |
|---|---|---|---|
| **Filesystem isolation** | Mount namespaces + bind mounts | Profile rules on real FS | AppContainer SID + BFS brokered access |
| **Network isolation** | Network namespace | Profile rules | AppContainer capabilities |
| **Syscall filtering** | Seccomp-BPF | Built into Seatbelt profiles | Not directly (rely on token/capability restrictions) |
| **Resource limits** | cgroups | Not built-in (launchd can limit) | Job Objects |
| **Process isolation** | PID namespace | Not built-in | Job Objects + desktop isolation |
| **Privilege reduction** | Capability dropping + `NO_NEW_PRIVS` | Deny-by-default profiles | Restricted tokens + integrity levels |
| **Unprivileged use** | Yes (user namespaces) | Yes (profiles loaded at exec) | Partially (AppContainer needs token creation) |
| **Composability** | High (mix and match primitives) | Medium (profile language is flexible) | Medium (combine tokens + jobs + integrity) |
| **App Store enforcement** | N/A (Flatpak uses bwrap) | Mandatory for Mac App Store | Mandatory for Microsoft Store (UWP) |

### 7.3 Capability Mapping Across Platforms

| Linux Mechanism | Windows Equivalent | Purpose |
|---|---|---|
| Restricted Tokens (capabilities + seccomp) | Restricted Tokens | Strip privileges/SIDs from a process token |
| cgroups + PID namespace | Job Objects | Group processes, limit CPU/memory/process count, control termination |
| User namespaces | No direct equivalent (closest: integrity levels) | Prevent writes to higher-integrity objects |
| X11/Wayland separation | Desktop isolation | Separate window station prevents message-based attacks |
| Mount namespaces | BFS (Brokered File System) | Construct a custom filesystem view |
| Network namespaces | AppContainer network capabilities | Isolate or restrict network access |
| Seccomp-BPF | No equivalent | Syscall-level filtering |

### 7.4 Composability

No single mechanism on any platform provides complete isolation. Real sandboxes
are compositions:

**Linux (typical composition):**
- Mount namespace (filesystem isolation) +
- PID namespace (process visibility) +
- Network namespace (network isolation) +
- IPC namespace (IPC isolation) +
- UTS namespace (hostname) +
- seccomp-BPF (syscall filtering) +
- cgroups v2 (resource limits) +
- Landlock (additional filesystem/network rules, self-applied)

This is the composition Docker uses by default.

**Windows (typical composition):**
- AppContainer (deny-by-default filesystem, network, IPC via SID) +
- BFS (controlled file/directory access through the AppContainer boundary) +
- Job Object (resource limits, process grouping) +
- Integrity Level (write prevention to higher-integrity objects) +
- Optionally: Restricted Token (stripped SIDs/privileges) +
- Optionally: Desktop isolation (window station separation)

This is the composition Win32 App Isolation uses. Chromium uses a similar
composition (without BFS) for renderer processes.

**macOS:**
- Seatbelt profile (filesystem, network, IPC, devices — all in one) +
- Optional: XPC service boundaries (privilege separation)

macOS is the least compositional — Seatbelt is a comprehensive single mechanism
rather than a set of orthogonal primitives.

**Composability implications for cross-platform policy:**

A policy system that targets all three platforms must handle this asymmetry:
- On Linux, each policy dimension maps to a separate mechanism. Policy rules
  are distributed across multiple enforcement primitives.
- On macOS, most dimensions are enforced by a single mechanism (Seatbelt).
  The policy compiles to one profile.
- On Windows, enforcement falls between these extremes. AppContainer handles
  several dimensions but needs Job Objects for resource limits and integrity
  levels for write prevention.

The cross-platform policy language must be mechanism-agnostic — it expresses
*what* should be enforced, not *how*. The platform-specific binding and
compilation steps translate policy dimensions into the appropriate mechanism
composition for each platform. This is addressed in the companion document.

---

## Appendix A: macOS Seatbelt Profile Language

Seatbelt profiles are written in an S-expression (Lisp-like) syntax and stored
as `.sb` text files. Apple ships built-in profiles at `/usr/share/sandbox/`
(e.g., `sshd.sb`, `mds.sb`, `ntpd.sb`). The language itself is undocumented by
Apple but well reverse-engineered.

### Basic Structure

```scheme
(version 1)          ; required — always 1
(deny default)       ; deny everything not explicitly allowed
(import "system.sb") ; import Apple's base rules for basic OS functionality

;; then: a series of (allow ...) and (deny ...) rules
```

### Rule Grammar

```
(allow|deny  <operation>  [<filter> ...])
```

### Operations Reference

| Category | Operations | What It Controls |
|---|---|---|
| **Files** | `file-read*`, `file-read-data`, `file-read-metadata` | Reading files |
| | `file-write*`, `file-write-data`, `file-write-create`, `file-write-unlink` | Writing/creating/deleting files |
| | `file-ioctl` | ioctl calls on files |
| **Network** | `network-outbound`, `network-inbound`, `network-bind` | TCP/UDP connections, listening |
| **Mach IPC** | `mach-lookup`, `mach-register` | XPC/Mach service access |
| **Process** | `process-fork`, `process-exec`, `process-exec-interpreter` | Spawning processes |
| **Signals** | `signal` | Sending signals to other processes |
| **Sysctl** | `sysctl-read`, `sysctl-write` | Reading/writing kernel parameters |
| **IOKit** | `iokit-open` | Accessing hardware device interfaces |
| **Preferences** | `user-preference-read`, `user-preference-write` | NSUserDefaults / plist access |
| **Info** | `process-info-pidinfo`, `process-info-codesignature` | Inspecting other processes |
| **Generic** | `default` | Catch-all (used with `deny default`) |

### Filter Types

```scheme
;; Path filters
(literal "/etc/resolv.conf")              ; exact path
(subpath "/Users/alice/project")          ; path and everything under it
(prefix "/usr/lib/")                      ; paths starting with this string
(regex #"/tmp/myapp-[0-9]+\.log")         ; regex match on path

;; Path construction
(string-append (param "HOME") "/Documents")  ; runtime parameter expansion

;; Network filters
(remote ip "*:443")                       ; outbound to any host, port 443
(local ip "localhost:8080")               ; bind to localhost:8080

;; Mach service filters
(global-name "com.apple.FontServer")      ; specific Mach service by name
(global-name-prefix "com.apple.")         ; any Apple service

;; Boolean combinators
(require-all <filter1> <filter2>)         ; AND
(require-any <filter1> <filter2>)         ; OR
(require-not <filter>)                    ; NOT
```

### Example Profiles

#### Minimal: Read-Only Access to One Directory

```scheme
(version 1)
(deny default)
(allow file-read* (subpath "/Users/alice/project"))
```

#### Web-Facing Tool: Network + Limited Files

```scheme
(version 1)
(deny default)
(import "system.sb")

(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library/Frameworks"))

(allow file-read*  (subpath "/Users/alice/project"))
(allow file-write* (subpath "/Users/alice/project/output"))

(allow network-outbound (remote tcp "*:443"))
(allow network-outbound (literal "/private/var/run/mDNSResponder"))

(allow user-preference-read (preference-domain "com.example.mytool"))
```

#### Locked-Down Daemon

```scheme
(version 1)
(deny default)
(import "system.sb")

(allow file-read*
    (literal "/etc/sshd_config")
    (subpath "/usr/libexec")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom"))

(allow network-inbound  (local tcp "*:22"))
(allow network-outbound (remote tcp))

(allow process-fork)
(allow process-exec (literal "/usr/libexec/sshd-session"))

(allow mach-lookup
    (global-name "com.apple.system.logger")
    (global-name "com.apple.system.notification_center"))

(allow signal (target self))
```

#### Reusable Macros with `define`

```scheme
(version 1)
(deny default)

(define (home-subpath path)
    (subpath (string-append (param "HOME") path)))

(allow file-read*  (home-subpath "/Documents"))
(allow file-write* (home-subpath "/Downloads"))
```

### Running a Profile

```sh
# Run a command under a sandbox profile
sandbox-exec -f myprofile.sb /usr/bin/my-command --args

# Or inline
sandbox-exec -p '(version 1)(deny default)(allow file-read* (subpath "/tmp"))' /bin/ls /tmp
```

---

## Appendix B: Seccomp-BPF Programming Details

### The BPF Virtual Machine

The seccomp filter operates on a `struct seccomp_data`:

```c
struct seccomp_data {
    int   nr;                  // syscall number
    __u32 arch;                // AUDIT_ARCH_* value
    __u64 instruction_pointer; // where the syscall was made
    __u64 args[6];             // raw syscall arguments (not dereferenced!)
};
```

### Return Actions

| Action | Effect |
|---|---|
| `SECCOMP_RET_ALLOW` | Syscall proceeds normally |
| `SECCOMP_RET_KILL_PROCESS` | Entire process killed with `SIGSYS` |
| `SECCOMP_RET_KILL_THREAD` | Calling thread killed |
| `SECCOMP_RET_ERRNO(val)` | Syscall blocked, returns `-val` to caller |
| `SECCOMP_RET_TRAP` | Sends `SIGSYS` to process (can be caught) |
| `SECCOMP_RET_TRACE` | Notifies a `ptrace`-attached tracer |
| `SECCOMP_RET_LOG` | Allow, but log the syscall |
| `SECCOMP_RET_USER_NOTIF` | Delegate decision to userspace supervisor (newer kernels) |

### Code Example (C, using libseccomp)

```c
#include <seccomp.h>
#include <unistd.h>

int main() {
    // Create filter: default action = kill process
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    // Allowlist only what we need
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // Can also filter by argument value:
    // Only allow write() to stdout (fd == 1)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                     SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));

    // Load and enforce the filter
    seccomp_load(ctx);

    write(1, "allowed\n", 8);   // works
    open("/etc/passwd", 0);      // KILLED — open() not in allowlist

    seccomp_release(ctx);
    return 0;
}
```

### Raw BPF Instructions (without libseccomp)

```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};
struct sock_fprog prog = { .len = 4, .filter = filter };
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
```

---

## Appendix C: Landlock Programming Details

### Code Example (C)

```c
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    // 1. Check ABI version
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return 1;  // Landlock not available

    // 2. Create ruleset: govern filesystem read/write/execute
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR  |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_EXECUTE
    };
    int ruleset_fd = syscall(SYS_landlock_create_ruleset,
                             &ruleset_attr, sizeof(ruleset_attr), 0);

    // 3. Allow read-only access to /usr
    int usr_fd = open("/usr", O_PATH | O_CLOEXEC);
    struct landlock_path_beneath_attr rule1 = {
        .parent_fd = usr_fd,
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR  |
                          LANDLOCK_ACCESS_FS_EXECUTE
    };
    syscall(SYS_landlock_add_rule, ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH, &rule1, 0);
    close(usr_fd);

    // 4. Allow read+write to /tmp/myapp
    int tmp_fd = open("/tmp/myapp", O_PATH | O_CLOEXEC);
    struct landlock_path_beneath_attr rule2 = {
        .parent_fd = tmp_fd,
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR  |
                          LANDLOCK_ACCESS_FS_WRITE_FILE
    };
    syscall(SYS_landlock_add_rule, ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH, &rule2, 0);
    close(tmp_fd);

    // 5. Lock it in
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_landlock_restrict_self, ruleset_fd, 0);
    close(ruleset_fd);

    // From here: can read /usr, read+write /tmp/myapp, nothing else.
    // open("/etc/passwd", O_RDONLY) → EACCES
    // open("/home/user/.ssh/id_rsa", O_RDONLY) → EACCES
}
```

### ABI Version Handling

Programs should check the ABI version at runtime and adapt their ruleset
accordingly. Newer ABI versions add capabilities that older kernels don't
support:

```
ABI ≥ 1: Filesystem rules (read, write, execute, create, remove, etc.)
ABI ≥ 2: Cross-directory rename/link control (REFER)
ABI ≥ 3: File truncation control
ABI ≥ 4: Network TCP bind/connect control
ABI ≥ 5: Device ioctl control
ABI ≥ 6: Abstract Unix socket and signal scoping
```

When running on an older kernel, graceful degradation means: apply all rules
the kernel supports, log warnings for unsupported rules, and optionally fail
if a critical rule cannot be enforced.

### Landlock vs Other Linux Sandboxing

| Dimension | Landlock | Seccomp-BPF | BubbleWrap (namespaces) | SELinux / AppArmor |
|---|---|---|---|---|
| **Who defines policy** | The process itself | The process itself | The caller/wrapper | System administrator |
| **What it controls** | Files, dirs, network (TCP), devices, signals | Which syscalls are allowed | Entire filesystem/PID/network view | Files, network, capabilities, IPC, etc. |
| **Granularity** | Path-hierarchy rules | Syscall number + args | Mount-level (whole dirs) | Label/path-based rules |
| **Needs root** | No | No | No (user namespaces) | Yes (to write policy) |
| **Irreversible** | Yes | Yes | N/A (separate process) | N/A (admin policy) |
| **Stacks with others** | Yes | Yes | Orthogonal | Yes |
| **Best for** | "I only need these files/ports" | "I only need these syscalls" | "Give me a different filesystem" | "Enterprise-wide mandatory policy" |

---

## Appendix D: SELinux Policy Language

### Type Enforcement Rules

The policy is expressed as rules allowing specific operations between types:

```
# Allow Apache to read its content files
allow httpd_t httpd_sys_content_t:file { read open getattr };

# Allow Apache to listen on HTTP ports
allow httpd_t http_port_t:tcp_socket { name_bind };

# Allow Apache to connect to database ports
allow httpd_t postgresql_port_t:tcp_socket { name_connect };

# Allow Apache to execute CGI scripts
allow httpd_t httpd_sys_script_exec_t:file { execute execute_no_trans };

# Allow Apache to write to its log directory
allow httpd_t httpd_log_t:file { write create append };
allow httpd_t httpd_log_t:dir  { search add_name };
```

### Domain Transitions

When a process executes a new binary, SELinux can force a *domain transition*:

```
# When init_t executes /usr/sbin/httpd (labeled httpd_exec_t),
# the new process transitions to httpd_t
type_transition init_t httpd_exec_t:process httpd_t;

# Required supporting rules:
allow init_t httpd_exec_t:file { execute };       # init can execute the binary
allow init_t httpd_t:process { transition };       # init can transition to httpd_t
allow httpd_t httpd_exec_t:file { entrypoint };    # httpd_exec_t is a valid
                                                    # entrypoint for httpd_t
```

### Practical Workflow

```sh
# Check a file's security context
ls -Z /var/www/html/index.html
# → system_u:object_r:httpd_sys_content_t:s0

# Check a process's security context
ps -eZ | grep httpd
# → system_u:system_r:httpd_t:s0   1234  httpd

# Relabel a file to the correct type
chcon -t httpd_sys_content_t /var/www/html/newfile.html

# Restore default labels from policy
restorecon -Rv /var/www/html/

# Search for denied operations in the audit log
ausearch -m avc -ts recent

# Generate a policy module from denials
audit2allow -a -M mypolicy
semodule -i mypolicy.pp
```

### SELinux vs Other Linux Security Mechanisms

| Dimension | SELinux | AppArmor | Landlock | Seccomp-BPF |
|---|---|---|---|---|
| **Policy model** | Label-based (types on everything) | Path-based (profiles name files by path) | Path-based (fd-based rules) | Syscall-number-based |
| **Who defines policy** | System administrator | System administrator | The process itself | The process itself |
| **Scope** | System-wide, all processes | Per-profile, named processes | Per-process, self-applied | Per-process, self-applied |
| **What it controls** | Files, network, IPC, processes, devices, capabilities | Files, network, capabilities, some IPC | Files, network (TCP), devices, signals | Which syscalls are allowed |
| **Granularity** | Fine — per-type, per-operation, per-object-class | Medium — per-path, per-capability | Medium — per-directory-hierarchy | Fine — per-syscall + arg values |
| **Needs root to configure** | Yes | Yes | No | No |
| **Stacks with others** | Yes | Mutually exclusive with SELinux | Yes | Yes |
| **Survives exec** | Yes (domain transitions) | Yes (profile follows binary) | Yes (inherited) | Yes (inherited) |
| **Indirection** | Labels survive rename/move | Path-based — rename can bypass | fd-based — survives rename | N/A |
| **Best for** | System-wide mandatory confinement | Simpler admin-defined confinement | App self-sandboxing (files/net) | App self-sandboxing (syscalls) |

---

## Appendix E: BFS Architecture and Programming Details

BFS (Brokered File System) is implemented as a Windows kernel-mode mini-filter
driver. This appendix covers the internal architecture, policy storage format,
driver interfaces, and security token handling for those who need to understand
or extend the mechanism.

### Mini-Filter Registration

BFS registers with the Windows Filter Manager (FltMgr) framework:

| Property | Value |
|---|---|
| **Altitude** | 150,000 |
| **Group** | FSFilter Virtualization |
| **Device name** | `\Device\Bfs` |
| **Start type** | Automatic (boot) |
| **Dependencies** | FltMgr, CNG (cryptography) |

The altitude places BFS in the virtualization filter group, meaning it
processes I/O *after* base filesystem drivers but *before* higher-level filters
like antivirus. This is important because BFS needs to see the real filesystem
paths before any other virtualization layer rewrites them.

**Intercepted operations:**

| IRP | Purpose |
|---|---|
| `IRP_MJ_CREATE` | File open/create — the primary enforcement point |
| `IRP_MJ_SET_INFORMATION` | Rename/delete tracking — invalidates cached policies |
| `IRP_MJ_CLEANUP` | Handle close — cleanup file tracking state |
| `IRP_MJ_CREATE_NAMED_PIPE` | Named pipe creation — apply pipe redirection |

### Policy Storage Format

BFS uses a custom block-based filesystem for policy storage rather than
relying on NTFS directories or the registry. This design choice provides:

- Compact representation (16 KB blocks, ~106 directory entries per block)
- Atomic updates via block-level operations
- Independence from NTFS ACL complexity
- Efficient hierarchical path lookups via AVL trees

**Storage location:** `%SystemRoot%\System32\config\BFS\`

**On-disk layout:**

```
Block 0: Core Block (magic: 'CsfB', version 1.0)
  ├── BlockSize: 16384 bytes
  ├── RootBlock → root directory block
  ├── IndexBlock → file ID index
  └── BlockBitmap[] → allocation tracking

Directory Blocks (magic: 'DsfB'):
  ├── NextBlock → linked list for overflow
  └── Entries[~106]:
        ├── EntryType: File | Directory
        ├── Policy: AsSelf | AsUser | AsUserQueryOnly | AsSelfNoPrompt
        ├── InheritFlags: None | ContainerInherit | Protected
        ├── DirectoryBlock → child directory (if type is Directory)
        └── Name[256] → UTF-16 path component

Index Blocks (magic: 'IsfB'):
  └── Entries[] → FILE_ID_128 mappings for rename/delete tracking
```

**Policy tree structure:** Policies form a hierarchical tree that mirrors the
filesystem path structure. Looking up a policy for
`C:\Users\Alice\Documents\report.docx` walks:

```
Root → Users → Alice → Documents → report.docx
```

At each level, the entry carries a `BFS_POLICY` value and inheritance flags.
If `report.docx` has no explicit entry but `Documents` has
`ContainerInherit`, the directory's policy applies.

### Policy Table and Caching

The in-memory policy table is a hash table keyed by `{UserSID, PackageSID}`:

```
BFS_POLICY_TABLE
  ├── HashTable: RTL_DYNAMIC_HASH_TABLE
  │     Key: Hash(UserSID + PackageSID)
  │     Value: BFS_POLICY_ENTRY
  ├── LastVisitListHead → LRU tracking for idle eviction
  └── IdleCheckTimer → fires every 30 seconds

BFS_POLICY_ENTRY
  ├── UserSid, PackageSid → identity pair
  ├── Storage → handle to on-disk policy file
  ├── State: Uninitialized | Active | PendingCreation | NotPresent | Failed
  ├── PromptState → whether user prompting is enabled
  ├── ReferenceCount → thread-safe ref counting
  └── RegistryPrefix1, RegistryPrefix2 → registry virtualization paths
```

**Idle eviction:** Policies not accessed for 5 minutes are unloaded from
memory. The background timer checks every 30 seconds and releases entries
whose last-visit timestamp exceeds the idle threshold. This bounds kernel
memory usage when many isolated apps are installed but few are running.

### IOCTL Interface

User-mode tools (primarily `bfscfg.exe`) manage policies through the
`\Device\Bfs` control device:

| IOCTL | Purpose |
|---|---|
| `SET_POLICY` | Add or modify a policy entry for a file/directory |
| `QUERY_POLICY` | Retrieve all policies for an app (by token) |
| `QUERY_POLICY_SIZE` | Get required buffer size before querying |
| `DELETE_POLICY` | Remove a single policy entry |
| `CLEAR_POLICY` | Remove all policies for an app |

**Example: adding a policy via `bfscfg`:**

```
bfscfg --addpolicy --appid <PackageFamilyName> \
       --filename "C:\Users\Alice\Documents" \
       --entrytype directory \
       --policybrokerreadonly \
       --containerinherit
```

This grants the isolated app read-only brokered access to the Documents
directory and all its children.

### Named Pipe Redirection

Isolated apps cannot directly open named pipes created by host-side services
because the pipe's ACL does not include the app's AppContainer SID. BFS
solves this by transparently rewriting pipe names:

```
App opens \\.\pipe\MyService
  → BFS looks up mapping for {UserSID, PackageSID, "MyService"}
  → Rewrites to \\.\pipe\{PackageSID}\MyService
  → Host-side service listens on the redirected name
  → Both ends communicate transparently
```

Pipe mappings are stored in a separate hash table
(`BFS_PIPE_MAPPING_TABLE`) and keyed by `{UserSID, PackageSID, PipeName}`.
The rewrite happens during `IRP_MJ_CREATE_NAMED_PIPE` processing via a
reparse operation — the filter completes the original IRP with
`STATUS_REPARSE` and the I/O manager reissues the request with the rewritten
path.

### Security Token Handling

The token handling flow during a brokered file operation:

1. **Extract token** — get the caller's impersonation or primary token
2. **Validate applicability** — confirm the token belongs to an AppContainer,
   App Silo, or agentic app context
3. **Check impersonation level** — must be at least `SecurityImpersonation`
4. **Apply policy:**
   - *AsSelf:* operation proceeds with the app's own token
   - *AsUser:* BFS impersonates the user's token for the duration of the
     operation, but strips `WRITE_OWNER` and `WRITE_DAC` to prevent the
     sandboxed app from modifying ACLs or taking ownership
5. **Post-operation cleanup** — restore the original security context

**Consent prompting flow** (when no policy exists and prompting is enabled):

1. Pre-create callback defers the operation to a worker thread
2. Worker calls `BfsPromptForConsent()` via RPC to a user-mode service
3. The user-mode service presents a consent dialog (requires
   `appSiloFileSystem` capability)
4. User's decision is cached as a new policy entry
5. On approval, the file operation is retried with the new policy; on denial,
   `AsSelfNoPrompt` is stored to suppress future prompts for that path

### Browser Isolation Containers

BFS is used extensively by browser isolation, where different process types
run in different container configurations:

| Container | Code | Purpose |
|---|---|---|
| MRAC | `mrac` | Multi-process rendering agent |
| LRAC | `lrac` | Low-integrity rendering agent |
| WebView | `webvw` | WebView2 hosting |
| Flash | `flash` | Adobe Flash plugin (legacy) |
| JIT | `jit` | JavaScript JIT compilation |
| Dev | `dev` | Developer/content hosting |
| EDP | `edp` | Enterprise Data Protection |

Each container type has its own set of mandatory and optional mitigations
(DEP, ASLR, CFG, ACG, Win32k filtering) in addition to BFS file system
policies. The Win32k filter in particular provides a limited form of syscall
filtering — it restricts which Win32k (GUI subsystem) system calls the
container process can make, with per-container-type allow lists for
operations like IME input, PDF rendering, and Flash content.

### ETW Logging

BFS provides operational telemetry through ETW:

- **Provider:** `Microsoft-Windows-Security-Isolation-BrokeringFileSystem`
- **Channel:** Operational
- **Events:** File access decisions, policy loads/unloads, prompt outcomes,
  errors
