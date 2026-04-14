# Container Policy Thoughts

This document captures research and design thinking around cross-platform sandbox
policy — comparing Linux BubbleWrap, macOS Seatbelt, Linux Landlock, seccomp-BPF,
and Windows AppContainer/Restricted Tokens — and proposes a unified JSON-based policy
language compiled to FlatBuffers for efficient runtime consumption.

---

## Table of Contents

- [1. Linux BubbleWrap vs macOS Seatbelt](#1-linux-bubblewrap-vs-macos-seatbelt)
- [2. Seccomp-BPF Filters](#2-seccomp-bpf-filters)
- [3. Linux Landlock](#3-linux-landlock)
- [4. Windows Equivalents](#4-windows-equivalents)
- [5. Common Policy Dimensions](#5-common-policy-dimensions)
- [6. macOS Seatbelt Profile Language](#6-macos-seatbelt-profile-language)
- [7. Proposed Cross-Platform JSON Policy Language](#7-proposed-cross-platform-json-policy-language)
- [8. FlatBuffer Compiled Format](#8-flatbuffer-compiled-format)
- [9. Policy Layers](#9-policy-layers)

---

## 1. Linux BubbleWrap vs macOS Seatbelt

### Linux BubbleWrap (`bwrap`)

BubbleWrap is a lightweight, unprivileged sandboxing tool. It is a *building block*,
not a turnkey sandbox — the caller defines the exact policy.

It leverages Linux kernel namespaces (mount, user, PID, network, IPC, UTS, cgroup)
to give each sandboxed process an isolated view of the system.

| Mechanism | Purpose |
|---|---|
| **User namespaces** | Allows unprivileged users to create sandboxes without root |
| **Mount namespaces + bind mounts** | Constructs a custom filesystem view (read-only or read-write) |
| **Seccomp filters** | Restricts which system calls the process can make |
| **Capability dropping** | Removes Linux capabilities to prevent privilege escalation |
| **`PR_SET_NO_NEW_PRIVS`** | Blocks setuid escalation from within the sandbox |

**Policy model:** *Explicit allowlist* — nothing is visible unless you bind-mount it
in. There is no profile language; the policy is expressed entirely through CLI flags.

**Used by:** Flatpak (as its core isolation engine), developer sandboxes, build environments.

### macOS Seatbelt (`sandbox-exec`)

Seatbelt is a kernel-enforced mandatory access control framework. Processes are
restricted by a *profile* written in an S-expression policy language.

The kernel intercepts system calls and checks them against the loaded profile.

| Mechanism | Purpose |
|---|---|
| **Kernel-level MAC enforcement** | All syscalls filtered at the kernel before execution |
| **S-expression profile language** | Declarative rules for file, network, Mach port, IPC, device access |
| **Deny-by-default model** | Everything is forbidden unless the profile explicitly `(allow ...)`s it |
| **Violation logging** | Blocked operations are logged to the system log for debugging |
| **App Sandbox entitlements** | App Store apps are forced into sandboxing via `com.apple.security.app-sandbox` |

**Policy model:** *Deny-by-default with declarative profiles*.

**Used by:** All Mac App Store apps (mandatory), Chromium renderer processes,
developer tooling.

### Head-to-Head Comparison

| Dimension | BubbleWrap (Linux) | Seatbelt (macOS) |
|---|---|---|
| **Isolation approach** | Namespace-based (process sees an entirely different world) | MAC/filter-based (process sees the real world but is blocked from actions) |
| **Policy language** | CLI flags — no declarative language | S-expression profiles — declarative, reusable |
| **Default posture** | Nothing visible unless explicitly mounted | Everything denied unless explicitly allowed |
| **Filesystem isolation** | Full: custom rootfs via bind mounts, tmpfs, overlays | Partial: rules filter access to the real filesystem |
| **Network isolation** | Yes — via network namespace (full or none) | Yes — granular per-profile rules |
| **Privilege model** | Works as unprivileged user (via user namespaces) | Requires profile to be loaded at process start; no special privilege needed |
| **Scope** | Low-level building block — you compose a sandbox from primitives | Higher-level framework — you write a profile, kernel enforces it |
| **Syscall filtering** | Via seccomp (separate mechanism, composable) | Built into the framework (profile controls which operations allowed) |
| **OS integration** | Generic Linux kernel features | Deep macOS integration (Mach ports, IOKit, XPC, TCC) |
| **Maintenance** | Stable kernel ABI; profiles rarely break | Apple changes internals across OS versions; profiles can break on upgrade |
| **Status** | Actively maintained, widely used | `sandbox-exec` CLI is deprecated; App Sandbox entitlement system is the supported path |

**Key philosophical difference:** BubbleWrap gives the sandboxed process a
*different universe* (new PID space, new mount tree, new network stack). Seatbelt
keeps the process in the *same universe* but puts guards on every door.

---

## 2. Seccomp-BPF Filters

### What Problem Does It Solve?

The Linux kernel exposes ~400+ system calls. Most applications only use a small
fraction. Every unused syscall is a potential attack vector — if an attacker gets
code execution inside your process, they can call `mount()`, `ptrace()`, `reboot()`,
etc. Seccomp lets you say: *"this process may only use these specific syscalls."*

### The Two Modes

**Strict Mode (original, rarely used):**
Process can only call `read()`, `write()`, `exit()`, and `sigreturn()`. Anything
else results in instant `SIGKILL`.

**Filter Mode (seccomp-BPF, the one everyone uses):**
You attach a BPF program that inspects every syscall and decides what to do.

### How It Works Architecturally

```
  User process calls write(fd, buf, len)
          │
          ▼
  ┌──────────────────────┐
  │   Kernel syscall      │
  │   entry point         │
  │                       │
  │  ┌─────────────────┐  │
  │  │ seccomp BPF VM  │  │  ◄── tiny in-kernel virtual machine
  │  │                 │  │      executes your filter program
  │  │ Input:          │  │
  │  │  .nr   = 1      │  │  (syscall number for write)
  │  │  .arch = x86_64  │  │
  │  │  .args[0] = fd   │  │
  │  │  .args[1] = buf  │  │  (raw value, NOT dereferenced)
  │  │  .args[2] = len  │  │
  │  │                 │  │
  │  │ Output: ACTION   │  │
  │  └─────────────────┘  │
  │          │             │
  │          ▼             │
  │   ALLOW? → execute     │
  │   KILL?  → SIGKILL     │
  │   ERRNO? → return err  │
  │   TRAP?  → SIGSYS      │
  │   TRACE? → notify ptrace│
  └──────────────────────┘
```

The BPF program operates on a `struct seccomp_data`:

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
| `SECCOMP_RET_ERRNO(val)` | Syscall blocked, returns `-val` to caller (e.g., `EPERM`) |
| `SECCOMP_RET_TRAP` | Sends `SIGSYS` to process (can be caught by a handler) |
| `SECCOMP_RET_TRACE` | Notifies a `ptrace`-attached tracer to decide |
| `SECCOMP_RET_LOG` | Allow, but log the syscall |
| `SECCOMP_RET_USER_NOTIF` | Delegate decision to a userspace supervisor (newer kernels) |

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

Without libseccomp, you write raw BPF instructions:

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

### Key Security Properties

1. **Immutable once loaded** — a process cannot weaken its own filter after installation
2. **Inherited by children** — `fork()` and `execve()` carry the filter forward
3. **Stackable** — multiple filters can be layered; *all* must agree to allow a syscall
4. **No pointer dereferencing** — the BPF program sees raw argument *values*, not the
   memory they point to; this prevents TOCTOU races where userspace changes memory
   between the check and the actual syscall
5. **Requires `PR_SET_NO_NEW_PRIVS`** — the process must first commit to never gaining
   new privileges

### Who Uses It?

| User | How |
|---|---|
| **Docker/containers** | Default seccomp profile blocks ~44 dangerous syscalls |
| **Chromium** | Renderer processes can only use ~20 syscalls |
| **systemd** | `SystemCallFilter=` directive in unit files |
| **Android** | Zygote process applies seccomp before spawning apps |
| **Flatpak/BubbleWrap** | Passed via `--seccomp` flag |
| **OpenSSH** | Privilege-separated child uses seccomp |

### Limitations

- **Cannot inspect pointed-to memory** — only raw argument values (by design, to
  avoid TOCTOU)
- **Not a full sandbox alone** — only restricts syscalls, not file paths, network
  destinations, etc.
- **Architecture-dependent** — syscall numbers differ across architectures; always
  check `arch` first
- **Classic BPF only** — uses the older cBPF instruction set, not eBPF

---

## 3. Linux Landlock

### What It Is

Landlock is a Linux Security Module (merged in kernel 5.13) that lets a process
*restrict itself* — no root, no admin policy, no container runtime needed. A process
creates a ruleset describing what it is allowed to access, then permanently locks
itself into that ruleset.

Think of it as: *"I'm about to run untrusted code, so let me voluntarily give up my
own rights first."*

### Where It Fits in the Linux Security Stack

```
  ┌──────────────────────────────────────────────────┐
  │                  Access Request                    │
  │         (e.g., open("/etc/shadow", O_RDONLY))      │
  └──────────────┬───────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────┐
  │  DAC (Unix perms)    │  ← owner/group/other, rwx bits
  │  Must pass           │
  └──────────┬───────────┘
             ▼
  ┌──────────────────────┐
  │  LSM: SELinux /      │  ← admin-defined, system-wide, label-based
  │       AppArmor       │     policy (if enabled)
  │  Must pass           │
  └──────────┬───────────┘
             ▼
  ┌──────────────────────┐
  │  LSM: Landlock       │  ← process-defined, per-process, runtime
  │  Must pass           │     (stacks with everything above)
  └──────────┬───────────┘
             ▼
        Access granted
```

Landlock **only restricts further** — it can never grant access that DAC or other
LSMs would deny.

### The Three Syscalls

| Syscall | Purpose |
|---|---|
| `landlock_create_ruleset()` | Create a new ruleset; declare which access types you want to govern |
| `landlock_add_rule()` | Add rules to the ruleset (e.g., "allow read on this directory") |
| `landlock_restrict_self()` | Apply the ruleset to the calling process — **permanent and irreversible** |

### How It Works (Step by Step)

```
1. Create ruleset       "I want to control filesystem reads, writes, and execution"
       │
2. Add rules            "Allow read+execute under /usr"
       │                "Allow read+write under /tmp/myapp"
       │                "Allow read under /etc/resolv.conf"
       │
3. prctl(NO_NEW_PRIVS)  Commit to never gaining new privileges
       │
4. Restrict self         Lock it in — from here on, ONLY those paths are accessible
       │
5. exec(untrusted_app)   The app (and all its children) are confined
```

Everything NOT mentioned in the rules is **denied by default**.

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

### ABI Versions

| ABI Version | Kernel | New Capabilities |
|---|---|---|
| **v1** | 5.13 | Filesystem: read, write, execute, create, remove, make dirs/chars/blocks/fifos/sockets/symlinks/links |
| **v2** | 5.19 | `LANDLOCK_ACCESS_FS_REFER` — control cross-directory renames and links |
| **v3** | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` — control file truncation |
| **v4** | 6.7 | **Network**: `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` |
| **v5** | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` — control `ioctl()` on device files |
| **v6** | 6.12 | **Unix sockets**: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, **signals**: `LANDLOCK_SCOPE_SIGNAL` |

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

### Key Design Principles

1. **Self-restriction only** — a process can only restrict itself, never other processes
2. **Additive restrictions** — you can add more rulesets (tighten), never remove them (loosen)
3. **Inherited by children** — `fork()` and `execve()` carry all restrictions forward
4. **Composable** — Landlock + seccomp + namespaces + SELinux all stack cleanly
5. **No kernel policy language** — rules are defined via syscall structs, not config files

The mental model: Landlock is to **files and network ports** what seccomp is to
**syscalls** — a way for a process to voluntarily shed its own power before doing
something risky.

---

## 4. Windows Equivalents

Windows does not have a single direct equivalent to BubbleWrap or Seatbelt. Instead,
it has several complementary mechanisms:

### AppContainer (closest equivalent)

The most analogous to BubbleWrap/Seatbelt for application sandboxing. Introduced in
Windows 8.

- Process runs with a **restricted token** under a unique per-app SID
- **Deny-by-default** for file, registry, network, and process access
- Capabilities must be explicitly granted in the app manifest
- Each container gets its own writable area
- Network access is granular (can block localhost, internet, etc.)
- Used by: UWP/Store apps, Edge renderer processes, and increasingly Win32 apps via
  **Win32 App Isolation** (preview)

### Restricted Tokens + Job Objects (low-level building blocks)

These are the Windows analog to BubbleWrap's composable primitives:

| Windows Mechanism | Linux Equivalent | Purpose |
|---|---|---|
| **Restricted Tokens** | Linux capabilities + seccomp | Strip privileges/SIDs from a process token |
| **Job Objects** | cgroups + PID namespace | Group processes, limit CPU/memory/process count, control termination |
| **Integrity Levels** (Low/Untrusted) | No direct equivalent (closest: user namespaces) | Prevent writes to higher-integrity objects |
| **Desktop isolation** | X11/Wayland separation | Separate window station prevents message-based attacks |

Chromium on Windows uses all four together to sandbox renderer processes.

### Windows Sandbox (VM-based, highest isolation)

A disposable Hyper-V-based lightweight VM. Closest analog is running a throwaway
QEMU/KVM VM on Linux. Provides complete OS-level isolation but with higher overhead.
Destroyed on close — no persistence.

### Win32 App Isolation (newer, in preview)

Microsoft's latest effort to bring AppContainer-style isolation to traditional Win32
desktop apps. Aims to close the gap with Linux/macOS app sandboxing for non-Store apps.

### Cross-Platform Summary

| Capability | Linux (BubbleWrap + kernel) | macOS (Seatbelt/App Sandbox) | Windows (AppContainer + primitives) |
|---|---|---|---|
| **Filesystem isolation** | Mount namespaces + bind mounts | Profile rules on real FS | AppContainer SID + virtualized paths |
| **Network isolation** | Network namespace | Profile rules | AppContainer capabilities |
| **Syscall filtering** | Seccomp-BPF | Built into Seatbelt profiles | Not directly (rely on token/capability restrictions) |
| **Resource limits** | cgroups | Not built-in (launchd can limit) | Job Objects |
| **Process isolation** | PID namespace | Not built-in | Job Objects + desktop isolation |
| **Privilege reduction** | Capability dropping + `NO_NEW_PRIVS` | Deny-by-default profiles | Restricted tokens + integrity levels |
| **Unprivileged use** | Yes (user namespaces) | Yes (profiles loaded at exec) | Partially (AppContainer needs token creation) |
| **Composability** | High (mix and match primitives) | Medium (profile language is flexible) | Medium (combine tokens + jobs + integrity) |
| **App Store enforcement** | N/A (Flatpak uses bwrap) | Mandatory for Mac App Store | Mandatory for Microsoft Store (UWP) |

---

## 5. Common Policy Dimensions

When you look across all these systems, common policy dimensions emerge. They don't
all cover every dimension, but they draw from the same well.

### Universal Policy Dimensions

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

✓ = native to the system, ○ = achievable by composition, — = not addressed

### Filesystem Access — Three Fundamental Strategies

**Strategy A: "Different Universe" (Namespace/Mount-based)**
Used by BubbleWrap, AppContainer. The process literally cannot *see* files that
aren't explicitly mounted/mapped in.

**Strategy B: "Same Universe, Guarded Doors" (MAC/Filter-based)**
Used by Seatbelt, Landlock. The process can *see* the full path namespace but is
blocked at access time.

**Strategy C: "Reduced Credentials" (Token/ACL-based)**
Used by Restricted Tokens, AppContainer. The process's identity token is stripped
down so that existing OS ACLs deny it access.

### What They All Share on Filesystem Policy

Despite the different mechanisms, every system expresses filesystem policy along the
same axes:

| Axis | How It Appears |
|---|---|
| **Which paths** | Specific file, directory subtree, prefix, or regex |
| **Read vs Write vs Execute** | Always distinguished; read-only is the most common restriction |
| **Direction of default** | Deny-by-default (allow specific paths) vs allow-by-default (block specific paths) |
| **Hierarchy inheritance** | "Allow read on `/usr`" implies all children |
| **Mutability vs creation** | Separate controls for writing existing files vs creating new files |

### Network Access Granularity

| Granularity | BubbleWrap | Seatbelt | Landlock | AppContainer |
|---|---|---|---|---|
| **All-or-nothing** | ✓ | — | — | — |
| **Inbound vs outbound** | — | ✓ | ✓ | ✓ |
| **By port** | — | ✓ | ✓ | ✓ |
| **By destination host/IP** | — | ✓ | — | — |
| **By protocol (TCP/UDP)** | — | ✓ | TCP only (so far) | ✓ |
| **Localhost specifically** | — | ✓ | ✓ | ✓ |

### IPC — OS-Specific but Same Intent

| System | IPC Mechanism Controlled | Policy Expression |
|---|---|---|
| BubbleWrap | Unix sockets, shared memory | `--unshare-ipc` (all-or-nothing) |
| Seatbelt | Mach ports, XPC, Unix sockets | `(allow mach-lookup (global-name "..."))` |
| Landlock | Abstract Unix sockets, signals | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` |
| AppContainer | COM, RPC, named pipes, ALPC | Capability-based in manifest |

### Privilege Escalation Prevention — Universal

| Mechanism | How It Prevents Escalation |
|---|---|
| BubbleWrap | `PR_SET_NO_NEW_PRIVS` — setuid binaries won't elevate |
| Seatbelt | Deny-by-default + kernel enforcement — no way to load a weaker profile |
| Landlock | `PR_SET_NO_NEW_PRIVS` + restrictions are additive-only |
| Seccomp | `PR_SET_NO_NEW_PRIVS` + filters are immutable once loaded and stack |
| AppContainer | Low integrity level + unique SID |
| Restricted Tokens | Stripped privileges + deny-only SIDs |

**Universal principle:** the sandbox boundary is monotonically shrinking — once
restricted, you cannot regain what you lost.

### The Meta-Pattern

Every sandboxing policy answers the same five questions:

```
1. WHAT RESOURCES?     Files, network, IPC, devices, processes, syscalls
2. WHICH ONES?         By path, by port, by service name, by syscall number
3. WHAT OPERATIONS?    Read vs write vs execute vs create vs delete
4. DEFAULT POSTURE?    Deny-by-default (allowlist) vs allow-by-default (denylist)
5. CAN IT BE UNDONE?   No. (Always no.)
```

These five questions describe the *shape* of a single policy. But real-world
sandboxing involves multiple stakeholders, each contributing constraints at
different layers. See [§9 Policy Layers](#9-policy-layers) for that orthogonal
axis.

---

## 6. macOS Seatbelt Profile Language

Profiles are written in an S-expression (Lisp-like) syntax and stored as `.sb` text
files. Apple ships built-in ones at `/usr/share/sandbox/` (e.g., `sshd.sb`, `mds.sb`,
`ntpd.sb`). The language itself is undocumented by Apple but well reverse-engineered.

### Basic Structure

```scheme
(version 1)          ; required — always 1
(deny default)       ; deny everything not explicitly allowed
(import "system.sb") ; import Apple's base rules for basic OS functionality

;; then: a series of (allow ...) and (deny ...) rules
```

### The Rule Grammar

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

### Real-World Examples

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

#### Using `define` for Reusable Macros

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

### Caveats

- `sandbox-exec` is **deprecated** by Apple (no replacement CLI; App Sandbox
  entitlements are the supported path)
- The profile language is **undocumented** — reverse-engineered from shipped `.sb`
  files and security research
- Profiles can **break across macOS upgrades** as Apple renames/moves system services
- No **memory or thread isolation** — Seatbelt controls access to resources, not
  computation

---

## 7. Proposed Cross-Platform JSON Policy Language

### Design Principles

1. **Deny-by-default always** — no `"default": "allow"` option; you only express what
   is permitted
2. **Declarative, not mechanistic** — say *what* access, not *how* to implement it
3. **Platform-specific escape hatches** — because real-world policies will need them
4. **Graduated granularity** — simple things should be simple; complex things should
   be possible

> **Note on policy layers:** This JSON schema primarily represents a *bound
> deployment policy* — concrete paths, ports, and hosts are specified. In the
> layered model described in [§9](#9-policy-layers), this corresponds mostly to
> **Layer 2 (Instance Binding)**, with the platform overrides section touching on
> **Layer 7 (Container Enforcement Capabilities)**. Abstract resource-type
> requirements (Layer 1) and authority-based constraints (Layers 3–5) are upstream
> of this format.

### Example Policy

```jsonc
{
  "version": "1.0",
  "name": "my-web-scraper-sandbox",
  "description": "Sandbox for an untrusted Python web scraper",

  // ─── Filesystem ───────────────────────────────────────────────
  "filesystem": {
    // Each rule: a path scope + a set of allowed operations
    "rules": [
      {
        "path": "/usr/lib",
        "scope": "subtree",          // "exact", "subtree", "prefix", "pattern"
        "allow": ["read", "execute"]
      },
      {
        "path": "/usr/bin/python3",
        "scope": "exact",
        "allow": ["read", "execute"]
      },
      {
        "path": "${WORK_DIR}",
        "scope": "subtree",
        "allow": ["read", "write", "create", "delete"]
      },
      {
        "path": "${WORK_DIR}/output",
        "scope": "subtree",
        "allow": ["read", "write", "create"]
      },
      {
        "path": "${HOME}/.config/scraper.conf",
        "scope": "exact",
        "allow": ["read"]
      },
      {
        "path": "/tmp",
        "scope": "subtree",
        "allow": ["read", "write", "create", "delete"],
        "ephemeral": true
      }
    ],

    // Paths to mask (replace with empty/null)
    "mask": [
      "${HOME}/.env",
      "${HOME}/.aws/credentials"
    ],

    // Synthetic mounts (not backed by host filesystem)
    "synthetic": {
      "/dev":  "minimal",
      "/proc": "sandboxed",
      "/tmp":  "ephemeral"
    }
  },

  // ─── Network ──────────────────────────────────────────────────
  "network": {
    // "none" | "full" | "rules"
    "mode": "rules",

    "rules": [
      {
        "direction": "outbound",
        "action": "connect",
        "protocol": "tcp",
        "host": "*",
        "port": 443
      },
      {
        "direction": "outbound",
        "action": "connect",
        "protocol": "tcp",
        "host": "*",
        "port": 80
      },
      {
        "direction": "outbound",
        "action": "connect",
        "protocol": "udp",
        "host": "*",
        "port": 53,
        "comment": "Allow DNS resolution"
      }
    ],

    "allow_dns": true,
    "allow_localhost": false
  },

  // ─── Processes ────────────────────────────────────────────────
  "process": {
    "allow_fork": true,
    "allow_exec": [
      "/usr/bin/python3",
      "/usr/bin/curl"
    ],
    "visibility": "self",
    "signals": "self",
    "hostname": "sandbox",
    "die_with_parent": true
  },

  // ─── IPC / Services ──────────────────────────────────────────
  "ipc": {
    "isolation": "full",

    "services": [
      {
        "name": "com.apple.system.logger",
        "allow": ["lookup"]
      },
      {
        "name": "org.freedesktop.resolve1",
        "allow": ["call"]
      }
    ]
  },

  // ─── Devices ──────────────────────────────────────────────────
  "devices": {
    "allow": []
  },

  // ─── Resource Limits ──────────────────────────────────────────
  "resources": {
    "max_memory_mb": 512,
    "max_cpu_percent": 50,
    "max_processes": 10,
    "max_open_files": 256,
    "max_wall_time_seconds": 300
  },

  // ─── Environment ──────────────────────────────────────────────
  "environment": {
    "mode": "clean",
    "set": {
      "HOME": "/home/sandbox",
      "LANG": "en_US.UTF-8",
      "PATH": "/usr/bin:/usr/local/bin"
    },
    "pass_through": [
      "HTTPS_PROXY",
      "NO_PROXY"
    ]
  },

  // ─── Variables ────────────────────────────────────────────────
  "variables": {
    "WORK_DIR": "/home/alice/scraper-project",
    "HOME": "/home/alice"
  },

  // ─── Platform Overrides ───────────────────────────────────────
  "platform": {
    "linux": {
      "seccomp": {
        "mode": "allowlist",
        "syscalls": ["read", "write", "open", "close", "stat", "fstat",
                     "mmap", "mprotect", "munmap", "brk", "ioctl",
                     "socket", "connect", "sendto", "recvfrom",
                     "clone", "execve", "exit_group", "futex",
                     "getpid", "getuid", "arch_prctl"]
      },
      "landlock_abi": 4,
      "namespaces": {
        "user": true, "mount": true, "pid": true,
        "net": true, "ipc": true, "uts": true, "cgroup": true
      }
    },
    "macos": {
      "seatbelt_import": ["system.sb"],
      "extra_rules": [
        "(allow mach-lookup (global-name-prefix \"com.apple.cfprefsd\"))"
      ]
    },
    "windows": {
      "integrity_level": "low",
      "appcontainer": {
        "capabilities": ["internetClient"],
        "deny_capabilities": ["privateNetworkClientServer"]
      }
    }
  }
}
```

### How Each Section Maps to Backends

#### Filesystem Rules

| Policy JSON | BubbleWrap | Seatbelt | Landlock | AppContainer |
|---|---|---|---|---|
| `"allow": ["read"]` | `--ro-bind path path` | `(allow file-read* (subpath path))` | `READ_FILE \| READ_DIR` | Read ACE on container SID |
| `"allow": ["read","write","create"]` | `--bind path path` | `(allow file-read* file-write* ...)` | `READ_FILE \| WRITE_FILE \| MAKE_REG` | Read+Write ACE |
| `"scope": "exact"` | `--ro-bind file file` | `(literal path)` | Rule with `O_PATH` on file | ACE on specific file |
| `"scope": "subtree"` | `--ro-bind dir dir` | `(subpath path)` | `LANDLOCK_RULE_PATH_BENEATH` | ACE with inheritance |
| `"ephemeral": true` | `--tmpfs path` | N/A (external setup) | N/A (external setup) | Virtualized path |
| `"mask": [path]` | `--bind /dev/null path` | `(deny file-read* (literal path))` | No rule for path (denied) | Deny ACE |

#### Network Rules

| Policy JSON | BubbleWrap | Seatbelt | Landlock | AppContainer |
|---|---|---|---|---|
| `"mode": "none"` | `--unshare-net` | `(deny network*)` | No `NET_*` rules | Remove `internetClient` cap |
| `"mode": "full"` | `--share-net` | `(allow network*)` | Allow all `NET_*` | Grant all network caps |
| `outbound/connect/tcp/443` | `--share-net` (all-or-nothing) | `(allow network-outbound (remote tcp "*:443"))` | `NET_CONNECT_TCP` + port=443 | `internetClient` cap |

---

## 8. FlatBuffer Compiled Format

### Why FlatBuffers

The policy is write-once at build/deploy time, read-many at every sandbox launch,
often on a hot startup path where you don't want JSON parsing overhead, allocations,
or dependencies. Zero-copy mmap access means the sandbox runtime can validate and
apply policy without deserializing anything.

| Format | Parse Cost | Random Access | Zero-Copy | Schema Evolution |
|---|---|---|---|---|
| **JSON** | High (full parse) | No | No | N/A |
| **Protobuf** | Medium (decode) | No (sequential) | No | Yes |
| **Cap'n Proto** | Zero | Yes | Yes | Yes |
| **FlatBuffers** | Zero | Yes | Yes | Yes |

### The Pipeline

```
                    Author time                          Deploy/Runtime
              ┌──────────────────────┐           ┌─────────────────────────┐
              │                      │           │                         │
  policy.jsonc│  Human-readable      │  compile  │  policy.sbxp            │
  (or .yaml)  │  authoring format    ├──────────►│  FlatBuffer binary      │
              │  with comments,      │           │  - zero-copy mmap       │
              │  variables, extends  │           │  - validated at compile │
              │                      │           │  - optionally signed    │
              └──────────────────────┘           └────────┬────────────────┘
                                                          │
                                                     ┌────┴────┐
                                                     │ Runtime │
                                                     │ mmap()  │
                                                     │ verify  │
                                                     │ apply   │
                                                     └─────────┘
```

### FlatBuffer Schema (`sandbox_policy.fbs`)

```flatbuffers
namespace Sandbox;

// ═══════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════

enum PathScope : byte {
    Exact = 0,
    Subtree,
    Prefix,
    Pattern
}

enum FileOps : uint16 (bit_flags) {
    Read = 0,       // 0x01
    Write,          // 0x02
    Execute,        // 0x04
    Create,         // 0x08
    Delete,         // 0x10
    Metadata,       // 0x20
    Truncate,       // 0x40
    Ioctl           // 0x80
}

enum NetDirection : byte {
    Outbound = 0,
    Inbound
}

enum NetAction : byte {
    Connect = 0,
    Bind,
    Any
}

enum NetProtocol : byte {
    TCP = 0,
    UDP,
    Any
}

enum NetworkMode : byte {
    None = 0,
    Full,
    Rules
}

enum ProcessVisibility : byte {
    Self = 0,
    Host
}

enum SignalScope : byte {
    None = 0,
    Self,
    Any
}

enum IpcIsolation : byte {
    Full = 0,
    Shared
}

enum EnvironmentMode : byte {
    Clean = 0,
    Inherit
}

enum IntegrityLevel : byte {
    Untrusted = 0,
    Low,
    Medium,
    High
}

enum SyntheticType : byte {
    Minimal = 0,
    Sandboxed,
    Ephemeral
}

// ═══════════════════════════════════════════════════════════════
// Tables
// ═══════════════════════════════════════════════════════════════

// ─── Filesystem ────────────────────────────────────────────────

table FsRule {
    path:         string (required);
    scope:        PathScope = Exact;
    allowed_ops:  FileOps;
    ephemeral:    bool = false;
}

table FsMask {
    path: string (required);
}

table SyntheticMount {
    path: string (required);
    type: SyntheticType;
}

table Filesystem {
    rules:      [FsRule];
    masks:      [FsMask];
    synthetics: [SyntheticMount];
}

// ─── Network ───────────────────────────────────────────────────

table NetRule {
    direction: NetDirection;
    action:    NetAction;
    protocol:  NetProtocol;
    host:      string;
    port_min:  uint16 = 0;
    port_max:  uint16 = 0;
}

table Network {
    mode:            NetworkMode = None;
    rules:           [NetRule];
    allow_dns:       bool = false;
    allow_localhost:  bool = false;
}

// ─── Process ───────────────────────────────────────────────────

table Process {
    allow_fork:      bool = true;
    allowed_exec:    [string];
    visibility:      ProcessVisibility = Self;
    signals:         SignalScope = Self;
    hostname:        string;
    die_with_parent: bool = true;
}

// ─── IPC ───────────────────────────────────────────────────────

table ServiceRule {
    name:   string (required);
    allow:  [string];
}

table Ipc {
    isolation: IpcIsolation = Full;
    services:  [ServiceRule];
}

// ─── Devices ───────────────────────────────────────────────────

table DeviceRule {
    path:       string (required);
    allowed_ops: FileOps;
}

table Devices {
    rules: [DeviceRule];
}

// ─── Resources ─────────────────────────────────────────────────

table Resources {
    max_memory_mb:         uint32 = 0;
    max_cpu_percent:       uint16 = 0;
    max_processes:         uint16 = 0;
    max_open_files:        uint16 = 0;
    max_wall_time_seconds: uint32 = 0;
}

// ─── Environment ───────────────────────────────────────────────

table EnvVar {
    key:   string (required);
    value: string (required);
}

table Environment {
    mode:         EnvironmentMode = Clean;
    vars:         [EnvVar];
    pass_through: [string];
}

// ─── Platform-Specific ─────────────────────────────────────────

table SeccompConfig {
    allowlist: bool = true;
    syscalls:  [string];
}

table LinuxNamespaces {
    user:   bool = true;
    mount:  bool = true;
    pid:    bool = true;
    net:    bool = true;
    ipc:    bool = true;
    uts:    bool = true;
    cgroup: bool = true;
}

table LinuxPlatform {
    seccomp:           SeccompConfig;
    landlock_min_abi:  uint8 = 1;
    namespaces:        LinuxNamespaces;
}

table MacOSPlatform {
    seatbelt_imports: [string];
    extra_rules:      [string];
}

table WindowsPlatform {
    integrity_level:    IntegrityLevel = Low;
    capabilities:       [string];
    deny_capabilities:  [string];
}

table Platform {
    linux:   LinuxPlatform;
    macos:   MacOSPlatform;
    windows: WindowsPlatform;
}

// ─── Signature / Integrity ─────────────────────────────────────

table Signature {
    algorithm:  string;
    key_id:     string;
    value:      [ubyte];
}

// ─── Root ──────────────────────────────────────────────────────

table Policy {
    name:           string;
    description:    string;
    schema_version: uint16 = 1;

    filesystem:  Filesystem;
    network:     Network;
    process:     Process;
    ipc:         Ipc;
    devices:     Devices;
    resources:   Resources;
    environment: Environment;
    platform:    Platform;

    signature:   Signature;
}

root_type Policy;

file_identifier "SBXP";
file_extension "sbxp";
```

### Runtime Access Pattern (C++)

```cpp
// mmap the file — no parsing, no allocation
auto buf = mmap(fd, PROT_READ, MAP_PRIVATE);

// Verify magic + schema
auto policy = Sandbox::GetPolicy(buf);
assert(Sandbox::PolicyBufferHasIdentifier(buf));

// Direct field access — pointer arithmetic, no deserialization
auto net = policy->network();
if (net->mode() == Sandbox::NetworkMode_None) {
    unshare(CLONE_NEWNET);
} else {
    for (auto rule : *net->rules()) {
        // rule->direction(), rule->port_min(), etc.
    }
}

// Check signature before trusting
auto sig = policy->signature();
verify_ed25519(sig->key_id(), sig->value(), buf, buf_len);
```

### Size Estimates

| Component | Small Policy | Large Policy (50 FS rules, 20 net rules) |
|---|---|---|
| JSON (authoring) | ~3.5 KB | ~15 KB |
| FlatBuffer (compiled) | ~800 bytes | ~3-4 KB |
| With Ed25519 signature | ~870 bytes | ~4 KB |

Small enough to embed in an executable, pass over a pipe, or store in an xattr.

### Signature / Trust Model

Since the policy controls what an untrusted process can do, the policy itself must
be trusted:

```
  Author → policy.jsonc → compiler → policy.sbxp → sign(key) → policy.sbxp (signed)
                                                                      │
  Runtime: mmap → verify(pubkey) → apply                              │
           │                                                          │
           └── if verification fails → refuse to launch sandbox ──────┘
```

### Compile-Time vs Runtime Responsibilities

| Concern | Compiler (JSON → .sbxp) | Runtime (.sbxp → enforcement) |
|---|---|---|
| Variable resolution | `${HOME}` → `/home/alice` | Sees only resolved paths |
| `extends` / inheritance | Flattened into single policy | Sees only final merged result |
| Schema validation | Full validation + warnings | Quick `Verify()` + magic check |
| Platform rule checking | "Warning: regex scope not supported on Landlock" | Skips rules marked unsupported |
| Signature generation | Signs the buffer | Verifies before applying |
| Path canonicalization | Resolves symlinks, normalizes paths | Trusts paths are canonical |

---

## 9. Policy Layers

The preceding sections describe the *shape* of a sandbox policy — what dimensions
it covers (§5), what the authoring format looks like (§7), and how it compiles to an
efficient binary (§8). But they treat policy as a monolithic artifact. In practice,
**multiple stakeholders at different layers** contribute to the final effective
policy. This section introduces that orthogonal axis.

### The Seven Layers

```
                         POLICY INPUTS                    REALIZATION
                   (what is wanted/allowed)            (what can be delivered)
              ┌───────────────────────────────┐   ┌──────────────────────────┐
              │                               │   │                          │
  Layer 1     │  Code Requirements            │   │                          │
              │  (resource types)             │   │                          │
              │         │                     │   │                          │
  Layer 2     │  Instance Binding             │   │                          │
              │  (concrete resources)         │   │                          │
              │         │                     │   │                          │
  Layer 3     │  User Consent                 │   │                          │
              │  (what the user allows)       │   │                          │
              │         │                     │   │                          │
  Layer 4     │  IT Admin Policy              │   │                          │
              │  (organizational constraints) │   │                          │
              │         │                     │   │                          │
  Layer 5     │  System Policy                │   │                          │
              │  (OS-level constraints)       │   │                          │
              │         │                     │   │                          │
              └─────────┼─────────────────────┘   │                          │
                        │                         │                          │
                        ▼                         │                          │
               Declared/Authorized Policy ───────►│                          │
                                                  │                          │
  Layer 6     │                                   │  System Security Promises│
              │                                   │  (what guarantees hold)  │
              │                                   │                          │
  Layer 7     │                                   │  Container Enforcement   │
              │                                   │  Capabilities            │
              │                                   │  (what can be enforced)  │
              │                                   │                          │
              │                                   └──────────┬───────────────┘
              │                                              │
              │                                              ▼
              │                                    Realized Policy
              │                                    + Assurance Level
              └──────────────────────────────────────────────┘
```

There is a fundamental split between **Layers 1–5** and **Layers 6–7**:

- **Layers 1–5 are normative** — they express what is wanted, consented to, or
  forbidden. The effective declared policy is the intersection: each layer can only
  further restrict, never broaden.

- **Layers 6–7 are descriptive** — they express what the system can actually deliver.
  They do not add permissions or restrictions; they determine whether the declared
  policy can be faithfully enforced, and with what level of assurance.

### Layer 1: Code Requirements (Resource Types)

What *types* of resources does the code need? This is the most abstract layer — a
declaration of capabilities the code expects, without specifying concrete instances.

| Example Requirement | What It Means |
|---|---|
| "needs filesystem" | The code reads or writes files |
| "needs network" | The code makes or accepts connections |
| "needs GPU" | The code uses hardware-accelerated compute |
| "needs IPC" | The code communicates with other processes |
| "needs camera" | The code captures video input |

This layer is analogous to Android's `<uses-permission>` declarations, macOS
entitlements (`com.apple.security.network.client`), or UWP capability declarations
in `Package.appxmanifest`.

The key property: **Layer 1 does not name specific files, hosts, or devices.** It
describes the *kinds* of access, not the *instances*.

### Layer 2: Instance Binding (Concrete Resources)

Where abstract requirements meet concrete resources. This is where "needs
filesystem" becomes "needs read access to `/data/input.csv`" and "needs network"
becomes "needs to connect to `api.example.com:443`."

| Abstract (Layer 1) | Bound (Layer 2) |
|---|---|
| Filesystem access | `/usr/lib` (read), `${WORK_DIR}` (read/write) |
| Network access | Outbound TCP to `*:443`, DNS on UDP `*:53` |
| IPC access | Mach lookup `com.apple.system.logger` |
| Device access | `/dev/dri/renderD128` (GPU) |

Binding can happen in several ways:

- **Statically** — the developer specifies exact paths/hosts in a policy file (this
  is what the JSON schema in §7 primarily expresses)
- **Via brokered selection** — the user picks a file or folder through a system
  dialog, and that choice becomes the binding (e.g., macOS Powerbox, Android
  `ACTION_OPEN_DOCUMENT`)
- **Via convention** — the runtime maps abstract requirements to well-known paths
  (e.g., XDG directories, `%APPDATA%`)

> **Note:** Binding and user consent (Layer 3) are often interleaved in practice.
> When a user picks a file via a system open-dialog, they are simultaneously
> binding a concrete resource *and* consenting to its use. The layered model is
> conceptual, not a strict temporal sequence.

### Layer 3: User Consent (What the User Allows)

The human running the code decides what access they are comfortable granting. This
layer is the user's opportunity to narrow the policy beyond what the code requests.

| Platform | Consent Mechanism |
|---|---|
| **macOS** | TCC dialogs ("App X wants to access your Documents"), Powerbox file picker |
| **Android** | Runtime permission prompts (camera, location, contacts) |
| **iOS** | Runtime permission prompts + App Tracking Transparency |
| **Windows** | UAC prompts, broker-mediated file pickers, privacy settings |
| **Linux** | XDG portals (file chooser, screen capture), Flatpak permission prompts |
| **Web** | `navigator.permissions`, `<input type="file">`, getUserMedia prompts |

Key properties:

- The user can **deny** a Layer 1 requirement — the code says "I need camera" but
  the user says no. The sandbox must handle this gracefully (deny access, not crash).
- Consent may be **revocable** — the user can change their mind later (unlike sandbox
  restrictions, which are monotonically shrinking within a session).
- Consent may be **granular** — "yes to this specific folder, no to the rest of
  filesystem."

### Layer 4: IT Admin Policy (Organizational Constraints)

Enterprise and organizational policy that constrains what is allowed regardless of
what the code requests or the user consents to. Defined by **organizational
authority** — the IT administrator, fleet operator, or MDM profile.

| Platform | Admin Policy Mechanism |
|---|---|
| **Windows** | Group Policy (GPO), Intune/MDM, WDAC, AppLocker |
| **macOS** | MDM profiles (e.g., Jamf), managed TCC overrides, managed App restrictions |
| **Linux** | Centralized SELinux/AppArmor policy distribution, fleet management tools |
| **ChromeOS** | Google Admin Console policies |

Examples:

- "No application may access external network endpoints outside `*.corp.example.com`"
- "Code execution from USB drives is forbidden"
- "Only signed executables may run"

> **Relationship to Layer 5:** IT admin policy is distinguished from system policy
> by **who sets it**, not by the enforcement mechanism. An admin may express a
> constraint through GPO, which is then enforced by WDAC (a system-level mechanism).
> Layer 4 is the *authority*; Layer 5 is often the *enforcement substrate*.

### Layer 5: System Policy (OS-Level Constraints)

Constraints enforced by the operating system or platform itself, independent of any
specific application, user, or administrator. These are the platform's own security
invariants.

| Platform | System Policy Examples |
|---|---|
| **macOS** | System Integrity Protection (SIP), Gatekeeper, hardened runtime requirements |
| **Windows** | Protected Process Light (PPL), kernel-mode code signing (KMCS), Secure Boot |
| **Linux** | SELinux/AppArmor in enforcing mode (base policy), Secure Boot + IMA, kernel lockdown |
| **All** | Address space layout randomization (ASLR), W^X enforcement, stack protections |

Key properties:

- System policy applies **universally** — even a root/admin user cannot bypass SIP on
  macOS without rebooting into recovery mode.
- It represents the platform's **own security invariants**, not delegated authority.
- It is the **floor** — nothing below this layer (including admin policy) can
  weaken it.

### Layer 6: System Security Promises (What Guarantees Hold)

This layer shifts from *intent* to *capability*. What security guarantees can the
system actually deliver given its current configuration and kernel version?

| Question | Example |
|---|---|
| Is kernel Landlock available? | If no: cannot enforce per-file access rules via Landlock; must fall back to mount-based isolation or fail |
| What Landlock ABI version? | ABI < 4: no network port rules; ABI < 6: no Unix socket or signal scoping |
| Does the kernel support user namespaces? | If no: BubbleWrap cannot run unprivileged |
| Is Secure Boot enabled? | If no: kernel integrity chain is unverified |
| Is the hypervisor present? | If no: VM-based isolation (Windows Sandbox, Hyper-V containers) is unavailable |
| Is TCC database intact? | If compromised: user consent records may be untrustworthy |

This layer determines the **assurance level** of the realized policy. A policy may
be *declared* but only *partially enforceable* on a given system. The sandbox
runtime must decide how to handle the gap (see [Failure Modes](#failure-modes)
below).

### Layer 7: Container Enforcement Capabilities (What Can Be Enforced)

Given a specific container technology, what subset of the declared policy can it
actually implement?

| Declared Policy | BubbleWrap | Seatbelt | Landlock + seccomp | AppContainer |
|---|---|---|---|---|
| File read/write rules | ✓ (bind mounts) | ✓ (profile rules) | ✓ (path rules) | ✓ (ACLs on SID) |
| Per-port network rules | ✗ (all-or-nothing) | ✓ | ✓ (ABI ≥ 4) | ✓ (capabilities) |
| Syscall filtering | ✗ (needs seccomp) | ✓ (built-in) | ✗ (needs seccomp) | ✗ |
| Resource limits (CPU/mem) | ✗ (needs cgroups) | ✗ | ✗ (needs cgroups) | ✓ (Job Objects) |
| Process visibility | ✓ (PID namespace) | ✗ | ✗ | Partial (Job Objects) |
| IPC isolation | ✓ (IPC namespace) | ✓ (Mach port rules) | Partial (ABI ≥ 6) | ✓ (capability-based) |
| Device access control | ✓ (bind mounts) | ✓ (IOKit rules) | ✓ (ABI ≥ 5) | ✓ (capabilities) |

No single container technology covers every policy dimension. In practice, backends
are composed: BubbleWrap + seccomp + cgroups on Linux, AppContainer + Job Objects +
Restricted Tokens on Windows. Layer 7 determines which composition is needed and
whether any policy rules cannot be realized at all.

### The Evaluation Pipeline

The effective realized policy is computed as follows:

```
  Layer 1  ─── Code Requirements ──────────────────────┐
                                                        │
  Layer 2  ─── Instance Binding ───────────────────┐    │  Normalize each
                                                   │    │  layer to a common
  Layer 3  ─── User Consent ──────────────────┐    │    │  policy model
                                              │    │    │
  Layer 4  ─── IT Admin Policy ──────────┐    │    │    │
                                         │    │    │    │
  Layer 5  ─── System Policy ───────┐    │    │    │    │
                                    ▼    ▼    ▼    ▼    ▼
                              ┌─────────────────────────────┐
                              │  Intersection (greatest      │
                              │  lower bound of all          │
                              │  normative inputs)           │
                              └──────────┬──────────────────┘
                                         │
                                   Declared Policy
                                         │
                              ┌──────────▼──────────────────┐
  Layer 6  ─── Security ─────►│  Can the system deliver     │
               Promises       │  these guarantees?          │
                              └──────────┬──────────────────┘
                                         │
                              ┌──────────▼──────────────────┐
  Layer 7  ─── Container ────►│  Can the chosen backend     │
               Capabilities   │  enforce these rules?       │
                              └──────────┬──────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────────────┐
                              │  Realized Policy             │
                              │  + Assurance Level           │
                              │  + Unenforceable Rule Set    │
                              └─────────────────────────────┘
```

The intersection of Layers 1–5 requires **normalization to a common semantic
model**. These layers do not all speak the same language — Layer 1 deals in resource
classes, Layer 2 in concrete instances, Layer 3 in consented grants, Layer 5 in
OS-native controls. If a layer's constraints cannot be translated into the common
model, evaluation must **fail closed** — deny rather than ignore.

### Failure Modes

When layers disagree or enforcement gaps exist, the system must choose a response.
The guiding principle is **fail closed** — when in doubt, deny.

| Situation | Response |
|---|---|
| **Empty intersection** — no access satisfies all layers | Launch denied. The code's requirements cannot be met within the constraints. |
| **Backend cannot enforce a rule** — e.g., BubbleWrap cannot do per-port network filtering | Either reject the launch, compose an additional backend that can (BubbleWrap + iptables), or degrade with an explicit reduction in assurance level. Never silently skip the rule. |
| **System cannot provide promised isolation** — e.g., Landlock unavailable on kernel < 5.13 | Fail closed (refuse to launch) or fall back to a weaker mechanism with a clear assurance downgrade. |
| **User/admin revokes access after compile time** — e.g., user revokes camera permission mid-session | Re-evaluate at access time. The compiled `.sbxp` policy represents a point-in-time snapshot; dynamic consent must be checked at runtime against the live authority. |
| **Layer contradiction** — code requires network but admin policy forbids all network | Launch denied. The code cannot function within the constraints. Surface a clear diagnostic to the user explaining which layers conflict. |

### How This Relates to the JSON Schema (§7) and Compiled Format (§8)

The JSON policy schema in §7 is a **bound deployment policy** — it lives primarily
at Layer 2, with concrete paths, ports, and hosts already specified. The platform
overrides section touches Layer 7 by acknowledging backend-specific knobs.

In a fully layered system, additional artifacts would exist upstream:

| Layer | Artifact |
|---|---|
| Layer 1 | **Requirements manifest** — abstract capability declarations (analogous to Android permissions or UWP capabilities) |
| Layer 2 | **Bound policy** — the current JSON schema (§7), with variables resolved to concrete values |
| Layer 3 | **Consent records** — runtime state tracking user decisions (analogous to macOS TCC database or Android permission grants) |
| Layer 4 | **Admin policy profiles** — organizational constraints distributed via MDM/GPO (consumed as input to the compiler or enforced at launch) |
| Layer 5 | **System security baseline** — queried at runtime, not expressed as an artifact |
| Layer 6 | **Capability probe results** — what the system reports it can do (kernel version, LSM availability, hypervisor presence) |
| Layer 7 | **Backend rule-support matrix** — what the chosen container technology can enforce (drives backend selection and composition) |

The compiled FlatBuffer (`.sbxp`) represents the **realized policy** — the output
of evaluating all layers. It is what the sandbox runtime consumes: a fully resolved,
concrete, enforceable rule set with no remaining variables, authorities, or
capability questions.
