# AF_UNIX support across MXC backends

AF_UNIX sockets are local interprocess-communication channels exposed through
the sockets API. They are not uniformly a filesystem feature or a network
feature:

- a **pathname** socket has a filesystem name, so path visibility and
  permissions matter;
- an **abstract** socket has a kernel-managed name, so filesystem policy cannot
  govern it;
- an **unnamed** socket, normally created with `socketpair()`, has no name to
  authorize.

Consequently, MXC should claim AF_UNIX support per backend and per socket form,
not as one platform-independent boolean.

## What a support claim requires

A backend can claim pathname AF_UNIX support only after all of the following
are true:

1. The sandbox can create, bind, listen, connect, accept, and exchange data
   using the claimed socket types.
2. A pathname under `readwritePaths` supports both server and client use.
3. A pre-existing host listener is reachable only when its path is deliberately
   shared.
4. `readonlyPaths` and `deniedPaths` cannot inherit socket authority from a
   broader grant.
5. Root and interior symlinks cannot turn a narrower deny into a dead rule.
6. AF_UNIX grants do not enable TCP or UDP bind, listen, or egress.
7. Both `network.defaultPolicy: "allow"` and `"block"` preserve the documented
   filesystem behavior.
8. Failures are bounded and leave no socket or helper-process leaks.

Abstract sockets, unnamed sockets, `SOCK_DGRAM`, `SOCK_SEQPACKET`, descriptor
passing, and peer-credential APIs each require separate qualification. Success
with pathname `SOCK_STREAM` does not establish support for any of them.

## macOS Seatbelt

### Enforcement model

Seatbelt distinguishes pathname AF_UNIX operations from IP operations by the
filter attached to the rule:

- `network-bind` with a path filter authorizes AF_UNIX `bind()`;
- `network-outbound` with a path filter authorizes AF_UNIX `connect()` and
  datagram sends;
- `(local ip)` and `(remote ip)` filters govern IP sockets instead.

MXC therefore maps pathname AF_UNIX authority to filesystem policy:

| Filesystem policy | Pathname AF_UNIX effect |
|---|---|
| `readwritePaths` | Allows bind and connect under the subtree |
| `readonlyPaths` | Allows file reads but explicitly denies bind and connect |
| `deniedPaths` | Explicitly denies file and socket operations |

This avoids coupling local IPC to `allowLocalNetwork`, which would grant
unrelated IP ingress. It also means a broad read-write share is a communication
grant: a sandbox can connect to a pre-existing Docker, SSH agent, GPG agent, or
other control socket beneath that share. Sensitive sockets need a narrower
`deniedPaths` entry.

Seatbelt compares filters with kernel-resolved paths. MXC must therefore
canonicalize every existing prefix, preserve a normalized not-yet-existing
tail, and reapply `deny > readonly > readwrite` precedence after physical
resolution. Otherwise an interior symlink can make a deny rule fail open.
Resolution is still a point-in-time operation: callers must not replace an
already-resolved prefix, or introduce a symlink in an absent tail, while the
sandbox is starting.

### Qualified scope

The Seatbelt backend currently qualifies:

- pathname `SOCK_STREAM`;
- pathname `SOCK_DGRAM`;
- unnamed `socketpair(AF_UNIX, SOCK_STREAM)`.

macOS has no Linux abstract AF_UNIX namespace. MXC has not yet qualified
`SOCK_SEQPACKET`, descriptor passing, credential passing, every peer-credential
API, or every possible socket type. Those are outside the support claim even
when Darwin implements some of them.

## Linux

Linux has a broader AF_UNIX implementation than the currently qualified macOS
surface. It supports pathname, abstract, and unnamed sockets;
`SOCK_STREAM`, `SOCK_DGRAM`, and `SOCK_SEQPACKET`; `socketpair()`; descriptor
passing with `SCM_RIGHTS`; and credential exchange. The abstract namespace is a
Linux-specific extension and has no filesystem permissions.

### How MXC's Linux containment differs

Bubblewrap and LXC do not emit a Seatbelt-like socket rule. They primarily
control pathname sockets through mount visibility and ordinary Unix
permissions:

- `readwritePaths` is a read-write bind mount;
- `readonlyPaths` is a read-only bind mount;
- `deniedPaths` is hidden by a mask or omitted from the container.

That is sufficient to make an unshared pathname absent and to permit socket
creation in a writable shared directory, but it does not yet establish the
same contract as Seatbelt. In particular:

- a read-only mount prevents creation or deletion, but connecting to an
  existing socket is a socket operation governed by the socket inode's
  permissions; MXC needs an end-to-end test before claiming that
  `readonlyPaths` always removes connect authority;
- path canonicalization, absent tails, nested rebinds, and masked symlinks must
  be tested with sockets, not inferred from regular-file tests;
- an abstract socket bypasses filesystem policy entirely.

Abstract-socket exposure follows the Linux network namespace. LXC uses a
container network namespace. Bubblewrap uses a private network namespace for
strict block and modern proxy modes, but some allow/legacy modes share the
host network namespace. In a shared namespace, `readonlyPaths` and
`deniedPaths` cannot hide a host abstract socket because it has no path. A
defensible Linux claim must either qualify this as intentional, reject abstract
addresses, or guarantee a private network namespace for the relevant policy.

### Linux qualification gaps

MXC should add backend-specific tests for:

1. pathname stream and datagram traffic under read-write paths;
2. connection to a pre-existing host socket;
3. read-only and denied behavior, including nested and symlinked paths;
4. abstract sockets in both private and shared network namespaces;
5. unnamed stream and datagram `socketpair()` use;
6. `SOCK_SEQPACKET`;
7. `SCM_RIGHTS`, credentials, and peer-credential APIs;
8. proof that AF_UNIX policy does not widen IP networking.

Until those tests exist, Linux has the stronger operating-system substrate but
does not have the same checked-in MXC qualification claim as Seatbelt.

## Windows

### Native AF_UNIX

Windows has a similar native socket family, implemented by `afunix.sys` and
exposed through Winsock. Microsoft introduced it in Windows 10 build 17063.
The documented implementation supports pathname, abstract, and unnamed
addresses, but only `SOCK_STREAM`. It does not document support for
`SOCK_DGRAM`, `SOCK_SEQPACKET`, ancillary data, abstract autobind, or the
Winsock equivalent of `socketpair()`.

A pathname socket is represented by an NTFS reparse point. Microsoft documents
directory write permission for `bind()` and socket-file write permission for
`connect()`. This resembles Linux pathname security, not Seatbelt's explicit
path-filtered `network-bind` and `network-outbound` rules.

### The analogous MXC stack

The closest MXC equivalent is the Windows ProcessContainer stack:

| Concern | macOS Seatbelt | Windows ProcessContainer |
|---|---|---|
| Path access | Seatbelt path filters | BaseContainer policy, AppContainer BFS, or AppContainer/DACL fallback |
| IP networking | Seatbelt IP-filtered network operations | AppContainer capabilities, loopback exemptions, proxy policy, and WFP |
| Pathname AF_UNIX | Explicit path-filtered socket operations | Expected to flow through NTFS/reparse-point access, but not yet qualified by MXC |
| Abstract AF_UNIX | Not implemented by macOS | Implemented by Windows, but has no NTFS path and is not covered by MXC filesystem policy |

MXC cannot claim Windows parity merely because ordinary files and TCP are
covered. The three ProcessContainer filesystem tiers use different enforcement
mechanisms, and AF_UNIX creates and opens a special NTFS reparse point. Each
tier must be tested independently. The relationship between abstract AF_UNIX,
AppContainer identity, and network capabilities must also be measured rather
than inferred from pathname behavior.

Windows Sandbox and IsolationSession are separate containment stacks. A VM
boundary naturally prevents direct access to host pathname or abstract sockets
unless MXC deliberately bridges them, while guest-local Windows AF_UNIX may
still work. That is a different claim from ProcessContainer host IPC and needs
its own guest tests.

Windows named pipes are the traditional analogous IPC mechanism, but they are
not AF_UNIX. They use Windows named-object and pipe security semantics, have a
different API, and cannot substitute for AF_UNIX compatibility tests.

### Windows qualification work

To make a Windows support claim, MXC needs:

1. a minimum supported Windows build and an `afunix.sys` availability probe;
2. pathname `SOCK_STREAM` server/client tests on BaseContainer, BFS, and DACL
   tiers;
3. read-write, read-only, denied, nested-path, and symlink/reparse-point tests;
4. host-listener and sandbox-listener directionality tests;
5. abstract and unnamed-address tests with an explicit policy decision;
6. stale socket reparse-point cleanup and name-reuse tests;
7. proof that AF_UNIX use does not add IP capabilities or loopback exemptions;
8. separate Windows Sandbox and IsolationSession guest-local qualification.

Given Windows' documented socket-type limitations, cross-platform SDKs should
target pathname `SOCK_STREAM` for the common macOS/Linux/Windows subset.
Datagrams, `socketpair()`, abstract names, descriptor passing, and credential
passing require platform-specific fallbacks.

## Current MXC support summary

| Capability | macOS Seatbelt | Linux Bubblewrap/LXC | Windows ProcessContainer |
|---|---|---|---|
| Pathname `SOCK_STREAM` | Qualified | OS-supported; MXC qualification pending | OS-supported; MXC qualification pending |
| Pathname `SOCK_DGRAM` | Qualified | OS-supported; MXC qualification pending | Not documented as supported |
| Unnamed stream `socketpair()` | Qualified | OS-supported; MXC qualification pending | Winsock has no `socketpair()` |
| Abstract namespace | Not available on macOS | Linux-supported; policy depends on network namespace | Windows-supported; MXC policy not qualified |
| `SOCK_SEQPACKET` | Not qualified | Linux-supported; MXC qualification pending | Not documented as supported |
| Descriptor/credential passing | Not qualified | Linux-supported; MXC qualification pending | Not documented as supported |
| Deny beneath broader read-write path | Qualified, including symlinks | Mount machinery exists; socket tests pending | Filesystem tiers exist; socket tests pending |
| Proven not to widen IP access | Qualified | Test pending | Test pending |

## References

- [Linux `unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)
- [AF_UNIX comes to Windows](https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/)
- [AppContainer isolation](https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation)
- [Seatbelt backend](macos-support/seatbelt-backend.md)
- [Bubblewrap backend](bwrap-support/bubblewrap-backend.md)
- [LXC backend](lxc-support/lxc-backend.md)
- [ProcessContainer networking](process-container/networking.md)
