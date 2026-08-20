// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rootless private networking for Bubblewrap proxy mode.

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::unistd::{access, dup2, pipe2, AccessFlags};
use tempfile::TempDir;
use wxc_common::filesystem_resolve::{resolve_mount_order, FsIntent};
use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, ProxyAddress, ProxyHostPin};

use crate::bwrap_command::COMMAND_TAIL;
use crate::network_rules::{
    payload_file_name, render_filter_payloads, EgressPlan, IngressPlan, RuleFamily,
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single `iptables` call may block on the host's `/run/xtables.lock`.
///
/// Only the legacy backend takes that lock, and `nsenter --net` leaves the mount
/// namespace alone, so there it is shared with every other sandbox. Waiting is
/// what makes concurrent provisioning work; the ceiling keeps a wedged lock from
/// hanging startup. `nf_tables` takes no lock and ignores the wait.
const XTABLES_LOCK_WAIT: Duration = Duration::from_secs(5);
/// Lock file the legacy `iptables` backend opens before touching any table.
/// `nf_tables` does not use it. See [`iptables_backend_is_usable`].
const XTABLES_LOCK_PATH: &str = "/run/xtables.lock";
/// Budget for the phase that starts slirp and installs the rules.
///
/// The worst-case lock wait for every transaction plus explicit headroom,
/// because the timer starts in [`ProxyNetworkNamespace::attach`] *before* slirp
/// signals readiness and so also covers slirp startup. A single
/// [`STARTUP_TIMEOUT`] cannot cover this: it would reject a viable sandbox the
/// moment one call waited on a busy host.
///
/// A large policy needs more than one transaction per family, so this scales
/// with the rendered payload count -- but only up to [`RULE_INSTALL_CEILING`].
/// Scaling without a ceiling is what made the previous per-rule budget
/// unusable: a long host list could push startup past any sane bound. The
/// ceiling keeps a wedged host bounded, and it is generous enough that a
/// policy reaching it is contending for the lock rather than merely large.
fn rule_install_timeout(transactions: usize) -> Duration {
    let waits = XTABLES_LOCK_WAIT
        .checked_mul(u32::try_from(transactions).unwrap_or(u32::MAX))
        .unwrap_or(RULE_INSTALL_CEILING);
    waits
        .saturating_add(RULE_INSTALL_HEADROOM)
        .min(RULE_INSTALL_CEILING)
}
/// Slack for slirp startup and process spawn inside [`rule_install_timeout`].
const RULE_INSTALL_HEADROOM: Duration = Duration::from_secs(20);
/// Upper bound on [`rule_install_timeout`], however large the policy is.
const RULE_INSTALL_CEILING: Duration = Duration::from_secs(120);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Ceiling for a single dependency probe. Generous next to a `--version` call,
/// which returns in milliseconds, so only a genuinely wedged binary trips it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SLIRP_HOST_GATEWAY: &str = "10.0.2.2";
/// The gateway as an address, for rules and pins. Kept in step with
/// [`SLIRP_HOST_GATEWAY`] by [`tests::gateway_constants_agree`].
const SLIRP_HOST_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
/// The network slirp gives the sandbox, for diagnostics.
const SLIRP_NETWORK: &str = "10.0.2.0/24";
/// Path the hosts-file pin is mounted over inside the sandbox.
const SANDBOX_HOSTS_PATH: &str = "/etc/hosts";
/// Egress chain installed inside the sandbox's own network namespace.
const EGRESS_CHAIN: &str = "MXC_EGRESS";
/// Chain carrying the inbound posture, hooked into `INPUT`.
const INGRESS_CHAIN: &str = "MXC_INGRESS";
/// Descriptor numbers the supervisor script hardcodes. They must stay single
/// digit and below [`FD_STAGING_BASE`]: dash cannot name a descriptor >= 10 in
/// a redirection, which is the whole reason the parent pins them.
const SUPERVISOR_PID_FD: RawFd = 3;
const SUPERVISOR_EXIT_FD: RawFd = 4;
/// Descriptors are staged above every target before being landed, so a source
/// already sitting on a target cannot be clobbered mid-remap.
const FD_STAGING_BASE: RawFd = 10;
/// Brings up the private network, then closes it down to the proxy before the
/// workload runs.
///
/// Ordering is the security property: the readiness signal is written only
/// after every rule is installed, and `set -e` turns a failed rule into
/// supervisor death rather than an unenforced sandbox. Rules are applied here
/// because that needs `CAP_NET_ADMIN` in the owning user namespace, which the
/// supervisor holds (`--keep-caps`) and the caller does not.
const SUPERVISOR_SCRIPT: &str = r#"
set -eu
state_dir="$1"
lock_wait="$2"
# Inherited descriptors are remapped to fixed numbers by the parent (see
# `remap_descriptors`): 3 is the parent's PID pipe, 4 is slirp's exit pipe.
# They are hardcoded rather than passed in argv because /bin/sh is dash on
# Debian/Ubuntu, which rejects a *variable* descriptor >= 10 ("Bad fd number")
# at parse time -- a failure that depends on how many files the parent happens
# to hold open, so it surfaces nondeterministically and never in unit tests.
printf ready > "$state_dir/userns.ready"
# Block on the parent-owned PID pipe rather than polling for a file: if the
# parent dies before it can publish the PID, the read ends at EOF and this
# supervisor exits instead of spinning forever as an orphan.
if ! IFS= read -r child_pid <&3; then
    child_pid="${child_pid:-}"
fi
exec 3<&-
if [ -z "$child_pid" ]; then
    echo "mxc: parent exited before publishing the sandbox PID" >&2
    exit 1
fi

# slirp signals readiness internally so the supervisor, not slirp, decides when
# the sandbox is ready -- the rules below must be in place first. Descriptor 9
# is safe to hardcode: the parent hands this child exactly 0-4, so nothing else
# can be sitting on it.
exec 9> "$state_dir/slirp.internal"
slirp4netns --configure --mtu=65520 \
    --ready-fd 9 --exit-fd 4 \
    "$child_pid" tap0 &
slirp_pid=$!
trap 'kill "$slirp_pid" 2>/dev/null || true' TERM INT
while [ ! -s "$state_dir/slirp.internal" ]; do
    if ! kill -0 "$slirp_pid" 2>/dev/null; then
        echo "slirp4netns exited before signalling readiness" >&2
        exit 1
    fi
    sleep 0.01
done

ns="/proc/$child_pid/ns/net"
# Network filtering in both directions, programmed here because it needs
# CAP_NET_ADMIN in the owning user namespace, which this supervisor holds
# (`--keep-caps`) and the caller does not.
#
# Each family's rules arrive as one or more `iptables-restore` transactions,
# numbered so this glob applies them in order. Both built-in hooks travel in
# the *last* transaction of a family, so a hook is never live over a partially
# built chain and the rules cannot be observed half-installed. Splitting is
# forced by the kernel: one restore is one bounded netlink transaction, and a
# large host list would otherwise exceed it and install nothing. The payloads
# are rendered in Rust from parsed addresses, so nothing here echoes caller
# text.
#
# -w matters only on the legacy backend, the one that takes a lock: nsenter
# enters the network namespace but not the mount namespace, so concurrent
# sandboxes contend for the *host's* /run/xtables.lock, and set -e turns a lost
# race into a dead supervisor. nf_tables takes no lock and ignores the wait.
# A backend that cannot take the lock at all is refused by probe_dependencies.
# -n keeps the restore additive, so it never clears a table it did not write
# and so a later transaction appends to the chain an earlier one declared.
#
# A rejected transaction applies nothing, so a host that cannot support a rule
# fails closed here rather than starting an unenforced sandbox. The most likely
# cause is worth naming, because iptables reports it only as "Invalid argument".
conntrack_hint="mxc: could not install the sandbox network policy. If the error above says \
'Invalid argument', this host is missing the nf_conntrack kernel module that the inbound \
connection-state match requires, and an unprivileged sandbox cannot load it."
for payload in "$state_dir"/rules.v4.*; do
    nsenter --net="$ns" -- iptables-restore -w "$lock_wait" -n "$payload" || { echo "$conntrack_hint" >&2; exit 1; }
done
for payload in "$state_dir"/rules.v6.*; do
    nsenter --net="$ns" -- ip6tables-restore -w "$lock_wait" -n "$payload" || { echo "$conntrack_hint" >&2; exit 1; }
done

# Signalled by path, not through a descriptor: this is a plain file the parent
# polls, so it needs no shell redirection and cannot hit dash's fd limit.
printf ready > "$state_dir/slirp.ready"
wait "$slirp_pid"
"#;

/// The single destination a proxy-only sandbox may reach.
///
/// The address is IPv4 because the rule is emitted with IPv4 `iptables`. A
/// hostname endpoint is resolved on the host and carried here as its address
/// plus the [`ProxyHostPin`] the sandbox needs to agree with it: DNS is closed
/// inside the sandbox, so a hosts-file pin is the only way the workload can
/// reach a name the firewall has authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyEgress {
    ip: Ipv4Addr,
    port: u16,
    pin: Option<ProxyHostPin>,
}

impl ProxyEgress {
    /// The hosts-file pin the sandbox needs, if the endpoint is a hostname.
    pub(crate) fn pin(&self) -> Option<&ProxyHostPin> {
        self.pin.as_ref()
    }

    /// The filtering posture that opens this endpoint and nothing else.
    pub(crate) fn plan(&self) -> EgressPlan {
        EgressPlan::for_proxy(self.ip, self.port)
    }
}

/// The proxy as the sandbox sees it: the URL handed to the workload, and the
/// single endpoint the egress chain opens for it.
///
/// Both come from one host-side lookup. Resolving twice can disagree -- DNS
/// round-robin reorders, or a TTL expires between the calls -- and a sandbox
/// pinned to an address the chain did not authorize cannot reach its proxy at
/// all.
#[derive(Debug)]
pub(crate) struct SandboxProxy {
    address: ProxyAddress,
    egress: ProxyEgress,
}

impl SandboxProxy {
    /// Derive the sandbox-visible proxy from the configured one.
    ///
    /// A hostname keeps its URL and is pinned, rather than being rewritten to
    /// an address: the workload then presents the `Host` header and proxy-auth
    /// realm the operator configured. An IP literal has no name to pin, so a
    /// loopback literal is rewritten to slirp's gateway instead.
    pub(crate) fn resolve(configured: &ProxyAddress) -> Result<Self, String> {
        Self::resolve_with(configured, resolve_ipv4)
    }

    /// Apply every rejection [`Self::resolve`] can reach without a lookup.
    ///
    /// A hostname's verdict depends on what it resolves to, and that answer is
    /// also the pin the sandbox is given -- so it has to come from the single
    /// lookup `run` performs, not from a second one here. Deferring is detected
    /// rather than predicted: the injected resolver records that it was asked.
    pub(crate) fn check_without_resolving(configured: &ProxyAddress) -> Result<(), String> {
        let (needs_lookup, checked) = Self::inspect_without_resolving(configured);
        if needs_lookup {
            return Ok(());
        }
        checked
    }

    /// Run the static checks, reporting whether a lookup would have followed.
    ///
    /// A lookup is needed exactly when the endpoint is a hostname, which is
    /// also exactly when a hosts pin is created -- an IP literal resolves to
    /// `Ok(None)` from [`ProxyAddress::host_pin`]. Callers use the flag to
    /// reason about the pin without duplicating that classification.
    fn inspect_without_resolving(configured: &ProxyAddress) -> (bool, Result<(), String>) {
        let asked_to_resolve = Cell::new(false);
        let checked = Self::resolve_with(configured, |_, _| {
            asked_to_resolve.set(true);
            Err(String::new())
        });

        (asked_to_resolve.get(), checked.map(|_| ()))
    }

    /// [`Self::resolve`] against an injected resolver.
    ///
    /// Resolution is the one step that depends on the host's DNS, so it is a
    /// parameter: the decisions layered on top of it are then testable without
    /// a lookup whose answer the test does not control.
    fn resolve_with(
        configured: &ProxyAddress,
        resolve: impl Fn(&str, u16) -> Result<Ipv4Addr, String>,
    ) -> Result<Self, String> {
        if configured.port() == 0 {
            return Err("Bubblewrap: proxy-only egress requires a non-zero proxy port".to_string());
        }
        let host = configured.host().trim_matches(['[', ']']);

        // `localhost` is reserved to loopback (RFC 6761), so it is rewritten
        // rather than pinned. A pin is a sandbox-wide mapping: pointing this
        // name at the gateway would redirect the workload's own loopback
        // traffic to the host.
        let is_reserved_loopback_name = host.eq_ignore_ascii_case("localhost");

        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            // A literal cannot be pinned, so loopback and the wildcard are
            // reached by rewriting the URL to the address slirp maps back to
            // the host. `0.0.0.0` names the host just as `127.0.0.1` does.
            return if ip.is_loopback() || ip.is_unspecified() {
                Ok(Self::rewritten(configured)?)
            } else {
                reject_slirp_reserved(ip, host)?;
                Ok(Self {
                    address: configured.clone(),
                    egress: ProxyEgress {
                        ip,
                        port: configured.port(),
                        pin: None,
                    },
                })
            };
        }

        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            // A dual-stack wildcard listener accepts the gateway's IPv4
            // connection, so `::` can be rewritten. `::1` cannot: it listens
            // on the IPv6 loopback only, so the rewrite would hand the sandbox
            // an address nothing answers on -- failing at connect time rather
            // than at policy time.
            if ip.is_unspecified() {
                return Self::rewritten(configured);
            }
            if ip.is_loopback() {
                return Err(format!(
                    "Bubblewrap: proxy address '{}' uses the IPv6 loopback, which the private \
                     network namespace cannot reach; bind the proxy to 127.0.0.1 or a dual-stack \
                     wildcard address instead. The egress rule is emitted with IPv4 iptables.",
                    configured.host()
                ));
            }
            return Err(ipv6_unsupported(host));
        }

        if is_reserved_loopback_name {
            return Self::rewritten(configured);
        }

        let resolved = resolve(host, configured.port())?;
        reject_slirp_reserved(resolved, host)?;
        let ip = sandbox_facing_ip(resolved);
        let pin = configured
            .host_pin(IpAddr::V4(ip))
            .map_err(|error| format!("Bubblewrap: {error}"))?;

        Ok(Self {
            address: configured.clone(),
            egress: ProxyEgress {
                ip,
                port: configured.port(),
                pin,
            },
        })
    }

    /// The proxy reached by rewriting its URL to slirp's gateway.
    fn rewritten(configured: &ProxyAddress) -> Result<Self, String> {
        Ok(Self {
            address: rewrite_to_gateway(configured)?,
            egress: ProxyEgress {
                ip: SLIRP_HOST_GATEWAY_IP,
                port: configured.port(),
                pin: None,
            },
        })
    }

    /// The proxy URL the workload is given.
    pub(crate) fn address(&self) -> &ProxyAddress {
        &self.address
    }

    /// The endpoint the egress chain opens.
    pub(crate) fn egress(&self) -> &ProxyEgress {
        &self.egress
    }
}

/// The address the sandbox reaches a host-resolved endpoint at.
///
/// slirp gives the sandbox its own loopback, so a name that resolves to the
/// host's loopback is pinned to the gateway instead: pinning it verbatim would
/// aim the workload at itself. `0.0.0.0` is an answer `/etc/hosts` can produce
/// and names the host the same way, so it is translated alongside loopback --
/// matching the IP-literal path, which rewrites both.
fn sandbox_facing_ip(resolved: Ipv4Addr) -> Ipv4Addr {
    if resolved.is_loopback() || resolved.is_unspecified() {
        SLIRP_HOST_GATEWAY_IP
    } else {
        resolved
    }
}

/// Reject an endpoint the host resolved into the sandbox's own slirp network.
///
/// Every address in [`SLIRP_NETWORK`] is on-link inside the namespace, so it
/// does not name the machine the host meant: [`SLIRP_HOST_GATEWAY`] is the
/// route to host loopback, `.100` is the sandbox itself, and the rest have no
/// neighbour at all. Opening the gateway is the sharp case -- the egress rule
/// would grant the workload an unrelated host-loopback service on the proxy
/// port. Applied to what the host answered, so the deliberate loopback and
/// wildcard translations in [`sandbox_facing_ip`] still reach the gateway.
fn reject_slirp_reserved(resolved: Ipv4Addr, host: &str) -> Result<(), String> {
    if !SLIRP_NETWORK_OCTETS.eq(&resolved.octets()[..3]) {
        return Ok(());
    }
    Err(format!(
        "Bubblewrap: proxy endpoint '{host}' is {resolved}, which is inside the sandbox's own \
         network ({SLIRP_NETWORK}); there that address is slirp's own, not the host's \
         {resolved}, so the egress rule would open an unrelated service. Bind the proxy to \
         127.0.0.1 -- which is translated to the gateway deliberately -- or give it an address \
         outside {SLIRP_NETWORK}."
    ))
}

/// Leading octets of [`SLIRP_NETWORK`], asserted against it by
/// [`tests::gateway_constants_agree`].
const SLIRP_NETWORK_OCTETS: [u8; 3] = [10, 0, 2];

/// Bound on the host lookup performed by [`resolve_ipv4`].
///
/// Sized so a resolver whose first nameserver is dead still answers: glibc
/// defaults to a 5s timeout with 2 attempts per server, so a single failed
/// server costs ~10s before the next is tried. A black-holed resolver would
/// otherwise run to ~30s or more across three servers.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Thread name for the lookup [`resolve_ipv4`] bounds.
const RESOLVE_TIMEOUT_LABEL: &str = "mxc-proxy-resolve";

/// Run `work` on its own thread and wait at most `timeout` for its answer.
///
/// Used for calls that cannot be cancelled: on expiry the thread is abandoned
/// and its result discarded, which bounds the caller's wait even though the
/// work itself runs to completion. `label` names the thread for diagnostics.
fn with_deadline<T: Send + 'static>(
    label: &str,
    timeout: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<Result<T, mpsc::RecvTimeoutError>, std::io::Error> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name(label.to_string())
        .spawn(move || {
            // Abandoned on expiry: the receiver is gone, so this send fails
            // and the answer is discarded rather than blocking the thread.
            let _ = sender.send(work());
        })?;

    Ok(receiver.recv_timeout(timeout))
}

/// Resolve `host` to the address the egress chain will open, without waiting
/// on the resolver indefinitely.
///
/// This runs during setup, before the sandbox starts, so it is outside the
/// script timeout: an unbounded lookup would stall a run that never began.
/// `getaddrinfo` cannot be cancelled, so the lookup is moved to a thread and
/// abandoned once the bound expires -- the wait is bounded even though the
/// query itself keeps running until the resolver gives up.
fn resolve_ipv4(host: &str, port: u16) -> Result<Ipv4Addr, String> {
    let query = host.to_string();
    let waited = with_deadline(RESOLVE_TIMEOUT_LABEL, RESOLVE_TIMEOUT, move || {
        lookup_ipv4(&query, port)
    })
    .map_err(|error| {
        format!("Bubblewrap: could not start the lookup of proxy host '{host}': {error}")
    })?;

    match waited {
        Ok(resolved) => resolved,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "Bubblewrap: resolving proxy host '{host}' exceeded {}s. The proxy endpoint is \
             resolved on the host because DNS is closed inside the sandbox, so an unresponsive \
             host resolver blocks the sandbox from starting. Check the host's DNS configuration, \
             or give the proxy as an IPv4 address to skip resolution.",
            RESOLVE_TIMEOUT.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
            "Bubblewrap: the lookup of proxy host '{host}' ended without an answer."
        )),
    }
}

/// The blocking lookup behind [`resolve_ipv4`].
///
/// Only the first IPv4 answer is used, and it is the same one the sandbox is
/// pinned to. Opening the rest would widen the chain to addresses the sandbox
/// can no longer select: with DNS closed, the pin is its only resolution path.
fn lookup_ipv4(host: &str, port: u16) -> Result<Ipv4Addr, String> {
    let resolved: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| {
            format!(
                "Bubblewrap: could not resolve proxy host '{host}': {error}. The proxy endpoint \
                 is resolved on the host because DNS is closed inside the sandbox."
            )
        })?
        .map(|addr| addr.ip())
        .collect();

    if let Some(IpAddr::V4(ip)) = resolved.iter().find(|ip| ip.is_ipv4()) {
        return Ok(*ip);
    }

    // A name with AAAA records and no A records is the same unenforceable case
    // as an IPv6 literal, so say so rather than claiming it does not resolve.
    if resolved.is_empty() {
        Err(format!(
            "Bubblewrap: proxy host '{host}' did not resolve to any address."
        ))
    } else {
        Err(ipv6_unsupported(host))
    }
}

/// The error for an endpoint that only IPv6 can reach.
fn ipv6_unsupported(host: &str) -> String {
    format!(
        "Bubblewrap: proxy-only egress requires an IPv4 proxy endpoint, but '{host}' is reachable \
         over IPv6 only. The egress rule is emitted with IPv4 iptables, so an IPv6 endpoint would \
         be silently dropped. Use an IPv4 proxy address."
    )
}

/// Runtime file descriptors Bubblewrap needs while establishing its child.
pub(crate) struct BwrapStartup {
    info_reader: File,
    info_writer: Option<OwnedFd>,
    gate_reader: Option<OwnedFd>,
    gate_writer: Option<OwnedFd>,
    /// Descriptors bwrap must inherit, cleared of `FD_CLOEXEC` in the child
    /// only. See [`inherit_descriptors`].
    inheritable: Vec<RawFd>,
}

impl BwrapStartup {
    /// Arrange for bwrap -- and only bwrap -- to inherit the startup
    /// descriptors.
    pub(crate) fn prepare_command(&self, command: &mut Command) {
        inherit_descriptors(command, self.inheritable.clone());
    }

    /// Close the parent copies of the descriptors inherited by Bubblewrap.
    pub(crate) fn child_spawned(&mut self) {
        self.info_writer.take();
        self.gate_reader.take();
    }

    /// Wait for Bubblewrap to report the host-visible PID of its sandbox child.
    pub(crate) fn child_pid(&mut self, child: &mut Child) -> Result<u32, String> {
        set_nonblocking(self.info_reader.as_raw_fd())?;
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut json = Vec::new();
        let mut chunk = [0_u8; 512];

        loop {
            match self.info_reader.read(&mut chunk) {
                Ok(0) => {}
                Ok(count) => json.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => {
                    return Err(format!(
                        "Bubblewrap: failed to read bwrap child information: {error}"
                    ));
                }
            }

            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&json) {
                if let Some(pid) = value.get("child-pid").and_then(|pid| pid.as_u64()) {
                    return u32::try_from(pid).map_err(|_| {
                        format!("Bubblewrap: bwrap reported an out-of-range child PID: {pid}")
                    });
                }
                return Err(format!(
                    "Bubblewrap: bwrap child information omitted 'child-pid': {value}"
                ));
            }

            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("Bubblewrap: failed to inspect bwrap startup: {error}"))?
            {
                return Err(format!(
                    "Bubblewrap: bwrap exited before publishing child information ({status})"
                ));
            }
            if Instant::now() >= deadline {
                return Err("Bubblewrap: timed out waiting for bwrap child information".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Allow Bubblewrap to execute the workload after networking is ready.
    pub(crate) fn release(mut self) -> Result<(), String> {
        let writer = self
            .gate_writer
            .take()
            .ok_or_else(|| "Bubblewrap: workload startup gate is already closed".to_string())?;
        File::from(writer)
            .write_all(&[1])
            .map_err(|error| format!("Bubblewrap: failed to release workload startup: {error}"))
    }
}

/// A same-UID user-namespace supervisor and its `slirp4netns` process.
pub(crate) struct ProxyNetworkNamespace {
    state_dir: TempDir,
    supervisor: Child,
    exit_writer: Option<OwnedFd>,
    /// Write end of the pipe carrying the sandbox PID to the supervisor.
    /// Dropping it without writing ends the supervisor's wait at EOF.
    pid_writer: Option<OwnedFd>,
    /// Handle to the supervisor's user namespace, passed to bwrap as
    /// `--userns`. Released once bwrap owns it; see [`Self::userns_handed_off`].
    userns: Option<File>,
    /// Hosts file mounted over `/etc/hosts`, when the endpoint is a hostname.
    hosts: Option<PathBuf>,
    /// Restore transactions the supervisor will apply, which sizes the
    /// readiness budget in [`Self::attach`].
    transactions: usize,
}

impl ProxyNetworkNamespace {
    /// Create the capability-retaining namespace supervisor.
    ///
    /// `plan` is the outbound filtering posture the sandbox runs under once the
    /// supervisor signals readiness; anything it does not accept is dropped.
    /// `ingress` is the matching inbound posture. `pin` is the hosts-file entry
    /// the sandbox needs to agree with the plan, which only a hostname proxy
    /// endpoint produces.
    ///
    /// Callers reach this only after `BwrapRunner::validate` has already run
    /// [`probe_dependencies`], so the probe is not repeated here.
    pub(crate) fn start(
        plan: &EgressPlan,
        ingress: &IngressPlan,
        pin: Option<&ProxyHostPin>,
        logger: &mut Logger,
    ) -> Result<Self, String> {
        let state_dir = tempfile::Builder::new()
            .prefix("mxc-bwrap-proxy-")
            .tempdir()
            .map_err(|error| {
                format!("Bubblewrap: failed to create proxy-network state: {error}")
            })?;
        // Written before the supervisor is spawned: the script reads them
        // during startup, so a missing or partial file must not be possible.
        // A family renders to as many transactions as its size needs; the
        // supervisor applies them in name order.
        let mut transactions = 0usize;
        for family in [RuleFamily::V4, RuleFamily::V6] {
            let payloads =
                render_filter_payloads(plan, ingress, family, EGRESS_CHAIN, INGRESS_CHAIN);
            transactions += payloads.len();
            for (index, payload) in payloads.iter().enumerate() {
                let path = state_dir
                    .path()
                    .join(payload_file_name(family, index, payloads.len()));
                std::fs::write(&path, payload).map_err(|error| {
                    format!("Bubblewrap: failed to write network rules to {path:?}: {error}")
                })?;
            }
        }
        let stderr_path = state_dir.path().join("supervisor.stderr");
        let stderr = File::create(&stderr_path).map_err(|error| {
            format!("Bubblewrap: failed to create proxy-network diagnostics: {error}")
        })?;
        let (exit_reader, exit_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;
        let (pid_reader, pid_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;

        let mut command = Command::new("unshare");
        command
            .args([
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--",
                "sh",
                "-c",
                SUPERVISOR_SCRIPT,
                "mxc-bwrap-proxy-supervisor",
            ])
            .arg(state_dir.path())
            .arg(XTABLES_LOCK_WAIT.as_secs().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        // Both pipes stay CLOEXEC in this process, so a concurrent spawn from
        // another thread cannot inherit them; only the supervisor gets them,
        // and only at the fixed numbers its script names.
        remap_descriptors(
            &mut command,
            [
                (pid_reader.as_raw_fd(), SUPERVISOR_PID_FD),
                (exit_reader.as_raw_fd(), SUPERVISOR_EXIT_FD),
            ],
        );

        let mut supervisor = command.spawn().map_err(|error| {
            format!("Bubblewrap: failed to start proxy-network supervisor: {error}")
        })?;
        drop(exit_reader);
        drop(pid_reader);

        if let Err(error) = wait_for_file(
            state_dir.path().join("userns.ready"),
            &mut supervisor,
            &stderr_path,
            "user namespace startup",
            STARTUP_TIMEOUT,
        ) {
            terminate_child(&mut supervisor);
            return Err(error);
        }

        let userns_path = format!("/proc/{}/ns/user", supervisor.id());
        let userns = match File::open(&userns_path) {
            Ok(file) => file,
            Err(error) => {
                terminate_child(&mut supervisor);
                return Err(format!(
                    "Bubblewrap: failed to open proxy user namespace {userns_path}: {error}"
                ));
            }
        };
        logger.log_line("Bubblewrap: created rootless proxy network namespace supervisor");

        let hosts = match pin {
            Some(pin) => {
                let path = state_dir.path().join("hosts");
                if let Err(error) = write_pinned_hosts(&path, pin) {
                    terminate_child(&mut supervisor);
                    return Err(error);
                }
                logger.log_line(&format!(
                    "Bubblewrap: pinned proxy host '{}' to {} for the sandbox",
                    pin.hostname(),
                    pin.ip()
                ));
                Some(path)
            }
            None => None,
        };

        Ok(Self {
            state_dir,
            supervisor,
            exit_writer: Some(exit_writer),
            pid_writer: Some(pid_writer),
            userns: Some(userns),
            hosts,
            transactions,
        })
    }

    /// Add the dynamic namespace and startup-barrier descriptors to bwrap.
    pub(crate) fn configure_bwrap(
        &self,
        args: &mut Vec<String>,
        logger: &mut Logger,
    ) -> Result<BwrapStartup, String> {
        let (info_reader, info_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;
        let (gate_reader, gate_writer) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| format!("Bubblewrap: pipe failed: {error}"))?;

        let userns = self
            .userns
            .as_ref()
            .ok_or_else(|| "Bubblewrap: proxy user namespace is already handed off".to_string())?;

        if let Some(hosts) = &self.hosts {
            let path = hosts
                .to_str()
                .ok_or_else(|| "Bubblewrap: proxy hosts pin path is not valid UTF-8".to_string())?;
            if insert_hosts_bind(args, path)? {
                logger.log_line(
                    "Bubblewrap: the proxy host pin overrides an earlier mount of \
                     /etc/hosts; the sandbox sees the pinned file",
                );
            }
        }

        let runtime_args = [
            "--userns".to_string(),
            userns.as_raw_fd().to_string(),
            "--info-fd".to_string(),
            info_writer.as_raw_fd().to_string(),
            "--block-fd".to_string(),
            gate_reader.as_raw_fd().to_string(),
        ];
        args.splice(0..0, runtime_args);

        Ok(BwrapStartup {
            inheritable: vec![
                userns.as_raw_fd(),
                info_writer.as_raw_fd(),
                gate_reader.as_raw_fd(),
            ],
            info_reader: File::from(info_reader),
            info_writer: Some(info_writer),
            gate_reader: Some(gate_reader),
            gate_writer: Some(gate_writer),
        })
    }

    /// Drop this process's handle to the user namespace once bwrap holds it.
    ///
    /// The namespace itself stays alive through the supervisor, which is a
    /// member of it. Releasing here bounds the window in which a concurrent
    /// spawn could pick the descriptor up to the bwrap spawn itself, rather
    /// than the whole sandbox lifetime.
    pub(crate) fn userns_handed_off(&mut self) {
        self.userns.take();
    }

    /// Give the supervisor the Bubblewrap child PID and wait for slirp readiness.
    pub(crate) fn attach(&mut self, child_pid: u32, logger: &mut Logger) -> Result<(), String> {
        let mut writer = self
            .pid_writer
            .take()
            .map(File::from)
            .ok_or_else(|| "Bubblewrap: sandbox PID was already published".to_string())?;
        writer
            .write_all(format!("{child_pid}\n").as_bytes())
            .map_err(|error| format!("Bubblewrap: failed to publish bwrap child PID: {error}"))?;
        drop(writer);

        wait_for_file(
            self.state_dir.path().join("slirp.ready"),
            &mut self.supervisor,
            &self.state_dir.path().join("supervisor.stderr"),
            // Names both phases: this signal is written after slirp is up *and*
            // every egress rule is installed, so attributing a stall to
            // slirp alone would send the reader to the wrong place.
            "slirp4netns startup and egress rule installation",
            rule_install_timeout(self.transactions),
        )?;
        logger.log_line(
            "Bubblewrap: slirp4netns configured the private network namespace and the egress \
             rules are in force",
        );
        Ok(())
    }

    /// Stop slirp and reap the namespace supervisor.
    pub(crate) fn stop(&mut self, logger: &mut Logger) {
        // Release the PID pipe too: a supervisor still waiting for the sandbox
        // PID sees EOF and exits rather than lingering.
        self.pid_writer.take();
        self.exit_writer.take();
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match self.supervisor.try_wait() {
                Ok(Some(status)) => {
                    // A clean teardown closes the exit pipe and slirp leaves
                    // with success. Anything else means it died on its own --
                    // and since slirp carries the sandbox's only route, that
                    // is otherwise indistinguishable from the workload's own
                    // network calls failing. Say so, with whatever it wrote.
                    if !status.success() {
                        logger.log_line(&format!(
                            "WARNING: Bubblewrap: proxy network supervisor exited with {status} \
                             ({})",
                            stderr_detail(&self.state_dir.path().join("supervisor.stderr"))
                        ));
                    }
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    logger.log_line(&format!(
                        "WARNING: Bubblewrap: slirp4netns did not stop promptly; terminating it \
                         ({})",
                        stderr_detail(&self.state_dir.path().join("supervisor.stderr"))
                    ));
                    terminate_child(&mut self.supervisor);
                    return;
                }
                Err(error) => {
                    logger.log_line(&format!(
                        "WARNING: Bubblewrap: failed to inspect slirp4netns shutdown: {error}"
                    ));
                    terminate_child(&mut self.supervisor);
                    return;
                }
            }
        }
    }
}

impl Drop for ProxyNetworkNamespace {
    fn drop(&mut self) {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.stop(&mut logger);
    }
}

/// Rewrite a loopback or wildcard proxy URL to slirp's host gateway.
///
/// Only IP literals reach here. A hostname is pinned instead, so that the URL
/// the workload receives is the one the operator configured.
fn rewrite_to_gateway(address: &ProxyAddress) -> Result<ProxyAddress, String> {
    if let Some(original_url) = &address.original_url {
        let mut url = url::Url::parse(original_url).map_err(|error| {
            format!("Bubblewrap: failed to translate proxy URL for private networking: {error}")
        })?;
        url.set_host(Some(SLIRP_HOST_GATEWAY)).map_err(|_| {
            "Bubblewrap: failed to translate proxy URL host for private networking".to_string()
        })?;
        return Ok(ProxyAddress::from_url(
            url.as_str(),
            SLIRP_HOST_GATEWAY.to_string(),
            address.port(),
        ));
    }

    Ok(ProxyAddress::new(
        SLIRP_HOST_GATEWAY.to_string(),
        address.port(),
    ))
}

/// Outcome of a bounded dependency probe.
#[derive(Debug)]
struct ProbeOutput {
    status: ExitStatus,
    stdout: String,
}

/// Run `command` to completion, killing it if it outlives [`PROBE_TIMEOUT`].
///
/// `Command::output()` waits forever. These probes run inside `validate`, so a
/// single wedged binary would stall every proxy-mode execution on the host with
/// no diagnostic -- a hang is far harder to chase than a failure, so bound it
/// and name the tool that stalled.
///
/// stdout is collected only after the child exits. That is safe for probes that
/// print a version banner or a help page (kilobytes, against a 64 KiB pipe
/// buffer); a probe whose output could fill the pipe would deadlock against
/// this wait and must drain the pipe concurrently instead.
fn run_probe(mut command: Command, label: &str) -> Result<ProbeOutput, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{error}"))?;

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                // Leaving it running would keep the pipe open and strand the
                // process for the lifetime of the host process.
                terminate_child(&mut child);
                return Err(format!(
                    "Bubblewrap: '{label}' did not respond within {PROBE_TIMEOUT:?}; \
                     the host's {label} installation appears to be hung"
                ));
            }
            Err(error) => {
                terminate_child(&mut child);
                return Err(format!("failed to inspect '{label}': {error}"));
            }
        }
    };

    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    Ok(ProbeOutput { status, stdout })
}

/// Write the sandbox's `/etc/hosts`: the pin, then the host's own entries with
/// every competing mapping for the pinned name removed.
///
/// Ordering alone is *not* enough, which is why the name is stripped rather
/// than merely outranked. glibc's `files` backend collects **every** line that
/// matches a name and hands the whole set to `getaddrinfo`, which then re-sorts
/// it by RFC 6724 destination-address rules. Those rules promote a loopback
/// address above a global one, so a leftover `127.0.0.1 <proxy>` entry is
/// returned *ahead* of a pin written on line 1. A client walking the result in
/// order then dials an address the egress chain never authorized -- or, worse,
/// dials back into the sandbox's own loopback.
///
/// The host's other entries are kept so the sandbox retains the mappings a
/// workload expects (`localhost` above all). They are read before the file is
/// created, so a read failure cannot leave a half-written pin behind.
fn write_pinned_hosts(path: &Path, pin: &ProxyHostPin) -> Result<(), String> {
    // The host file is optional: a host without one simply contributes no
    // entries, which is not a reason to refuse to pin.
    let existing = match fs::read_to_string(SANDBOX_HOSTS_PATH) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "Bubblewrap: failed to read {SANDBOX_HOSTS_PATH} while pinning the proxy host: \
                 {error}"
            ))
        }
    };

    let contents = format!(
        "{}\n{}",
        pin.hosts_line(),
        strip_host_from_hosts(&existing, pin.hostname())
    );
    fs::write(path, contents)
        .map_err(|error| format!("Bubblewrap: failed to write the proxy hosts pin: {error}"))
}

/// Remove `hostname` from every entry in a hosts file, dropping a line that has
/// no names left.
///
/// Only the name is removed, never the whole line: an entry like
/// `127.0.0.1 localhost <proxy>` still has to keep resolving `localhost`.
/// Comments and blank lines pass through untouched so the sandbox's file stays
/// recognizable, and a trailing comment on a mapping line is preserved.
///
/// Matching is ASCII-case-insensitive because DNS names are, so a host file
/// spelling the proxy name in a different case would otherwise survive and
/// reintroduce exactly the competing mapping this removes.
fn strip_host_from_hosts(contents: &str, hostname: &str) -> String {
    let mut out = String::with_capacity(contents.len());
    for line in contents.lines() {
        let (body, comment) = match line.split_once('#') {
            Some((body, comment)) => (body, Some(comment)),
            None => (line, None),
        };

        let mut fields = body.split_whitespace();
        let Some(address) = fields.next() else {
            out.push_str(line);
            out.push('\n');
            continue;
        };

        // Lines that never mention the pinned name are passed through byte for
        // byte. Rewriting them would normalize the operator's tabs and column
        // alignment for no benefit.
        let names: Vec<&str> = fields.collect();
        if !names.iter().any(|name| name.eq_ignore_ascii_case(hostname)) {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let kept: Vec<&str> = names
            .into_iter()
            .filter(|name| !name.eq_ignore_ascii_case(hostname))
            .collect();

        // Every name on the line was the pinned one, so the mapping is gone.
        // Keep a trailing comment rather than silently deleting the operator's
        // text along with the entry.
        if kept.is_empty() {
            if let Some(comment) = comment {
                out.push('#');
                out.push_str(comment);
                out.push('\n');
            }
            continue;
        }

        out.push_str(address);
        for name in kept {
            out.push(' ');
            out.push_str(name);
        }
        if let Some(comment) = comment {
            out.push_str(" #");
            out.push_str(comment);
        }
        out.push('\n');
    }
    out
}

/// Reject a hostname endpoint whose pin would defeat a denied `/etc/hosts`.
///
/// The pin is spliced after every filesystem-policy mount so it survives them
/// (see [`insert_hosts_bind`]), which means it would also survive a denial --
/// handing back a readable file, populated from the host's own `/etc/hosts`,
/// that the policy asked to mask. Refusing at policy time is the only honest
/// outcome: dropping the pin instead would leave the proxy name unresolvable
/// and fail at connect time, long after the caller could act on it.
///
/// Only a denial is refused. A `readonlyPaths` or `readwritePaths` entry is
/// still overridden with a warning: shadowing a mount the caller asked to
/// *read* narrows their access rather than widening it.
pub(crate) fn check_hosts_pin_against_policy(
    configured: &ProxyAddress,
    policy: &ContainerPolicy,
) -> Result<(), String> {
    let (needs_pin, _) = SandboxProxy::inspect_without_resolving(configured);
    if !needs_pin || !hosts_file_is_denied(policy) {
        return Ok(());
    }

    Err(format!(
        "Bubblewrap: the proxy endpoint '{}' is a hostname, which is reached by pinning it in \
         the sandbox's {SANDBOX_HOSTS_PATH}, but the filesystem policy denies that path. The pin \
         is applied after every policy mount, so honouring it would expose the file the policy \
         masks. Remove {SANDBOX_HOSTS_PATH} from deniedPaths, or give the proxy an IP address, \
         which needs no pin.",
        configured.host()
    ))
}

/// Whether the filesystem policy masks the sandbox's hosts file.
///
/// The plan is ordered shallow-to-deep and bwrap applies the last mount at a
/// path, so the deepest entry covering the file is the one that takes effect:
/// an ancestor denial counts, and a more specific grant beneath it wins back.
fn hosts_file_is_denied(policy: &ContainerPolicy) -> bool {
    resolve_mount_order(policy)
        .iter()
        .rfind(|mount| covers_hosts_file(&mount.path))
        .is_some_and(|mount| mount.intent == FsIntent::Denied)
}

/// Whether `path` is the sandbox hosts file or a directory holding it.
fn covers_hosts_file(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == SANDBOX_HOSTS_PATH
        || SANDBOX_HOSTS_PATH
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Splice the pinned-hosts bind in just before the command separator.
///
/// bwrap applies mounts in argument order and the last mount at a path wins,
/// so the bind must come after every baseline and user-policy mount for the
/// pin to survive -- including one that would otherwise expose the host's own
/// `/etc/hosts`. Returns `true` when an earlier mount already targeted
/// `/etc/hosts`, so the caller can report that the pin overrides it.
/// Index of the separator that ends bwrap's options and begins the command.
///
/// Scanning for the first `--` would find a caller-controlled value instead:
/// `process.env` of `FOO=--` is emitted as `--setenv FOO --` ahead of the real
/// separator, and splicing there would shift the pin's three arguments into
/// that option's operands. Scanning for the *last* one is no better -- the
/// script is arbitrary text. The command is appended last with a fixed shape,
/// so that trailing shape is what identifies it.
fn command_separator(args: &[String]) -> Result<usize, String> {
    args.len()
        .checked_sub(COMMAND_TAIL.len() + 1)
        .filter(|&separator| args[separator..separator + COMMAND_TAIL.len()] == COMMAND_TAIL[..])
        .ok_or_else(|| "Bubblewrap: argument list has no command separator".to_string())
}

fn insert_hosts_bind(args: &mut Vec<String>, hosts_path: &str) -> Result<bool, String> {
    let separator = command_separator(args)?;
    let overrides = args[..separator]
        .iter()
        .any(|arg| arg == SANDBOX_HOSTS_PATH);
    args.splice(
        separator..separator,
        [
            "--ro-bind".to_string(),
            hosts_path.to_string(),
            SANDBOX_HOSTS_PATH.to_string(),
        ],
    );
    Ok(overrides)
}

/// What pulled this request into a private network namespace.
///
/// The dependency probe is shared by proxy-only egress and firewall
/// enforcement, but the remedy it should suggest is not: telling a caller who
/// set `enforcementMode: "firewall"` to "omit network.proxy" names a field they
/// never set. Carries the caller's own words into every probe message.
///
/// The two are mutually exclusive — the parser rejects a proxy combined with a
/// firewall mode — so a request always maps to exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateNetworkUse {
    ProxyOnlyEgress,
    FirewallEnforcement,
}

impl PrivateNetworkUse {
    /// The config element that made the private namespace necessary.
    fn requirement(self) -> &'static str {
        match self {
            Self::ProxyOnlyEgress => "network.proxy",
            Self::FirewallEnforcement => "network.enforcementMode='firewall'",
        }
    }

    /// What the caller can drop to stop needing these dependencies.
    fn remedy(self) -> &'static str {
        match self {
            Self::ProxyOnlyEgress => "omit network.proxy",
            Self::FirewallEnforcement => "select a different network.enforcementMode",
        }
    }

    /// The mechanism the installed rules implement.
    fn mechanism(self) -> &'static str {
        match self {
            Self::ProxyOnlyEgress => "proxy-only egress",
            Self::FirewallEnforcement => "firewall enforcement",
        }
    }
}

pub(crate) fn probe_dependencies(use_case: PrivateNetworkUse) -> Result<(), String> {
    // Probing costs five subprocess spawns, and the host's tooling does not
    // change under a running process often enough to pay that on every
    // sandbox. Cache the *success* only: a failure is usually "the operator
    // has not installed slirp4netns yet", and caching that would keep failing
    // long after they did.
    //
    // Caching across use cases is safe because the probe asks the same
    // questions either way -- only the wording of a failure differs, and
    // failures are never cached.
    static PROBED: OnceLock<()> = OnceLock::new();
    if PROBED.get().is_some() {
        return Ok(());
    }
    probe_dependencies_uncached(use_case)?;
    let _ = PROBED.set(());
    Ok(())
}

fn probe_dependencies_uncached(use_case: PrivateNetworkUse) -> Result<(), String> {
    let requirement = use_case.requirement();
    let mut slirp_command = Command::new("slirp4netns");
    slirp_command.arg("--version");
    let slirp = run_probe(slirp_command, "slirp4netns").map_err(|error| {
        format!(
            "Bubblewrap: {requirement} requires 'slirp4netns' on PATH: {error}. \
             Install slirp4netns or {}.",
            use_case.remedy()
        )
    })?;
    if !slirp.status.success() {
        return Err(format!(
            "Bubblewrap: {requirement} requires a working slirp4netns installation \
             (slirp4netns --version exited with {})",
            slirp.status
        ));
    }

    let mut unshare_command = Command::new("unshare");
    unshare_command.arg("--help");
    let unshare = run_probe(unshare_command, "unshare").map_err(|error| {
        format!("Bubblewrap: {requirement} requires util-linux 'unshare' on PATH: {error}")
    })?;
    if !unshare.status.success()
        || !unshare.stdout.contains("--map-current-user")
        || !unshare.stdout.contains("--keep-caps")
    {
        return Err(format!(
            "Bubblewrap: {requirement} requires util-linux unshare with \
             --map-current-user and --keep-caps support"
        ));
    }

    // The in-namespace rules are programmed with these, so a host missing them
    // must fail here rather than deep inside supervisor startup.
    for (binary, probe, has_backend) in [
        ("nsenter", "--version", false),
        ("iptables", "--version", true),
        ("ip6tables", "--version", true),
        ("iptables-restore", "--version", true),
        ("ip6tables-restore", "--version", true),
    ] {
        let mut command = Command::new(binary);
        command.arg(probe);
        let output = run_probe(command, binary).map_err(|error| {
            format!(
                "Bubblewrap: {requirement} requires '{binary}' on PATH to enforce {}: {error}",
                use_case.mechanism()
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "Bubblewrap: {requirement} requires a working '{binary}' installation \
                 ({binary} {probe} exited with {})",
                output.status
            ));
        }
        // Presence is not enough: the binary can work while its backend is one
        // this supervisor cannot drive.
        if has_backend {
            iptables_backend_is_usable(
                binary,
                &output.stdout,
                Path::new(XTABLES_LOCK_PATH),
                use_case,
            )?;
        }
    }
    Ok(())
}

/// Whether `binary`'s backend can install rules from the unprivileged supervisor.
///
/// The supervisor runs under `unshare --user --map-current-user`, so it keeps the
/// caller's uid: its capabilities apply inside the new user namespace, not to
/// root-owned files in the initial one. The legacy backend opens
/// [`XTABLES_LOCK_PATH`] before touching any table, so on a stock host (root-owned
/// `/run`, no lock file) it fails with `EACCES` and `set -e` kills the supervisor
/// at the first rule. `nf_tables` takes no lock.
///
/// The banner alone cannot decide this: legacy *does* work where the lock is
/// reachable (as root, or with a writable lock). So the backend picks the
/// question, and for legacy the lock itself is tested.
fn iptables_backend_is_usable(
    binary: &str,
    banner: &str,
    lock: &Path,
    use_case: PrivateNetworkUse,
) -> Result<(), String> {
    if banner.contains("nf_tables") {
        return Ok(());
    }
    if lock_is_writable(lock) {
        return Ok(());
    }

    // A pre-1.8 banner carries no marker at all; those builds are legacy-only.
    Err(format!(
        "Bubblewrap: {} requires an iptables backend the sandbox supervisor can \
         drive without privilege, but '{binary}' resolves to the legacy backend ({}) and \
         '{}' is not writable by this user. The {} rules are installed by an \
         unprivileged supervisor in a user namespace, which keeps the caller's uid, so the \
         root-owned lock is unreachable and every rule would fail. Select the nf_tables \
         backend (for example: update-alternatives --set {binary} /usr/sbin/{binary}-nft), \
         or make '{}' writable.",
        use_case.requirement(),
        banner.trim(),
        lock.display(),
        use_case.mechanism(),
        lock.display()
    ))
}

/// Whether the legacy backend could take its lock as the current user.
///
/// The lock is created on first use, so an absent file makes the *directory* the
/// thing that must be writable. `access` tests the real uid — the uid the
/// supervisor itself runs under.
fn lock_is_writable(lock: &Path) -> bool {
    let target = if lock.exists() {
        lock
    } else {
        match lock.parent() {
            Some(parent) => parent,
            None => return false,
        }
    };
    access(target, AccessFlags::W_OK).is_ok()
}

/// Cap on how much component stderr is quoted into a diagnostic.
///
/// A wedged component can write without bound, and this is read from `Drop`, so
/// the read itself must be bounded rather than trimmed after the fact.
const MAX_STDERR_TAIL: u64 = 2048;

/// Last [`MAX_STDERR_TAIL`] bytes of `path`, phrased for an error message.
///
/// The tail, not the head: whatever actually killed the component is written
/// last, and a truncated head would quote its startup banner instead.
fn stderr_detail(path: &std::path::Path) -> String {
    let text = read_stderr_tail(path);
    let text = text.trim();
    if text.is_empty() {
        return "no stderr output".to_string();
    }
    format!("stderr: {text}")
}

fn read_stderr_tail(path: &std::path::Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    if len > MAX_STDERR_TAIL && file.seek(SeekFrom::End(-(MAX_STDERR_TAIL as i64))).is_err() {
        return String::new();
    }
    let mut buffer = Vec::new();
    if file.take(MAX_STDERR_TAIL).read_to_end(&mut buffer).is_err() {
        return String::new();
    }
    // Seeking to a byte offset can land mid-character; lossy keeps the rest
    // readable instead of discarding the whole tail.
    String::from_utf8_lossy(&buffer).into_owned()
}

fn wait_for_file(
    path: impl AsRef<std::path::Path>,
    child: &mut Child,
    stderr_path: &std::path::Path,
    component: &str,
    timeout: Duration,
) -> Result<(), String> {
    let path = path.as_ref();
    let deadline = Instant::now() + timeout;
    loop {
        if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            format!("Bubblewrap: failed to inspect {component} startup: {error}")
        })? {
            return Err(format!(
                "Bubblewrap: {component} exited during startup ({status}): {}",
                stderr_detail(stderr_path)
            ));
        }
        if Instant::now() >= deadline {
            // Include whatever the component wrote to stderr: on a timeout it
            // is usually the only evidence of *why* startup stalled, and the
            // process is still alive so no exit status will explain it.
            return Err(format!(
                "Bubblewrap: timed out waiting for {component} after {timeout:?} ({})",
                stderr_detail(stderr_path)
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Hand `fds` to one specific child, without exposing them process-wide.
///
/// `FD_CLOEXEC` is per-process, so clearing it on the parent's copy would leak
/// the descriptors to every concurrent `Command::spawn` -- a real window, since
/// this crate is reachable from the SDK and FFI. Clearing it in the forked child
/// instead gives them to the intended child and no one else.
///
/// The number is left as the OS assigned it, which is safe here because bwrap
/// receives it in argv (`--info-fd N`) and parses it as an integer. A child
/// that must *redirect* to the descriptor from a shell needs
/// [`remap_descriptors`] instead.
fn inherit_descriptors(command: &mut Command, fds: Vec<RawFd>) {
    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `fcntl` is async-signal-safe and
    // this closure allocates nothing -- `fds` is captured by move and holds
    // plain integers.
    unsafe {
        command.pre_exec(move || {
            for fd in &fds {
                fcntl(*fd, FcntlArg::F_SETFD(FdFlag::empty())).map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
}

/// Hand `mapping` to one specific child at fixed, known descriptor numbers.
///
/// Two problems are solved together. `FD_CLOEXEC` is per-process, so clearing
/// it on the parent's copy would leak the descriptors to every concurrent
/// `Command::spawn` -- a real window, since this crate is reachable from the
/// SDK and FFI. And an OS-assigned descriptor number cannot be named from
/// `/bin/sh`: dash rejects `>&$fd` and `<&$fd` for any descriptor >= 10 with
/// `Bad fd number` at *parse* time, so interpolating a raw number breaks the
/// supervisor as soon as the parent holds enough open files.
///
/// `dup2` in the forked child solves both: it clears `FD_CLOEXEC` on the new
/// descriptor only, and it puts that descriptor on a number the script can
/// hardcode. The originals stay CLOEXEC and close at exec.
fn remap_descriptors<const N: usize>(command: &mut Command, mapping: [(RawFd, RawFd); N]) {
    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `fcntl` and `dup2` are both
    // async-signal-safe and this closure allocates nothing -- `mapping` is a
    // fixed-size array of plain integers captured by move, and the staging
    // buffer is a fixed-size array too.
    unsafe {
        command.pre_exec(move || {
            // Stage every source above the target range before landing any of
            // them: a direct `dup2` could otherwise clobber a source that
            // happens to already sit on a later target.
            let mut staged = [-1; N];
            for (index, (source, _)) in mapping.iter().enumerate() {
                staged[index] = fcntl(*source, FcntlArg::F_DUPFD_CLOEXEC(FD_STAGING_BASE))
                    .map_err(std::io::Error::from)?;
            }
            for (index, (_, target)) in mapping.iter().enumerate() {
                dup2(staged[index], *target).map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), String> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|error| format!("Bubblewrap: failed to read descriptor flags: {error}"))?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map(|_| ())
        .map_err(|error| format!("Bubblewrap: failed to make descriptor nonblocking: {error}"))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reported concern: a hostname proxy resolves through the host's
    /// resolver during setup, before the script timeout applies, so an
    /// unresponsive resolver would stall a run that never started.
    #[test]
    fn work_that_outlives_its_deadline_is_abandoned() {
        let started = Instant::now();
        let waited = with_deadline("mxc-test-deadline", Duration::from_millis(50), || {
            thread::sleep(Duration::from_secs(30));
            "an answer that arrives too late"
        })
        .expect("the worker thread starts");

        assert!(
            matches!(waited, Err(mpsc::RecvTimeoutError::Timeout)),
            "the wait must end on the deadline rather than on the work"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the caller waited {:?}, so the deadline did not bound it",
            started.elapsed()
        );
    }

    #[test]
    fn work_that_finishes_within_its_deadline_returns_its_answer() {
        let waited = with_deadline("mxc-test-deadline", Duration::from_secs(30), || 7)
            .expect("the worker thread starts");

        assert_eq!(waited, Ok(7));
    }

    /// The bound is only useful if it is longer than a working resolver's
    /// slow path; see [`RESOLVE_TIMEOUT`].
    #[test]
    fn the_resolver_bound_survives_one_dead_nameserver() {
        assert!(RESOLVE_TIMEOUT > Duration::from_secs(10));
    }

    #[test]
    fn gateway_constants_agree() {
        // The rule and the pin are written from the address; the URL rewrite
        // from the string. A drift between them would open one endpoint and
        // point the workload at another.
        assert_eq!(SLIRP_HOST_GATEWAY_IP.to_string(), SLIRP_HOST_GATEWAY);
        // The reserved-range check is written from the octets, the diagnostic
        // from the string; the gateway must fall inside the range it names.
        assert!(SLIRP_NETWORK.starts_with(&format!(
            "{}.{}.{}.",
            SLIRP_NETWORK_OCTETS[0], SLIRP_NETWORK_OCTETS[1], SLIRP_NETWORK_OCTETS[2]
        )));
        assert_eq!(SLIRP_HOST_GATEWAY_IP.octets()[..3], SLIRP_NETWORK_OCTETS);
    }

    /// A hostname answering with the gateway is the sharp case: the address is
    /// routable on the host, so nothing else flags it, but inside the namespace
    /// it is the route to host loopback. Pinning it would hand the workload an
    /// unrelated host service on the proxy port.
    #[test]
    fn egress_rejects_a_hostname_resolving_into_the_sandbox_network() {
        let address = ProxyAddress::new("proxy.example".into(), 3128);
        let error = SandboxProxy::resolve_with(&address, resolver([10, 0, 2, 2]))
            .expect_err("the slirp gateway must not be pinned as if it were a host address");

        assert!(
            error.contains("10.0.2.0/24") && error.contains("127.0.0.1"),
            "error should name the reserved range and the supported alternative: {error}"
        );
    }

    /// The sandbox's own tap address, and a plain neighbour, are wrong for the
    /// same reason -- so the whole range is rejected, not just the gateway.
    #[test]
    fn egress_rejects_every_address_in_the_sandbox_network() {
        for octets in [[10, 0, 2, 3], [10, 0, 2, 100], [10, 0, 2, 50]] {
            let address = ProxyAddress::new("proxy.example".into(), 3128);
            assert!(
                SandboxProxy::resolve_with(&address, resolver(octets)).is_err(),
                "{octets:?} is on-link inside the namespace and cannot name a host endpoint"
            );

            let literal = ProxyAddress::new(Ipv4Addr::from(octets).to_string(), 3128);
            assert!(
                SandboxProxy::resolve(&literal).is_err(),
                "{octets:?} must be rejected as a literal too, not only as an answer"
            );
        }
    }

    /// The rejection must not swallow the translation it sits next to: a
    /// loopback answer is *meant* to become the gateway.
    #[test]
    fn rejecting_the_sandbox_network_leaves_the_loopback_translation_intact() {
        let address = ProxyAddress::new("proxy.example".into(), 3128);
        let resolved = SandboxProxy::resolve_with(&address, resolver([127, 0, 0, 1]))
            .expect("a loopback answer is translated, not rejected");

        assert_eq!(resolved.egress().ip, SLIRP_HOST_GATEWAY_IP);
    }

    /// The neighbouring /24 is ordinary host space, so the check must not
    /// widen past the network slirp actually assigns.
    #[test]
    fn egress_accepts_an_address_just_outside_the_sandbox_network() {
        let address = ProxyAddress::new("proxy.example".into(), 3128);
        let resolved = SandboxProxy::resolve_with(&address, resolver([10, 0, 3, 2]))
            .expect("10.0.3.2 is a normal routable answer");

        assert_eq!(resolved.egress().ip, Ipv4Addr::new(10, 0, 3, 2));
    }

    #[test]
    fn egress_opens_the_gateway_for_a_loopback_literal() {
        // A literal has no name to pin, so the URL is rewritten and the rule
        // must open the rewritten address, not the original loopback.
        let address = ProxyAddress::new("127.0.0.1".into(), 8080);
        let resolved = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(resolved.address().host(), SLIRP_HOST_GATEWAY);
        assert_eq!(resolved.egress().ip.to_string(), SLIRP_HOST_GATEWAY);
        assert_eq!(resolved.egress().port, 8080);
        assert!(resolved.egress().pin().is_none());
    }

    #[test]
    fn egress_accepts_a_routable_ipv4_proxy() {
        let address = ProxyAddress::new("10.1.2.3".into(), 3128);
        let resolved = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(resolved.address().host(), "10.1.2.3");
        assert_eq!(resolved.egress().ip.to_string(), "10.1.2.3");
        assert_eq!(resolved.egress().port, 3128);
        assert!(resolved.egress().pin().is_none());
    }

    /// A resolver that answers every name with `ip`, so pin decisions can be
    /// tested without a lookup the test does not control.
    fn resolver(ip: [u8; 4]) -> impl Fn(&str, u16) -> Result<Ipv4Addr, String> {
        move |_, _| Ok(Ipv4Addr::from(ip))
    }

    #[test]
    fn pins_a_hostname_and_keeps_its_url() {
        // The workload must present the configured name -- proxy-auth realms
        // and Host headers are keyed on it -- so the name is pinned rather
        // than rewritten to an address.
        let address = ProxyAddress::from_url(
            "http://proxy.corp.example:3128/",
            "proxy.corp.example".into(),
            3128,
        );
        let resolved = SandboxProxy::resolve_with(&address, resolver([10, 1, 2, 3])).unwrap();

        assert_eq!(
            resolved.address().to_url(),
            "http://proxy.corp.example:3128/"
        );

        let pin = resolved.egress().pin().expect("hostname must be pinned");
        assert_eq!(pin.hostname(), "proxy.corp.example");
        assert_eq!(pin.ip().to_string(), "10.1.2.3");
        assert_eq!(resolved.egress().ip.to_string(), "10.1.2.3");
    }

    #[test]
    fn pins_a_loopback_hostname_to_the_gateway() {
        // slirp gives the sandbox its own loopback, so a name resolving to the
        // host's loopback must be pinned to the gateway -- pinning it verbatim
        // would aim the workload at itself.
        let address = ProxyAddress::from_url("http://proxy.local:3128", "proxy.local".into(), 3128);
        let resolved = SandboxProxy::resolve_with(&address, resolver([127, 0, 1, 1])).unwrap();

        let pin = resolved.egress().pin().expect("hostname must be pinned");
        assert_eq!(pin.ip().to_string(), SLIRP_HOST_GATEWAY);
        assert_eq!(resolved.egress().ip.to_string(), SLIRP_HOST_GATEWAY);
    }

    #[test]
    fn rewrites_localhost_instead_of_pinning_it() {
        // `localhost` is reserved to loopback (RFC 6761). A pin is sandbox
        // wide, so pinning it would redirect the workload's own loopback
        // traffic to the host.
        let address = ProxyAddress::from_url("http://localhost:3128/", "localhost".into(), 3128);
        let resolved =
            SandboxProxy::resolve_with(&address, |_, _| panic!("localhost must not be resolved"))
                .unwrap();

        assert_eq!(resolved.address().host(), SLIRP_HOST_GATEWAY);
        assert!(resolved.egress().pin().is_none());
        assert_eq!(resolved.egress().ip.to_string(), SLIRP_HOST_GATEWAY);
    }

    /// The pre-flight check exists to fail fast, not to duplicate work: a name
    /// must survive it untouched so `run` performs the only lookup, whose
    /// answer is also the pin the sandbox is given.
    #[test]
    fn the_pre_flight_check_defers_every_verdict_that_needs_a_lookup() {
        // `.invalid` is reserved as never-resolvable (RFC 2606), so a real
        // lookup here could only fail -- passing proves none was made.
        let named = ProxyAddress::new("proxy.this-name-cannot-exist.invalid".into(), 3128);
        assert!(
            SandboxProxy::check_without_resolving(&named).is_ok(),
            "a hostname's verdict belongs to the lookup in `run`"
        );
    }

    #[test]
    fn the_pre_flight_check_still_rejects_what_no_lookup_could_rescue() {
        // Decided by the configured address alone, so deferring these would
        // only move the same rejection past a started proxy.
        for unusable in [
            ProxyAddress::new("[::1]".into(), 3128),
            ProxyAddress::new("2001:db8::1".into(), 3128),
            ProxyAddress::new("127.0.0.1".into(), 0),
        ] {
            assert!(
                SandboxProxy::check_without_resolving(&unusable).is_err(),
                "endpoint '{}' is unusable regardless of DNS",
                unusable.host()
            );
        }
    }

    /// The effective intent is the deepest entry covering the file, so an
    /// ancestor denial masks it and a grant beneath that denial wins it back.
    #[test]
    fn a_denied_ancestor_counts_as_denying_the_hosts_file() {
        let denied_parent = ContainerPolicy {
            denied_paths: vec!["/etc".into()],
            ..Default::default()
        };
        assert!(hosts_file_is_denied(&denied_parent));

        let regranted = ContainerPolicy {
            denied_paths: vec!["/etc".into()],
            readonly_paths: vec![SANDBOX_HOSTS_PATH.into()],
            ..Default::default()
        };
        assert!(
            !hosts_file_is_denied(&regranted),
            "a more specific grant beneath the denial takes effect"
        );

        let unrelated = ContainerPolicy {
            denied_paths: vec!["/etc/hostname".into(), "/etc/hosts.allow".into()],
            ..Default::default()
        };
        assert!(
            !hosts_file_is_denied(&unrelated),
            "a sibling with a shared prefix must not be mistaken for the file"
        );
    }

    #[test]
    fn pins_a_routable_hostname_to_its_resolved_address() {
        // Only a loopback answer is redirected to the gateway; a routable one
        // is reached directly through slirp.
        assert_eq!(
            sandbox_facing_ip(Ipv4Addr::new(10, 1, 2, 3)),
            Ipv4Addr::new(10, 1, 2, 3)
        );
        assert_eq!(
            sandbox_facing_ip(Ipv4Addr::new(127, 0, 0, 1)),
            SLIRP_HOST_GATEWAY_IP
        );
        // `/etc/hosts` can map a name to `0.0.0.0`, which names the host the
        // same way loopback does -- and which the IP-literal path rewrites.
        assert_eq!(
            sandbox_facing_ip(Ipv4Addr::UNSPECIFIED),
            SLIRP_HOST_GATEWAY_IP
        );
    }

    #[test]
    fn egress_rejects_an_ipv6_proxy() {
        // Rules are IPv4-only, so an IPv6 endpoint would never be opened.
        let loopback = ProxyAddress::new("[::1]".into(), 8080);
        let error = SandboxProxy::resolve(&loopback).unwrap_err();
        assert!(
            error.contains("IPv4"),
            "error should explain the IPv4 requirement: {error}"
        );

        let routable = ProxyAddress::new("2001:db8::1".into(), 8080);
        assert!(SandboxProxy::resolve(&routable).is_err());
    }

    #[test]
    fn egress_rejects_an_unresolvable_hostname() {
        // `.invalid` is reserved by RFC 2606 and never resolves, so a name
        // that cannot be pinned must fail loudly rather than yield a rule the
        // sandbox can never reach.
        let address = ProxyAddress::from_url(
            "http://proxy.corp.invalid:3128",
            "proxy.corp.invalid".into(),
            3128,
        );
        let error = SandboxProxy::resolve(&address).unwrap_err();

        assert!(
            error.contains("proxy.corp.invalid"),
            "error should name the offending host: {error}"
        );
    }

    /// `::1` used to be rewritten to the IPv4 gateway, which handed the sandbox
    /// an address the proxy never listens on: an IPv6-loopback listener does
    /// not accept the IPv4 connection slirp's gateway produces. Rejecting at
    /// policy time beats failing at connect time.
    #[test]
    fn rejects_an_ipv6_loopback_proxy_instead_of_translating_it() {
        for host in ["[::1]", "::1"] {
            let address = ProxyAddress::new(host.into(), 8080);
            let error = SandboxProxy::resolve(&address).unwrap_err();

            assert!(
                error.contains("IPv6 loopback"),
                "error should name the unreachable address family: {error}"
            );
        }
    }

    /// The rejection must not swallow `::`: a dual-stack wildcard listener does
    /// accept the gateway's IPv4 connection, so it still translates.
    #[test]
    fn ipv6_loopback_rejection_leaves_the_ipv6_wildcard_translatable() {
        let address = ProxyAddress::new("[::]".into(), 8080);
        let translated = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(translated.address().host(), SLIRP_HOST_GATEWAY);
    }

    #[test]
    fn egress_rejects_a_zero_port() {
        let address = ProxyAddress::new("10.0.2.2".into(), 0);
        let error = SandboxProxy::resolve(&address).unwrap_err();

        assert!(
            error.contains("non-zero"),
            "error should explain the port requirement: {error}"
        );
    }

    /// The supervisor script with the lock-wait flag elided.
    ///
    /// The flag is an operational detail, not part of the egress policy these
    /// tests pin. Normalising it away keeps a change in lock handling from
    /// failing every ordering assertion -- while
    /// `every_rule_command_waits_for_the_xtables_lock` still asserts it is
    /// present on all of them.
    fn normalised_script() -> String {
        SUPERVISOR_SCRIPT.replace(r#" -w "$lock_wait""#, "")
    }

    /// The pin a hostname proxy produces, for the hosts-file tests.
    fn test_pin() -> ProxyHostPin {
        ProxyAddress::new("proxy.example".into(), 3128)
            .host_pin(IpAddr::V4(SLIRP_HOST_GATEWAY_IP))
            .expect("hostname must be pinnable")
            .expect("a hostname needs a pin")
    }

    #[test]
    fn pinned_hosts_file_puts_the_pin_first() {
        // Ordering is not sufficient on its own (see the duplicate-name tests
        // below), but the pin still leads the file so the intent is legible.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        write_pinned_hosts(&path, &test_pin()).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents.lines().next().unwrap(),
            format!("{SLIRP_HOST_GATEWAY} proxy.example")
        );
    }

    /// The reason the name is stripped rather than merely outranked: glibc
    /// returns *every* matching hosts line to `getaddrinfo`, which re-sorts
    /// them by RFC 6724 and promotes a loopback address above the pin. A
    /// surviving duplicate is therefore tried first, sending the workload to an
    /// address the egress chain never authorized -- or back into the sandbox.
    #[test]
    fn a_competing_mapping_for_the_pinned_name_is_removed() {
        let stripped = strip_host_from_hosts(
            "127.0.0.1 localhost\n127.0.0.1 proxy.example\n10.9.9.9 proxy.example\n",
            "proxy.example",
        );
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn stripping_the_pinned_name_keeps_the_other_names_on_its_line() {
        // Dropping the whole line would cost the sandbox `localhost`.
        let stripped =
            strip_host_from_hosts("127.0.0.1 localhost proxy.example\n", "proxy.example");
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn stripping_the_pinned_name_ignores_case() {
        // DNS names are case-insensitive, so a differently cased duplicate
        // would otherwise survive and reintroduce the competing mapping.
        let stripped = strip_host_from_hosts("127.0.0.1 Proxy.EXAMPLE\n", "proxy.example");
        assert_eq!(stripped, "");
    }

    #[test]
    fn stripping_leaves_unrelated_lines_byte_for_byte() {
        // Real hosts files are tab-aligned; normalizing them would churn the
        // sandbox's file for no benefit.
        let original = "127.0.0.1\tlocalhost\n\n# a comment\n::1\tip6-localhost ip6-loopback\n";
        assert_eq!(strip_host_from_hosts(original, "proxy.example"), original);
    }

    #[test]
    fn stripping_an_entire_entry_keeps_its_trailing_comment() {
        let stripped =
            strip_host_from_hosts("10.9.9.9 proxy.example # operator note\n", "proxy.example");
        assert_eq!(stripped, "# operator note\n");
    }

    #[test]
    fn the_written_hosts_file_has_exactly_one_mapping_for_the_pinned_name() {
        // End-to-end twin of the unit tests above, against the real host file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        write_pinned_hosts(&path, &test_pin()).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        let matches = written
            .lines()
            .filter(|line| {
                let body = line.split('#').next().unwrap_or("");
                body.split_whitespace()
                    .skip(1)
                    .any(|name| name.eq_ignore_ascii_case("proxy.example"))
            })
            .count();
        assert_eq!(
            matches, 1,
            "exactly one mapping may survive for the pinned name:\n{written}"
        );
    }

    #[test]
    fn pinned_hosts_file_keeps_the_host_entries() {
        // Dropping them would cost the sandbox `localhost`, which workloads
        // and the loopback exemption both rely on.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        write_pinned_hosts(&path, &test_pin()).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        let host_file = fs::read_to_string(SANDBOX_HOSTS_PATH).unwrap_or_default();
        for line in host_file.lines().filter(|line| {
            // A line mapping the pinned name is *expected* to be rewritten;
            // every other line must survive untouched.
            !line.trim().is_empty()
                && !line
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .skip(1)
                    .any(|name| name.eq_ignore_ascii_case("proxy.example"))
        }) {
            assert!(
                written.contains(line),
                "host entry should be preserved: {line}"
            );
        }
    }

    #[test]
    fn hosts_bind_is_applied_after_policy_mounts() {
        // bwrap applies mounts in order and the last at a path wins, so the
        // pin must land past every policy mount -- including one that would
        // otherwise expose the host's own /etc/hosts.
        let mut args = vec![
            "--ro-bind-try".to_string(),
            "/etc".to_string(),
            "/etc".to_string(),
            "--bind".to_string(),
            "/etc/hosts".to_string(),
            "/etc/hosts".to_string(),
        ];
        args.extend(command_tail());
        insert_hosts_bind(&mut args, "/tmp/pin/hosts").unwrap();

        let pin = args
            .windows(3)
            .position(|window| window == ["--ro-bind", "/tmp/pin/hosts", SANDBOX_HOSTS_PATH])
            .expect("pin bind should be present");
        let policy = args
            .windows(3)
            .position(|window| window == ["--bind", "/etc/hosts", "/etc/hosts"])
            .expect("policy mount should be retained");
        let separator = command_separator(&args).unwrap();

        assert!(pin > policy, "pin must be applied after the policy mount");
        assert!(pin < separator, "pin must precede the command separator");
    }

    #[test]
    fn hosts_bind_reports_an_overridden_policy_mount() {
        // Silently shadowing a user's own /etc/hosts mount would make the
        // sandbox's view of the file inexplicable from the config alone.
        let mut args = vec![
            "--bind".to_string(),
            "/custom/hosts".to_string(),
            "/etc/hosts".to_string(),
        ];
        args.extend(command_tail());
        assert!(insert_hosts_bind(&mut args, "/tmp/pin/hosts").unwrap());

        let mut untouched = vec!["--ro-bind-try".to_string()];
        untouched.extend(command_tail());
        assert!(!insert_hosts_bind(&mut untouched, "/tmp/pin/hosts").unwrap());
    }

    #[test]
    fn hosts_bind_requires_a_command_separator() {
        // Appending blindly to an argument list with no separator would pass
        // the bind to the workload as arguments and leave it unpinned.
        let mut args = vec!["--ro-bind-try".to_string(), "/etc".to_string()];
        assert!(insert_hosts_bind(&mut args, "/tmp/pin/hosts").is_err());
    }

    /// The command bwrap is asked to run, as `build_args` appends it.
    fn command_tail() -> Vec<String> {
        COMMAND_TAIL
            .iter()
            .map(|arg| arg.to_string())
            .chain(["echo hello".to_string()])
            .collect()
    }

    /// Environment values are caller-controlled and reach the argument vector
    /// verbatim, so one that happens to be `--` must not be mistaken for the
    /// separator: splicing there would consume the pin's arguments as that
    /// `--setenv`'s operands and leave the sandbox reading the host's hosts
    /// file.
    #[test]
    fn a_caller_supplied_separator_value_is_not_mistaken_for_the_command() {
        let mut args = vec![
            "--setenv".to_string(),
            "FOO".to_string(),
            "--".to_string(),
            "--ro-bind-try".to_string(),
            "/etc".to_string(),
            "/etc".to_string(),
        ];
        args.extend(command_tail());
        let decoy = 2;

        insert_hosts_bind(&mut args, "/tmp/pin/hosts").unwrap();

        assert_eq!(
            args[..=decoy],
            ["--setenv", "FOO", "--"],
            "the environment value must survive the splice intact"
        );
        let pin = args
            .windows(3)
            .position(|window| window == ["--ro-bind", "/tmp/pin/hosts", SANDBOX_HOSTS_PATH])
            .expect("pin bind should be present");
        assert!(
            pin > decoy,
            "the pin must be spliced at the command, not at the decoy value"
        );
        assert_eq!(
            args[args.len() - COMMAND_TAIL.len() - 1..],
            ["--", "sh", "-c", "echo hello"],
            "the command must remain last"
        );
    }

    /// Byte offset of `needle` in the normalised supervisor script.
    fn script_offset(needle: &str) -> usize {
        normalised_script()
            .find(needle)
            .unwrap_or_else(|| panic!("supervisor script should contain {needle:?}"))
    }

    #[test]
    fn script_signals_readiness_only_after_rules_are_installed() {
        // The caller releases the workload on this signal, so emitting it early
        // would let the workload run with egress wide open.
        let last_restore = script_offset("ip6tables-restore");
        let ready = script_offset(r#"printf ready > "$state_dir/slirp.ready""#);

        assert!(
            last_restore < ready,
            "readiness must be signalled after the final restore"
        );
    }

    #[test]
    fn the_script_hardcodes_no_rule_of_its_own() {
        // Every rule reaches iptables through a restore payload rendered in
        // Rust from parsed addresses, which is what makes the posture auditable
        // in one place and keeps caller text out of the shell entirely. A rule
        // written into the script -- a port 53 accept being the obvious
        // temptation -- would be invisible to the rule model and to every
        // policy test written against it.
        for line in normalised_script().lines() {
            for fragment in [" -j ACCEPT", " -j DROP", " -d ", " -A ", " -N "] {
                assert!(
                    !line.contains(fragment),
                    "the script names a rule that did not come from the payload: {line}"
                );
            }
        }
    }

    #[test]
    fn script_restores_both_families() {
        // A family left unrestored is a family with no chain and no terminal
        // verdict, so it would stay wide open.
        script_offset("-- iptables-restore ");
        script_offset("-- ip6tables-restore ");
    }

    #[test]
    fn script_installs_rules_synchronously() {
        // Offset-based ordering assertions only hold if the restores run
        // inline. Backgrounding one would satisfy those tests while destroying
        // the guarantee that rules precede readiness.
        let rules_start = script_offset("-- iptables-restore ");
        let ready = script_offset(r#"printf ready > "$state_dir/slirp.ready""#);
        let script = normalised_script();
        let region = &script[rules_start..ready];

        for line in region.lines().filter(|line| line.contains("nsenter")) {
            assert!(
                !line.trim_end().ends_with('&'),
                "rule must not be backgrounded: {line}"
            );
            assert!(
                !line.contains('('),
                "rule must not run in a subshell: {line}"
            );
        }
    }

    #[test]
    fn translates_loopback_literal_to_slirp_gateway() {
        let address = ProxyAddress::new("127.0.0.1".into(), 8080);
        let resolved = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(resolved.address().host(), SLIRP_HOST_GATEWAY);
        assert_eq!(resolved.address().port(), 8080);
        assert_eq!(resolved.address().to_url(), "http://10.0.2.2:8080");
    }

    #[test]
    fn translates_loopback_url_without_losing_url_components() {
        let address =
            ProxyAddress::from_url("http://user:pass@127.0.0.1:3128/", "127.0.0.1".into(), 3128);
        let resolved = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(resolved.address().host(), SLIRP_HOST_GATEWAY);
        assert_eq!(resolved.address().port(), 3128);
        assert_eq!(
            resolved.address().to_url(),
            "http://user:pass@10.0.2.2:3128/"
        );
    }

    #[test]
    fn leaves_a_routable_literal_proxy_unchanged() {
        let address = ProxyAddress::from_url("https://10.1.2.3:8443", "10.1.2.3".into(), 8443);
        let resolved = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(resolved.address().to_url(), address.to_url());
    }

    /// A proxy bound to the wildcard address is reachable on the host's
    /// loopback, which the sandbox's private namespace cannot see, so it needs
    /// the same gateway rewrite `127.0.0.1` gets.
    #[test]
    fn translates_wildcard_proxy_to_slirp_gateway() {
        let address = ProxyAddress::new("0.0.0.0".into(), 8080);
        let translated = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(translated.address().host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.address().port(), 8080);
    }

    #[test]
    fn translates_bracketed_ipv6_wildcard_proxy_to_slirp_gateway() {
        let address = ProxyAddress::from_url("http://[::]:3128/", "[::]".into(), 3128);
        let translated = SandboxProxy::resolve(&address).unwrap();

        assert_eq!(translated.address().host(), SLIRP_HOST_GATEWAY);
        assert_eq!(translated.address().port(), 3128);
        assert_eq!(translated.address().to_url(), "http://10.0.2.2:3128/");
    }

    /// The descriptor must reach the child that was prepared and no other. The
    /// obvious alternative -- clearing `FD_CLOEXEC` on the parent's copy --
    /// passes the first assertion and fails the other two.
    #[test]
    fn inherited_descriptors_reach_only_the_prepared_child() {
        let (reader, _writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let fd = reader.as_raw_fd();
        let probe = format!("test -e /proc/self/fd/{fd} && echo present || echo absent");

        let mut prepared = Command::new("sh");
        prepared.arg("-c").arg(&probe);
        inherit_descriptors(&mut prepared, vec![fd]);
        let prepared_out = prepared.output().expect("spawn prepared child");

        let bystander = Command::new("sh")
            .arg("-c")
            .arg(&probe)
            .output()
            .expect("spawn bystander child");

        assert_eq!(
            String::from_utf8_lossy(&prepared_out.stdout).trim(),
            "present",
            "the prepared child did not inherit the descriptor"
        );
        assert_eq!(
            String::from_utf8_lossy(&bystander.stdout).trim(),
            "absent",
            "an unrelated child inherited the descriptor"
        );

        let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).expect("F_GETFD"));
        assert!(
            flags.contains(FdFlag::FD_CLOEXEC),
            "the parent's own descriptor was left inheritable"
        );
    }

    /// Regression for the defect this scheme exists to prevent: dash rejects a
    /// redirection to a *variable* descriptor >= 10 at parse time, so the old
    /// `eval "... >&$fd"` form failed based on how many files the parent
    /// happened to hold open. Remapping must land the pipe on a fixed low
    /// number regardless of what the OS originally assigned.
    #[test]
    fn remapped_descriptors_land_on_fixed_numbers_from_any_source() {
        // Force a high source number -- the exact case the old scheme broke on.
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let high = fcntl(reader.as_raw_fd(), FcntlArg::F_DUPFD_CLOEXEC(20)).expect("dup high");
        assert!(high >= 20, "test needs a two-digit source descriptor");

        File::from(writer).write_all(b"4242\n").expect("write pid");

        let mut command = Command::new("sh");
        command
            .arg("-c")
            // Reads through the *literal* descriptor the script hardcodes.
            .arg(format!(
                "IFS= read -r v <&{SUPERVISOR_PID_FD}; printf %s \"$v\""
            ));
        remap_descriptors(&mut command, [(high, SUPERVISOR_PID_FD)]);

        let out = command.output().expect("spawn remapped child");
        assert!(
            out.status.success(),
            "remapped child failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "4242",
            "the pipe did not arrive on the fixed descriptor"
        );
    }

    /// A source already sitting on another mapping's target must survive the
    /// remap. A naive sequential `dup2` clobbers it and this catches that.
    #[test]
    fn remapping_survives_a_source_already_on_a_target_number() {
        let (a_reader, a_writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let (b_reader, b_writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let a = a_reader.as_raw_fd();
        let b = b_reader.as_raw_fd();

        File::from(a_writer).write_all(b"AAA\n").expect("write a");
        File::from(b_writer).write_all(b"BBB\n").expect("write b");

        // The second mapping's source is the first mapping's target, so a
        // sequential `dup2` would overwrite `b` before it had been landed.
        let mapping = [(a, b), (b, SUPERVISOR_PID_FD)];

        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "printf 'first=%s second=%s' \
             \"$(cat /proc/self/fd/{b})\" \"$(cat /proc/self/fd/{SUPERVISOR_PID_FD})\""
        ));
        remap_descriptors(&mut command, mapping);

        let out = command.output().expect("spawn remapped child");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "first=AAA second=BBB",
            "a source sitting on another target was clobbered during remap"
        );
    }

    /// The supervisor runs under `/bin/sh`, which is dash on Debian/Ubuntu.
    /// Parse it with the real shell so a construct dash rejects cannot ship.
    #[test]
    fn supervisor_script_parses_under_the_shell_that_runs_it() {
        let out = Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(SUPERVISOR_SCRIPT)
            .output()
            .expect("spawn sh");

        assert!(
            out.status.success(),
            "supervisor script is not valid /bin/sh: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The script may only name descriptors the parent actually pins. Two
    /// forms are banned: `>&$var`, which broke on dash for fd >= 10, and
    /// `{var}>`, the varfd allocation the review proposed as a fix — dash
    /// *parses* that as a plain word, so it fails silently rather than loudly
    /// and `sh -n` cannot catch it.
    #[test]
    fn supervisor_script_never_redirects_to_a_variable_descriptor() {
        for line in SUPERVISOR_SCRIPT.lines() {
            let code = line.trim();
            if code.starts_with('#') {
                continue;
            }
            assert!(
                !code.contains(">&$") && !code.contains("<&$"),
                "variable descriptor redirection breaks dash for fd >= 10: {code}"
            );
            assert!(
                !code.contains("}>") && !code.contains("}<"),
                "varfd allocation is a bash-ism; dash parses it as a word: {code}"
            );
        }
    }

    /// Every restore call must wait for the shared host lock. One unguarded
    /// call is enough to fail a concurrent launch under `set -e`.
    #[test]
    fn every_rule_command_waits_for_the_xtables_lock() {
        let code: Vec<&str> = SUPERVISOR_SCRIPT
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .collect();

        let restores: Vec<&&str> = code
            .iter()
            .filter(|line| line.contains("tables-restore"))
            .collect();
        assert_eq!(
            restores.len(),
            2,
            "one restore call site per family; the per-family loop is what scales"
        );

        for restore in &restores {
            assert!(
                restore.contains(r#"-w "$lock_wait""#),
                "restore may fail instantly on a contended host lock: {restore}"
            );
            assert!(
                restore.contains(" -n "),
                "restore without -n flushes tables it did not write: {restore}"
            );
        }

        // The whole policy travels in the restore payloads now, so any
        // surviving per-rule invocation would be an unbatched leftover.
        assert!(
            !code
                .iter()
                .any(|line| line.contains("-- iptables ") || line.contains("-- ip6tables ")),
            "rule installation must go through iptables-restore, not per-rule calls"
        );
    }

    /// The budget must cover the worst case it was sized for, or `-w` just
    /// moves the failure from iptables to the parent's timeout.
    #[test]
    fn rule_install_budget_covers_every_transaction_blocking_on_the_lock() {
        for transactions in [2usize, 5, 11] {
            let budget = rule_install_timeout(transactions);
            assert!(
                budget > XTABLES_LOCK_WAIT * transactions as u32,
                "a fully contended host would time out before -w could succeed, and the \
                 budget also covers slirp startup, so it needs headroom above the lock \
                 waits: {transactions} transactions got {budget:?}"
            );
        }
    }

    /// The reason the budget scales at all is a large policy, so it must not
    /// scale without bound -- that is the failure mode the previous per-rule
    /// budget had.
    #[test]
    fn the_rule_install_budget_is_bounded_however_large_the_policy_is() {
        assert_eq!(rule_install_timeout(usize::MAX), RULE_INSTALL_CEILING);
        assert!(
            rule_install_timeout(2) < RULE_INSTALL_CEILING,
            "an ordinary policy must not be charged the ceiling"
        );
    }

    /// A plan whose rule count is what the test cares about. Sized through the
    /// public constructor so the count matches what the supervisor installs.
    fn plan_with_rule_count(count: usize) -> EgressPlan {
        let mut request = wxc_common::models::ExecutionRequest {
            schema_version: "0.8.0-alpha".into(),
            ..Default::default()
        };
        request.policy.allowed_hosts = (0..count)
            .map(|n| format!("10.0.{}.{}", n / 256, n % 256))
            .collect();
        EgressPlan::for_policy(&request).expect("literal addresses must build a plan")
    }

    /// A rejected transaction installs nothing, so the supervisor must fail
    /// closed *and* name the likeliest cause: iptables reports a missing
    /// `nf_conntrack` only as "Invalid argument", which is unactionable.
    #[test]
    fn a_rejected_transaction_surfaces_the_conntrack_hint() {
        let plan = plan_with_rule_count(3);
        for transaction in 1..=2 {
            let mut supervisor =
                spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), Some(transaction), false);
            supervisor.publish_sandbox_pid();
            let status = supervisor.wait_for_exit();

            assert!(
                !status.success(),
                "transaction {transaction} failed but the supervisor lived on"
            );
            let stderr = supervisor.stderr();
            assert!(
                stderr.contains("nf_conntrack"),
                "a rejected transaction must name the missing kernel module, got: {stderr}"
            );
        }
    }

    /// The payload filenames are a contract between the Rust renderer and the
    /// shell globs that apply them. They live in different languages, so
    /// nothing but this test stops one side from drifting.
    #[test]
    fn the_script_globs_match_the_rendered_payload_names() {
        for family in [RuleFamily::V4, RuleFamily::V6] {
            let glob = format!("\"$state_dir\"/{}*", family.payload_prefix());
            assert!(
                SUPERVISOR_SCRIPT.contains(&glob),
                "the script has no glob {glob} for the payloads the renderer writes"
            );
            assert!(
                payload_file_name(family, 0, 1).starts_with(family.payload_prefix()),
                "the renderer stopped using the prefix the glob matches"
            );
        }
    }

    /// IPv6 stays off until the rules carry the RFC 4890 ICMPv6 exemptions:
    /// enabling it without them would break neighbour discovery and PMTUD
    /// behind a chain that ends in DROP.
    #[test]
    fn the_supervisor_leaves_ipv6_disabled_in_the_namespace() {
        assert!(
            !SUPERVISOR_SCRIPT.contains("--enable-ipv6"),
            "slirp4netns must not offer IPv6 while the ingress chain lacks ICMPv6 exemptions"
        );
    }

    #[test]
    fn probe_gives_up_on_a_hung_binary_instead_of_blocking_forever() {
        let mut command = Command::new("sleep");
        command.arg("120");

        let started = Instant::now();
        let error = run_probe(command, "wedged-tool").expect_err("a hung probe must not succeed");
        let elapsed = started.elapsed();

        assert!(
            error.contains("wedged-tool"),
            "the error must name the tool that hung, got: {error}"
        );
        // The point of the change: bounded, not merely eventual. `sleep 120`
        // would blow this budget by two orders of magnitude if unbounded.
        assert!(
            elapsed < PROBE_TIMEOUT * 3,
            "probe took {elapsed:?}, expected to give up near {PROBE_TIMEOUT:?}"
        );
    }

    #[test]
    fn probe_returns_stdout_of_a_well_behaved_binary() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo probe-stdout-marker"]);

        let probe = run_probe(command, "echo").expect("a fast probe must succeed");

        assert!(
            probe.status.success(),
            "expected success, got {:?}",
            probe.status
        );
        assert!(
            probe.stdout.contains("probe-stdout-marker"),
            "stdout was not captured, got: {:?}",
            probe.stdout
        );
    }

    #[test]
    fn probe_reports_a_failing_binary_without_treating_it_as_a_hang() {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 3"]);

        let probe = run_probe(command, "failing").expect("a clean non-zero exit is not an error");

        assert!(!probe.status.success(), "expected a non-zero exit status");
    }

    /// A path whose parent does not exist, standing in for the root-owned `/run`
    /// an unprivileged supervisor meets. Keeps the test deterministic and
    /// root-free while hitting the same branch.
    fn unreachable_lock(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("no-such-dir").join("xtables.lock")
    }

    /// Verified live: with the lock absent and `/run` unwritable, `iptables-nft
    /// -N` still succeeds.
    #[test]
    fn the_nft_backend_is_accepted_even_when_the_lock_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            iptables_backend_is_usable(
                "iptables",
                "iptables v1.8.10 (nf_tables)\n",
                &unreachable_lock(&dir),
                PrivateNetworkUse::ProxyOnlyEgress
            )
            .is_ok(),
            "the nf_tables backend takes no lock, so an unreachable lock must not refuse it"
        );
    }

    /// The regression this check exists for: legacy opens the lock
    /// unconditionally, so the supervisor dies at the first rule.
    #[test]
    fn the_legacy_backend_is_refused_when_it_could_not_take_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");

        let error = iptables_backend_is_usable(
            "iptables",
            "iptables v1.8.10 (legacy)\n",
            &unreachable_lock(&dir),
            PrivateNetworkUse::ProxyOnlyEgress,
        )
        .expect_err("a legacy backend with an unreachable lock cannot install rules");

        assert!(
            error.contains("iptables") && error.contains("nf_tables"),
            "the error must name the binary and the backend to switch to: {error}"
        );
    }

    /// Firewall enforcement shares this probe with proxy-only egress, so a
    /// missing dependency used to advise a caller to "omit network.proxy" --
    /// a field a firewall-only request never set. The advice must name what
    /// the caller actually configured.
    #[test]
    fn a_firewall_request_is_never_advised_about_the_proxy() {
        let dir = tempfile::tempdir().expect("tempdir");

        let error = iptables_backend_is_usable(
            "iptables",
            "iptables v1.8.10 (legacy)\n",
            &unreachable_lock(&dir),
            PrivateNetworkUse::FirewallEnforcement,
        )
        .expect_err("a legacy backend with an unreachable lock cannot install rules");

        assert!(
            !error.contains("network.proxy"),
            "a firewall-only request must not be told about a field it never set: {error}"
        );
        assert!(
            error.contains("network.enforcementMode='firewall'"),
            "the error must name what the caller configured: {error}"
        );
    }

    /// The mirror image: the proxy wording must not drift to firewall terms.
    #[test]
    fn a_proxy_request_is_never_advised_about_the_enforcement_mode() {
        let dir = tempfile::tempdir().expect("tempdir");

        let error = iptables_backend_is_usable(
            "iptables",
            "iptables v1.8.10 (legacy)\n",
            &unreachable_lock(&dir),
            PrivateNetworkUse::ProxyOnlyEgress,
        )
        .expect_err("a legacy backend with an unreachable lock cannot install rules");

        assert!(
            error.contains("network.proxy") && !error.contains("enforcementMode"),
            "a proxy request must keep the proxy wording: {error}"
        );
    }

    /// Every use case must produce a distinct, non-empty vocabulary -- an empty
    /// or shared string would silently reintroduce the mismatch above.
    #[test]
    fn each_private_network_use_names_itself_distinctly() {
        let proxy = PrivateNetworkUse::ProxyOnlyEgress;
        let firewall = PrivateNetworkUse::FirewallEnforcement;

        for (a, b) in [
            (proxy.requirement(), firewall.requirement()),
            (proxy.remedy(), firewall.remedy()),
            (proxy.mechanism(), firewall.mechanism()),
        ] {
            assert!(!a.is_empty() && !b.is_empty(), "wording must not be empty");
            assert_ne!(a, b, "the two use cases must not share wording");
        }
    }

    /// Legacy is refused for being unable to take its lock, not for being
    /// legacy: it works as root, and rejecting that would break a valid host.
    #[test]
    fn the_legacy_backend_is_accepted_when_the_lock_is_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("xtables.lock");
        fs::write(&lock, b"").expect("create lock");

        assert!(
            iptables_backend_is_usable(
                "iptables",
                "iptables v1.8.10 (legacy)\n",
                &lock,
                PrivateNetworkUse::ProxyOnlyEgress
            )
            .is_ok(),
            "a legacy backend that can take its lock installs rules fine"
        );
    }

    /// The lock is created on first use, so the check must ask about the
    /// directory rather than report the absent file as a failure.
    #[test]
    fn an_absent_lock_in_a_writable_directory_is_usable() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            lock_is_writable(&dir.path().join("xtables.lock")),
            "the lock is created on demand, so a writable directory is enough"
        );
    }

    /// Pre-1.8 builds print no backend marker and are legacy-only, so an
    /// unmarked banner must not be assumed usable.
    #[test]
    fn a_banner_without_a_backend_marker_is_treated_as_legacy() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(
            iptables_backend_is_usable(
                "iptables",
                "iptables v1.6.1\n",
                &unreachable_lock(&dir),
                PrivateNetworkUse::ProxyOnlyEgress
            )
            .is_err(),
            "a pre-1.8 build is legacy-only and must not be assumed usable"
        );
    }

    #[test]
    fn stderr_detail_keeps_the_tail_and_stays_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.stderr");
        // The interesting line is last; everything before it is noise that must
        // not push it out of the quoted region.
        let mut noise = "x".repeat(MAX_STDERR_TAIL as usize * 4);
        noise.push_str("\nfatal: the-actual-failure\n");
        fs::write(&path, &noise).expect("write stderr");

        let detail = stderr_detail(&path);

        assert!(
            detail.contains("fatal: the-actual-failure"),
            "the tail (where the failure is) was dropped: {detail}"
        );
        assert!(
            detail.len() <= MAX_STDERR_TAIL as usize + 64,
            "quoted stderr was not bounded, got {} bytes",
            detail.len()
        );
    }

    #[test]
    fn stderr_detail_reports_absence_rather_than_an_empty_string() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        assert_eq!(stderr_detail(&missing), "no stderr output");

        let empty = dir.path().join("empty.stderr");
        fs::write(&empty, "   \n").expect("write stderr");
        assert_eq!(stderr_detail(&empty), "no stderr output");
    }

    /// Chain name the fake supervisor installs into. Distinct from
    /// [`EGRESS_CHAIN`] so a test can never pass by matching production text.
    const TEST_CHAIN: &str = "mxc-test-chain";
    /// Inbound counterpart to [`TEST_CHAIN`].
    const TEST_INGRESS_CHAIN: &str = "mxc-test-ingress";

    /// Counts the restore commands and fails the one named by
    /// `MXC_TEST_FAIL_AT`. The real `nsenter` needs a live namespace and
    /// `CAP_SYS_ADMIN`; the script only cares whether it succeeded.
    ///
    /// The payload each restore would have applied is logged as
    /// `<tool> <line>`, so tests can still assert on the rules that reached
    /// iptables rather than only on the argument vector. The payload is found
    /// by being the one argument that names an existing file, so the stub does
    /// not have to track the renderer's filename scheme.
    const FAKE_NSENTER: &str = r#"#!/bin/sh
count=$(cat "$MXC_TEST_COUNT" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s' "$count" > "$MXC_TEST_COUNT"
printf '%s\n' "$*" >> "$MXC_TEST_ARGS"
if [ "${MXC_TEST_FAIL_AT:-0}" = "$count" ]; then
    echo "fake nsenter: forced failure on rule $count" >&2
    exit 1
fi
tool=""
payload=""
for arg in "$@"; do
    case "$arg" in
        iptables-restore|ip6tables-restore) tool="${arg%-restore}" ;;
        -*) ;;
        *) [ -f "$arg" ] && payload="$arg" ;;
    esac
done
if [ -n "$tool" ] && [ -n "$payload" ]; then
    while IFS= read -r line; do
        printf '%s %s\n' "$tool" "$line" >> "$MXC_TEST_PAYLOAD"
    done < "$payload"
fi
exit 0
"#;

    /// Signals readiness on the descriptor the supervisor opened for it (9),
    /// then idles so the supervisor's `wait` has something to wait on.
    const FAKE_SLIRP: &str = r#"#!/bin/sh
echo $$ > "$MXC_TEST_SLIRP_PID"
if [ "${MXC_TEST_SLIRP_DIES:-0}" = "1" ]; then
    echo "fake slirp4netns: exiting before readiness" >&2
    exit 1
fi
printf ready >&9
exec sleep 30
"#;

    /// The supervisor script running for real against fake tools.
    ///
    /// The six text-matching tests above assert what the script *says*; they
    /// cannot assert what it *does*. This runs it under the same `sh` a host
    /// would use, with `nsenter`/`slirp4netns` replaced by stubs that can fail
    /// on demand, so the fail-closed ordering can be observed rather than read.
    struct FakeSupervisor {
        dir: TempDir,
        child: Child,
        pid_writer: Option<File>,
        _exit_writer: OwnedFd,
    }

    impl FakeSupervisor {
        fn state_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("state")
        }

        /// How many restore commands actually ran.
        fn rule_invocations(&self) -> u32 {
            fs::read_to_string(self.dir.path().join("rules.count"))
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)
        }

        /// Whether the supervisor told the parent the sandbox is enforced.
        fn signalled_ready(&self) -> bool {
            self.state_dir().join("slirp.ready").exists()
        }

        /// The argument vector of each `nsenter` call, in the order made.
        ///
        /// The count alone cannot distinguish a correct chain from one whose
        /// rules carry the wrong address, verdict or order, so the arguments
        /// that actually reached iptables are what the policy tests assert on.
        fn rule_log(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("rules.args"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// The `-A <chain>` rules, stripped to the part that expresses policy.
        ///
        /// Read from the restore payloads the supervisor actually handed to
        /// iptables: the count and argument vector alone cannot distinguish a
        /// correct chain from one whose rules carry the wrong address, verdict
        /// or order.
        fn chain_rules(&self) -> Vec<String> {
            let prefix = format!(" -A {TEST_CHAIN} ");
            fs::read_to_string(self.dir.path().join("rules.payload"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let (tool, rest) = line.split_once(&prefix)?;
                    Some(format!("{tool} {rest}"))
                })
                .collect()
        }

        /// Every line of every restore payload, prefixed with its tool.
        fn payload_lines(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("rules.payload"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn stderr(&self) -> String {
            stderr_detail(&self.dir.path().join("supervisor.stderr"))
        }

        /// Hand over a sandbox PID, as the parent does once bwrap is up.
        fn publish_sandbox_pid(&mut self) {
            let mut writer = self.pid_writer.take().expect("pid writer");
            writer.write_all(b"4242\n").expect("publish pid");
        }

        /// Close the PID pipe without writing, as a parent that died would.
        fn abandon_without_publishing_pid(&mut self) {
            drop(self.pid_writer.take());
        }

        fn wait_for_exit(&mut self) -> ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    return status;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "supervisor did not exit; stderr: {}, rules run: {}",
                self.stderr(),
                self.rule_invocations()
            );
        }

        fn wait_until_ready(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if self.signalled_ready() {
                    return;
                }
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    panic!(
                        "supervisor exited ({status}) without signalling readiness; \
                         stderr: {}, rules run: {}",
                        self.stderr(),
                        self.rule_invocations()
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "supervisor never signalled readiness; stderr: {}",
                self.stderr()
            );
        }
    }

    impl Drop for FakeSupervisor {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // `set -e` bypasses the script's TERM trap, so a stub left running
            // by an aborted supervisor has to be reaped here.
            if let Ok(pid) = fs::read_to_string(self.dir.path().join("slirp.pid")) {
                let pid = pid.trim();
                if !pid.is_empty() {
                    let _ = Command::new("kill")
                        .args(["-9", pid])
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }

    fn install_stub(path: &std::path::Path, body: &str) {
        fs::write(path, body).expect("write stub");
        let mut perms = fs::metadata(path).expect("stat stub").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(path, perms).expect("chmod stub");
    }

    fn spawn_fake_supervisor(fail_at: Option<u32>, slirp_dies: bool) -> FakeSupervisor {
        spawn_fake_supervisor_with_plan(
            &EgressPlan::for_proxy(SLIRP_HOST_GATEWAY_IP, 3128),
            &denied_ingress(),
            fail_at,
            slirp_dies,
        )
    }

    fn denied_ingress() -> IngressPlan {
        IngressPlan::for_policy(&Default::default())
    }

    fn spawn_fake_supervisor_with_plan(
        plan: &EgressPlan,
        ingress: &IngressPlan,
        fail_at: Option<u32>,
        slirp_dies: bool,
    ) -> FakeSupervisor {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        let state = dir.path().join("state");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::create_dir_all(&state).expect("state dir");
        for family in [RuleFamily::V4, RuleFamily::V6] {
            let payloads =
                render_filter_payloads(plan, ingress, family, TEST_CHAIN, TEST_INGRESS_CHAIN);
            for (index, payload) in payloads.iter().enumerate() {
                fs::write(
                    state.join(payload_file_name(family, index, payloads.len())),
                    payload,
                )
                .expect("rules payload");
            }
        }
        install_stub(&bin.join("nsenter"), FAKE_NSENTER);
        install_stub(&bin.join("slirp4netns"), FAKE_SLIRP);

        let stderr = File::create(dir.path().join("supervisor.stderr")).expect("stderr");
        let (exit_reader, exit_writer) = pipe2(OFlag::O_CLOEXEC).expect("exit pipe");
        let (pid_reader, pid_writer) = pipe2(OFlag::O_CLOEXEC).expect("pid pipe");

        // The stubs shadow the real tools; the rest of PATH still supplies the
        // coreutils the script uses (`sleep`, `cat`).
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("sh");
        command
            .args(["-c", SUPERVISOR_SCRIPT, "mxc-test-supervisor"])
            .arg(&state)
            .arg("1")
            .env("PATH", path)
            .env("MXC_TEST_COUNT", dir.path().join("rules.count"))
            .env("MXC_TEST_ARGS", dir.path().join("rules.args"))
            .env("MXC_TEST_PAYLOAD", dir.path().join("rules.payload"))
            .env("MXC_TEST_SLIRP_PID", dir.path().join("slirp.pid"))
            .env(
                "MXC_TEST_FAIL_AT",
                fail_at.map(|n| n.to_string()).unwrap_or_default(),
            )
            .env("MXC_TEST_SLIRP_DIES", if slirp_dies { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        remap_descriptors(
            &mut command,
            [
                (pid_reader.as_raw_fd(), SUPERVISOR_PID_FD),
                (exit_reader.as_raw_fd(), SUPERVISOR_EXIT_FD),
            ],
        );
        let child = command.spawn().expect("spawn supervisor");
        drop(exit_reader);
        drop(pid_reader);

        FakeSupervisor {
            dir,
            child,
            pid_writer: Some(File::from(pid_writer)),
            _exit_writer: exit_writer,
        }
    }

    /// An ordinary policy still fits one transaction per family, and both hooks
    /// ride in it, so a hook is never live over a partially built chain.
    #[test]
    fn each_family_is_restored_from_its_own_payload_in_one_transaction() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        let calls = supervisor.rule_log();
        assert_eq!(calls.len(), 2, "{calls:?}");
        for (call, tool) in calls.iter().zip(["iptables-restore", "ip6tables-restore"]) {
            assert!(call.contains(tool), "{calls:?}");
            assert!(call.contains(" -n "), "restore must be additive: {call}");
        }

        for tool in ["iptables", "ip6tables"] {
            let lines: Vec<String> = supervisor
                .payload_lines()
                .into_iter()
                .filter_map(|line| line.strip_prefix(&format!("{tool} ")).map(str::to_owned))
                .collect();
            assert_eq!(lines.first().map(String::as_str), Some("*filter"), "{tool}");
            assert_eq!(
                lines[lines.len() - 3],
                format!("-A OUTPUT -j {TEST_CHAIN}"),
                "the {tool} egress hook must be committed with its chain"
            );
            assert_eq!(
                lines[lines.len() - 2],
                format!("-A INPUT -j {TEST_INGRESS_CHAIN}"),
                "the {tool} ingress hook must be committed with its chain"
            );
            assert_eq!(lines.last().map(String::as_str), Some("COMMIT"), "{tool}");
        }
    }

    /// The inbound chain has to survive the trip through the supervisor, not
    /// just the renderer: it is only real once iptables receives it.
    #[test]
    fn the_supervisor_installs_the_inbound_chain_alongside_the_outbound_one() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        for tool in ["iptables", "ip6tables"] {
            let lines: Vec<String> = supervisor
                .payload_lines()
                .into_iter()
                .filter_map(|line| line.strip_prefix(&format!("{tool} ")).map(str::to_owned))
                .collect();
            assert!(
                lines.contains(&format!(":{TEST_INGRESS_CHAIN} - [0:0]")),
                "{tool} must declare the inbound chain: {lines:?}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("ESTABLISHED,RELATED -j ACCEPT")),
                "{tool} must keep replies flowing: {lines:?}"
            );
        }

        assert_eq!(
            supervisor.rule_log().len(),
            2,
            "the inbound chain must not cost an extra transaction"
        );
    }

    /// Executing the script also re-checks that the whole policy travels in
    /// the restore transactions the budget is sized for.
    #[test]
    fn the_supervisor_signals_readiness_only_after_every_rule_is_installed() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert_eq!(
            supervisor.rule_invocations(),
            2,
            "readiness was signalled after a different number of restores than the \
             startup budget is sized for; stderr: {}",
            supervisor.stderr()
        );
    }

    /// Batching is the point: an ordinary policy costs two transactions however
    /// many host rules it carries.
    #[test]
    fn a_policy_plan_installs_a_fixed_number_of_commands() {
        for rule_count in [0, 1, 5, 50] {
            let plan = plan_with_rule_count(rule_count);
            let mut supervisor =
                spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
            supervisor.publish_sandbox_pid();
            supervisor.wait_until_ready();

            assert_eq!(
                supervisor.rule_invocations(),
                2,
                "a {rule_count}-rule policy installed the wrong number of commands; \
                 stderr: {}",
                supervisor.stderr()
            );
            assert_eq!(
                supervisor
                    .chain_rules()
                    .iter()
                    .filter(|rule| rule.contains(" -d "))
                    .count(),
                rule_count,
                "a {rule_count}-rule policy reached iptables with the wrong rule count"
            );
        }
    }

    /// The regression the byte budget exists for. A policy too large for one
    /// netlink transaction must still arrive complete and in order, spread over
    /// as many restores as it takes -- the previous single-transaction renderer
    /// failed the whole table instead, and installed nothing.
    #[test]
    fn a_policy_too_large_for_one_transaction_is_split_and_still_arrives_whole() {
        let rule_count = 2000;
        let plan = plan_with_rule_count(rule_count);
        let mut supervisor = spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert!(
            supervisor.rule_invocations() > 2,
            "a {rule_count}-rule policy must not fit two transactions, or this test \
             is not exercising the split"
        );

        let installed: Vec<String> = supervisor
            .chain_rules()
            .into_iter()
            .filter(|rule| rule.contains(" -d "))
            .collect();
        assert_eq!(
            installed.len(),
            rule_count,
            "splitting dropped rules; stderr: {}",
            supervisor.stderr()
        );
        // Order is the policy, so the split must preserve it end to end.
        for (index, rule) in installed.iter().enumerate() {
            let expected = format!(" -d 10.0.{}.{} ", index / 256, index % 256);
            assert!(
                rule.contains(&expected),
                "rule {index} arrived out of order: {rule}"
            );
        }
    }

    /// The fail-closed guarantee of the whole feature: a restore that does not
    /// apply must take the supervisor down *before* readiness, so the parent
    /// never releases a sandbox whose egress is unenforced.
    ///
    /// Asserting it for every position is the point. A future edit that moves
    /// one command into a pipeline, an `if` condition or a subshell escapes
    /// `set -e` and would start an unenforced sandbox while every text-matching
    /// test above stayed green.
    #[test]
    fn a_failed_rule_kills_the_supervisor_instead_of_signalling_readiness() {
        let plan = plan_with_rule_count(3);
        for rule in 1..=2 {
            let mut supervisor =
                spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), Some(rule), false);
            supervisor.publish_sandbox_pid();
            let status = supervisor.wait_for_exit();

            assert!(
                !status.success(),
                "restore {rule} failed but the supervisor exited successfully; stderr: {}",
                supervisor.stderr()
            );
            assert!(
                !supervisor.signalled_ready(),
                "restore {rule} failed yet the sandbox was signalled ready -- it would \
                 have run with unenforced egress"
            );
            assert_eq!(
                supervisor.rule_invocations(),
                rule,
                "restore {rule} failed but the script carried on installing rules"
            );
        }
    }

    /// The chain the workload actually runs under, for a policy the reviewer
    /// can read off the config. Ordering is asserted as a whole sequence
    /// because in a first-match chain a correct set of rules in the wrong order
    /// is a different policy.
    #[test]
    fn a_block_policy_accepts_only_its_allowlist_and_closes_both_families() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.default_network_policy = wxc_common::models::NetworkPolicy::Block;
        request.policy.allowed_hosts = vec!["203.0.113.7".into(), "2001:db8::/32".into()];
        let plan = EgressPlan::for_policy(&request).expect("literals must build a plan");

        let mut supervisor = spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert_eq!(
            supervisor.chain_rules(),
            vec![
                "iptables -o lo -j ACCEPT".to_string(),
                "iptables -d 203.0.113.7 -j ACCEPT".to_string(),
                "iptables -j DROP".to_string(),
                "ip6tables -o lo -j ACCEPT".to_string(),
                "ip6tables -d 2001:db8::/32 -j ACCEPT".to_string(),
                "ip6tables -j DROP".to_string(),
            ],
            "stderr: {}",
            supervisor.stderr()
        );
    }

    /// D4: an explicit deny beats a broader allow. In an ordered chain that is
    /// purely a question of which rule is appended first, so it is asserted
    /// against what reached iptables rather than against the plan alone.
    #[test]
    fn an_allow_policy_denies_its_blocklist_before_the_open_terminal() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.default_network_policy = wxc_common::models::NetworkPolicy::Allow;
        request.policy.blocked_hosts = vec!["198.51.100.0/24".into()];
        request.policy.allowed_hosts = vec!["198.51.100.9".into()];
        let plan = EgressPlan::for_policy(&request).expect("literals must build a plan");

        let mut supervisor = spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        let rules = supervisor.chain_rules();
        let deny = rules
            .iter()
            .position(|rule| rule == "iptables -d 198.51.100.0/24 -j DROP")
            .expect("the deny must be installed");
        let allow = rules
            .iter()
            .position(|rule| rule == "iptables -d 198.51.100.9 -j ACCEPT")
            .expect("the allow must be installed");
        let terminal = rules
            .iter()
            .position(|rule| rule == "iptables -j ACCEPT")
            .expect("an allow policy must end in ACCEPT");

        assert!(
            deny < allow,
            "the narrower deny must be evaluated first, or it never matches: {rules:?}"
        );
        assert!(
            allow < terminal,
            "the open terminal must come last: {rules:?}"
        );
    }

    /// The proxy posture must be byte-for-byte what it was before the rule list
    /// generalised it: this path is already reviewed and already shipping.
    #[test]
    fn the_proxy_posture_is_unchanged_by_the_rule_list() {
        let plan = EgressPlan::for_proxy(Ipv4Addr::new(10, 1, 2, 3), 3128);
        let mut supervisor = spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert_eq!(
            supervisor.chain_rules(),
            vec![
                "iptables -o lo -j ACCEPT".to_string(),
                "iptables -p tcp -d 10.1.2.3 --dport 3128 -j ACCEPT".to_string(),
                "iptables -j DROP".to_string(),
                "ip6tables -o lo -j ACCEPT".to_string(),
                "ip6tables -j DROP".to_string(),
            ],
            "stderr: {}",
            supervisor.stderr()
        );
    }

    /// An IPv4-only rule set must still close IPv6, or the sandbox keeps a
    /// silent v6 exit that no rule in the config mentions.
    #[test]
    fn a_v4_only_policy_still_closes_ipv6() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.default_network_policy = wxc_common::models::NetworkPolicy::Block;
        request.policy.allowed_hosts = vec!["203.0.113.7".into()];
        let plan = EgressPlan::for_policy(&request).expect("literals must build a plan");

        let mut supervisor = spawn_fake_supervisor_with_plan(&plan, &denied_ingress(), None, false);
        supervisor.publish_sandbox_pid();
        supervisor.wait_until_ready();

        assert!(
            supervisor
                .chain_rules()
                .contains(&"ip6tables -j DROP".to_string()),
            "IPv6 was left open by a v4-only policy: {:?}",
            supervisor.chain_rules()
        );
    }

    #[test]
    fn the_supervisor_gives_up_when_slirp_dies_before_signalling_readiness() {
        let mut supervisor = spawn_fake_supervisor(None, true);
        supervisor.publish_sandbox_pid();
        let status = supervisor.wait_for_exit();

        assert!(!status.success(), "a dead slirp must fail the startup");
        assert!(!supervisor.signalled_ready());
        assert!(
            supervisor.stderr().contains("before signalling readiness"),
            "the failure must say slirp never came up: {}",
            supervisor.stderr()
        );
        assert_eq!(
            supervisor.rule_invocations(),
            0,
            "rules were installed against a namespace with no connectivity"
        );
    }

    /// The blocking read on the PID pipe exists so a supervisor whose parent
    /// died exits instead of spinning as an orphan holding a namespace.
    #[test]
    fn the_supervisor_exits_when_the_parent_never_publishes_the_sandbox_pid() {
        let mut supervisor = spawn_fake_supervisor(None, false);
        supervisor.abandon_without_publishing_pid();
        let status = supervisor.wait_for_exit();

        assert!(
            !status.success(),
            "an unpublished PID must fail the startup"
        );
        assert!(!supervisor.signalled_ready());
        assert!(
            supervisor.stderr().contains("before publishing"),
            "the failure must name the missing PID: {}",
            supervisor.stderr()
        );
        assert_eq!(supervisor.rule_invocations(), 0);
    }
}
