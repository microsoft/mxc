// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inbound network policy enforcement via iptables, scoped to the container's
//! own network namespace.
//!
//! Implements the `allowLocalNetwork` inbound control for the LXC backend:
//! host-to-container and external inbound traffic is dropped by default. This
//! is a **separate, orthogonal chain** from the egress control in
//! [`crate::network_iptables`]: the egress chain lives in the host netns, is
//! hooked into `FORWARD` on the container's veth interface, and filters by
//! destination; this ingress chain lives in the *container's* netns (reached
//! via `nsenter -t <init-pid> -n`), is hooked into `INPUT`, and filters by
//! connection state. The two chains share only main's chain-naming and IPv6
//! probing machinery, and they carry distinct chain names
//! ([`ingress_chain_name_for`] vs
//! [`chain_name_for`](crate::network_iptables::chain_name_for)) so neither can
//! ever tear down or collide with the other.
//!
//! **Dual-stack.** A dual-stack container is reachable over IPv4 or IPv6, so an
//! IPv4-only chain would let IPv6 inbound bypass the deny entirely. A rule set
//! is installed through `iptables` and, when the family is usable, a
//! separately built one through `ip6tables`; teardown removes both. The IPv6
//! set is not a verbatim replay of the IPv4 set: because IPv6 uses ICMPv6
//! Neighbor Discovery (RFC 4861) in place of IPv4's layer-2 ARP, and ND *is*
//! filtered by `ip6tables`, the IPv6 chain additionally accepts the ICMPv6
//! control-plane types (see [`IpFamily`] / [`ICMPV6_ALLOW_TYPES`]) so a
//! hardened default-deny container keeps working IPv6 address resolution and
//! autoconfiguration while ordinary new inbound connections stay dropped.
//! The usable-vs-fail-closed decision reuses the richer IPv6 probe
//! ([`NetworkIptablesManager::ip6tables_status`]), evaluated against the
//! *container's* namespace: `ip6tables` unusable is only safe when IPv6 is
//! positively known to be disabled there; when IPv6 is live but `ip6tables`
//! cannot run, the inbound deny is unenforceable for that family, so the run
//! fails closed rather than silently leaving IPv6 open.
//!
//! **Permissive path is not yet implemented.** Three settings ask for the
//! sandboxed process to bind, listen, and accept incoming connections:
//! `allowLocalNetwork: true`, its 0.8 successor
//! `network.ingress.default: "allow"`, and
//! `network.ingress.hostLoopback: "allow"`, which is new in 0.8 and has no 0.7
//! equivalent. LXC has a single inbound chain and the policy carries no way to
//! narrow an accept to particular ports, sources, or interfaces, so the only
//! rule available today is an unscoped
//! `--state NEW -j ACCEPT` accepting inbound from every interface and source, LAN
//! and WAN included. Rather than install that silently,
//! [`IngressManager::apply_firewall_rules`] returns a not-yet-implemented error
//! naming the field the operator wrote. Scoping the host-loopback field on its own
//! additionally needs a `loopbackPorts` policy field and an MXC-owned forwarder,
//! tracked as AB#63505947. The internal rule *builder* still supports both toggle
//! values so the decision table is testable.
//!
//! **Why the container netns.** A packet destined to a container socket
//! traverses the *container's* `INPUT` chain, inside the container's network
//! namespace — never the host's `INPUT` (the host only ever sees such packets
//! in `FORWARD`, if it routes them). So the rules are executed with
//! `nsenter -t <init-pid> -n iptables …`, landing them in the container's
//! netfilter tables. Egress (allow/deny lists, DNS, proxy) is a separate
//! control handled in [`crate::network_iptables`] and intentionally not here.

use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkIngressPolicy};

use crate::network_iptables::{
    ingress_chain_name_for, plan_network, HostIpv6State, Ip6tablesStatus, NetworkIptablesManager,
};

/// IP family an inbound chain is being built for.
///
/// The two families are *not* interchangeable at install time. IPv4 address
/// resolution is ARP, a layer-2 protocol that never traverses `iptables`, so
/// the IPv4 chain needs no special allowances. IPv6 replaces ARP with ICMPv6
/// Neighbor Discovery (RFC 4861) — Neighbor/Router Solicitation and
/// Advertisement — which rides on IPv6 and *is* filtered by `ip6tables`.
/// Inbound ND packets are connection-state `NEW`, so replaying the IPv4 rule
/// set (a single `--state NEW` accept-or-drop then a terminal `DROP`) into
/// `ip6tables` drops ND and breaks IPv6 address resolution and stateless
/// autoconfiguration. [`IpFamily::V6`] therefore additionally permits the
/// ICMPv6 control-plane types in [`ICMPV6_ALLOW_TYPES`]; [`IpFamily::V4`] does
/// not, so IPv4 behavior is unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    /// The packet-filter binary for this family.
    fn binary(self) -> &'static str {
        match self {
            IpFamily::V4 => "iptables",
            IpFamily::V6 => "ip6tables",
        }
    }

    /// Index into a per-family `[T; 2]`, so callers can track family-scoped
    /// state (e.g. "this family's teardown is blocked") without a map.
    fn index(self) -> usize {
        match self {
            IpFamily::V4 => 0,
            IpFamily::V6 => 1,
        }
    }
}

/// ICMPv6 message types the IPv6 inbound chain accepts so a hardened
/// default-deny container still has a functioning IPv6 stack. Numeric values
/// are used rather than names because RFC 4443 defines the numbers
/// normatively, so they are unambiguous and cannot be mis-spelled; each is
/// annotated with its RFC 4443 name below. Note that the named forms are not
/// known to be broken — `ip6tables` v1.8.10 (nf_tables) resolves both
/// `neighbour-solicitation` and `neighbor-solicitation` — so the numbers are
/// chosen for determinism, not to work around a specific build.
/// Selection follows RFC 4890 ("Recommendations for Filtering ICMPv6
/// Messages in Firewalls"):
///
///   - 133–136 Neighbor Discovery (RS/RA/NS/NA) — RFC 4890 §4.4.1 "must not be
///     dropped"; without these IPv6 address resolution and SLAAC stop working.
///   - 130–132, 143 Multicast Listener Discovery — RFC 4890 §4.3.1; required
///     for multicast group membership, which ND itself relies on
///     (solicited-node multicast).
///   - 1–4 essential errors (destination-unreachable, packet-too-big,
///     time-exceeded, parameter-problem) — RFC 4890 §4.4.1 "must not be
///     dropped"; packet-too-big (2) in particular is required for Path MTU
///     Discovery.
///
/// Echo request/reply (128/129) and Redirect (137) are deliberately *omitted*:
/// leaving inbound ping and router redirects dropped keeps the hardened
/// posture (RFC 4890 permits dropping echo at a firewall), while every type
/// above is needed for basic IPv6 operation. Ordinary `NEW` inbound
/// connections are still dropped — only these control-plane types are opened.
const ICMPV6_ALLOW_TYPES: [&str; 12] = [
    // Neighbor Discovery (RFC 4861), RFC 4890 §4.4.1.
    "133", // router-solicitation
    "134", // router-advertisement
    "135", // neighbor-solicitation
    "136", // neighbor-advertisement
    // Multicast Listener Discovery (RFC 2710 / RFC 3810), RFC 4890 §4.3.1.
    "130", // multicast-listener-query
    "131", // multicast-listener-report
    "132", // multicast-listener-done
    "143", // multicast-listener-report-v2
    // Essential error messages, RFC 4890 §4.4.1.
    "1", // destination-unreachable
    "2", // packet-too-big (Path MTU Discovery)
    "3", // time-exceeded
    "4", // parameter-problem
];

/// Manages the container's inbound iptables `INPUT` chain.
pub struct IngressManager {
    /// Deterministic chain name for this container, prefixed distinctly from
    /// the egress chain. See [`ingress_chain_name_for`] for the collision
    /// bound.
    chain_name: String,
    /// PID of the container's init process. **Mandatory** — the ingress chain
    /// is *defined* as living inside the container's own network namespace, so
    /// every `iptables`/`ip6tables` invocation is executed via
    /// `nsenter -t <pid> -n`. The IPv6 address probe instead reads
    /// `/proc/<pid>/net/if_inet6`, which names the same namespace by PID
    /// without entering it. A caller that cannot supply a PID must not
    /// construct an `IngressManager` at all. See `lxc_runner`, which aborts the
    /// run when a firewall mode is requested but no init PID can be found.
    netns_pid: u32,
    /// Per-resource ownership. What we actually created or hooked, tracked
    /// separately per family, so teardown attempts only the operations this run
    /// has something to undo. A single `bool` cannot distinguish "created the
    /// v4 chain but not v6" from "created nothing", and every choice of *when*
    /// to flip one flag is wrong because the flag cannot carry the information
    /// teardown needs. Each flag is set immediately after that specific command
    /// succeeds — never before, never batched — and cleared as its resource is
    /// torn down. Note the unhook step is deliberately broader than the flag:
    /// it removes every matching `INPUT` reference, not only the one this run
    /// installed.
    v4_chain_created: bool,
    v6_chain_created: bool,
    v4_hooked: bool,
    v6_hooked: bool,
    /// Whether the caller asked for a successfully installed policy to outlive
    /// this run (the lifecycle's `preservePolicy`). Consulted by [`Drop`] and
    /// not only by the runner's explicit teardown call, because `Drop` fires on
    /// every path out of the run and would otherwise silently undo the request.
    preserve_policy: bool,
    /// True when the request declared the directional (0.8) network schema.
    /// Required at construction: unlike the egress manager there is no legacy
    /// caller to default for, and a run that forgot to state it would silently
    /// enforce the wrong schema.
    uses_directional_schema: bool,
}

/// The outcome of a single `iptables`/`ip6tables` invocation, structured so the
/// cleanup path can tell "the object is gone" from "the command could not run".
///
/// Only [`RunError::Exit`] — the command ran and exited non-zero — may ever be
/// read as "already absent", and only against iptables' own missing-object
/// message. [`RunError::Spawn`] (the binary or `nsenter` could not be executed)
/// is *always* a real error: it is the strongest possible evidence that the
/// state is unknown, never proof that there is nothing to remove.
enum RunError {
    /// The command could not be spawned at all (binary missing, `nsenter`
    /// missing, exec failure). Never treated as absence.
    Spawn(String),
    /// The command ran and exited non-zero. `stderr` is iptables' own message —
    /// the only thing that may indicate an object was already absent.
    Exit { stderr: String, msg: String },
}

impl RunError {
    /// The human-readable message for logging or returning.
    fn into_message(self) -> String {
        match self {
            RunError::Spawn(msg) => msg,
            RunError::Exit { msg, .. } => msg,
        }
    }

    /// The human-readable message, borrowed — for logging without consuming the
    /// error (the caller still needs to classify it).
    fn message(&self) -> &str {
        match self {
            RunError::Spawn(msg) => msg,
            RunError::Exit { msg, .. } => msg,
        }
    }
}

/// A single teardown command against one family's chain.
struct TeardownStep {
    family: IpFamily,
    kind: StepKind,
    /// iptables args (not `nsenter`-prefixed); the executor wraps them.
    args: Vec<String>,
}

/// Which teardown operation a [`TeardownStep`] performs. Determines both the
/// order (unhook before flush before delete) and which "already absent" message
/// is acceptable for that step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StepKind {
    Unhook,
    Flush,
    Delete,
}

impl StepKind {
    /// Whether this step's non-zero exit means the target was *already gone*
    /// (so removal is a no-op), matched only against iptables' actual messages.
    /// A spawn failure never reaches here — it is a real error by construction.
    fn stderr_means_absent(self, stderr: &str) -> bool {
        let s = stderr.to_ascii_lowercase();
        // An absent chain is reported without the "no chain/target/match"
        // phrasing.  iptables 1.8.10, nf_tables: "Chain 'X' does not exist";
        // legacy: "Couldn't load target `X':No such file or directory".
        let absent_chain = s.contains("does not exist") || s.contains("couldn't load target");
        match self {
            // The jump rule is absent because its target chain is gone, or
            // because the chain remains with no INPUT reference left.
            StepKind::Unhook => {
                s.contains("no chain/target/match by that name")
                    || s.contains("does a matching rule exist")
                    || absent_chain
            }
            // Flushing or deleting a chain that does not exist.
            StepKind::Flush | StepKind::Delete => {
                s.contains("no chain/target/match by that name") || absent_chain
            }
        }
    }
}

impl TeardownStep {
    /// `-D INPUT -j <chain>`: remove one INPUT jump to the chain.
    fn unhook(family: IpFamily, chain: &str) -> Self {
        Self {
            family,
            kind: StepKind::Unhook,
            args: vec![
                "-D".to_string(),
                "INPUT".to_string(),
                "-j".to_string(),
                chain.to_string(),
            ],
        }
    }

    /// `-F <chain>`: empty the chain.
    fn flush(family: IpFamily, chain: &str) -> Self {
        Self {
            family,
            kind: StepKind::Flush,
            args: vec!["-F".to_string(), chain.to_string()],
        }
    }

    /// `-X <chain>`: delete the (now empty, unreferenced) chain.
    fn delete(family: IpFamily, chain: &str) -> Self {
        Self {
            family,
            kind: StepKind::Delete,
            args: vec!["-X".to_string(), chain.to_string()],
        }
    }
}

/// Upper bound on `-D INPUT -j <chain>` repetitions when unhooking during a
/// reset or teardown. One `-D` removes one reference and a crashed run may have
/// left several, but a count this high can only mean the delete is not making
/// progress; we treat exhausting the bound as a real error rather than spin
/// forever.
const MAX_UNHOOK_ATTEMPTS: usize = 128;

/// Executes one fully-formed (already `nsenter`-wrapped) `iptables`/`ip6tables`
/// command and classifies its outcome.
///
/// A seam: production wraps `Command`, and tests substitute a runner that
/// captures the argv and scripts outcomes without spawning a process. Because
/// the manager builds the `nsenter -t <pid> -n …` prefix *before* calling the
/// runner, a test runner observes the exact argv the host would execute — so
/// the "every command targets the container netns" invariant is testable on any
/// host.
trait CommandRunner {
    fn run(&mut self, argv: &[String]) -> Result<(), RunError>;
}

/// Build the `iptables`/`ip6tables` invocation with the message locale pinned.
///
/// [`StepKind::stderr_means_absent`] decides whether a non-zero exit means the
/// target was already gone by matching iptables' own diagnostic text, and that
/// text is localized. A subprocess inherits the host environment, so on a host
/// running a non-English locale the benign "no chain by that name" message
/// arrives translated, fails every match, and turns an idempotent teardown step
/// into a fatal error — which aborts each fresh install, because install resets
/// any leftover state before creating the chain. Exit codes cannot substitute:
/// iptables returns 1 both for "no such chain" and for real failures.
///
/// Only these two keys are set, so the child keeps the rest of the environment
/// it needs (`PATH` above all). `LANG` is pinned alongside `LC_ALL` because it
/// is the fallback consulted when `LC_ALL` is absent.
///
/// Split out from [`NsenterRunner::run`] so the guarantee is unit testable:
/// `run` spawns a real process and cannot execute in a test, but the [`Command`]
/// it would spawn can be inspected.
fn nsenter_command(argv: &[String]) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    // `nsenter` execs the target binary in this same environment, so pinning
    // here reaches `iptables` itself.
    command.env("LC_ALL", "C").env("LANG", "C");
    command
}

/// The production [`CommandRunner`]: spawns the argv and distinguishes a spawn
/// failure (state unknown, always a real error) from a non-zero exit (whose
/// stderr may mean "already absent").
struct NsenterRunner;

impl CommandRunner for NsenterRunner {
    fn run(&mut self, argv: &[String]) -> Result<(), RunError> {
        let output = match nsenter_command(argv).output() {
            Ok(output) => output,
            Err(e) => {
                return Err(RunError::Spawn(format!(
                    "Failed to spawn '{}': {}",
                    argv.join(" "),
                    e
                )));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let msg = format!("{} failed: {}", argv.join(" "), stderr);
            return Err(RunError::Exit { stderr, msg });
        }

        Ok(())
    }
}

/// Build the full argv for running `binary args...` inside the network
/// namespace of process `netns_pid`: `["nsenter", "-t", <pid>, "-n", binary,
/// args...]`. Pure — no process execution — so the `nsenter` wrapping (the
/// guarantee that every mutating command targets the container netns and never
/// the host) is unit-testable.
fn build_nsenter_argv(netns_pid: u32, binary: &str, args: &[&str]) -> Vec<String> {
    let mut argv = vec![
        "nsenter".to_string(),
        "-t".to_string(),
        netns_pid.to_string(),
        "-n".to_string(),
        binary.to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    argv
}

/// One family's inbound rules, split so install cannot confuse the chain body
/// with the `INPUT` hook. The `-N` creation appears in neither field: the
/// caller issues it explicitly so its success gates ownership. Keeping the hook
/// separate lets install append the body first and hook *last*, so a hooked
/// chain is never momentarily empty.
struct IngressRules {
    /// The `-A` rules that populate the chain, in order: loopback, established,
    /// ICMPv6 (IPv6 only), the NEW-state decision, and the terminal drop.
    body: Vec<Vec<String>>,
    /// The `-I INPUT -j <chain>` jump, installed last after the body is in
    /// place.
    hook: Vec<String>,
}

impl IngressManager {
    /// Create a new manager for the given container name and init PID.
    ///
    /// The PID is required: the chain is enforced inside the container's own
    /// netns, so there is no way to install or probe it without one.
    pub fn new(container_name: &str, netns_pid: u32, uses_directional_schema: bool) -> Self {
        Self {
            chain_name: ingress_chain_name_for(container_name),
            netns_pid,
            v4_chain_created: false,
            v6_chain_created: false,
            v4_hooked: false,
            v6_hooked: false,
            preserve_policy: false,
            uses_directional_schema,
        }
    }

    /// Ask for the installed chain to outlive this manager, honoring the
    /// lifecycle's `preservePolicy`.
    ///
    /// Call this only after [`Self::apply_firewall_rules`] has reported success.
    /// The flag suppresses [`Drop`]'s teardown, so setting it beforehand would
    /// strand whatever partial chain a failed install left behind — enforcement
    /// the caller never asked for and did not know to look for.
    pub fn set_preserve_policy(&mut self, preserve: bool) {
        self.preserve_policy = preserve;
    }

    /// Whether [`Drop`] should tear the chain down.
    ///
    /// Extracted as a pure predicate because `Drop` itself runs against the real
    /// `nsenter` path and so cannot be exercised in a unit test. Keeping the
    /// decision here means the `preservePolicy` gate stays tested even though
    /// the teardown it guards does not.
    fn should_cleanup_on_drop(&self) -> bool {
        self.rules_applied() && !self.preserve_policy
    }

    /// The iptables chain name this manager owns.
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// Whether this run installed anything that still needs cleanup. Derived
    /// from the per-resource flags rather than stored, so it can never disagree
    /// with what teardown will actually remove.
    pub fn rules_applied(&self) -> bool {
        self.v4_chain_created || self.v6_chain_created || self.v4_hooked || self.v6_hooked
    }

    /// Record that this run created `family`'s chain.
    fn set_created(&mut self, family: IpFamily) {
        match family {
            IpFamily::V4 => self.v4_chain_created = true,
            IpFamily::V6 => self.v6_chain_created = true,
        }
    }

    /// Record that this run hooked `family`'s chain into INPUT.
    fn set_hooked(&mut self, family: IpFamily) {
        match family {
            IpFamily::V4 => self.v4_hooked = true,
            IpFamily::V6 => self.v6_hooked = true,
        }
    }

    fn created(&self, family: IpFamily) -> bool {
        match family {
            IpFamily::V4 => self.v4_chain_created,
            IpFamily::V6 => self.v6_chain_created,
        }
    }

    fn hooked(&self, family: IpFamily) -> bool {
        match family {
            IpFamily::V4 => self.v4_hooked,
            IpFamily::V6 => self.v6_hooked,
        }
    }

    fn clear_created(&mut self, family: IpFamily) {
        match family {
            IpFamily::V4 => self.v4_chain_created = false,
            IpFamily::V6 => self.v6_chain_created = false,
        }
    }

    fn clear_hooked(&mut self, family: IpFamily) {
        match family {
            IpFamily::V4 => self.v4_hooked = false,
            IpFamily::V6 => self.v6_hooked = false,
        }
    }

    /// The 0.8 `network.ingress` section, or `None` when this run was given the
    /// legacy schema.
    fn stated_ingress(
        policy: &ContainerPolicy,
        uses_directional_schema: bool,
    ) -> Option<&NetworkIngressPolicy> {
        if uses_directional_schema {
            policy.network_ingress.as_ref()
        } else {
            None
        }
    }

    /// The policy field asking for permissive inbound, if any, named as the
    /// operator wrote it.
    ///
    /// 0.7 states this in `allowLocalNetwork`; 0.8 splits it across
    /// `network.ingress.default` and `network.ingress.hostLoopback`, but
    /// LXC's single inbound chain refuses either `allow` value alike.
    fn permissive_inbound_field(
        policy: &ContainerPolicy,
        uses_directional_schema: bool,
    ) -> Option<&'static str> {
        if let Some(ingress) = Self::stated_ingress(policy, uses_directional_schema) {
            if ingress.default == NetworkAction::Allow {
                return Some("network.ingress.default");
            }
            if ingress.host_loopback == NetworkAction::Allow {
                return Some("network.ingress.hostLoopback");
            }
            return None;
        }

        policy.allow_local_network.then_some("allowLocalNetwork")
    }

    /// Apply the inbound firewall rules for `policy`.
    ///
    /// Delegates argv construction to the pure [`Self::build_ingress_rules`]
    /// (unit-testable without root or `iptables`), then executes each resulting
    /// vector inside the container netns via `nsenter -t <pid> -n`.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let uses_directional_schema = self.uses_directional_schema;
        if !plan_network(policy, uses_directional_schema).installs_firewall() {
            logger.log_line("Network policy requests no firewall; skipping ingress chain.");
            return Ok(true);
        }

        // Refusing also keeps the support declaration honest: LXC claims the
        // 0.8 ingress bits because it enforces their `deny` values, and a bit
        // claimed is a promise to either enforce the field or reject it.
        // Unconditional: we always have a real container netns to hook (the PID
        // is mandatory), so there is no inert path that could safely emit it.
        if let Some(field) = Self::permissive_inbound_field(policy, uses_directional_schema) {
            return Err(format!(
                "{field} asks for permissive inbound, which is not yet implemented for \
                 the LXC firewall path. LXC has a single inbound chain and the policy \
                 carries no way to scope an accept to particular ports, sources, or \
                 interfaces; the only rule available today would accept new inbound \
                 connections from every interface and source (LAN and WAN), which is \
                 broader than requested. Refusing rather than installing an over-broad \
                 accept."
            ));
        }

        logger.log_line(&format!(
            "Creating inbound iptables chain: {}",
            self.chain_name
        ));
        let inbound_field = if uses_directional_schema {
            "network.ingress"
        } else {
            "allowLocalNetwork"
        };
        logger.log_line(&format!(
            "Inbound ({inbound_field}) policy: {}",
            if policy.allow_local_network {
                "ACCEPT new inbound connections"
            } else {
                "DROP new inbound connections (default-deny)"
            }
        ));

        // Every command lands in the container netns via `nsenter -t <pid> -n`.
        let mut runner = NsenterRunner;

        // Decide IPv6 enforcement against the *container's* namespace, not the
        // host's: a host that reports IPv6 disabled says nothing about the
        // namespace we are actually filtering. Fail-closed semantics are
        // preserved — IPv6 live in the container but ip6tables unusable there
        // => abort; ip6tables unusable AND IPv6 positively disabled *in that
        // namespace* => the IPv4 chain alone is acceptable.
        let ipv6_enabled = match self.container_ip6tables_status(&mut runner, logger) {
            Ip6tablesStatus::Available => true,
            Ip6tablesStatus::KernelIpv6Disabled => {
                logger.log_line(
                    "ip6tables unusable and no live IPv6 stack in the container namespace; \
                     enforcing the IPv4 inbound policy only.",
                );
                false
            }
            Ip6tablesStatus::UnusableButIpv6Active => {
                return Err(format!(
                    "ip6tables is unusable in the container namespace but IPv6 is live there, \
                     so inbound IPv6 for chain '{}' cannot be denied. Refusing to start with an \
                     unenforceable inbound policy: disable IPv6 in the container, or \
                     install/enable ip6tables.",
                    self.chain_name
                ));
            }
        };

        let ipv4_rules = Self::build_ingress_rules(
            &self.chain_name,
            policy,
            uses_directional_schema,
            IpFamily::V4,
        );

        // Install per family, tracking ownership per resource. The IPv4 chain is
        // always installed; the IPv6 chain only when the family is usable in the
        // container namespace, so IPv6 inbound cannot bypass an IPv4-only deny on
        // a dual-stack container. The two rule sets are not identical: the IPv6
        // set additionally permits ICMPv6 Neighbor Discovery (see [`IpFamily`]).
        //
        // Each `install_family` resets any leftover to a known-empty baseline,
        // then sets `created`/`hooked` immediately after the specific command
        // succeeds, so a failure partway through returns via `?` with exactly
        // the flags for what was actually installed. `Drop` and
        // `remove_firewall_rules` then tear down precisely that partial state —
        // no more (which would destroy a chain we did not create) and no less
        // (which would leak installed rules).
        self.install_family(IpFamily::V4, &ipv4_rules, &mut runner, logger)?;
        if ipv6_enabled {
            let ipv6_rules = Self::build_ingress_rules(
                &self.chain_name,
                policy,
                uses_directional_schema,
                IpFamily::V6,
            );
            self.install_family(IpFamily::V6, &ipv6_rules, &mut runner, logger)?;
        }

        Ok(true)
    }

    /// Install one family's chain: reset any leftover to a known-empty baseline,
    /// create the chain fresh, append the body rules, then hook into INPUT last
    /// — marking ownership immediately after each specific command succeeds.
    ///
    /// The hook is added only after the body is fully in place, so a chain
    /// this call hooks is never momentarily empty. That covers the fresh-install
    /// case only. When a *leftover* hooked chain from a crashed run exists, step
    /// 1's reset unhooks it before the replacement is built, so whatever that
    /// leftover was still enforcing lapses until the new hook lands at step 4.
    /// Closing that gap needs an atomic swap this call cannot express, and the
    /// gap is contained inside the larger window between container start and
    /// ingress install. Neither is closed here. Because the reset removes every
    /// prior reference first (see [`Self::reset_family`]), one `hooked` flag per
    /// family is enough to describe what this install added. Ownership is
    /// recorded per resource, so a failure partway through tears down what this
    /// run installed.
    fn install_family(
        &mut self,
        family: IpFamily,
        rules: &IngressRules,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let binary = family.binary();
        let chain = self.chain_name.clone();

        // 1. Force a known-empty baseline, removing any leftover of our own from
        //    a crashed run (deterministic per-container name — see
        //    `reset_family`). This closes the duplicate-hook and stale-rule
        //    hazards before we create anything.
        self.reset_family(family, runner, logger)?;

        // 2. Create the chain fresh — the reset guarantees it does not already
        //    exist, so `-N` cannot fail with "chain already exists". Sets
        //    `created` only on success.
        self.run(runner, binary, &["-N", &chain], logger)
            .map_err(RunError::into_message)?;
        self.set_created(family);

        // 3. Append the body rules (loopback, established, ICMPv6, NEW decision,
        //    terminal drop). Neither `-N` nor `-I` appears here — those are
        //    issued explicitly so their success gates the ownership flags.
        for rule in &rules.body {
            let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
            self.run(runner, binary, &argv, logger)
                .map_err(RunError::into_message)?;
        }

        // 4. Hook into INPUT last, after the chain is fully populated. Sets
        //    `hooked` only after the jump is in place.
        let hook: Vec<&str> = rules.hook.iter().map(String::as_str).collect();
        self.run(runner, binary, &hook, logger)
            .map_err(RunError::into_message)?;
        self.set_hooked(family);

        Ok(())
    }

    /// Reset `family`'s chain to a known-empty baseline before (re)creating it.
    ///
    /// Unconditional by design. The chain lives inside *this container's own*
    /// network namespace, and the name is deterministic per container, so
    /// anything found under it there is this container's own leftover from a
    /// crashed or killed run. (Namespace scoping is what makes that true — the
    /// name alone is not unique across LXC storage paths.) We do not try to
    /// *infer* what the leftover was from a single error message, because one
    /// message cannot distinguish one stale `INPUT` reference from several.
    /// Instead we *force* a known state: remove every INPUT reference (there
    /// may be more than one), then flush and delete any existing chain. This
    /// reuses the same over-approximating teardown planner and executor as
    /// `force_cleanup` ("assume everything might exist"), so install-time reset
    /// and ownership teardown share one shape. A genuinely absent rule or chain
    /// is a no-op; any real failure aborts install fail-closed.
    fn reset_family(
        &mut self,
        family: IpFamily,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let steps = Self::reset_steps(family, &self.chain_name);
        self.execute_teardown(&steps, runner, logger)
    }

    /// The over-approximating teardown steps for `family`: assume the chain may
    /// exist and be hooked (possibly several times) and plan to remove all of
    /// it. Same shape and order as [`Self::owned_teardown_steps`] — unhook, then
    /// flush, then delete — so reset and ownership teardown share one plan.
    fn reset_steps(family: IpFamily, chain: &str) -> Vec<TeardownStep> {
        vec![
            TeardownStep::unhook(family, chain),
            TeardownStep::flush(family, chain),
            TeardownStep::delete(family, chain),
        ]
    }

    /// Run one command through `runner`, logging any failure. Returns the
    /// structured [`RunError`] so callers can classify it (spawn failure vs a
    /// non-zero exit whose stderr may mean "already absent"). Builds the
    /// `nsenter -t <pid> -n` prefix here, so every command the runner sees is
    /// already scoped to the container netns.
    fn run(
        &self,
        runner: &mut dyn CommandRunner,
        binary: &str,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<(), RunError> {
        let argv = self.nsenter_argv(binary, args);
        match runner.run(&argv) {
            Ok(()) => Ok(()),
            Err(e) => {
                logger.log_line(e.message());
                Err(e)
            }
        }
    }

    /// Build the ordered list of `iptables` argument vectors for `policy`.
    ///
    /// Pure: performs no process execution, no I/O, and no logging. Every
    /// input is passed in, so this compiles and can be unit-tested on any host.
    ///
    /// `family` selects the IP family. The IPv4 and IPv6 rule sets are
    /// intentionally *not* identical: the IPv6 set additionally accepts the
    /// ICMPv6 control-plane types in [`ICMPV6_ALLOW_TYPES`] (Neighbor Discovery,
    /// Multicast Listener Discovery, and essential errors) so a hardened
    /// default-deny container keeps a working IPv6 stack. The IPv4 set carries
    /// no ICMP allowances — IPv4 uses ARP, a layer-2 protocol iptables never
    /// sees.
    ///
    /// The `-I INPUT` jump is returned separately from the chain body ([`IngressRules`]),
    /// so install appends the body first and hooks *last* — a hooked chain is
    /// never momentarily empty. The `-N` creation is *not* included here: install
    /// issues it explicitly so its success can gate ownership. The chain is
    /// hooked into the container's `INPUT` chain (executed inside the container
    /// netns by the caller), so every packet it sees is destined *to a container
    /// socket*. The caller always has a container netns to enter (the PID is
    /// mandatory), so this never risks attaching to the host's own `INPUT`
    /// chain.
    fn build_ingress_rules(
        chain: &str,
        policy: &ContainerPolicy,
        uses_directional_schema: bool,
        family: IpFamily,
    ) -> IngressRules {
        fn argv(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| s.to_string()).collect()
        }

        let accept = "ACCEPT";
        let drop = "DROP";
        let mut body: Vec<Vec<String>> = Vec::new();

        // Intra-container loopback (127.0.0.1 / ::1 inside the sandbox) must
        // always pass — it is unaffected by the host-to-container inbound
        // policy.
        body.push(argv(&["-A", chain, "-i", "lo", "-j", accept]));

        // Accept return traffic for connections the container itself opened.
        // MUST precede the NEW-inbound decision below so container-initiated
        // flows survive an inbound DROP.
        body.push(argv(&[
            "-A",
            chain,
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            accept,
        ]));

        // IPv6 only: permit the ICMPv6 control-plane types a functioning IPv6
        // stack needs (Neighbor Discovery, Multicast Listener Discovery, and
        // essential errors). These arrive as `NEW`, so they MUST precede the
        // `--state NEW` decision and the terminal `DROP` below or address
        // resolution and autoconfiguration break. IPv4 emits nothing here —
        // ARP is layer 2 and never reaches iptables. See `ICMPV6_ALLOW_TYPES`
        // for the type list and RFC 4890 citation.
        if family == IpFamily::V6 {
            for icmpv6_type in ICMPV6_ALLOW_TYPES {
                body.push(argv(&[
                    "-A",
                    chain,
                    "-p",
                    "icmpv6",
                    "--icmpv6-type",
                    icmpv6_type,
                    "-j",
                    accept,
                ]));
            }
        }

        // Accept or drop NEW inbound connections to the container's listening
        // sockets. A permissive request is refused before any rule is built.
        let inbound_verb =
            if Self::permissive_inbound_field(policy, uses_directional_schema).is_some() {
                accept
            } else {
                drop
            };
        body.push(argv(&[
            "-A",
            chain,
            "-m",
            "state",
            "--state",
            "NEW",
            "-j",
            inbound_verb,
        ]));

        // Inbound default-deny: host/external inbound is blocked by default.
        // Deliberately independent of the egress `default_network_policy` — an
        // "allow" egress posture must not open the container to inbound.
        body.push(argv(&["-A", chain, "-j", drop]));

        // The hook into the container's INPUT chain, returned separately so
        // install can emit it last, after the body is fully in place.
        let hook = argv(&["-I", "INPUT", "-j", chain]);

        IngressRules { body, hook }
    }

    /// Remove the resources this run installed.
    ///
    /// Reads the per-resource ownership flags, tears each owned resource down in
    /// reverse order — unhook if hooked, then flush and delete if created — and
    /// clears each flag as its resource is removed. It never flushes or deletes a
    /// chain this run did not create. The unhook step is deliberately broader:
    /// it removes every matching `INPUT` reference, not only the one this run
    /// installed, because a crashed run can leave extras behind and a dangling
    /// jump to a deleted chain is worse than an extra delete.
    ///
    /// Failure handling is fail-closed for cleanup: a step whose command *ran
    /// and exited non-zero with iptables' own "already absent" message* is a
    /// no-op (the object is genuinely gone), but a spawn failure or any other
    /// exit error keeps that resource's ownership so `Drop` can retry, and the
    /// collected errors are returned as an `Err`. Crucially, if a family's
    /// unhook (or flush) fails for a real reason, the rest of that family's
    /// teardown is skipped: flushing a chain that is still hooked from INPUT
    /// would empty it while packets still traverse it. Converting a failed
    /// teardown into a silent success would strand real rules and block retry.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        let mut runner = NsenterRunner;
        self.remove_firewall_rules_with(&mut runner, logger)
    }

    /// Teardown against an injectable [`CommandRunner`] — the real path passes
    /// [`NsenterRunner`]; tests pass a runner that captures the planned argv.
    fn remove_firewall_rules_with(
        &mut self,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        if !self.rules_applied() {
            return Ok(());
        }

        logger.log_line(&format!(
            "Removing inbound iptables chain: {}",
            self.chain_name
        ));

        let steps = self.owned_teardown_steps();
        self.execute_teardown(&steps, runner, logger)
    }

    /// Execute an ordered list of teardown [`TeardownStep`]s, clearing each
    /// resource's ownership flag as it is removed.
    ///
    /// Shared by ownership teardown ([`Self::remove_firewall_rules_with`]) and
    /// install-time reset ([`Self::reset_family`]), so the two cannot drift.
    ///
    /// Failure handling is fail-closed. An unhook step loops `-D INPUT` until
    /// iptables reports no matching rule, removing every reference a crashed run
    /// may have left (bounded by [`MAX_UNHOOK_ATTEMPTS`]; exhausting the bound is
    /// a real error). A step whose command *ran and exited non-zero with
    /// iptables' own "already absent" message* is a no-op — the object is
    /// genuinely gone. A spawn failure or any other exit error keeps that
    /// resource's ownership (so `Drop` can retry) and, crucially, blocks the
    /// rest of *that family's* steps: we never flush or delete a chain we could
    /// not first unhook, which would empty a chain still referenced from INPUT.
    /// Any collected failure is returned as an `Err`.
    fn execute_teardown(
        &mut self,
        steps: &[TeardownStep],
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();
        // Once a family's teardown hits a real error we stop that family.
        let mut blocked = [false, false];

        for step in steps {
            let fi = step.family.index();
            if blocked[fi] {
                // Leave this resource's flag set so `Drop` retries it.
                continue;
            }
            let binary = step.family.binary();
            let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();

            match step.kind {
                StepKind::Unhook => {
                    // Remove every INPUT reference: one `-D` deletes one, and a
                    // crashed run may have left several. Loop until iptables
                    // reports no matching rule, bounded so a persistently
                    // failing delete cannot spin forever.
                    let mut cleared = false;
                    for _ in 0..MAX_UNHOOK_ATTEMPTS {
                        match self.run(runner, binary, &arg_refs, logger) {
                            // One reference gone; try again in case there are more.
                            Ok(()) => continue,
                            Err(RunError::Exit { ref stderr, .. })
                                if step.kind.stderr_means_absent(stderr) =>
                            {
                                cleared = true;
                                break;
                            }
                            Err(e) => {
                                failures.push(e.into_message());
                                blocked[fi] = true;
                                break;
                            }
                        }
                    }
                    if blocked[fi] {
                        continue;
                    }
                    if !cleared {
                        // Still deleting references after the bound: abnormal,
                        // treat as a real error rather than assume success.
                        let msg = format!(
                            "still removing INPUT references to chain '{}' after {} attempts",
                            self.chain_name, MAX_UNHOOK_ATTEMPTS
                        );
                        logger.log_line(&msg);
                        failures.push(msg);
                        blocked[fi] = true;
                        continue;
                    }
                    self.clear_hooked(step.family);
                }
                StepKind::Flush | StepKind::Delete => {
                    match self.run(runner, binary, &arg_refs, logger) {
                        Ok(()) => self.clear_step_flag(step),
                        Err(RunError::Exit { ref stderr, .. })
                            if step.kind.stderr_means_absent(stderr) =>
                        {
                            // The object is genuinely gone; removal is a no-op.
                            self.clear_step_flag(step);
                        }
                        Err(e) => {
                            failures.push(e.into_message());
                            blocked[fi] = true;
                        }
                    }
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "inbound teardown for chain '{}' failed: {}",
                self.chain_name,
                failures.join("; ")
            ))
        }
    }

    /// The ordered teardown commands for the resources this run currently owns.
    ///
    /// Pure — no execution — so both the executor and the tests share one source
    /// of truth for what teardown will run. Per family, in reverse of install:
    /// unhook (if hooked), then flush and delete (if created).
    fn owned_teardown_steps(&self) -> Vec<TeardownStep> {
        let chain = &self.chain_name;
        let mut steps: Vec<TeardownStep> = Vec::new();
        for family in [IpFamily::V4, IpFamily::V6] {
            if self.hooked(family) {
                steps.push(TeardownStep::unhook(family, chain));
            }
            if self.created(family) {
                steps.push(TeardownStep::flush(family, chain));
                steps.push(TeardownStep::delete(family, chain));
            }
        }
        steps
    }

    /// Clear the ownership flag a successfully-removed (or already-absent) step
    /// corresponds to. Flushing does not clear `created` — the chain still
    /// exists until it is deleted.
    fn clear_step_flag(&mut self, step: &TeardownStep) {
        match step.kind {
            StepKind::Unhook => self.clear_hooked(step.family),
            StepKind::Flush => {}
            StepKind::Delete => self.clear_created(step.family),
        }
    }

    /// Best-effort cleanup of iptables state when the owning [`IngressManager`]
    /// instance isn't reachable (e.g. signal-time cleanup from the watchdog
    /// thread). We do not know which resources a prior run installed, so this
    /// assumes all of them and lets teardown over-approximate: a genuinely
    /// absent chain or hook is treated as an already-removed no-op. The caller
    /// supplies the container's init PID, which it only has while the netns
    /// still exists — once the container is gone there is nothing to remove, so
    /// the caller simply does not call this. The result is ignored: this path is
    /// best-effort by nature.
    pub fn force_cleanup(container_name: &str, netns_pid: u32, logger: &mut Logger) {
        let mut runner = NsenterRunner;
        Self::force_cleanup_with(container_name, netns_pid, &mut runner, logger);
    }

    /// The body of [`Self::force_cleanup`] against an injectable
    /// [`CommandRunner`] — the real path passes [`NsenterRunner`]; tests pass a
    /// runner that captures the planned argv without spawning. Constructs the
    /// over-approximating manager and runs teardown; the result is ignored
    /// because this path is best-effort by nature.
    fn force_cleanup_with(
        container_name: &str,
        netns_pid: u32,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) {
        let mut mgr = Self::for_full_reset(container_name, netns_pid);
        let _ = mgr.remove_firewall_rules_with(runner, logger);
    }

    /// A manager that assumes every resource might exist, for over-approximating
    /// cleanup where we do not know what a dead run installed. Used by
    /// [`Self::force_cleanup`].
    fn for_full_reset(container_name: &str, netns_pid: u32) -> Self {
        // Teardown removes whatever is there; no rule is built, so the schema
        // this manager reports is never read.
        let mut mgr = Self::new(container_name, netns_pid, false);
        mgr.v4_chain_created = true;
        mgr.v6_chain_created = true;
        mgr.v4_hooked = true;
        mgr.v6_hooked = true;
        mgr
    }

    /// Build the full argv for running `binary args...` inside this container's
    /// network namespace: `["nsenter", "-t", <pid>, "-n", binary, args...]`.
    ///
    /// Pure — no process execution — so the `nsenter` wrapping (the guarantee
    /// that every mutating command targets the container netns and never the
    /// host) is unit-testable. Delegates to the free [`build_nsenter_argv`] with
    /// this manager's PID; [`Self::run`] is the sole production caller.
    fn nsenter_argv(&self, binary: &str, args: &[&str]) -> Vec<String> {
        build_nsenter_argv(self.netns_pid, binary, args)
    }

    /// Classify `ip6tables` usability *for the container's network namespace*.
    ///
    /// Reuses main's pure classifiers ([`NetworkIptablesManager::classify_ip6tables_status`]
    /// and [`NetworkIptablesManager::ipv6_state_treated_as_active`]) but feeds
    /// them namespace-scoped inputs — an in-namespace `ip6tables -S` probe and
    /// [`Self::classify_container_ipv6_state`], which reads
    /// `/proc/<pid>/net/if_inet6` — rather than the host's. A host that has IPv6
    /// disabled says nothing about the container namespace we are filtering, so
    /// probing the host would let a container's IPv6 inbound bypass the deny.
    fn container_ip6tables_status(
        &self,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Ip6tablesStatus {
        let probe_succeeded = self.container_ip6tables_probe_succeeded(runner, logger);
        let ipv6_state = self.container_ipv6_state();
        if ipv6_state == HostIpv6State::Unknown {
            logger.log_line(
                "Could not read the container namespace IPv6 state; treating IPv6 as \
                 potentially active and refusing to fail open.",
            );
        }
        NetworkIptablesManager::classify_ip6tables_status(
            probe_succeeded,
            NetworkIptablesManager::ipv6_state_treated_as_active(ipv6_state),
        )
    }

    /// Whether the container namespace has a live IPv6 stack.
    /// Reads `/proc/<pid>/net/if_inet6` (the netns view of process `<pid>`) and
    /// defers to [`Self::classify_container_ipv6_state`] so the mapping stays
    /// unit-tested. `/proc/<pid>/net` presence separates "IPv6 is off in
    /// this namespace" from "we could not read it" (fail-closed).
    fn container_ipv6_state(&self) -> HostIpv6State {
        let if_inet6 = format!("/proc/{}/net/if_inet6", self.netns_pid);
        let proc_net = format!("/proc/{}/net", self.netns_pid);
        NetworkIptablesManager::classify_container_ipv6_state(
            std::fs::read_to_string(&if_inet6),
            std::path::Path::new(&proc_net).is_dir(),
        )
    }

    /// Run a read-only `ip6tables -S` inside the container namespace, reporting
    /// whether the tool is usable there. Probed via `nsenter` so it reflects
    /// the namespace we will actually program, not the host's `ip6tables`.
    fn container_ip6tables_probe_succeeded(
        &self,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> bool {
        match self.run(runner, "ip6tables", &["-S"], logger) {
            Ok(()) => true,
            Err(e) => {
                logger.log_line(&format!(
                    "container ip6tables probe failed ({})",
                    e.into_message()
                ));
                false
            }
        }
    }
}

impl Drop for IngressManager {
    fn drop(&mut self) {
        // `preserve_policy` is checked here and not only at the runner's
        // explicit teardown call. `Drop` runs on every path out of the run, so
        // gating the explicit call alone would still remove the rules the
        // caller asked to keep.
        if self.should_cleanup_on_drop() {
            let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
            let _ = self.remove_firewall_rules(&mut logger);
        }
    }
}

#[cfg(test)]
#[path = "network_ingress_permissive_spec_tests.rs"]
mod permissive_spec_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_iptables::plan_network;
    use wxc_common::models::{
        NetworkAction, NetworkEnforcementMode, NetworkIngressPolicy, NetworkPolicy,
    };

    /// The 0.8 ingress posture as the parser delivers it.
    fn directional_ingress(
        default: NetworkAction,
        host_loopback: NetworkAction,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_ingress: Some(NetworkIngressPolicy {
                default,
                host_loopback,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_deny_deny_directional_ingress_asks_for_nothing_permissive() {
        assert_eq!(
            IngressManager::permissive_inbound_field(
                &directional_ingress(NetworkAction::Deny, NetworkAction::Deny),
                true
            ),
            None,
            "the GA ingress defaults are what the existing default-deny chain already \
             enforces, so they must not be refused"
        );
    }

    #[test]
    fn a_permissive_directional_ingress_default_is_named_in_the_refusal() {
        assert_eq!(
            IngressManager::permissive_inbound_field(
                &directional_ingress(NetworkAction::Allow, NetworkAction::Deny),
                true
            ),
            Some("network.ingress.default"),
            "an unenforceable value must be refused by the name the operator wrote"
        );
    }

    #[test]
    fn a_permissive_directional_host_loopback_is_named_in_the_refusal() {
        assert_eq!(
            IngressManager::permissive_inbound_field(
                &directional_ingress(NetworkAction::Deny, NetworkAction::Allow),
                true
            ),
            Some("network.ingress.hostLoopback"),
            "an unenforceable value must be refused by the name the operator wrote"
        );
    }

    // A 0.8 config never writes the legacy toggle, and a 0.7 config never
    // carries an ingress section. Neither schema can be reported under the
    // other's field name.
    #[test]
    fn a_legacy_permissive_request_is_still_named_allow_local_network() {
        let policy = ContainerPolicy {
            allow_local_network: true,
            ..Default::default()
        };

        assert_eq!(
            IngressManager::permissive_inbound_field(&policy, false),
            Some("allowLocalNetwork"),
            "the 0.7 refusal must keep naming the 0.7 field"
        );
    }

    // A bare 0.8 config gets the parser's fill-in, which denies on both
    // fields. Nothing permissive is being asked for, and nothing is refused.
    #[test]
    fn a_bare_directional_config_asks_for_nothing_permissive() {
        let policy = ContainerPolicy {
            network_ingress: Some(NetworkIngressPolicy::default()),
            ..Default::default()
        };

        assert_eq!(
            IngressManager::permissive_inbound_field(&policy, true),
            None,
            "the parser's fill-in denies inbound, which the default chain already enforces"
        );
    }

    // A 0.8 operator never writes allowLocalNetwork, so naming it in the log
    // would point at a field their schema does not have.
    #[test]
    fn the_inbound_log_line_names_the_schema_that_asked_for_the_posture() {
        for (directional, expected, absent) in [
            (true, "network.ingress", "allowLocalNetwork"),
            (false, "allowLocalNetwork", "network.ingress"),
        ] {
            let mut policy = ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                ..Default::default()
            };
            if directional {
                // A policy admitting no peer at all is given no interface to
                // hook.
                policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    ..Default::default()
                });
                policy.network_ingress = Some(NetworkIngressPolicy::default());
            }

            let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
            let mut manager = IngressManager::new("log-field-test", 1, directional);
            let _ = manager.apply_firewall_rules(&policy, &mut logger);
            let logged = logger.get_buffer().to_string();

            assert!(
                logged.contains(expected),
                "directional={directional}: inbound log must name {expected}, got: {logged}"
            );
            assert!(
                !logged.contains(absent),
                "directional={directional}: inbound log must not name {absent}, got: {logged}"
            );
        }
    }

    /// A `ContainerPolicy` with the two fields these tests vary; everything
    /// else defaults.
    fn policy_with(allow_local: bool, default: NetworkPolicy) -> ContainerPolicy {
        ContainerPolicy {
            allow_local_network: allow_local,
            default_network_policy: default,
            ..Default::default()
        }
    }

    /// Exact-match a single rule against an expected argv.
    fn is(rule: &[String], want: &[&str]) -> bool {
        rule.len() == want.len() && rule.iter().zip(want).all(|(a, b)| a == b)
    }

    fn has(rules: &[Vec<String>], want: &[&str]) -> bool {
        rules.iter().any(|r| is(r, want))
    }

    fn pos(rules: &[Vec<String>], want: &[&str]) -> Option<usize> {
        rules.iter().position(|r| is(r, want))
    }

    /// The chain name these builder tests pin against.
    const TEST_CHAIN: &str = "MXC-t";

    // ── Container-namespace IPv6 classification ──────────────────────────────
    //
    // These pin the difference between this module's classifier and main's.
    // Swapping `classify_container_ipv6_state` back to
    // `NetworkIptablesManager::classify_host_ipv6_state` fails the first three;
    // the last three keep the correction from swinging too far and making the
    // legitimate IPv4-only path unreachable.

    /// A real `/proc/net/if_inet6` loopback line: address, if_index, prefix_len,
    /// scope, flags, device.
    const LOOPBACK_ONLY_IF_INET6: &str = "00000000000000000000000000000001 01 80 10 80       lo\n";

    /// The race this classifier exists to close. A container that has not been
    /// assigned an IPv6 address yet shows the same address-less `if_inet6` as
    /// one with IPv6 switched off, so contents cannot be read as "IPv6 is off".
    #[test]
    fn container_if_inet6_with_only_loopback_is_still_active() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(
            Ok(LOOPBACK_ONLY_IF_INET6.to_string()),
            true,
        );
        assert_eq!(
            state,
            HostIpv6State::Active,
            "a container carrying only loopback may still be waiting for its IPv6 address; \
             calling that Inactive is the fail-open this classifier exists to prevent"
        );
    }

    /// An empty file is the same situation as loopback-only: the kernel created
    /// it, so the stack is there; it simply has no addresses yet.
    #[test]
    fn container_empty_if_inet6_is_still_active() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(Ok(String::new()), true);
        assert_eq!(
            state,
            HostIpv6State::Active,
            "an empty if_inet6 means no addresses *yet*, not IPv6 disabled"
        );
    }

    /// The consequence stated as an outcome rather than an intermediate state:
    /// an unusable `ip6tables` plus an address-less container must abort, not
    /// quietly install IPv4-only enforcement.
    #[test]
    fn address_less_container_with_unusable_ip6tables_fails_closed() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(
            Ok(LOOPBACK_ONLY_IF_INET6.to_string()),
            true,
        );
        let status = NetworkIptablesManager::classify_ip6tables_status(
            false,
            NetworkIptablesManager::ipv6_state_treated_as_active(state),
        );
        assert!(
            matches!(status, Ip6tablesStatus::UnusableButIpv6Active),
            "a failed probe against a container that may still receive an IPv6 address must \
             fail closed, not take the IPv4-only path"
        );
    }

    /// The genuine IPv4-only case must still work. A kernel with IPv6 disabled
    /// at boot never creates `if_inet6`, and that absence -- with
    /// `/proc/<pid>/net` present to prove the read was real -- is the one signal
    /// that still means "off".
    #[test]
    fn container_missing_if_inet6_with_proc_net_is_inactive() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            true,
        );
        assert_eq!(
            state,
            HostIpv6State::Inactive,
            "a kernel with IPv6 off at boot creates no if_inet6; that must stay the IPv4-only \
             path or default-deny could never install on such a host"
        );
    }

    /// A missing file with no `/proc/<pid>/net` behind it is "we could not read
    /// it", not "IPv6 is off" -- the process may simply be gone.
    #[test]
    fn container_missing_if_inet6_without_proc_net_is_unknown() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            false,
        );
        assert_eq!(
            state,
            HostIpv6State::Unknown,
            "without /proc/<pid>/net the read proves nothing and must not become a confirmed \
             negative"
        );
    }

    /// Any other read error is uncertainty, which must not be downgraded.
    #[test]
    fn container_unreadable_if_inet6_is_unknown() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            true,
        );
        assert_eq!(
            state,
            HostIpv6State::Unknown,
            "an unreadable if_inet6 means we do not know, not that IPv6 is off"
        );
    }

    /// The full install sequence for one policy/family: `-N`, then the chain
    /// body, then the `-I INPUT` hook. Composed from the split [`IngressRules`]
    /// the builder returns, so the pinned-sequence and ordering tests assert the
    /// exact install order while the builder keeps body and hook separate.
    fn full_sequence(
        policy: &ContainerPolicy,
        uses_directional_schema: bool,
        family: IpFamily,
    ) -> Vec<Vec<String>> {
        let rules = IngressManager::build_ingress_rules(
            TEST_CHAIN,
            policy,
            uses_directional_schema,
            family,
        );
        let mut seq = vec![vec!["-N".to_string(), TEST_CHAIN.to_string()]];
        seq.extend(rules.body.iter().cloned());
        seq.push(rules.hook.clone());
        seq
    }

    fn build(allow_local: bool) -> Vec<Vec<String>> {
        full_sequence(
            &policy_with(allow_local, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        )
    }

    /// A [`CommandRunner`] that records every fully-formed (nsenter-wrapped)
    /// argv it is asked to run and returns a scripted outcome, so the apply,
    /// reset, teardown, and force-cleanup paths can be exercised — and their
    /// exact commands asserted — on a host with no `iptables`.
    struct FakeRunner<F: FnMut(&[String]) -> Result<(), RunError>> {
        calls: Vec<Vec<String>>,
        respond: F,
    }

    impl<F: FnMut(&[String]) -> Result<(), RunError>> CommandRunner for FakeRunner<F> {
        fn run(&mut self, argv: &[String]) -> Result<(), RunError> {
            self.calls.push(argv.to_vec());
            (self.respond)(argv)
        }
    }

    /// The iptables verb (first arg after `nsenter -t <pid> -n <binary>`) of a
    /// recorded argv, e.g. `-N`, `-A`, `-I`, `-D`, `-F`, `-X`, `-S`.
    fn verb(argv: &[String]) -> &str {
        argv.get(5).map(String::as_str).unwrap_or("")
    }

    /// An [`RunError::Exit`] carrying iptables' own "no matching rule" message,
    /// so an unhook step reads it as already-absent.
    fn absent_rule() -> RunError {
        RunError::Exit {
            stderr: "iptables: Bad rule (does a matching rule exist in that chain?).".to_string(),
            msg: "unhook: already absent".to_string(),
        }
    }

    /// An [`RunError::Exit`] carrying iptables' own "no such chain" message, so
    /// a flush/delete step reads it as already-absent.
    fn absent_chain() -> RunError {
        RunError::Exit {
            stderr: "iptables: No chain/target/match by that name.".to_string(),
            msg: "chain: already absent".to_string(),
        }
    }

    /// The C-locale messages iptables emits when the target is already gone,
    /// paired with the step whose non-zero exit they are allowed to excuse.
    /// These are the exact strings [`StepKind::stderr_means_absent`] is written
    /// against, so they are the contract the locale pin exists to guarantee.
    const C_LOCALE_ABSENT: &[(StepKind, &str)] = &[
        (
            StepKind::Unhook,
            "iptables: Bad rule (does a matching rule exist in that chain?).",
        ),
        (
            StepKind::Unhook,
            "iptables: No chain/target/match by that name.",
        ),
        (
            StepKind::Flush,
            "iptables: No chain/target/match by that name.",
        ),
        (
            StepKind::Delete,
            "iptables: No chain/target/match by that name.",
        ),
    ];

    #[test]
    fn subprocess_env_pins_iptables_messages_to_the_c_locale() {
        let argv = vec![
            "nsenter".to_string(),
            "-t".to_string(),
            "42".to_string(),
            "-n".to_string(),
            "iptables".to_string(),
        ];

        let command = nsenter_command(&argv);
        let env: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();

        assert!(
            env.contains(&("LC_ALL".to_string(), Some("C".to_string()))),
            "LC_ALL must be pinned to C so iptables' diagnostics are not translated; got {env:?}"
        );
        assert!(
            env.contains(&("LANG".to_string(), Some("C".to_string()))),
            "LANG must be pinned to C as the fallback when LC_ALL is unset; got {env:?}"
        );
    }

    #[test]
    fn pinning_the_locale_does_not_disturb_the_command_being_run() {
        let argv = vec![
            "nsenter".to_string(),
            "-t".to_string(),
            "42".to_string(),
            "-n".to_string(),
            "ip6tables".to_string(),
            "-F".to_string(),
        ];

        let command = nsenter_command(&argv);

        assert_eq!(command.get_program(), "nsenter");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, argv[1..].to_vec());
    }

    #[test]
    fn c_locale_absent_messages_are_recognized_by_their_step() {
        for (kind, stderr) in C_LOCALE_ABSENT {
            assert!(
                kind.stderr_means_absent(stderr),
                "{kind:?} must read {stderr:?} as already-absent"
            );
        }
    }

    /// The regression the locale pin exists to prevent.
    ///
    /// These are the same two conditions as [`C_LOCALE_ABSENT`], as a localized
    /// `iptables` emits them. Without the pin the subprocess inherits the host
    /// locale, these are what teardown would actually receive, and none of them
    /// matches — so a container that is already clean would report a fatal reset
    /// error and abort every fresh install on that host.
    #[test]
    fn localized_absent_messages_are_not_recognized_without_the_locale_pin() {
        // German and French renderings of "No chain/target/match by that name"
        // and "Bad rule (does a matching rule exist in that chain?)".
        let localized = [
            "iptables: Kein Chain/Target/Match mit diesem Namen.",
            "iptables: Pas de chaîne/cible/correspondance de ce nom.",
            "iptables: Règle incorrecte (une règle correspondante existe-t-elle dans cette chaîne ?).",
        ];

        for kind in [StepKind::Unhook, StepKind::Flush, StepKind::Delete] {
            for stderr in localized {
                assert!(
                    !kind.stderr_means_absent(stderr),
                    "{kind:?} matched localized text {stderr:?}; the locale pin in \
                     `nsenter_command` is the only thing keeping this classification sound, \
                     so it must not be removed"
                );
            }
        }
    }

    #[test]
    fn loopback_always_accepts_regardless_of_allow_local() {
        for allow in [true, false] {
            let rules = build(allow);
            assert!(
                has(&rules, &["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"]),
                "loopback must be an unconditional ACCEPT (allow_local={allow})"
            );
            assert!(
                !has(&rules, &["-A", "MXC-t", "-i", "lo", "-j", "DROP"]),
                "loopback must never be DROP (allow_local={allow})"
            );
        }
    }

    #[test]
    fn allow_local_true_accepts_new_inbound() {
        let rules = build(true);
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
        assert!(!has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
    }

    #[test]
    fn allow_local_false_drops_new_inbound() {
        let rules = build(false);
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
        assert!(!has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
    }

    #[test]
    fn established_precedes_new_inbound_decision() {
        let rules = build(false);
        let est = pos(
            &rules,
            &[
                "-A",
                "MXC-t",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )
        .expect("ESTABLISHED,RELATED rule must be emitted");
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
        )
        .expect("NEW rule must be emitted");
        assert!(
            est < new,
            "ESTABLISHED,RELATED must precede the NEW-inbound rule"
        );
    }

    #[test]
    fn new_inbound_precedes_terminal_default() {
        let rules = build(true);
        let new = pos(
            &rules,
            &[
                "-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT",
            ],
        )
        .expect("NEW rule must be emitted");
        let def =
            pos(&rules, &["-A", "MXC-t", "-j", "DROP"]).expect("terminal default must be emitted");
        assert!(
            new < def,
            "NEW-inbound accept must precede the terminal default DROP"
        );
    }

    #[test]
    fn terminal_default_is_always_drop_regardless_of_egress_policy() {
        // Inbound is default-deny; the egress `default_network_policy` must not
        // turn it into a default-accept.
        for default in [NetworkPolicy::Block, NetworkPolicy::Allow] {
            let rules = full_sequence(&policy_with(false, default.clone()), false, IpFamily::V4);
            assert!(
                has(&rules, &["-A", "MXC-t", "-j", "DROP"]),
                "terminal must be DROP (egress default={default:?})"
            );
            assert!(
                !has(&rules, &["-A", "MXC-t", "-j", "ACCEPT"]),
                "terminal must never be a bare ACCEPT (egress default={default:?})"
            );
        }
    }

    #[test]
    fn input_hook_present_with_netns() {
        let rules = build(true);
        assert!(has(&rules, &["-I", "INPUT", "-j", "MXC-t"]));
    }

    #[test]
    fn no_egress_dest_or_dns_rules_in_ingress_chain() {
        // The inbound chain is loopback + established + a single NEW-state
        // decision with no CIDR peers, so it must not carry egress-intent
        // destination or DNS accepts.
        let rules = build(false);
        assert!(
            !rules.iter().any(|r| r.iter().any(|a| a == "-d")),
            "ingress chain must not emit -d destination rules"
        );
        assert!(
            !rules.iter().any(|r| r.iter().any(|a| a == "--dport")),
            "ingress chain must not emit --dport (DNS) rules"
        );
    }

    #[test]
    fn chain_is_created_first() {
        let rules = build(false);
        assert!(
            is(&rules[0], &["-N", "MXC-t"]),
            "chain must be created first"
        );
    }

    // ---- family-awareness: IPv4 pinned, IPv6 gains ICMPv6 ND ------------

    fn build_family(allow_local: bool, family: IpFamily) -> Vec<Vec<String>> {
        full_sequence(
            &policy_with(allow_local, NetworkPolicy::Block),
            false,
            family,
        )
    }

    /// The IPv4 rule set must be exactly this sequence, in order — the
    /// regression pin proving IPv4 behavior is what the contract specifies and
    /// stays fixed as the IPv6 path evolves.
    #[test]
    fn ipv4_full_sequence_is_pinned_exactly() {
        let rules = build_family(false, IpFamily::V4);
        let want: &[&[&str]] = &[
            &["-N", "MXC-t"],
            &["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"],
            &[
                "-A",
                "MXC-t",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
            &["-A", "MXC-t", "-j", "DROP"],
            &["-I", "INPUT", "-j", "MXC-t"],
        ];
        assert_eq!(
            rules.len(),
            want.len(),
            "IPv4 rule count changed: got {rules:?}"
        );
        for (i, expected) in want.iter().enumerate() {
            assert!(
                is(&rules[i], expected),
                "IPv4 rule {i} changed: got {:?}, want {:?}",
                rules[i],
                expected
            );
        }
    }

    /// IPv4 must add no ICMP/ICMPv6 rules at all — ARP is layer 2, so the IPv4
    /// chain never needs a control-plane allowance.
    #[test]
    fn ipv4_emits_no_icmpv6_rules() {
        for allow in [true, false] {
            let rules = build_family(allow, IpFamily::V4);
            assert!(
                !rules
                    .iter()
                    .any(|r| r.iter().any(|a| a == "--icmpv6-type" || a == "icmpv6")),
                "IPv4 chain must not emit any ICMPv6 rule (allow_local={allow})"
            );
        }
    }

    /// IPv6 must accept each Neighbor Discovery type (RS/RA/NS/NA), or inbound
    /// ND is dropped by the NEW rule and IPv6 address resolution breaks.
    #[test]
    fn ipv6_permits_neighbor_discovery_types() {
        let rules = build_family(false, IpFamily::V6);
        for (num, name) in [
            ("133", "router-solicitation"),
            ("134", "router-advertisement"),
            ("135", "neighbor-solicitation"),
            ("136", "neighbor-advertisement"),
        ] {
            assert!(
                has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must accept ICMPv6 type {num} ({name})"
            );
        }
    }

    /// IPv6 must accept the Multicast Listener Discovery and essential-error
    /// types (packet-too-big is required for Path MTU Discovery).
    #[test]
    fn ipv6_permits_mld_and_essential_error_types() {
        let rules = build_family(false, IpFamily::V6);
        for (num, name) in [
            ("130", "multicast-listener-query"),
            ("131", "multicast-listener-report"),
            ("132", "multicast-listener-done"),
            ("143", "multicast-listener-report-v2"),
            ("1", "destination-unreachable"),
            ("2", "packet-too-big"),
            ("3", "time-exceeded"),
            ("4", "parameter-problem"),
        ] {
            assert!(
                has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must accept ICMPv6 type {num} ({name})"
            );
        }
    }

    /// Every ICMPv6 accept must come before the `--state NEW` decision and the
    /// terminal DROP, or ND (which is NEW) would be dropped before it matches.
    #[test]
    fn ipv6_icmpv6_accepts_precede_new_and_terminal_drop() {
        let rules = build_family(false, IpFamily::V6);
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
        )
        .expect("NEW rule must be emitted");
        let terminal = rules
            .iter()
            .rposition(|r| is(r, &["-A", "MXC-t", "-j", "DROP"]))
            .expect("terminal DROP must be emitted");
        for num in ["133", "134", "135", "136", "130", "143", "2"] {
            let at = pos(
                &rules,
                &[
                    "-A",
                    "MXC-t",
                    "-p",
                    "icmpv6",
                    "--icmpv6-type",
                    num,
                    "-j",
                    "ACCEPT",
                ],
            )
            .unwrap_or_else(|| panic!("ICMPv6 type {num} accept must be emitted"));
            assert!(
                at < new,
                "ICMPv6 type {num} accept must precede the NEW decision"
            );
            assert!(
                at < terminal,
                "ICMPv6 type {num} accept must precede the terminal DROP"
            );
        }
    }

    /// The IPv6 chain must not become a blanket ICMPv6 accept: only the
    /// specific control-plane types are opened, and ordinary new inbound (and
    /// inbound ping / redirects) stay dropped.
    #[test]
    fn ipv6_does_not_blanket_accept_icmpv6_or_new_inbound() {
        let rules = build_family(false, IpFamily::V6);
        // No untyped `-p icmpv6 -j ACCEPT` (would accept every ICMPv6 message).
        assert!(
            !has(&rules, &["-A", "MXC-t", "-p", "icmpv6", "-j", "ACCEPT"]),
            "IPv6 chain must not blanket-accept all ICMPv6"
        );
        // Echo request (128) and Redirect (137) are deliberately not opened.
        for num in ["128", "137"] {
            assert!(
                !has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must not accept ICMPv6 type {num}"
            );
        }
        // Default-deny still holds: NEW inbound dropped, terminal DROP present.
        assert!(
            has(
                &rules,
                &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
            ),
            "IPv6 chain must still drop NEW inbound by default"
        );
        assert!(
            has(&rules, &["-A", "MXC-t", "-j", "DROP"]),
            "IPv6 chain must still end in a terminal DROP"
        );
    }

    /// With `allowLocalNetwork: true` the IPv6 NEW decision flips to ACCEPT
    /// just like IPv4 — the ICMPv6 allowances are independent of the toggle.
    #[test]
    fn ipv6_new_decision_follows_allow_local_toggle() {
        let allow = build_family(true, IpFamily::V6);
        assert!(has(
            &allow,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
        let deny = build_family(false, IpFamily::V6);
        assert!(has(
            &deny,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
    }

    /// The ingress chain name must be distinct from the egress chain name for
    /// the same container, so the two chains can never collide or be torn down
    /// for each other.
    #[test]
    fn ingress_chain_name_is_distinct_from_egress() {
        let name = "my-container";
        let ingress = IngressManager::new(name, 4242, false);
        let egress = crate::network_iptables::chain_name_for(name);
        assert_ne!(
            ingress.chain_name(),
            egress,
            "ingress and egress chains must not share a name"
        );
        // iptables rejects chain names of 29+ characters.
        assert!(
            ingress.chain_name().len() <= crate::network_iptables::CHAIN_NAME_MAX_LEN,
            "ingress chain name '{}' exceeds the {}-char ceiling",
            ingress.chain_name(),
            crate::network_iptables::CHAIN_NAME_MAX_LEN
        );
    }

    /// A firewall-mode policy with `allowLocalNetwork: true`.
    fn permissive_firewall_policy() -> ContainerPolicy {
        ContainerPolicy {
            allow_local_network: true,
            default_network_policy: NetworkPolicy::Block,
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        }
    }

    /// The permissive path (`allowLocalNetwork: true`) must be refused by the
    /// public apply entry point — unconditionally, because the PID is always
    /// present now, so there is no "inert, no-netns" variant that could slip an
    /// over-broad `--state NEW -j ACCEPT` past the guard. The refusal returns
    /// before any command is issued, so this never spawns `nsenter`.
    #[test]
    fn permissive_apply_is_refused_unconditionally() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        // The PID value is irrelevant: the refusal precedes every use of it.
        for pid in [1u32, 42u32, 999_999u32] {
            let mut mgr = IngressManager::new("permissive-container", pid, false);
            let result = mgr.apply_firewall_rules(&permissive_firewall_policy(), &mut logger);
            assert!(
                result.is_err(),
                "allowLocalNetwork: true must be refused (pid={pid})"
            );
            let msg = result.unwrap_err();
            assert!(
                msg.contains("not yet implemented"),
                "refusal must explain it is not yet implemented, got: {msg}"
            );
            // The refusal must never have claimed ownership of any resource.
            assert!(
                !mgr.rules_applied(),
                "a refused permissive apply must install nothing (pid={pid})"
            );
            assert!(
                !mgr.v4_chain_created && !mgr.v6_chain_created && !mgr.v4_hooked && !mgr.v6_hooked,
                "no per-resource ownership flag may be set after a refusal (pid={pid})"
            );
        }
    }

    /// `network.ingress.default` and `allowLocalNetwork` govern LAN/private-network
    /// inbound; `network.ingress.hostLoopback` is the separate host-loopback control
    /// (`docs/sandbox-policy/0.8.0/policy.md`). A refusal that blames host loopback
    /// sends the operator to a field they did not write.
    #[test]
    fn a_lan_inbound_refusal_does_not_give_a_host_loopback_rationale() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        for (policy, uses_directional_schema, field) in [
            (
                directional_ingress(NetworkAction::Allow, NetworkAction::Deny),
                true,
                "network.ingress.default",
            ),
            (permissive_firewall_policy(), false, "allowLocalNetwork"),
        ] {
            let mut mgr = IngressManager::new("lan-inbound", 42, uses_directional_schema);
            let msg = mgr
                .apply_firewall_rules(&policy, &mut logger)
                .expect_err("permissive inbound must still be refused");

            assert!(msg.contains(field), "the refusal must name {field}: {msg}");
            assert!(
                !msg.to_lowercase().contains("loopback"),
                "{field} does not govern host loopback, so the refusal must not \
                 explain itself in host-loopback terms: {msg}"
            );
        }
    }

    /// Every command this manager issues must be scoped to the container netns
    /// with an `nsenter -t <pid> -n` prefix — the invariant that keeps the
    /// rules off the host. Assert the argv shape the pure builder produces, for
    /// a representative iptables rule and for the read-only ip6tables probe.
    #[test]
    fn every_emitted_command_is_nsenter_prefixed() {
        let pid = 31337u32;
        let mgr = IngressManager::new("argv-container", pid, false);
        let cases: &[&[&str]] = &[
            &["-N", "MXC-t"],
            &["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"],
            &["-D", "INPUT", "-j", "MXC-t"],
            &["-S"],
        ];
        for args in cases {
            for binary in ["iptables", "ip6tables"] {
                let argv = mgr.nsenter_argv(binary, args);
                assert_nsenter_prefixed(&argv, pid, binary, args);
            }
        }
    }

    /// Assert an argv is `["nsenter", "-t", <pid>, "-n", <binary>, <args...>]`.
    fn assert_nsenter_prefixed(argv: &[String], pid: u32, binary: &str, args: &[&str]) {
        assert_eq!(
            &argv[..5],
            &[
                "nsenter".to_string(),
                "-t".to_string(),
                pid.to_string(),
                "-n".to_string(),
                binary.to_string(),
            ],
            "command must be nsenter-prefixed for the container netns"
        );
        let tail: Vec<String> = argv[5..].to_vec();
        let want: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        assert_eq!(tail, want, "the wrapped command args must be preserved");
    }

    /// The teardown path (used by `remove_firewall_rules`, `Drop`, and
    /// `force_cleanup`) must also route every command through `nsenter`, and
    /// only against the manager's own chain. Assert the actual planned argv
    /// rather than just the pure helper: a command that skips `nsenter` would
    /// execute against the host's tables.
    #[test]
    fn teardown_commands_are_nsenter_prefixed_and_chain_scoped() {
        let pid = 4242u32;
        let mut mgr = IngressManager::new("teardown-container", pid, false);
        // Simulate a full dual-stack install: both families created and hooked.
        mgr.v4_chain_created = true;
        mgr.v6_chain_created = true;
        mgr.v4_hooked = true;
        mgr.v6_hooked = true;
        let chain = mgr.chain_name().to_string();

        let steps = mgr.owned_teardown_steps();
        // Unhook + flush + delete, per family.
        assert_eq!(
            steps.len(),
            6,
            "full ownership must plan six teardown steps"
        );
        for step in &steps {
            let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();
            let argv = mgr.nsenter_argv(step.family.binary(), &arg_refs);
            assert_nsenter_prefixed(&argv, pid, step.family.binary(), &arg_refs);
            // Every teardown command names our own chain and no other.
            assert!(
                step.args.iter().any(|a| a == &chain),
                "teardown step {:?} must target our chain '{}', got {:?}",
                step.kind,
                chain,
                step.args
            );
        }
        // Within each family, unhook must be planned before flush/delete so we
        // never flush a chain still referenced from INPUT.
        for family in [IpFamily::V4, IpFamily::V6] {
            let idx = |k: StepKind| {
                steps
                    .iter()
                    .position(|s| s.family == family && s.kind == k)
                    .unwrap_or_else(|| panic!("{:?} {:?} step missing", family, k))
            };
            assert!(idx(StepKind::Unhook) < idx(StepKind::Flush));
            assert!(idx(StepKind::Flush) < idx(StepKind::Delete));
        }
    }

    /// `preservePolicy` must survive `Drop`, not just the runner's explicit
    /// teardown call.
    ///
    /// `LxcScriptRunner` gates its explicit `remove_firewall_rules` call on
    /// `cleanup_policy` (`!preserve_policy`), but `Drop` fires on every path out
    /// of the run. An unconditional `Drop` therefore removes exactly the rules
    /// the caller asked to keep, and the config field silently does nothing.
    /// Assert the gate across all four states rather than the teardown itself,
    /// which would reach the real `nsenter`.
    #[test]
    fn drop_honors_preserve_policy() {
        let mut mgr = IngressManager::new("preserve-container", 4242, false);

        // Nothing installed: never any cleanup to do, either way.
        assert!(
            !mgr.should_cleanup_on_drop(),
            "a manager that installed nothing must not attempt teardown"
        );
        mgr.set_preserve_policy(true);
        assert!(!mgr.should_cleanup_on_drop());

        // A real install, preserved: Drop must leave the chain in place.
        mgr.v4_chain_created = true;
        mgr.v4_hooked = true;
        assert!(
            mgr.rules_applied(),
            "precondition: the manager owns installed state"
        );
        assert!(
            !mgr.should_cleanup_on_drop(),
            "preservePolicy was requested, so Drop must not remove the chain"
        );

        // The same install without preservation is still cleaned up, so the
        // flag cannot mask an ordinary leak.
        mgr.set_preserve_policy(false);
        assert!(
            mgr.should_cleanup_on_drop(),
            "without preservePolicy an installed chain must still be torn down"
        );

        // Leave nothing owned, so dropping this test's manager does not reach
        // the real nsenter path.
        mgr.v4_chain_created = false;
        mgr.v4_hooked = false;
    }

    /// `force_cleanup` must actually run — over the injectable runner — so a
    /// regression inside it fails this test, and it must plan to remove *all*
    /// resources (it cannot know what a dead run installed). Assert the real
    /// commands `force_cleanup_with` issues: every one nsenter-scoped to the
    /// container netns, naming only our chain, unhook before flush before
    /// delete, for both families. A no-leftover script (everything reports
    /// already-absent) lets cleanup complete without error.
    #[test]
    fn force_cleanup_removes_all_resources_via_nsenter() {
        let pid = 9001u32;
        let container = "force-cleanup-container";
        let chain = IngressManager::new(container, pid, false)
            .chain_name()
            .to_string();
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let mut runner = FakeRunner {
            calls: Vec::new(),
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Err(absent_rule()),
                _ => Err(absent_chain()),
            },
        };

        IngressManager::force_cleanup_with(container, pid, &mut runner, &mut logger);

        // Six commands: unhook + flush + delete, per family.
        assert_eq!(
            runner.calls.len(),
            6,
            "force_cleanup must issue all six teardown commands, got {:?}",
            runner.calls
        );

        // Every command is nsenter-scoped and names only our chain.
        for argv in &runner.calls {
            assert_eq!(
                &argv[..4],
                &[
                    "nsenter".to_string(),
                    "-t".to_string(),
                    pid.to_string(),
                    "-n".to_string(),
                ],
                "force_cleanup command must be nsenter-scoped to the netns: {argv:?}"
            );
            assert!(
                argv[4] == "iptables" || argv[4] == "ip6tables",
                "force_cleanup command must target a packet-filter binary: {argv:?}"
            );
            assert!(
                argv.iter().any(|a| a == &chain),
                "force_cleanup command must name our chain '{chain}': {argv:?}"
            );
        }

        // Both families are covered.
        for binary in ["iptables", "ip6tables"] {
            assert!(
                runner.calls.iter().any(|a| a[4] == binary),
                "force_cleanup must cover {binary}"
            );
        }

        // Per family: unhook (-D) before flush (-F) before delete (-X).
        for binary in ["iptables", "ip6tables"] {
            let idx = |v: &str| {
                runner
                    .calls
                    .iter()
                    .position(|a| a[4] == binary && verb(a) == v)
                    .unwrap_or_else(|| panic!("{binary} {v} command missing"))
            };
            assert!(idx("-D") < idx("-F"), "{binary}: unhook must precede flush");
            assert!(idx("-F") < idx("-X"), "{binary}: flush must precede delete");
        }
    }

    /// The pure builder must return the chain *body* and the `INPUT` *hook* as
    /// separate values, so install cannot confuse one for the other and needs no
    /// `-I`-filtering. The body carries neither the `-N` creation nor the `-I`
    /// hook; the hook is exactly the `-I INPUT` jump.
    #[test]
    fn builder_returns_body_and_hook_separately() {
        for family in [IpFamily::V4, IpFamily::V6] {
            let rules = IngressManager::build_ingress_rules(
                TEST_CHAIN,
                &policy_with(false, NetworkPolicy::Block),
                false,
                family,
            );
            assert_eq!(
                rules.hook,
                vec![
                    "-I".to_string(),
                    "INPUT".to_string(),
                    "-j".to_string(),
                    TEST_CHAIN.to_string(),
                ],
                "hook must be exactly the -I INPUT jump ({family:?})"
            );
            assert!(
                !rules
                    .body
                    .iter()
                    .any(|r| r.first().map(String::as_str) == Some("-I")),
                "body must not contain the -I hook ({family:?})"
            );
            assert!(
                !rules
                    .body
                    .iter()
                    .any(|r| r.first().map(String::as_str) == Some("-N")),
                "body must not contain the -N creation ({family:?})"
            );
            assert!(
                rules
                    .body
                    .iter()
                    .all(|r| r.first().map(String::as_str) == Some("-A")),
                "every body rule must be an -A append ({family:?})"
            );
        }
    }

    /// Install must reset before it creates, and hook only after the body is in
    /// place. Drive `install_family` over a runner that reports no leftover
    /// (so reset completes) and success for the create/body/hook, then assert
    /// the recorded order: the reset's unhook precedes its delete, the whole
    /// reset precedes `-N`, `-N` precedes every `-A`, and the `-I` hook is the
    /// very last command. Hooking last is what closes the empty-but-hooked
    /// fail-open window.
    #[test]
    fn install_resets_then_creates_then_hooks_last() {
        let pid = 4242u32;
        let container = "install-order-container";
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new(container, pid, false);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
            // No leftover: reset's -D/-F/-X all report already-absent; the
            // create/body/hook commands succeed.
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Err(absent_rule()),
                "-F" | "-X" => Err(absent_chain()),
                _ => Ok(()),
            },
        };

        mgr.install_family(IpFamily::V4, &rules, &mut runner, &mut logger)
            .expect("install should succeed when every command is scripted to pass");

        let verbs: Vec<&str> = runner.calls.iter().map(|a| verb(a)).collect();
        let first = |v: &str| verbs.iter().position(|x| *x == v).unwrap_or(usize::MAX);
        let last = |v: &str| verbs.iter().rposition(|x| *x == v).unwrap_or(usize::MAX);

        // Reset (unhook, flush, delete) all precede the fresh create.
        assert!(
            last("-D") < first("-N"),
            "reset unhook must precede create: {verbs:?}"
        );
        assert!(
            last("-D") < first("-X"),
            "reset unhook must precede reset delete: {verbs:?}"
        );
        assert!(
            last("-F") < first("-N"),
            "reset flush must precede create: {verbs:?}"
        );
        assert!(
            last("-X") < first("-N"),
            "reset delete must precede create: {verbs:?}"
        );
        // Create precedes every body append.
        assert!(
            first("-N") < first("-A"),
            "create must precede the body: {verbs:?}"
        );
        // The hook is the single last command.
        assert_eq!(
            verbs.last().copied(),
            Some("-I"),
            "the -I hook must be the final command (hook only after full body): {verbs:?}"
        );
        assert_eq!(
            verbs.iter().filter(|v| **v == "-I").count(),
            1,
            "exactly one hook"
        );
    }

    /// The reset must remove *every* leftover INPUT reference, not just one: a
    /// crashed run can leave several. Script the unhook to succeed twice (two
    /// leftover references) then report already-absent, and assert `reset_family`
    /// issued `-D` three times — two removals plus the terminating absent probe
    /// — all before any `-F`/`-X`.
    #[test]
    fn reset_repeats_unhook_until_absent_then_deletes() {
        let pid = 55u32;
        let container = "reset-repeat-container";
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new(container, pid, false);

        let mut d_seen = 0;
        let mut runner = FakeRunner {
            calls: Vec::new(),
            respond: move |argv: &[String]| match verb(argv) {
                "-D" => {
                    d_seen += 1;
                    // Two references present, then no matching rule.
                    if d_seen <= 2 {
                        Ok(())
                    } else {
                        Err(absent_rule())
                    }
                }
                _ => Err(absent_chain()),
            },
        };

        mgr.reset_family(IpFamily::V4, &mut runner, &mut logger)
            .expect("reset should succeed: unhook drains, chain reports absent");

        let verbs: Vec<&str> = runner.calls.iter().map(|a| verb(a)).collect();
        assert_eq!(
            verbs.iter().filter(|v| **v == "-D").count(),
            3,
            "unhook must repeat until absent (2 removals + 1 absent probe): {verbs:?}"
        );
        // Unhook-before-delete: every -D precedes the first -F and -X.
        let first_flush = verbs
            .iter()
            .position(|v| *v == "-F")
            .expect("flush planned");
        let first_delete = verbs
            .iter()
            .position(|v| *v == "-X")
            .expect("delete planned");
        let last_unhook = verbs
            .iter()
            .rposition(|v| *v == "-D")
            .expect("unhook planned");
        assert!(
            last_unhook < first_flush,
            "all unhooks precede flush: {verbs:?}"
        );
        assert!(
            first_flush < first_delete,
            "flush precedes delete: {verbs:?}"
        );
    }

    /// A partial install — the chain is created but a *body* rule fails before
    /// the hook lands — must leave ownership recording exactly what got
    /// installed: the chain is created, the hook is not, and teardown therefore
    /// plans flush and delete but NO unhook (there is no jump rule to remove).
    /// Drive it for real over a runner scripted so reset finds no leftover, `-N`
    /// succeeds, and the first body `-A` fails, rather than hand-setting the
    /// flags — the whole point is that a real body-rule failure is observed to
    /// produce this ownership state and never issues `-I INPUT`.
    #[test]
    fn partial_body_failure_plans_flush_delete_no_unhook() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("partial-container", pid, false);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
            // Reset finds no leftover; the fresh `-N` succeeds; the first body
            // `-A` fails for a real reason (not an absence).
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Err(absent_rule()),
                "-F" | "-X" => Err(absent_chain()),
                "-N" => Ok(()),
                "-A" => Err(RunError::Spawn("simulated body-rule failure".to_string())),
                _ => Ok(()),
            },
        };

        mgr.install_family(IpFamily::V4, &rules, &mut runner, &mut logger)
            .expect_err("install must fail when a body rule fails");

        // Ownership records the chain but not the hook.
        assert!(mgr.v4_chain_created, "the successful -N must set created");
        assert!(
            !mgr.v4_hooked,
            "the hook never landed, so hooked must stay false"
        );

        // The hook was never issued — the body failed before install reached it.
        assert!(
            !runner.calls.iter().any(|a| verb(a) == "-I"),
            "no -I INPUT hook may be issued when a body rule failed: {:?}",
            runner.calls
        );

        // Teardown plans flush + delete for the created chain, but no unhook.
        let steps = mgr.owned_teardown_steps();
        assert_eq!(
            steps.len(),
            2,
            "created-but-unhooked plans flush + delete only"
        );
        assert!(
            steps.iter().all(|s| s.family == IpFamily::V4),
            "no IPv6 teardown may be planned when IPv6 was never created"
        );
        assert!(
            !steps.iter().any(|s| s.kind == StepKind::Unhook),
            "no unhook may be planned when the hook never landed"
        );
        assert!(steps.iter().any(|s| s.kind == StepKind::Flush));
        assert!(steps.iter().any(|s| s.kind == StepKind::Delete));
    }

    /// Reset fail-closed, spawn case: if the reset's very first `-D` cannot even
    /// be spawned (e.g. `nsenter` or `iptables` missing), install must abort
    /// before creating anything — no `-N`, and no ownership flag set. A reset
    /// that cannot run must never let install proceed to a half-built, unowned
    /// chain, which would enforce nothing while looking installed.
    #[test]
    fn reset_spawn_failure_aborts_before_create_with_no_ownership() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("reset-spawn-fail-container", pid, false);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
            // The reset's first unhook cannot be spawned at all.
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Err(RunError::Spawn(
                    "nsenter: executable file not found".to_string(),
                )),
                _ => Ok(()),
            },
        };

        mgr.install_family(IpFamily::V4, &rules, &mut runner, &mut logger)
            .expect_err("install must abort when the reset cannot be spawned");

        assert!(
            !runner.calls.iter().any(|a| verb(a) == "-N"),
            "no chain may be created when reset fails: {:?}",
            runner.calls
        );
        assert!(
            !mgr.rules_applied(),
            "no ownership flag may be set after a failed reset"
        );
        assert!(
            !mgr.v4_chain_created && !mgr.v6_chain_created && !mgr.v4_hooked && !mgr.v6_hooked,
            "every ownership flag must stay clear after a failed reset"
        );
    }

    /// Reset fail-closed, exhaustion case: if `-D` keeps succeeding and never
    /// reports the rule absent, the unhook loop must give up after
    /// `MAX_UNHOOK_ATTEMPTS`, treat that as a real error, block the family, and
    /// abort install before `-N`. A persistently "successful" delete cannot be
    /// read as "drained" or the loop would spin forever and install would build
    /// on an unknown state.
    #[test]
    fn reset_unhook_exhaustion_aborts_before_create() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("reset-exhaustion-container", pid, false);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
            // Every unhook "succeeds" — there is always another reference — so
            // the loop never sees absence and must hit the bound.
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Ok(()),
                _ => Ok(()),
            },
        };

        let err = mgr
            .install_family(IpFamily::V4, &rules, &mut runner, &mut logger)
            .expect_err("install must abort when the unhook loop exhausts its bound");

        assert_eq!(
            runner.calls.iter().filter(|a| verb(a) == "-D").count(),
            MAX_UNHOOK_ATTEMPTS,
            "unhook must stop exactly at the bound, not spin forever"
        );
        assert!(
            !runner.calls.iter().any(|a| verb(a) == "-F"),
            "flush must not run for a family blocked by unhook exhaustion: {:?}",
            runner.calls
        );
        assert!(
            !runner.calls.iter().any(|a| verb(a) == "-N"),
            "no chain may be created when reset aborts: {:?}",
            runner.calls
        );
        assert!(
            err.contains("still removing INPUT references"),
            "the error must name the unhook-exhaustion cause, got: {err}"
        );
        assert!(
            !mgr.rules_applied(),
            "no ownership flag may be set after a failed reset"
        );
    }

    /// Pin the *entire* IPv6 chain body as a literal, in order, so a
    /// regression in the ICMPv6 allow-list — a dropped type, a reordering, or a
    /// type leaking past the NEW decision — fails here. Written out literally on
    /// purpose: building it from `ICMPV6_ALLOW_TYPES` would re-derive the very
    /// sequence this test exists to pin. The 12 ICMPv6 accepts must sit between
    /// the ESTABLISHED rule and the NEW decision (they arrive as NEW, so they
    /// must precede both the NEW drop and the terminal drop or Neighbor
    /// Discovery and SLAAC break).
    #[test]
    fn ipv6_full_body_sequence_is_pinned_exactly() {
        let rules = IngressManager::build_ingress_rules(
            TEST_CHAIN,
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V6,
        );

        let want: Vec<Vec<&str>> = vec![
            vec!["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"],
            vec![
                "-A",
                "MXC-t",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "133",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "134",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "135",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "136",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "130",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "131",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "132",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "143",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "1",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "2",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "3",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A",
                "MXC-t",
                "-p",
                "icmpv6",
                "--icmpv6-type",
                "4",
                "-j",
                "ACCEPT",
            ],
            vec!["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
            vec!["-A", "MXC-t", "-j", "DROP"],
        ];
        let want: Vec<Vec<String>> = want
            .iter()
            .map(|r| r.iter().map(|s| s.to_string()).collect())
            .collect();

        assert_eq!(
            rules.body, want,
            "the IPv6 chain body must match the pinned literal sequence exactly"
        );
    }

    /// The "already absent" classification must accept only iptables' own
    /// missing-object messages, never a spawn failure — treating "cannot run
    /// the tool" as "nothing to remove" would be a fail-open.
    #[test]
    fn absent_classification_rejects_spawn_style_messages() {
        // iptables' actual missing-chain / missing-rule messages: absent.
        assert!(
            StepKind::Flush.stderr_means_absent("iptables: No chain/target/match by that name.")
        );
        assert!(StepKind::Delete.stderr_means_absent("No chain/target/match by that name"));
        assert!(StepKind::Unhook.stderr_means_absent(
            "iptables: Bad rule (does a matching rule exist in that chain?)."
        ));
        // Spawn-style / unknown-state messages: never absent.
        for msg in [
            "executable file not found",
            "No such file or directory",
            "program not found in PATH",
            "Operation not permitted",
            "cannot find nsenter",
        ] {
            assert!(
                !StepKind::Flush.stderr_means_absent(msg),
                "must not treat '{msg}' as proof the chain is absent"
            );
            assert!(
                !StepKind::Unhook.stderr_means_absent(msg),
                "must not treat '{msg}' as proof the rule is absent"
            );
        }
        // A missing-*rule* message must not satisfy a chain step, and vice versa.
        assert!(
            !StepKind::Flush.stderr_means_absent("does a matching rule exist in that chain?"),
            "a missing-rule message must not clear a chain flush/delete step"
        );
    }

    /// A fresh container has no MXCI chain, so the reset that precedes every
    /// install must read an absent chain as benign.  Until it did, inbound
    /// default-deny could not install on any `iptables-nft` host.  Strings
    /// captured verbatim from iptables 1.8.10 under `LC_ALL=C`.
    #[test]
    fn absent_chain_messages_from_both_backends_are_recognized() {
        let observed = [
            "iptables v1.8.10 (nf_tables): Chain 'MXCI-CLI-LX-72gim3ftle7wtxye' does not exist",
            "ip6tables v1.8.10 (nf_tables): Chain 'MXCI-CLI-LX-72gim3ftle7wtxye' does not exist",
            "iptables v1.8.10 (legacy): Couldn't load target \
             `MXCI-CLI-LX-72gim3ftle7wtxye':No such file or directory",
        ];

        for stderr in observed {
            assert!(
                StepKind::Unhook.stderr_means_absent(stderr),
                "unhook must read {stderr:?} as an absent chain; misreading it aborts \
                 every install on that host"
            );
        }
    }

    fn legacy_firewall_mode_with_permissive_egress(
        mode: NetworkEnforcementMode,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_enforcement_mode: mode,
            default_network_policy: NetworkPolicy::Allow,
            ..Default::default()
        }
    }

    // A 0.7 config naming a firewall mode is owed the inbound deny even with
    // nothing to restrict outbound; skipping it would accept new inbound
    // connections on every interface, the fail-open direction.
    #[test]
    fn a_firewall_mode_config_with_nothing_to_restrict_outbound_still_installs_the_inbound_chain() {
        for mode in [
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let label = format!("{mode:?}");
            let policy = legacy_firewall_mode_with_permissive_egress(mode);

            assert!(
                plan_network(&policy, false).installs_firewall(),
                "{label}: a config naming a firewall enforcement mode is owed the inbound \
                 deny chain even with nothing to restrict outbound"
            );
        }
    }

    // A config that names no firewall mode, states no posture, and restricts
    // nothing has no inbound chain to install; skipping it is correct, not
    // dangerous.
    #[test]
    fn a_config_that_asks_for_no_firewall_at_all_installs_no_inbound_chain() {
        let policy =
            legacy_firewall_mode_with_permissive_egress(NetworkEnforcementMode::Capabilities);

        assert!(
            !plan_network(&policy, false).installs_firewall(),
            "a policy naming no firewall mode, no posture, no hosts and no proxy has \
             nothing inbound to enforce"
        );
    }

    // 0.8 states its posture with no enforcementMode to name, so the inbound
    // chain has to follow from the schema itself.
    #[test]
    fn a_stated_directional_posture_installs_the_inbound_chain() {
        let mut policy = directional_ingress(NetworkAction::Allow, NetworkAction::Deny);
        policy.default_network_policy = NetworkPolicy::Allow;
        policy.network_egress = Some(Default::default());

        assert!(plan_network(&policy, true).installs_firewall());
    }

    #[test]
    fn a_posture_admitting_no_peer_installs_no_inbound_chain() {
        let mut policy = directional_ingress(NetworkAction::Deny, NetworkAction::Deny);
        policy.network_egress = Some(Default::default());

        assert!(!plan_network(&policy, true).installs_firewall());
    }
}
