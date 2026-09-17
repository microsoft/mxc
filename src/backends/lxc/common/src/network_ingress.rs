// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Packets destined to container sockets traverse the container namespace's
//! `INPUT` chain.  IPv6 Neighbor Discovery uses ICMPv6, and `ip6tables`
//! filters those packets.

use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkIngressPolicy};

use crate::network_iptables::{
    ingress_chain_name_for, plan_network, uses_directional_keys, HostIpv6State, Ip6tablesStatus,
    NetworkIptablesManager,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn binary(self) -> &'static str {
        match self {
            IpFamily::V4 => "iptables",
            IpFamily::V6 => "ip6tables",
        }
    }

    fn index(self) -> usize {
        match self {
            IpFamily::V4 => 0,
            IpFamily::V6 => 1,
        }
    }
}

const ICMPV6_DESTINATION_UNREACHABLE: &str = "1";
const ICMPV6_PACKET_TOO_BIG: &str = "2";
const ICMPV6_TIME_EXCEEDED: &str = "3";
const ICMPV6_PARAMETER_PROBLEM: &str = "4";
const ICMPV6_MULTICAST_LISTENER_QUERY: &str = "130";
const ICMPV6_MULTICAST_LISTENER_REPORT: &str = "131";
const ICMPV6_MULTICAST_LISTENER_DONE: &str = "132";
const ICMPV6_ROUTER_SOLICITATION: &str = "133";
const ICMPV6_ROUTER_ADVERTISEMENT: &str = "134";
const ICMPV6_NEIGHBOR_SOLICITATION: &str = "135";
const ICMPV6_NEIGHBOR_ADVERTISEMENT: &str = "136";
const ICMPV6_MULTICAST_LISTENER_REPORT_V2: &str = "143";

/// RFC 4890 permits dropping echo request, echo reply, and redirect at a firewall.
const ICMPV6_ALLOW_TYPES: [&str; 12] = [
    ICMPV6_ROUTER_SOLICITATION,
    ICMPV6_ROUTER_ADVERTISEMENT,
    ICMPV6_NEIGHBOR_SOLICITATION,
    ICMPV6_NEIGHBOR_ADVERTISEMENT,
    ICMPV6_MULTICAST_LISTENER_QUERY,
    ICMPV6_MULTICAST_LISTENER_REPORT,
    ICMPV6_MULTICAST_LISTENER_DONE,
    ICMPV6_MULTICAST_LISTENER_REPORT_V2,
    ICMPV6_DESTINATION_UNREACHABLE,
    ICMPV6_PACKET_TOO_BIG,
    ICMPV6_TIME_EXCEEDED,
    ICMPV6_PARAMETER_PROBLEM,
];

pub struct IngressManager {
    chain_name: String,

    netns_pid: u32,

    v4_chain_created: bool,
    v6_chain_created: bool,
    v4_hooked: bool,
    v6_hooked: bool,
    preserve_policy: bool,
}

enum RunError {
    Spawn(String),
    Exit { stderr: String, msg: String },
}

impl RunError {
    fn into_message(self) -> String {
        match self {
            RunError::Spawn(msg) => msg,
            RunError::Exit { msg, .. } => msg,
        }
    }

    fn message(&self) -> &str {
        match self {
            RunError::Spawn(msg) => msg,
            RunError::Exit { msg, .. } => msg,
        }
    }
}

struct TeardownStep {
    family: IpFamily,
    kind: StepKind,
    args: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StepKind {
    Unhook,
    Flush,
    Delete,
}

impl StepKind {
    fn stderr_means_absent(self, stderr: &str) -> bool {
        let s = stderr.to_ascii_lowercase();
        let absent_chain = s.contains("does not exist") || s.contains("couldn't load target");
        match self {
            StepKind::Unhook => {
                s.contains("no chain/target/match by that name")
                    || s.contains("does a matching rule exist")
                    || absent_chain
            }
            StepKind::Flush | StepKind::Delete => {
                s.contains("no chain/target/match by that name") || absent_chain
            }
        }
    }
}

impl TeardownStep {
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

    fn flush(family: IpFamily, chain: &str) -> Self {
        Self {
            family,
            kind: StepKind::Flush,
            args: vec!["-F".to_string(), chain.to_string()],
        }
    }

    fn delete(family: IpFamily, chain: &str) -> Self {
        Self {
            family,
            kind: StepKind::Delete,
            args: vec!["-X".to_string(), chain.to_string()],
        }
    }
}

/// Bound `-D INPUT -j <chain>` retries high enough for repeated crashed
/// installs and low enough to detect a delete that is not making progress.
const MAX_UNHOOK_ATTEMPTS: usize = 128;

trait CommandRunner {
    fn run(&mut self, argv: &[String]) -> Result<(), RunError>;
}

/// Pin iptables diagnostics to the C locale before matching stderr.
///
/// iptables returns 1 for both missing objects and genuine errors, and its
/// diagnostic text is localized.
fn nsenter_command(argv: &[String]) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);

    command.env("LC_ALL", "C").env("LANG", "C");
    command
}

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

struct IngressRules {
    body: Vec<Vec<String>>,
    hook: Vec<String>,
}

impl IngressManager {
    pub fn new(container_name: &str, netns_pid: u32) -> Self {
        Self {
            chain_name: ingress_chain_name_for(container_name),
            netns_pid,
            v4_chain_created: false,
            v6_chain_created: false,
            v4_hooked: false,
            v6_hooked: false,
            preserve_policy: false,
        }
    }

    pub fn set_preserve_policy(&mut self, preserve: bool) {
        self.preserve_policy = preserve;
    }

    fn should_cleanup_on_drop(&self) -> bool {
        self.rules_applied() && !self.preserve_policy
    }

    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    pub fn rules_applied(&self) -> bool {
        self.v4_chain_created || self.v6_chain_created || self.v4_hooked || self.v6_hooked
    }

    fn set_created(&mut self, family: IpFamily) {
        match family {
            IpFamily::V4 => self.v4_chain_created = true,
            IpFamily::V6 => self.v6_chain_created = true,
        }
    }

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

    fn stated_ingress(
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
    ) -> Option<&NetworkIngressPolicy> {
        if uses_directional_keys {
            policy.network_ingress.as_ref()
        } else {
            None
        }
    }

    fn permissive_inbound_field(
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
    ) -> Option<&'static str> {
        if let Some(ingress) = Self::stated_ingress(policy, uses_directional_keys) {
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

    fn apply_rules_in_dialect(
        &mut self,
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        if !plan_network(policy).installs_firewall() {
            logger.log_line("Network policy requests no firewall; skipping ingress chain.");
            return Ok(true);
        }

        if let Some(field) = Self::permissive_inbound_field(policy, uses_directional_keys) {
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
        let inbound_field = if uses_directional_keys {
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

        let mut runner = NsenterRunner;

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
            uses_directional_keys,
            IpFamily::V4,
        );

        self.install_family(IpFamily::V4, &ipv4_rules, &mut runner, logger)?;
        if ipv6_enabled {
            let ipv6_rules = Self::build_ingress_rules(
                &self.chain_name,
                policy,
                uses_directional_keys,
                IpFamily::V6,
            );
            self.install_family(IpFamily::V6, &ipv6_rules, &mut runner, logger)?;
        }

        Ok(true)
    }

    pub fn apply_legacy_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        self.apply_rules_in_dialect(policy, false, logger)
    }

    pub fn apply_directional_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        self.apply_rules_in_dialect(policy, true, logger)
    }

    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let dialect = uses_directional_keys(policy);
        self.apply_rules_in_dialect(policy, dialect, logger)
    }

    fn install_family(
        &mut self,
        family: IpFamily,
        rules: &IngressRules,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let binary = family.binary();
        let chain = self.chain_name.clone();

        self.reset_family(family, runner, logger)?;

        self.run(runner, binary, &["-N", &chain], logger)
            .map_err(RunError::into_message)?;
        self.set_created(family);

        for rule in &rules.body {
            let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
            self.run(runner, binary, &argv, logger)
                .map_err(RunError::into_message)?;
        }

        let hook: Vec<&str> = rules.hook.iter().map(String::as_str).collect();
        self.run(runner, binary, &hook, logger)
            .map_err(RunError::into_message)?;
        self.set_hooked(family);

        Ok(())
    }

    fn reset_family(
        &mut self,
        family: IpFamily,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let steps = Self::reset_steps(family, &self.chain_name);
        self.execute_teardown(&steps, runner, logger)
    }

    fn reset_steps(family: IpFamily, chain: &str) -> Vec<TeardownStep> {
        vec![
            TeardownStep::unhook(family, chain),
            TeardownStep::flush(family, chain),
            TeardownStep::delete(family, chain),
        ]
    }

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

    fn build_ingress_rules(
        chain: &str,
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
        family: IpFamily,
    ) -> IngressRules {
        fn argv(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| s.to_string()).collect()
        }

        let accept = "ACCEPT";
        let drop = "DROP";
        let mut body: Vec<Vec<String>> = Vec::new();

        body.push(argv(&["-A", chain, "-i", "lo", "-j", accept]));

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

        let inbound_verb =
            if Self::permissive_inbound_field(policy, uses_directional_keys).is_some() {
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

        body.push(argv(&["-A", chain, "-j", drop]));

        let hook = argv(&["-I", "INPUT", "-j", chain]);

        IngressRules { body, hook }
    }

    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        let mut runner = NsenterRunner;
        self.remove_firewall_rules_with(&mut runner, logger)
    }

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

    fn execute_teardown(
        &mut self,
        steps: &[TeardownStep],
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();
        let mut blocked = [false, false];

        for step in steps {
            let fi = step.family.index();
            if blocked[fi] {
                continue;
            }
            let binary = step.family.binary();
            let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();

            match step.kind {
                StepKind::Unhook => {
                    let mut cleared = false;
                    for _ in 0..MAX_UNHOOK_ATTEMPTS {
                        match self.run(runner, binary, &arg_refs, logger) {
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

    fn clear_step_flag(&mut self, step: &TeardownStep) {
        match step.kind {
            StepKind::Unhook => self.clear_hooked(step.family),
            StepKind::Flush => {}
            StepKind::Delete => self.clear_created(step.family),
        }
    }

    pub fn force_cleanup(container_name: &str, netns_pid: u32, logger: &mut Logger) {
        let mut runner = NsenterRunner;
        Self::force_cleanup_with(container_name, netns_pid, &mut runner, logger);
    }

    fn force_cleanup_with(
        container_name: &str,
        netns_pid: u32,
        runner: &mut dyn CommandRunner,
        logger: &mut Logger,
    ) {
        let mut mgr = Self::for_full_reset(container_name, netns_pid);
        let _ = mgr.remove_firewall_rules_with(runner, logger);
    }

    fn for_full_reset(container_name: &str, netns_pid: u32) -> Self {
        let mut mgr = Self::new(container_name, netns_pid);
        mgr.v4_chain_created = true;
        mgr.v6_chain_created = true;
        mgr.v4_hooked = true;
        mgr.v6_hooked = true;
        mgr
    }

    fn nsenter_argv(&self, binary: &str, args: &[&str]) -> Vec<String> {
        build_nsenter_argv(self.netns_pid, binary, args)
    }

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

    fn container_ipv6_state(&self) -> HostIpv6State {
        let if_inet6 = format!("/proc/{}/net/if_inet6", self.netns_pid);
        let proc_net = format!("/proc/{}/net", self.netns_pid);
        NetworkIptablesManager::classify_container_ipv6_state(
            std::fs::read_to_string(&if_inet6),
            std::path::Path::new(&proc_net).is_dir(),
        )
    }

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

    #[test]
    fn the_inbound_log_line_names_the_schema_that_asked_for_the_posture() {
        for (directional, expected, absent) in [
            (true, "network.ingress", "allowLocalNetwork"),
            (false, "allowLocalNetwork", "network.ingress"),
        ] {
            let mut policy = ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            };
            if directional {
                policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    ..Default::default()
                });
                policy.network_ingress = Some(NetworkIngressPolicy::default());
            }

            let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
            let mut manager = IngressManager::new("log-field-test", 1);
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

    fn policy_with(allow_local: bool, default: NetworkPolicy) -> ContainerPolicy {
        ContainerPolicy {
            allow_local_network: allow_local,
            default_network_policy: default,
            ..Default::default()
        }
    }

    fn is(rule: &[String], want: &[&str]) -> bool {
        rule.len() == want.len() && rule.iter().zip(want).all(|(a, b)| a == b)
    }

    fn has(rules: &[Vec<String>], want: &[&str]) -> bool {
        rules.iter().any(|r| is(r, want))
    }

    fn pos(rules: &[Vec<String>], want: &[&str]) -> Option<usize> {
        rules.iter().position(|r| is(r, want))
    }

    const TEST_CHAIN: &str = "MXC-t";

    /// A `/proc/net/if_inet6` loopback line contains address, if_index,
    /// prefix_len, scope, flags, and device.
    const LOOPBACK_ONLY_IF_INET6: &str = "00000000000000000000000000000001 01 80 10 80       lo\n";

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

    #[test]
    fn container_empty_if_inet6_is_still_active() {
        let state = NetworkIptablesManager::classify_container_ipv6_state(Ok(String::new()), true);
        assert_eq!(
            state,
            HostIpv6State::Active,
            "an empty if_inet6 means no addresses *yet*, not IPv6 disabled"
        );
    }

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

    /// A kernel booted with IPv6 disabled does not create `if_inet6`.
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

    fn full_sequence(
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
        family: IpFamily,
    ) -> Vec<Vec<String>> {
        let rules =
            IngressManager::build_ingress_rules(TEST_CHAIN, policy, uses_directional_keys, family);
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

    fn verb(argv: &[String]) -> &str {
        argv.get(5).map(String::as_str).unwrap_or("")
    }

    fn absent_rule() -> RunError {
        RunError::Exit {
            stderr: "iptables: Bad rule (does a matching rule exist in that chain?).".to_string(),
            msg: "unhook: already absent".to_string(),
        }
    }

    fn absent_chain() -> RunError {
        RunError::Exit {
            stderr: "iptables: No chain/target/match by that name.".to_string(),
            msg: "chain: already absent".to_string(),
        }
    }

    /// C-locale iptables messages for missing rules and chains.
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

    #[test]
    fn localized_absent_messages_are_not_recognized_without_the_locale_pin() {
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

    fn build_family(allow_local: bool, family: IpFamily) -> Vec<Vec<String>> {
        full_sequence(
            &policy_with(allow_local, NetworkPolicy::Block),
            false,
            family,
        )
    }

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

    #[test]
    fn ipv6_does_not_blanket_accept_icmpv6_or_new_inbound() {
        let rules = build_family(false, IpFamily::V6);
        assert!(
            !has(&rules, &["-A", "MXC-t", "-p", "icmpv6", "-j", "ACCEPT"]),
            "IPv6 chain must not blanket-accept all ICMPv6"
        );
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

    #[test]
    fn ingress_chain_name_is_distinct_from_egress() {
        let name = "my-container";
        let ingress = IngressManager::new(name, 4242);
        let egress = crate::network_iptables::chain_name_for(name);
        assert_ne!(
            ingress.chain_name(),
            egress,
            "ingress and egress chains must not share a name"
        );
        assert!(
            ingress.chain_name().len() <= crate::network_iptables::CHAIN_NAME_MAX_LEN,
            "ingress chain name '{}' exceeds the {}-char ceiling",
            ingress.chain_name(),
            crate::network_iptables::CHAIN_NAME_MAX_LEN
        );
    }

    fn permissive_firewall_policy() -> ContainerPolicy {
        ContainerPolicy {
            allow_local_network: true,
            default_network_policy: NetworkPolicy::Block,
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        }
    }

    #[test]
    fn permissive_apply_is_refused_unconditionally() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        for pid in [1u32, 42u32, 999_999u32] {
            let mut mgr = IngressManager::new("permissive-container", pid);
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

    #[test]
    fn a_lan_inbound_refusal_does_not_give_a_host_loopback_rationale() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        for (policy, field) in [
            (
                directional_ingress(NetworkAction::Allow, NetworkAction::Deny),
                "network.ingress.default",
            ),
            (permissive_firewall_policy(), "allowLocalNetwork"),
        ] {
            let mut mgr = IngressManager::new("lan-inbound", 42);
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

    #[test]
    fn every_emitted_command_is_nsenter_prefixed() {
        let pid = 31337u32;
        let mgr = IngressManager::new("argv-container", pid);
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

    #[test]
    fn teardown_commands_are_nsenter_prefixed_and_chain_scoped() {
        let pid = 4242u32;
        let mut mgr = IngressManager::new("teardown-container", pid);

        mgr.v4_chain_created = true;
        mgr.v6_chain_created = true;
        mgr.v4_hooked = true;
        mgr.v6_hooked = true;
        let chain = mgr.chain_name().to_string();

        let steps = mgr.owned_teardown_steps();
        assert_eq!(
            steps.len(),
            6,
            "full ownership must plan six teardown steps"
        );
        for step in &steps {
            let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();
            let argv = mgr.nsenter_argv(step.family.binary(), &arg_refs);
            assert_nsenter_prefixed(&argv, pid, step.family.binary(), &arg_refs);
            assert!(
                step.args.iter().any(|a| a == &chain),
                "teardown step {:?} must target our chain '{}', got {:?}",
                step.kind,
                chain,
                step.args
            );
        }
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

    #[test]
    fn drop_honors_preserve_policy() {
        let mut mgr = IngressManager::new("preserve-container", 4242);

        assert!(
            !mgr.should_cleanup_on_drop(),
            "a manager that installed nothing must not attempt teardown"
        );
        mgr.set_preserve_policy(true);
        assert!(!mgr.should_cleanup_on_drop());

        mgr.v4_chain_created = true;
        mgr.v4_hooked = true;
        assert!(
            mgr.rules_applied(),
            "precondition: the manager owns installed state"
        );
        assert!(
            !mgr.should_cleanup_on_drop(),
            "preservePolicy was requested; Drop must not remove the chain"
        );

        mgr.set_preserve_policy(false);
        assert!(
            mgr.should_cleanup_on_drop(),
            "without preservePolicy an installed chain must still be torn down"
        );

        mgr.v4_chain_created = false;
        mgr.v4_hooked = false;
    }

    #[test]
    fn force_cleanup_removes_all_resources_via_nsenter() {
        let pid = 9001u32;
        let container = "force-cleanup-container";
        let chain = IngressManager::new(container, pid).chain_name().to_string();
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let mut runner = FakeRunner {
            calls: Vec::new(),
            respond: |argv: &[String]| match verb(argv) {
                "-D" => Err(absent_rule()),
                _ => Err(absent_chain()),
            },
        };

        IngressManager::force_cleanup_with(container, pid, &mut runner, &mut logger);

        assert_eq!(
            runner.calls.len(),
            6,
            "force_cleanup must issue all six teardown commands, got {:?}",
            runner.calls
        );

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

        for binary in ["iptables", "ip6tables"] {
            assert!(
                runner.calls.iter().any(|a| a[4] == binary),
                "force_cleanup must cover {binary}"
            );
        }

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

    #[test]
    fn install_resets_then_creates_then_hooks_last() {
        let pid = 4242u32;
        let container = "install-order-container";
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new(container, pid);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
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
        assert!(
            first("-N") < first("-A"),
            "create must precede the body: {verbs:?}"
        );
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

    #[test]
    fn reset_repeats_unhook_until_absent_then_deletes() {
        let pid = 55u32;
        let container = "reset-repeat-container";
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new(container, pid);

        let mut d_seen = 0;
        let mut runner = FakeRunner {
            calls: Vec::new(),
            respond: move |argv: &[String]| match verb(argv) {
                "-D" => {
                    d_seen += 1;
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

    #[test]
    fn partial_body_failure_plans_flush_delete_no_unhook() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("partial-container", pid);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
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

        assert!(mgr.v4_chain_created, "the successful -N must set created");
        assert!(
            !mgr.v4_hooked,
            "the hook never landed, so hooked must stay false"
        );

        assert!(
            !runner.calls.iter().any(|a| verb(a) == "-I"),
            "no -I INPUT hook may be issued when a body rule failed: {:?}",
            runner.calls
        );

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

    #[test]
    fn reset_spawn_failure_aborts_before_create_with_no_ownership() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("reset-spawn-fail-container", pid);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
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

    #[test]
    fn reset_unhook_exhaustion_aborts_before_create() {
        let pid = 7u32;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut mgr = IngressManager::new("reset-exhaustion-container", pid);
        let rules = IngressManager::build_ingress_rules(
            mgr.chain_name(),
            &policy_with(false, NetworkPolicy::Block),
            false,
            IpFamily::V4,
        );

        let mut runner = FakeRunner {
            calls: Vec::new(),
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

    #[test]
    fn absent_classification_rejects_spawn_style_messages() {
        assert!(
            StepKind::Flush.stderr_means_absent("iptables: No chain/target/match by that name.")
        );
        assert!(StepKind::Delete.stderr_means_absent("No chain/target/match by that name"));
        assert!(StepKind::Unhook.stderr_means_absent(
            "iptables: Bad rule (does a matching rule exist in that chain?)."
        ));
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
        assert!(
            !StepKind::Flush.stderr_means_absent("does a matching rule exist in that chain?"),
            "a missing-rule message must not clear a chain flush/delete step"
        );
    }

    /// Strings captured from iptables 1.8.10 under `LC_ALL=C`.
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

    #[test]
    fn a_firewall_mode_config_with_nothing_to_restrict_outbound_still_installs_the_inbound_chain() {
        for mode in [
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let label = format!("{mode:?}");
            let policy = legacy_firewall_mode_with_permissive_egress(mode);

            assert!(
                plan_network(&policy).installs_firewall(),
                "{label}: a config naming a firewall enforcement mode is owed the inbound \
                 deny chain even with nothing to restrict outbound"
            );
        }
    }

    #[test]
    fn a_stated_directional_posture_installs_the_inbound_chain() {
        let mut policy = directional_ingress(NetworkAction::Allow, NetworkAction::Deny);
        policy.default_network_policy = NetworkPolicy::Allow;
        policy.network_egress = Some(Default::default());

        assert!(plan_network(&policy).installs_firewall());
    }

    #[test]
    fn a_posture_admitting_no_peer_installs_no_inbound_chain() {
        let mut policy = directional_ingress(NetworkAction::Deny, NetworkAction::Deny);
        policy.network_egress = Some(Default::default());

        assert!(!plan_network(&policy).installs_firewall());
    }
}
