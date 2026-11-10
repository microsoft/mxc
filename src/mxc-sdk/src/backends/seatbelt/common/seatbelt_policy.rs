// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt policy invariants, enforced by the backend's own `validate`.
//!
//! `validate` runs on every execution path -- the JSON parser feeds one here,
//! and a Rust caller that hands `mxc_engine` an `ExecutionRequest` it built
//! itself reaches the same check -- so this is the only home the rules need.
//!
//! Each check returns the caller-facing message; the backend wraps it as a
//! `ScriptResponse`.

use crate::mxc_common::host_is_canonical_loopback;
use crate::mxc_common::models::{
    ClipboardPolicy, ContainerPolicy, ExecutionRequest, NetworkAction, SeatbeltConfig,
    SeatbeltCustomRules,
};

/// Effective GUI posture: `seatbelt.guiAccess` only means anything when the UI
/// policy leaves UI enabled, since every GUI grant is emitted alongside the
/// WindowServer allows. Single source of truth so the profile builder and the
/// runner cannot drift apart on what "GUI access" means.
///
/// [`validate_seatbelt_ui_policy`] rejects the contradictory combination, so on
/// an executed request this equals the raw `guiAccess` flag; the helper keeps
/// the direct `build_profile` callers (unit tests, embedders) consistent too.
pub fn gui_access_effective(request: &ExecutionRequest) -> bool {
    request.seatbelt.as_ref().is_some_and(|c| c.gui_access) && !request.policy.ui.disable
}

/// Reject a `guiAccess` request that the UI policy contradicts.
/// Fail loudly rather than hand back a sandbox that ignored the request.
pub fn validate_seatbelt_ui_policy(request: &ExecutionRequest) -> Result<(), String> {
    let gui_requested = request.seatbelt.as_ref().is_some_and(|c| c.gui_access);
    if gui_requested && request.policy.ui.disable {
        return Err("Seatbelt: seatbelt.guiAccess=true cannot be combined with \
                    ui.disable=true. The GUI grants (Mach IPC, mach-register, IOKit, \
                    pseudo-tty, per-user temp/cache writes) are only emitted when UI \
                    is enabled, so this combination would drop every GUI capability \
                    and deny WindowServer instead. Set 'ui.disable' to false to grant \
                    GUI access, or remove 'seatbelt.guiAccess'. Note that 'ui.disable' \
                    defaults to true, so an omitted 'ui' section conflicts too."
            .to_string());
    }
    Ok(())
}

/// Mach name prefix reserved for MXC's per-run process cleanup rules.
pub const RUN_MARKER_NAME_PREFIX: &str = "com.microsoft.mxc.run.";

/// Keychain servers, denied unless `keychainAccess` is set. `SecurityServer`
/// serves file-based keychains; the `com.apple.securityd` family serves the
/// data-protection keychain.
pub const KEYCHAIN_SERVER_NAMES: &[&str] = &["com.apple.SecurityServer"];
pub const KEYCHAIN_SERVER_PREFIXES: &[&str] = &["com.apple.securityd"];
/// Mach services that `keychainAccess: true` grants by name. `trustd` copies
/// system trust settings; without it every TLS handshake logs a failure per
/// root certificate.
pub const KEYCHAIN_GRANTED_NAMES: &[&str] = &[
    "com.apple.SecurityServer",
    "com.apple.securityd",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    "com.apple.ocspd",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.xpcd",
];
/// Mach service prefixes that `keychainAccess: true` grants (LaunchServices).
pub const KEYCHAIN_GRANTED_PREFIXES: &[&str] = &["com.apple.lsd."];
/// Mach services controlled by `ui.disable`.
pub const UI_SERVICE_NAMES: &[&str] = &[
    "com.apple.windowserver.active",
    "com.apple.windowserver.session",
    "com.apple.coreservices.launchservicesd",
];
/// Pasteboard server that a permitting `ui.clipboard` grants.
pub const PASTEBOARD_SERVICE_NAME: &str = "com.apple.pasteboard.1";
/// Pasteboard servers, denied when `ui.clipboard` is `"none"`.
pub const PASTEBOARD_SERVICE_PREFIX: &str = "com.apple.pasteboard.";
/// IOKit user-client class controlled by `ui.injection`.
pub const HID_USER_CLIENT_CLASS: &str = "IOHIDLibUserClient";
/// Longest POSIX shared memory name macOS accepts (`PSHMNAMLEN`).
const POSIX_SHM_NAME_MAX: usize = 31;

/// One entry of a Seatbelt custom rule list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamePattern<'a> {
    Exact(&'a str),
    /// An entry ending in `*`, stored without it.
    Prefix(&'a str),
}

impl<'a> NamePattern<'a> {
    pub fn parse(entry: &'a str) -> Self {
        match entry.strip_suffix('*') {
            Some(prefix) => Self::Prefix(prefix),
            None => Self::Exact(entry),
        }
    }

    fn text(self) -> &'a str {
        match self {
            Self::Exact(text) | Self::Prefix(text) => text,
        }
    }

    /// Whether every name this pattern matches also matches `other`.
    fn within(self, other: NamePattern<'_>) -> bool {
        match (self, other) {
            (NamePattern::Exact(name), NamePattern::Exact(other)) => name == other,
            (_, NamePattern::Prefix(other)) => self.text().starts_with(other),
            (NamePattern::Prefix(_), NamePattern::Exact(_)) => false,
        }
    }

    /// Whether some name matches both patterns.
    fn overlaps(self, other: NamePattern<'_>) -> bool {
        self.within(other) || other.within(self)
    }
}

/// Every custom rule list with its JSON name, and whether its entries are
/// IOKit class names.
fn custom_rule_sets(
    config: &SeatbeltConfig,
) -> Vec<(&'static str, &SeatbeltCustomRules, CustomNameKind)> {
    let registers = config.custom_mach_registers.as_ref();
    [
        (
            "customIoKits",
            config.custom_io_kits.as_ref(),
            CustomNameKind::IoKit,
        ),
        (
            "customMachLookups",
            config.custom_mach_lookups.as_ref(),
            CustomNameKind::MachLookup,
        ),
        (
            "customMachRegisters.global",
            registers.and_then(|r| r.global.as_ref()),
            CustomNameKind::MachRegister,
        ),
        (
            "customMachRegisters.local",
            registers.and_then(|r| r.local.as_ref()),
            CustomNameKind::MachRegister,
        ),
    ]
    .into_iter()
    .filter_map(|(field, rules, kind)| rules.map(|rules| (field, rules, kind)))
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomNameKind {
    IoKit,
    MachLookup,
    MachRegister,
    PosixShm,
}

/// Names that an explicit setting allows or denies.
struct SettingNames {
    patterns: Vec<NamePattern<'static>>,
    description: &'static str,
    setting: &'static str,
}

/// Names that explicit settings deny and grant, for one kind of name.
fn setting_names(
    request: &ExecutionRequest,
    kind: CustomNameKind,
) -> (Vec<SettingNames>, Vec<SettingNames>) {
    let ui = &request.policy.ui;
    let mut denied = Vec::new();
    let mut granted = Vec::new();
    match kind {
        CustomNameKind::MachLookup => {
            let keychain = request.seatbelt.as_ref().is_some_and(|c| c.keychain_access);
            let (target, patterns) = if keychain {
                (
                    &mut granted,
                    KEYCHAIN_GRANTED_NAMES
                        .iter()
                        .map(|n| NamePattern::Exact(n))
                        .chain(
                            KEYCHAIN_GRANTED_PREFIXES
                                .iter()
                                .map(|p| NamePattern::Prefix(p)),
                        )
                        .collect(),
                )
            } else {
                (
                    &mut denied,
                    KEYCHAIN_SERVER_NAMES
                        .iter()
                        .map(|n| NamePattern::Exact(n))
                        .chain(
                            KEYCHAIN_SERVER_PREFIXES
                                .iter()
                                .map(|p| NamePattern::Prefix(p)),
                        )
                        .collect(),
                )
            };
            target.push(SettingNames {
                patterns,
                description: "a Keychain server",
                setting: "seatbelt.keychainAccess",
            });
            let (target, pattern) = if matches!(ui.clipboard, ClipboardPolicy::None) {
                (&mut denied, NamePattern::Prefix(PASTEBOARD_SERVICE_PREFIX))
            } else {
                (&mut granted, NamePattern::Exact(PASTEBOARD_SERVICE_NAME))
            };
            target.push(SettingNames {
                patterns: vec![pattern],
                description: "a pasteboard server",
                setting: "ui.clipboard",
            });
            let target = if ui.disable {
                &mut denied
            } else {
                &mut granted
            };
            target.push(SettingNames {
                patterns: UI_SERVICE_NAMES
                    .iter()
                    .map(|n| NamePattern::Exact(n))
                    .collect(),
                description: "a WindowServer or LaunchServices service",
                setting: "ui.disable",
            });
        }
        CustomNameKind::IoKit => {
            let target = if ui.injection {
                &mut granted
            } else {
                &mut denied
            };
            target.push(SettingNames {
                patterns: vec![NamePattern::Exact(HID_USER_CLIENT_CLASS)],
                description: "the HID input client",
                setting: "ui.injection",
            });
        }
        CustomNameKind::MachRegister | CustomNameKind::PosixShm => {}
    }
    (denied, granted)
}

/// Reject allow entries that only name what a setting denies, and deny
/// entries that would remove what a setting grants.
fn check_setting_conflicts(
    request: &ExecutionRequest,
    kind: CustomNameKind,
    (allow_list, allow): (&str, &[String]),
    (deny_list, deny): (&str, &[String]),
) -> Result<(), String> {
    let (denied, granted) = setting_names(request, kind);
    for entry in allow {
        let pattern = NamePattern::parse(entry);
        if let Some(names) = denied
            .iter()
            .find(|names| names.patterns.iter().any(|d| pattern.within(*d)))
        {
            return Err(format!(
                "Seatbelt: {allow_list} entry '{entry}' names {}, which the current {} \
                 setting denies. Change {} instead.",
                names.description, names.setting, names.setting
            ));
        }
    }
    for entry in deny {
        let pattern = NamePattern::parse(entry);
        if let Some(names) = granted
            .iter()
            .find(|names| names.patterns.iter().any(|g| pattern.overlaps(*g)))
        {
            return Err(format!(
                "Seatbelt: {deny_list} entry '{entry}' would deny {}, which the current {} \
                 setting allows. Change {} instead.",
                names.description, names.setting, names.setting
            ));
        }
    }
    Ok(())
}

fn validate_custom_entry(list: &str, entry: &str, kind: CustomNameKind) -> Result<(), String> {
    let name = match NamePattern::parse(entry) {
        NamePattern::Exact(name) | NamePattern::Prefix(name) => name,
    };
    if name.is_empty() {
        return Err(format!(
            "Seatbelt: {list} entries must be non-empty names; a bare '*' is not \
             supported. Set 'default' to \"allow\" to allow every name."
        ));
    }
    if name.contains('*') {
        return Err(format!(
            "Seatbelt: {list} entry '{entry}' has a '*' that is not at the end. \
             Only a single trailing '*' (prefix match) is supported."
        ));
    }
    let is_class_name = |name: &str| {
        name.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if kind == CustomNameKind::IoKit && !is_class_name(name) {
        return Err(format!(
            "Seatbelt: {list} entry '{entry}' is not an IOKit user-client class name \
             (letters, digits, and '_', optionally ending in '*')."
        ));
    }
    if kind == CustomNameKind::PosixShm && name.len() > POSIX_SHM_NAME_MAX {
        return Err(format!(
            "Seatbelt: {list} entry '{entry}' is longer than {POSIX_SHM_NAME_MAX} bytes, \
             the longest POSIX shared memory name macOS accepts."
        ));
    }
    Ok(())
}

/// Validate `customIoKits`, `customMachLookups`, `customMachRegisters`,
/// `customPosixShm`, and the `extraMachLookups` entries they interact with.
pub fn validate_seatbelt_custom_rules(request: &ExecutionRequest) -> Result<(), String> {
    let Some(config) = request.seatbelt.as_ref() else {
        return Ok(());
    };
    let sets = custom_rule_sets(config);
    let has_custom = !sets.is_empty() || config.custom_posix_shm.is_some();
    if has_custom && config.profile_override.is_some() {
        return Err(
            "Seatbelt: seatbelt.profileOverride replaces the generated profile, so \
                    it cannot be combined with customIoKits, customMachLookups, \
                    customMachRegisters, or customPosixShm. Remove profileOverride, or \
                    write those rules into the override."
                .to_string(),
        );
    }
    if config.custom_mach_lookups.is_some() && !config.extra_mach_lookups.is_empty() {
        return Err(
            "Seatbelt: seatbelt.extraMachLookups cannot be combined with \
                    seatbelt.customMachLookups. Move the extraMachLookups entries into \
                    customMachLookups.allow."
                .to_string(),
        );
    }
    check_setting_conflicts(
        request,
        CustomNameKind::MachLookup,
        ("seatbelt.extraMachLookups", &config.extra_mach_lookups),
        ("", &[]),
    )?;
    for (field, rules, kind) in sets {
        let allow_list = format!("seatbelt.{field}.allow");
        let deny_list = format!("seatbelt.{field}.deny");
        for entry in &rules.allow {
            validate_custom_entry(&allow_list, entry, kind)?;
        }
        for entry in &rules.deny {
            validate_custom_entry(&deny_list, entry, kind)?;
        }
        check_setting_conflicts(
            request,
            kind,
            (&allow_list, &rules.allow),
            (&deny_list, &rules.deny),
        )?;
    }
    if let Some(shm) = config.custom_posix_shm.as_ref() {
        for (list, entries) in [
            ("read", &shm.read),
            ("readWrite", &shm.read_write),
            ("own", &shm.own),
            ("deny", &shm.deny),
        ] {
            let list = format!("seatbelt.customPosixShm.{list}");
            for entry in entries {
                validate_custom_entry(&list, entry, CustomNameKind::PosixShm)?;
            }
        }
    }
    Ok(())
}

/// Reject caller-supplied names in the reserved cleanup prefix. The rules MXC
/// appends to every profile override them, so they could never take effect.
pub fn validate_seatbelt_reserved_names(request: &ExecutionRequest) -> Result<(), String> {
    let Some(config) = request.seatbelt.as_ref() else {
        return Ok(());
    };
    if config
        .profile_override
        .as_deref()
        .is_some_and(|profile| profile.contains(RUN_MARKER_NAME_PREFIX))
    {
        return Err(format!(
            "Seatbelt: seatbelt.profileOverride contains '{RUN_MARKER_NAME_PREFIX}', which \
             MXC reserves for its process cleanup rules. Remove those rules (they are \
             specific to the run that printed them); MXC adds this run's own."
        ));
    }
    let custom_lookups = config.custom_mach_lookups.as_ref();
    let lookup_lists = [
        (
            "seatbelt.extraMachLookups",
            Some(&config.extra_mach_lookups),
        ),
        (
            "seatbelt.customMachLookups.allow",
            custom_lookups.map(|rules| &rules.allow),
        ),
        (
            "seatbelt.customMachLookups.deny",
            custom_lookups.map(|rules| &rules.deny),
        ),
    ];
    for (list, entries) in lookup_lists {
        if let Some(name) = entries
            .into_iter()
            .flatten()
            .find(|name| name.starts_with(RUN_MARKER_NAME_PREFIX))
        {
            return Err(format!(
                "Seatbelt: {list} entry '{name}' uses the prefix \
                 '{RUN_MARKER_NAME_PREFIX}', which MXC reserves for its process cleanup rules."
            ));
        }
    }
    Ok(())
}

/// Effective outbound posture; omission defaults to deny.
pub fn egress_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| egress.default == NetworkAction::Allow)
}

/// Effective inbound posture. Seatbelt maps `network.ingress.default` onto its
/// `(allow network-inbound (local ip))` rule; `hostLoopback` is enforced
/// separately on the container-to-host direction, so it plays no part here.
pub fn local_network_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.default == NetworkAction::Allow)
}

/// Effective host-loopback posture; omission defaults to deny.
pub fn host_loopback_allowed(policy: &ContainerPolicy) -> bool {
    policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Allow)
}

/// Check every Seatbelt network invariant before profile construction.
pub fn validate_seatbelt_network_policy(policy: &ContainerPolicy) -> Result<(), String> {
    let proxy_enabled = policy.network_proxy.is_enabled();
    let outbound_allowed = egress_allowed(policy);

    // A remote proxy can't be expressed as a reachability rule.
    if !outbound_allowed
        && policy
            .network_proxy
            .address
            .as_ref()
            .is_some_and(|addr| !host_is_canonical_loopback(addr.host()))
    {
        return Err(
            "Seatbelt: runtimeConfig.networkProxy must name a loopback endpoint \
                    (127.0.0.1, [::1], or localhost); a remote proxy cannot be reached \
                    under network.egress.default='deny'"
                .to_string(),
        );
    }

    // Outbound is already unrestricted, so the proxy adds no enforcement and
    // any intent to route through it is silently ignored.
    if proxy_enabled && outbound_allowed {
        return Err("Seatbelt: runtimeConfig.networkProxy requires \
                    network.egress.default='deny'; an allow default would bypass \
                    the proxy and leave direct outbound traffic unrestricted"
            .to_string());
    }

    // `hostLoopback` is bidirectional and Seatbelt can only enforce its
    // container-to-host half (see `write_host_loopback_rules`): an inbound
    // filter cannot be scoped by peer, so there is no rule that admits a
    // loopback peer while refusing a LAN one. Only `hostLoopback: "allow"`
    // under `default: "deny"` is inexpressible -- the blanket
    // `network-inbound` grant that would carry it is exactly what
    // `default: "deny"` withholds -- so only that pair is refused.
    if let Some(ingress) = policy.network_ingress.as_ref() {
        if ingress.host_loopback == NetworkAction::Allow && ingress.default == NetworkAction::Deny {
            return Err(
                "macOS Seatbelt cannot enforce network.ingress.hostLoopback='allow' \
                 alongside network.ingress.default='deny': the inbound half of \
                 host loopback rides the same Seatbelt rule as the inbound \
                 default, so it cannot be granted while that default denies it. \
                 Set network.ingress.default='allow' as well, or set \
                 hostLoopback='deny'. Note that an omitted 'hostLoopback' is \
                 'deny', not an inherit of 'default'."
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// `seatbelt.captureDenials` relies on tagging the rules of the generated
/// profile, so a replacement profile cannot be captured.
pub fn validate_seatbelt_capture_denials(request: &ExecutionRequest) -> Result<(), String> {
    let Some(config) = request.seatbelt.as_ref() else {
        return Ok(());
    };
    if config.capture_denials.is_some() && config.profile_override.is_some() {
        return Err("Seatbelt: seatbelt.captureDenials cannot be combined with \
                    seatbelt.profileOverride. Capture tags the rules in MXC's generated \
                    profile to find this run's log entries, and MXC does not rewrite a \
                    custom profile. Remove profileOverride, or add your own \
                    (with message ...) tags and read them with `log stream`"
            .to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ProxyAddress, ProxyConfig, SeatbeltConfig, SeatbeltCustomMachRegisters,
        SeatbeltCustomPosixShm,
    };

    #[test]
    fn omitted_host_loopback_defaults_to_deny() {
        assert!(!host_loopback_allowed(&policy()));
    }

    #[test]
    fn host_loopback_allowed_reads_the_directional_field() {
        let mut p = policy();
        for (action, expected) in [(NetworkAction::Allow, true), (NetworkAction::Deny, false)] {
            p.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
                default: action,
                host_loopback: action,
            });
            assert_eq!(host_loopback_allowed(&p), expected);
        }
    }

    fn policy() -> ContainerPolicy {
        ContainerPolicy::default()
    }

    fn proxy(host: &str) -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(
                &format!("http://{host}:8080"),
                host.to_string(),
                8080,
            )),
        }
    }

    #[test]
    fn rejects_proxy_with_default_allow() {
        let mut p = policy();
        p.network_egress = Some(crate::mxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        p.network_proxy = proxy("127.0.0.1");

        let msg = validate_seatbelt_network_policy(&p).unwrap_err();
        assert!(msg.contains("network.egress.default='deny'"), "got: {msg}");
    }

    /// The guard compared unbracketed literals only, so `http://[::1]` — the
    /// documented IPv6 form — was misread as remote and rejected.
    #[test]
    fn accepts_loopback_proxy_under_block_in_every_spelling() {
        for host in [
            "127.0.0.1",
            "[::1]",
            "localhost",
            "[0:0:0:0:0:0:0:1]",
            "[0000:0000:0000:0000:0000:0000:0000:0001]",
        ] {
            let mut p = policy();
            p.network_proxy = proxy(host);

            assert!(
                validate_seatbelt_network_policy(&p).is_ok(),
                "loopback proxy host {host:?} should be accepted under a deny default"
            );
        }
    }

    #[test]
    fn rejects_remote_proxy_under_block() {
        // The last three are the other half of the widening above: accepting
        // every ::1 spelling must not spill into the rest of 127.0.0.0/8, since
        // the profile's `(remote ip "localhost:<port>")` covers only the
        // canonical addresses.
        for host in [
            "proxy.corp.example",
            "10.0.0.5",
            "[2001:db8::1]",
            "127.0.0.2",
            "127.0.0.53",
            "0.0.0.0",
        ] {
            let mut p = policy();
            p.network_proxy = proxy(host);

            let msg = validate_seatbelt_network_policy(&p).unwrap_err();
            assert!(msg.contains("loopback endpoint"), "{host:?} got: {msg}");
        }
    }

    /// `guiAccess` with a `SeatbeltConfig` and the given `ui.disable`.
    fn gui_request(gui_access: bool, ui_disabled: bool) -> ExecutionRequest {
        let mut r = ExecutionRequest::default();
        r.policy.ui.disable = ui_disabled;
        r.seatbelt = Some(SeatbeltConfig {
            gui_access,
            ..Default::default()
        });
        r
    }

    #[test]
    fn rejects_gui_access_when_ui_is_disabled() {
        // ui.disable defaults to true, so this is what an omitted `ui`
        // section produces — the case that used to be silently ignored.
        let msg = validate_seatbelt_ui_policy(&gui_request(true, true)).unwrap_err();
        assert!(msg.contains("guiAccess"), "got: {msg}");
        assert!(msg.contains("ui.disable"), "got: {msg}");
    }

    #[test]
    fn accepts_gui_access_when_ui_is_enabled() {
        assert!(validate_seatbelt_ui_policy(&gui_request(true, false)).is_ok());
    }

    #[test]
    fn accepts_ui_disabled_without_gui_access() {
        assert!(validate_seatbelt_ui_policy(&gui_request(false, true)).is_ok());
        // An absent seatbelt section must not trip the rule either.
        assert!(validate_seatbelt_ui_policy(&ExecutionRequest::default()).is_ok());
    }

    fn seatbelt_request(config: SeatbeltConfig) -> ExecutionRequest {
        ExecutionRequest {
            seatbelt: Some(config),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_reserved_cleanup_names() {
        let copied_rule = "(version 1)(allow default)\n\
             (allow mach-lookup (global-name \"com.microsoft.mxc.run.0123\"))";
        let msg = validate_seatbelt_reserved_names(&seatbelt_request(SeatbeltConfig {
            profile_override: Some(copied_rule.into()),
            ..Default::default()
        }))
        .unwrap_err();
        assert!(msg.contains("profileOverride"), "got: {msg}");

        let msg = validate_seatbelt_reserved_names(&seatbelt_request(SeatbeltConfig {
            extra_mach_lookups: vec![
                "com.example.service".into(),
                "com.microsoft.mxc.run.0123".into(),
            ],
            ..Default::default()
        }))
        .unwrap_err();
        assert!(msg.contains("extraMachLookups"), "got: {msg}");
    }

    #[test]
    fn accepts_names_outside_the_reserved_prefix() {
        assert!(validate_seatbelt_reserved_names(&ExecutionRequest::default()).is_ok());
        let request = seatbelt_request(SeatbeltConfig {
            profile_override: Some("(version 1)(allow default)".into()),
            extra_mach_lookups: vec!["com.microsoft.mxc.runner".into()],
            ..Default::default()
        });
        assert!(validate_seatbelt_reserved_names(&request).is_ok());
    }

    fn lookups(allow: &[&str], deny: &[&str]) -> SeatbeltConfig {
        SeatbeltConfig {
            custom_mach_lookups: Some(SeatbeltCustomRules {
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: deny.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn custom_error(config: SeatbeltConfig) -> String {
        validate_seatbelt_custom_rules(&seatbelt_request(config)).unwrap_err()
    }

    #[test]
    fn rejects_malformed_custom_entries() {
        for (entry, expected) in [
            ("*", "bare '*'"),
            ("", "non-empty"),
            ("com.*.service", "not at the end"),
            ("com.example**", "not at the end"),
        ] {
            let msg = custom_error(lookups(&[entry], &[]));
            assert!(msg.contains("customMachLookups.allow"), "{entry}: {msg}");
            assert!(msg.contains(expected), "{entry}: {msg}");
        }
        for entry in ["com.apple.Foo", "9Class", "IO-Surface*"] {
            let msg = custom_error(SeatbeltConfig {
                custom_io_kits: Some(SeatbeltCustomRules {
                    deny: vec![entry.into()],
                    ..Default::default()
                }),
                ..Default::default()
            });
            assert!(msg.contains("customIoKits.deny"), "{entry}: {msg}");
            assert!(msg.contains("IOKit user-client class"), "{entry}: {msg}");
        }
        for (scope, entry) in [("global", "*"), ("local", "com.*.x")] {
            let rules = Some(SeatbeltCustomRules {
                allow: vec![entry.into()],
                ..Default::default()
            });
            let registers = if scope == "global" {
                SeatbeltCustomMachRegisters {
                    global: rules,
                    local: None,
                }
            } else {
                SeatbeltCustomMachRegisters {
                    global: None,
                    local: rules,
                }
            };
            let msg = custom_error(SeatbeltConfig {
                custom_mach_registers: Some(registers),
                ..Default::default()
            });
            let list = format!("customMachRegisters.{scope}.allow");
            assert!(msg.contains(&list), "{entry}: {msg}");
        }

        let shm = |list: &str, entry: &str| {
            let mut shm = SeatbeltCustomPosixShm::default();
            let target = match list {
                "read" => &mut shm.read,
                "readWrite" => &mut shm.read_write,
                "own" => &mut shm.own,
                _ => &mut shm.deny,
            };
            target.push(entry.into());
            seatbelt_request(SeatbeltConfig {
                custom_posix_shm: Some(shm),
                ..Default::default()
            })
        };
        // The limit counts bytes, not characters; a trailing '*' is not part
        // of the name.
        let longest = format!("/{}", "a".repeat(30));
        let multibyte = format!("/{}", "\u{e9}".repeat(15));
        for entry in [longest.clone(), format!("{longest}*"), multibyte.clone()] {
            validate_seatbelt_custom_rules(&shm("own", &entry)).unwrap();
        }
        for (list, entry, expected) in [
            ("read", format!("{longest}b"), "longer than 31 bytes"),
            (
                "readWrite",
                format!("{multibyte}\u{e9}"),
                "longer than 31 bytes",
            ),
            ("own", "*".to_string(), "bare '*'"),
            ("deny", "/app*.x".to_string(), "not at the end"),
        ] {
            let msg = validate_seatbelt_custom_rules(&shm(list, &entry)).unwrap_err();
            assert!(
                msg.contains(&format!("customPosixShm.{list}")),
                "{entry}: {msg}"
            );
            assert!(msg.contains(expected), "{entry}: {msg}");
        }
    }

    #[test]
    fn rejects_custom_rules_that_cannot_apply() {
        let msg = custom_error(SeatbeltConfig {
            profile_override: Some("(version 1)".into()),
            ..lookups(&["com.example.a"], &[])
        });
        assert!(msg.contains("profileOverride"), "{msg}");

        let msg = custom_error(SeatbeltConfig {
            profile_override: Some("(version 1)".into()),
            custom_posix_shm: Some(SeatbeltCustomPosixShm::default()),
            ..Default::default()
        });
        assert!(msg.contains("profileOverride"), "{msg}");

        let msg = custom_error(SeatbeltConfig {
            extra_mach_lookups: vec!["com.example.a".into()],
            ..lookups(&[], &[])
        });
        assert!(msg.contains("customMachLookups.allow"), "{msg}");
    }

    /// Explicit settings decide their own names; custom lists cannot
    /// contradict them.
    #[test]
    fn rejects_custom_entries_that_contradict_settings() {
        for (config, list, setting) in [
            (
                lookups(&["com.apple.SecurityServer"], &[]),
                "customMachLookups.allow",
                "keychainAccess",
            ),
            (
                lookups(&["com.apple.securityd.xpc*"], &[]),
                "customMachLookups.allow",
                "keychainAccess",
            ),
            (
                SeatbeltConfig {
                    extra_mach_lookups: vec!["com.apple.securityd".into()],
                    ..Default::default()
                },
                "extraMachLookups",
                "keychainAccess",
            ),
            (
                SeatbeltConfig {
                    keychain_access: true,
                    ..lookups(&[], &["com.apple.Security*"])
                },
                "customMachLookups.deny",
                "keychainAccess",
            ),
            (
                lookups(&["com.apple.pasteboard.1"], &[]),
                "customMachLookups.allow",
                "ui.clipboard",
            ),
            (
                lookups(&["com.apple.pasteboard.*"], &[]),
                "customMachLookups.allow",
                "ui.clipboard",
            ),
            (
                SeatbeltConfig {
                    extra_mach_lookups: vec!["com.apple.pasteboard.2".into()],
                    ..Default::default()
                },
                "extraMachLookups",
                "ui.clipboard",
            ),
            (
                lookups(&["com.apple.windowserver.active"], &[]),
                "customMachLookups.allow",
                "ui.disable",
            ),
            (
                SeatbeltConfig {
                    custom_io_kits: Some(SeatbeltCustomRules {
                        allow: vec!["IOHIDLibUserClient".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                "customIoKits.allow",
                "ui.injection",
            ),
        ] {
            let mut request = seatbelt_request(config);
            request.policy.ui.injection = false;
            let msg = validate_seatbelt_custom_rules(&request).unwrap_err();
            assert!(msg.contains(list), "{list}: {msg}");
            assert!(msg.contains(setting), "{list}: {msg}");
        }

        let mut request = seatbelt_request(lookups(&[], &["com.apple.windowserver.*"]));
        request.policy.ui.disable = false;
        let msg = validate_seatbelt_custom_rules(&request).unwrap_err();
        assert!(msg.contains("ui.disable"), "{msg}");

        let mut request = seatbelt_request(lookups(&[], &["com.apple.pasteboard.*"]));
        request.policy.ui.clipboard = ClipboardPolicy::All;
        let msg = validate_seatbelt_custom_rules(&request).unwrap_err();
        assert!(msg.contains("ui.clipboard"), "{msg}");

        // Every name keychainAccess grants, not only the Keychain servers.
        for entry in [
            "com.apple.trustd",
            "com.apple.xpcd",
            "com.apple.cfprefsd.*",
            "com.apple.lsd.mapdb",
            "com.apple.lsd.*",
        ] {
            let msg = custom_error(SeatbeltConfig {
                keychain_access: true,
                ..lookups(&[], &[entry])
            });
            assert!(msg.contains("customMachLookups.deny"), "{entry}: {msg}");
            assert!(msg.contains("keychainAccess"), "{entry}: {msg}");
        }

        let mut request = seatbelt_request(SeatbeltConfig {
            custom_io_kits: Some(SeatbeltCustomRules {
                deny: vec!["IOHID*".into()],
                ..Default::default()
            }),
            ..Default::default()
        });
        request.policy.ui.injection = true;
        let msg = validate_seatbelt_custom_rules(&request).unwrap_err();
        assert!(msg.contains("customIoKits.deny"), "{msg}");
        assert!(msg.contains("ui.injection"), "{msg}");
    }

    #[test]
    fn accepts_custom_entries_consistent_with_settings() {
        // A broad prefix may cover a denied name; the setting's deny wins.
        let mut request = seatbelt_request(lookups(
            &["com.apple.*", "com.example.service"],
            &["com.apple.windowserver.*", "com.apple.pasteboard.1"],
        ));
        request.policy.ui.injection = false;
        request.seatbelt.as_mut().unwrap().custom_io_kits = Some(SeatbeltCustomRules {
            allow: vec!["AGXDeviceUserClient".into(), "IO*".into()],
            deny: vec!["IOHIDLibUserClient".into()],
            ..Default::default()
        });
        validate_seatbelt_custom_rules(&request).unwrap();
        validate_seatbelt_custom_rules(&seatbelt_request(SeatbeltConfig {
            keychain_access: true,
            ..lookups(&["com.apple.SecurityServer"], &[])
        }))
        .unwrap();
    }

    #[test]
    fn rejects_reserved_names_in_custom_lookups() {
        let msg = validate_seatbelt_reserved_names(&seatbelt_request(lookups(
            &[],
            &["com.microsoft.mxc.run.*"],
        )))
        .unwrap_err();
        assert!(msg.contains("customMachLookups.deny"), "{msg}");
    }

    #[test]
    fn gui_access_effective_requires_both_flags() {
        assert!(gui_access_effective(&gui_request(true, false)));
        assert!(!gui_access_effective(&gui_request(true, true)));
        assert!(!gui_access_effective(&gui_request(false, false)));
        assert!(!gui_access_effective(&ExecutionRequest::default()));
    }

    #[test]
    fn capture_denials_requires_generated_profile() {
        let mut r = ExecutionRequest {
            seatbelt: Some(SeatbeltConfig {
                capture_denials: Some(Default::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_seatbelt_capture_denials(&r).is_ok());

        r.seatbelt.as_mut().unwrap().profile_override = Some("(version 1)".into());
        let msg = validate_seatbelt_capture_denials(&r).unwrap_err();
        assert!(msg.contains("profileOverride"), "got: {msg}");
    }
}
