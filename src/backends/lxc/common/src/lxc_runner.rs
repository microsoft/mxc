// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//!AIR/1 m=lxc_runner c=lxc_common impl=ScriptRunner tgt=linux/lxc
//!ENC id=opaque cmt=0 ws=min FROZEN=emitted-strings{err,log,shell,fmt}
//!PUB S:LxcScriptRunner F:new F:validate_runner F:execute  <-only names callers bind
//!K0 "#mxc-proxy-pin" own-line tag; lets a rerun strip its own pins only
//!K1 30s ceiling on the two /etc/hosts rewrites; never inherits script budget
//!S0 LxcScriptRunner{c:LxcConfig,i:id,d:destroy_on_exit,p:cleanup_policy=!preserve}
//!f0 ()->String        i.empty ? "mxc-"+f9 : i
//!f1 (n,to,lg)->bool   poll `lxc-info -n N -iH` @500ms until nonempty | to
//!f2 (n,cr,to,lg,pb,dz)->Opt<Resp>  pb ? None : (d|cr ? dz) + Err
//!f3 (rq,lg)->Resp     MAIN; see E-rows
//!f4 (line)->String    pin   = f5 + emit kept + emit line+K0  > /etc/hosts
//!f5 ()->String        read prologue: -h refuse; -e ? kept=$(grep -v K0); st>1 refuse
//!f6 ()->String        unpin = f5 + emit kept                 > /etc/hosts
//!f7 (verb,code)->String  "<verb> /etc/hosts exited with <code>"
//!f8 ()->NPS           EGRESS_DEFAULT|EGRESS_RULES|INGRESS_DEFAULT|HOST_LOOPBACK
//!f9 ()->String        8 hex of nanos&0xFFFF_FFFF
//!fa (ct,cmd,verb)->Opt<String>  attach_run@K1; 0=>None; n=>f7; err=>msg
//!MAC w!=writeln-discard  dz!=destroy-if(d|created)
//!E f3 is ordered; every row's ERR short-circuits via ScriptResponse::error
//!E01 normalize_object_conflicts  ERR=>ret   fs alias tighten deny>ro>rw
//!E02 check_delegation            ERR=>ret   D3 sandbox never exceeds caller
//!E03 cfg.distribution&&cfg.release EMPTY=>ret
//!E04 n=f0
//!E05 proxy-credential guard      HIT=>ret(redacted)  I7  PRE-any-container-work
//!E06 d => signal_cleanup::set_active(n)
//!E07 log n, dist:rel, experimental.test
//!E08 ct=LxcContainer::new; !is_defined => create, cr=1
//!E09 configure_filesystem_mounts ERR=>dz+ret
//!E10 !is_running => start        ERR=>dz+ret
//!E11 dir=supports_directional_network(schema_version)
//!E12 needs_network(pol,dir) => f2@30s  I10  SOME=>ret
//!E13 fw=NetworkIptablesManager::new; preserve=!p; directional=dir
//!E14 discover_veth SOME => set_veth + (d => set_active_veth)
//!E15 fw.apply_firewall_rules     FALSE|ERR=>dz+ret
//!E16 uf=installs_firewall(pol,dir)
//!E17 init_pid SOME(pid): (d=>set_active_pid); ingress.apply FALSE|ERR=>dz+ret;
//!    THEN preserve=!p  I8
//!E18 init_pid NONE && uf         =>dz+ret  I9 fail-closed
//!E19 fw.proxy_host_pin SOME => fa(f4,"writing") ERR=>(d|cr?destroy:stop)+ret; pin=1
//!E20 else !cr => fa(f6,"clearing") ERR=>(d?destroy:stop)+ret   stale-pin guard
//!E21 to = script_timeout==0 ? None : ms
//!E22 env = rq.env.clone + apply_proxy_env(pol.network_proxy)  I12
//!E23 resp = ct.attach_run(script, cwd, env, clear=1, to)
//!E24 pin&&p => fa(f6,"clearing") ERR=>WARN only; script already ran
//!E25 fw.rules_applied&&p => remove; ingress likewise
//!E26 d => destroy (warn on err)
//!E27 ret resp
//!I1  hosts cmds hold to a BusyBox toolset {grep,printf,[}; no sed/awk/tee/sponge
//!I2  kept lines stage in a shell var, never a file: `>` follows symlinks, and a
//!    predictable scratch name on a reused ct aims a privileged truncating write
//!    at whatever the workload linked it to
//!I3  capture completes BEFORE `> /etc/hosts` opens: `>` truncates on open
//!I4  read status 0|1 = outcome, >1 = abort ahead of the redirect (127 = no grep)
//!I5  -h refuses a symlink incl. dangling: a redirect onto one CREATES its target
//!I6  rewrite in place, never mv: LXC may bind-mount /etc/hosts
//!I7  proxy creds refused: the URL becomes an lxc-attach --set-var argv entry, and
//!    argv is world-readable via /proc/<pid>/cmdline; refusal uses redact_proxy_url
//!I8  ingress preserve flag set only AFTER apply success; a partial chain must drop
//!I9  no ingress without a netns => abort; never fail-open
//!I10 readiness fails closed at 30s; alpine DHCP leases observed ~9s
//!I11 attach_run streams the child and returns "" for both streams, so the exit
//!    code is the entire report; f7 must not trail a separator promising more
//!I12 env always cleared: else lxc-attach keep-env inherits the host env
//!G1  GAP: a NUL in /etc/hosts truncates silently; a shell var cannot hold one
//!G2  GAP: symlink TOCTOU between -h and the redirect; needs openat+O_NOFOLLOW

use std::fmt::Write;
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, LifecycleConfig, LxcConfig, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use crate::filesystem_mounts;
use crate::lxc_bindings::LxcContainer;
use crate::network_ingress::IngressManager;
use crate::network_iptables::{installs_firewall, needs_network, NetworkIptablesManager};
use crate::signal_cleanup;

macro_rules! w { ($l:expr, $($t:tt)*) => { let _ = writeln!($l, $($t)*); } }
macro_rules! dz { ($s:expr, $c:expr, $k:expr) => { if $s.d || $k { let _ = $c.destroy(); } } }

const K0: &str = "#mxc-proxy-pin";
const K1: Duration = Duration::from_secs(30);

pub struct LxcScriptRunner { c: LxcConfig, i: String, d: bool, p: bool }

impl LxcScriptRunner {
    pub fn new(config: &LxcConfig, container_id: &str, lifecycle: &LifecycleConfig) -> Self {
        Self { c: config.clone(), i: container_id.to_string(), d: lifecycle.destroy_on_exit, p: !lifecycle.preserve_policy }
    }

    fn f0(&self) -> String { if self.i.is_empty() { format!("mxc-{}", f9()) } else { self.i.clone() } }

    fn f1(n: &str, to: Duration, lg: &mut Logger) -> bool {
        let t0 = Instant::now();
        w!(lg, "Waiting for container network to initialize...");
        while t0.elapsed() < to {
            if let Ok(o) = std::process::Command::new("lxc-info").arg("-n").arg(n).arg("-iH").output() {
                let s = String::from_utf8_lossy(&o.stdout);
                let ip = s.trim();
                if !ip.is_empty() {
                    w!(lg, "Container network ready (IP: {}, waited {:.1}s)", ip, t0.elapsed().as_secs_f64());
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
        w!(lg, "Warning: container network not ready after {:.1}s", to.as_secs_f64());
        false
    }

    fn f2<P, D>(&self, n: &str, cr: bool, to: Duration, lg: &mut Logger, pb: P, mut dc: D) -> Option<ScriptResponse>
    where P: FnOnce(&str, Duration, &mut Logger) -> bool, D: FnMut() {
        if pb(n, to, lg) { return None; }
        if self.d || cr { dc(); }
        Some(ScriptResponse::error(&format!(
            "Container network did not initialize within {:.0}s; check that lxc-net/dnsmasq is running and able to assign an IP.",
            to.as_secs_f64())))
    }

    fn fa(ct: &LxcContainer, cmd: &str, verb: &str) -> Option<String> {
        match ct.attach_run(cmd, "/", &[], true, Some(K1)) {
            Ok((0, _, _)) => None,
            Ok((n, _, _)) => Some(Self::f7(verb, n)),
            Err(e) => Some(e.to_string()),
        }
    }

    fn f3(&self, rq: &ExecutionRequest, lg: &mut Logger) -> ScriptResponse {
        let nz;
        let rq = match wxc_common::filesystem_object::normalize_object_conflicts(&rq.policy, lg) {
            Ok(Some(pol)) => { nz = ExecutionRequest { policy: pol, ..rq.clone() }; &nz }
            Ok(None) => rq,
            Err(m) => return ScriptResponse::error(&m),
        };
        if let Err(m) = wxc_common::filesystem_access::check_delegation(&rq.policy) { return ScriptResponse::error(&m); }
        if self.c.distribution.is_empty() || self.c.release.is_empty() {
            return ScriptResponse::error("LXC distribution and release are required (e.g., \"distribution\": \"alpine\", \"release\": \"3.23\")");
        }

        let n = self.f0();
        if let Some(u) = rq.policy.network_proxy.address.as_ref().map(|a| a.to_url()) {
            if wxc_common::proxy_env::proxy_url_has_credentials(&u) {
                return ScriptResponse::error(&format!(
                    "LXC: network.proxy.url must not carry credentials ('{}'). LXC passes the proxy URL to lxc-attach as a --set-var command-line argument, and process arguments are world-readable through /proc/<pid>/cmdline, so the password would be visible to every local user while the command runs. Use a proxy that does not require inline credentials, or supply them to the proxy itself rather than through the URL.",
                    wxc_common::proxy_env::redact_proxy_url(&u)));
            }
        }
        if self.d { signal_cleanup::set_active(&n); }
        w!(lg, "Container name: {}", n);
        w!(lg, "Distribution: {}:{}", self.c.distribution, self.c.release);
        if rq.experimental_enabled {
            if let Some(ref x) = rq.experimental.test { w!(lg, "Experimental feature 'test' applied: {}", x.message); }
        }

        let ct = LxcContainer::new(&n, None);
        let mut cr = false;
        if !ct.is_defined() {
            w!(lg, "Creating LXC container...");
            if let Err(e) = ct.create(&self.c.distribution, &self.c.release) { return ScriptResponse::error(&format!("Failed to create container: {}", e)); }
            w!(lg, "Container created successfully.");
            cr = true;
        } else { w!(lg, "Container already exists, reusing."); }

        if let Err(e) = filesystem_mounts::configure_filesystem_mounts(&ct, &rq.policy, lg) {
            dz!(self, ct, cr);
            return ScriptResponse::error(&format!("Failed to configure filesystem: {}", e));
        }

        if !ct.is_running() {
            w!(lg, "Starting LXC container...");
            if let Err(e) = ct.start() {
                dz!(self, ct, cr);
                return ScriptResponse::error(&format!("Failed to start container: {}", e));
            }
            w!(lg, "Container started successfully.");
        } else { w!(lg, "Container already running."); }

        let dir = wxc_common::supports_directional_network(&rq.schema_version);
        if needs_network(&rq.policy, dir) {
            if let Some(r) = self.f2(&n, cr, Duration::from_secs(30), lg, Self::f1, || { let _ = ct.destroy(); }) { return r; }
        }

        let mut fw = NetworkIptablesManager::new(&n);
        fw.set_preserve_policy(!self.p);
        fw.set_directional_schema(dir);
        if let Some(v) = NetworkIptablesManager::discover_veth_interface(&n) {
            w!(lg, "Discovered veth interface: {}", v);
            fw.set_veth_interface(&v);
            if self.d { signal_cleanup::set_active_veth(&v); }
        }
        match fw.apply_firewall_rules(&rq.policy, lg) {
            Ok(true) => {}
            Ok(false) => { dz!(self, ct, cr); return ScriptResponse::error("Failed to apply network firewall rules."); }
            Err(e) => { dz!(self, ct, cr); return ScriptResponse::error(&format!("Network policy error: {}", e)); }
        }

        let uf = installs_firewall(&rq.policy, dir);
        let mut ig: Option<IngressManager> = None;
        match ct.init_pid() {
            Some(pid) => {
                w!(lg, "Container init PID: {}", pid);
                if self.d { signal_cleanup::set_active_pid(pid); }
                let mut m = IngressManager::new(&n, pid, dir);
                match m.apply_firewall_rules(&rq.policy, lg) {
                    Ok(true) => {}
                    Ok(false) => { dz!(self, ct, cr); return ScriptResponse::error("Failed to apply inbound network firewall rules."); }
                    Err(e) => { dz!(self, ct, cr); return ScriptResponse::error(&format!("Inbound network policy error: {}", e)); }
                }
                m.set_preserve_policy(!self.p);
                ig = Some(m);
            }
            None if uf => {
                dz!(self, ct, cr);
                return ScriptResponse::error("Failed to discover the container init PID; cannot enter the container network namespace to enforce the requested inbound firewall. Aborting rather than running with inbound enforcement silently disabled.");
            }
            None => {}
        }

        let mut pin = false;
        if let Some(hp) = fw.proxy_host_pin() {
            w!(lg, "Pinning proxy host {} to {} in the container's /etc/hosts.", hp.hostname(), hp.ip());
            if let Some(rz) = Self::fa(&ct, &Self::f4(&hp.hosts_line()), "writing") {
                if self.d || cr { let _ = ct.destroy(); } else { let _ = ct.stop(); }
                return ScriptResponse::error(&format!(
                    "Failed to pin the network proxy host inside the container: {}. The proxy would be unreachable, so the script was not run.", rz));
            }
            pin = true;
        } else if !cr {
            if let Some(rz) = Self::fa(&ct, &Self::f6(), "clearing") {
                if self.d { let _ = ct.destroy(); } else { let _ = ct.stop(); }
                return ScriptResponse::error(&format!(
                    "Failed to clear a stale network proxy pin from the container's /etc/hosts: {}. The script was not run, because it could have resolved the pinned hostname to an address this policy did not authorize.", rz));
            }
        }

        let to = if rq.script_timeout == 0 { None } else { Some(Duration::from_millis(u64::from(rq.script_timeout))) };
        w!(lg, "Executing script inside container...");
        let mut env = rq.env.clone();
        wxc_common::proxy_env::apply_proxy_env(&mut env, &rq.policy.network_proxy);
        let resp = match ct.attach_run(&rq.script_code, &rq.working_directory, &env, true, to) {
            Ok((ec, so, se)) => ScriptResponse { exit_code: ec, standard_out: so, standard_err: se, error_message: String::new(), ..Default::default() },
            Err(e) => ScriptResponse::error(&format!("Execution failed: {}", e)),
        };

        if pin && self.p {
            if let Some(rz) = Self::fa(&ct, &Self::f6(), "clearing") { w!(lg, "Warning: failed to clear the proxy host pin: {}", rz); }
        }
        if fw.rules_applied() && self.p { let _ = fw.remove_firewall_rules(lg); }
        if let Some(m) = &mut ig { if m.rules_applied() && self.p { let _ = m.remove_firewall_rules(lg); } }
        if self.d {
            w!(lg, "Destroying container...");
            if let Err(e) = ct.destroy() { w!(lg, "Warning: failed to destroy container: {}", e); }
        }
        resp
    }

    fn f4(h: &str) -> String {
        format!("{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; printf '%s {m}\\n' '{h}'; }} > /etc/hosts",
            Self::f5(), m = K0, h = h)
    }

    fn f5() -> String {
        format!("if [ -h /etc/hosts ]; then printf 'mxc: refusing to rewrite /etc/hosts: it is a symbolic link\\n' >&2; exit 4; fi; kept=''; if [ -e /etc/hosts ]; then kept=$(grep -v '{m}' /etc/hosts 2>/dev/null); status=$?; if [ \"$status\" -gt 1 ]; then printf 'mxc: refusing to rewrite /etc/hosts: reading it exited %s\\n' \"$status\" >&2; exit \"$status\"; fi; fi; ",
            m = K0)
    }

    fn f6() -> String {
        format!("{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; }} > /etc/hosts", Self::f5())
    }

    fn f7(verb: &str, code: i32) -> String { format!("{} /etc/hosts exited with {}", verb, code) }
}

fn f8() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT | NetworkPolicySupport::EGRESS_RULES
        | NetworkPolicySupport::INGRESS_DEFAULT | NetworkPolicySupport::HOST_LOOPBACK
}

impl ScriptRunner for LxcScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, f8())?;
        Ok(())
    }
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.f3(request, logger))) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during LXC script execution."),
        }
    }
}

fn f9() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{:08x}", (t & 0xFFFF_FFFF) as u32)
}

// T m0=string-level, m1=executed-under-/bin/sh; t*/x* assert-codes index the I-rows.
#[cfg(test)]
mod m0 {
    use super::*;
    use wxc_common::logger::Mode;
    use wxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig};

    // CU is the upstream fixture URL, reconstructed from the assertions in t16.
    const CU: &str = "http://alice:hunter2@proxy.example.com:8080";

    fn h0(u: &str) -> ExecutionRequest {
        let mut r = ExecutionRequest::default();
        r.policy.network_proxy = ProxyConfig { address: Some(ProxyAddress::from_url(u, "proxy.example.com".to_string(), 8080)), builtin_test_server: false };
        r
    }
    fn h1() -> LxcScriptRunner {
        LxcScriptRunner::new(&LxcConfig { distribution: "alpine".to_string(), release: "3.23".to_string() }, "mxc-guard-test", &LifecycleConfig::default())
    }
    fn h2(d: bool) -> LxcScriptRunner {
        LxcScriptRunner::new(&LxcConfig { distribution: "alpine".to_string(), release: "3.23".to_string() }, "mxc-network-test", &LifecycleConfig { destroy_on_exit: d, ..LifecycleConfig::default() })
    }
    fn h3(r: &LxcScriptRunner, cr: bool) -> (ScriptResponse, bool) {
        let mut lg = Logger::new(Mode::Buffer);
        let mut k = false;
        let resp = r.f2("mxc-network-test", cr, Duration::from_secs(1), &mut lg, |_n, _t, _l| false, || k = true).expect("E:probe-false-must-yield-response");
        (resp, k)
    }
    fn h4() -> ExecutionRequest {
        let mut r = ExecutionRequest::default();
        r.policy.network_mode_specified = true;
        r.policy.network_egress = Some(NetworkEgressPolicy::default());
        r.policy.network_ingress = Some(NetworkIngressPolicy::default());
        r
    }

    #[test] fn t0() { let s = f9(); assert_eq!(s.len(), 8); assert!(s.chars().all(|c| c.is_ascii_hexdigit())); }
    #[test] fn t1() { assert_eq!(LxcScriptRunner::new(&LxcConfig::default(), "my-test", &LifecycleConfig::default()).f0(), "my-test"); }
    #[test] fn t2() { assert!(LxcScriptRunner::new(&LxcConfig::default(), "", &LifecycleConfig::default()).f0().starts_with("mxc-")); }

    #[test] fn t3() {
        let c = LxcScriptRunner::f4("10.0.0.5 proxy.example.com");
        assert!(c.contains("'10.0.0.5 proxy.example.com'"), "E:mapping-verbatim {c}");
        assert!(c.contains("/etc/hosts"), "E:target {c}");
    }
    #[test] fn t4() {
        let c = LxcScriptRunner::f4("10.0.0.5 proxy.example.com");
        assert!(c.contains(&format!("grep -v '{}'", K0)), "E:strip-prior {c}");
        assert!(c.matches(K0).count() >= 2, "E:written-line-tagged {c}");
    }
    #[test] fn t5() {
        for v in ["writing", "clearing"] {
            let r = LxcScriptRunner::f7(v, 1);
            assert!(r.contains('1'), "E:I11-code {r}");
            assert!(!r.trim_end().ends_with(':'), "E:I11-no-dangling-colon {r:?}");
            assert_eq!(r.trim_end(), r, "E:I11-no-trailing-ws {r:?}");
        }
    }
    #[test] fn t6() { assert_ne!(LxcScriptRunner::f7("writing", 2), LxcScriptRunner::f7("clearing", 2), "E:step-distinguishable"); }
    #[test] fn t7() {
        let c = LxcScriptRunner::f6();
        assert!(c.contains(&format!("grep -v '{}'", K0)), "E:filter {c}");
        assert_eq!(c.matches(K0).count(), 1, "E:unpin-writes-no-tag {c}");
    }
    #[test] fn t8() {
        let c = LxcScriptRunner::f6();
        assert!(c.contains("> /etc/hosts"), "E:I6 {c}");
        assert!(!c.contains("mv "), "E:I6-no-inode-swap {c}");
    }
    #[test] fn t9() {
        let c = LxcScriptRunner::f4("10.0.0.5 proxy.example.com");
        assert!(c.contains("> /etc/hosts"), "E:I6 {c}");
        assert!(!c.contains("mv "), "E:I6-no-inode-swap {c}");
    }
    #[test] fn t10() {
        let c = LxcScriptRunner::f4("10.0.0.5 proxy.example.com");
        for x in ["sed ", "awk ", "tee ", "sponge "] { assert!(!c.contains(x), "E:I1 {x:?} {c}"); }
    }
    #[test] fn t11() {
        for c in [LxcScriptRunner::f4("10.0.0.5 proxy.example.com"), LxcScriptRunner::f6()] {
            for s in ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/"] { assert!(!c.contains(s), "E:I2 {s:?} {c}"); }
            assert_eq!(c.matches("> /etc/hosts").count(), 1, "E:I2-single-redirect {c}");
        }
    }
    #[test] fn t12() {
        for c in [LxcScriptRunner::f4("10.0.0.5 proxy.example.com"), LxcScriptRunner::f6()] {
            let cap = c.find("kept=$(").unwrap_or_else(|| panic!("E:I2-var-staging {c}"));
            let red = c.find("> /etc/hosts").unwrap_or_else(|| panic!("E:I6 {c}"));
            assert!(cap < red, "E:I3 {c}");
            assert!(!c[red..].contains("grep"), "E:I3-no-read-after-truncate {c}");
        }
    }

    #[test] fn t13() { assert!(h1().validate_runner(&h4()).is_ok(), "E:egress-only-0.8-must-reach-backend"); }
    #[test] fn t14() {
        assert!(validate_network_policy_support(&h4(), NetworkPolicySupport::EGRESS_DEFAULT | NetworkPolicySupport::EGRESS_RULES).is_err(),
            "E:directional-claim-is-all-or-nothing; if green, f8 may drop ingress bits");
    }

    #[test] fn t15() {
        let r = h1().f3(&h0(CU), &mut Logger::new(Mode::Buffer));
        assert!(r.error_message.contains("must not carry credentials"), "E:I7 {}", r.error_message);
    }
    #[test] fn t16() {
        let mut lg = Logger::new(Mode::Buffer);
        let r = h1().f3(&h0(CU), &mut lg);
        assert!(!r.error_message.contains("hunter2"), "E:I7-pw-leak {}", r.error_message);
        assert!(!r.error_message.contains("alice:hunter2"), "E:I7-userinfo-leak {}", r.error_message);
        assert!(!lg.get_buffer().contains("hunter2"), "E:I7-log-leak");
    }
    #[test] fn t17() {
        let r = h1().f3(&h0("http://proxy.example.com:8080"), &mut Logger::new(Mode::Buffer));
        assert!(!r.error_message.contains("must not carry credentials"), "E:I7-anti-vacuity {}", r.error_message);
    }
    #[test] fn t18() {
        let mut lg = Logger::new(Mode::Buffer);
        let _ = h1().f3(&h0(CU), &mut lg);
        let b = lg.get_buffer();
        assert!(!b.contains("Container name:"), "E:E05-ordering {b}");
        assert!(!b.contains("Creating LXC container"), "E:E05-ordering {b}");
    }

    #[test] fn t19() {
        let (r, _) = h3(&h2(false), false);
        assert!(r.error_message.contains("Container network did not initialize within 1s"), "E:I10 {}", r.error_message);
        assert_eq!(r.standard_err, r.error_message, "E:err-mirrored-to-stderr");
    }
    #[test] fn t20() { assert!(!h3(&h2(false), false).1, "E:reused+!d=>preserve"); }
    #[test] fn t21() { assert!(h3(&h2(false), true).1, "E:created=>destroy-even-if-!d"); }
    #[test] fn t22() { assert!(h3(&h2(true), false).1, "E:d=>destroy-reused"); }
}

#[cfg(all(test, unix))]
mod m1 {
    use super::*;
    use std::path::{Path, PathBuf};

    const O: &str = "127.0.0.1 localhost\n::1 ip6-localhost\n10.0.0.9 build.internal\n";
    const P: &str = "10.0.0.5 proxy.example.com";

    struct Z { dir: PathBuf }
    impl Z {
        fn n(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("mxc-hosts-{}-{}-{}", tag, std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("E:clock").as_nanos()));
            std::fs::create_dir_all(&dir).expect("E:mkdir");
            Self { dir }
        }
        fn h(&self) -> PathBuf { self.dir.join("hosts") }
        fn w(&self, s: &str) { std::fs::write(self.h(), s).expect("E:write-fixture"); }
        fn r(&self) -> String { std::fs::read_to_string(self.h()).expect("E:read-fixture") }
        fn g(&self, st: i32) -> String {
            use std::os::unix::fs::PermissionsExt;
            let bin = self.dir.join("bin");
            std::fs::create_dir_all(&bin).expect("E:mkdir-shim");
            let gp = bin.join("grep");
            std::fs::write(&gp, format!("#!/bin/sh\nexit {st}\n")).expect("E:write-shim");
            std::fs::set_permissions(&gp, std::fs::Permissions::from_mode(0o755)).expect("E:chmod-shim");
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default())
        }
        fn e(&self) -> String {
            let d = self.dir.join("empty");
            std::fs::create_dir_all(&d).expect("E:mkdir-empty");
            d.display().to_string()
        }
    }
    impl Drop for Z { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

    fn rt(c: &str, p: &Path) -> String { c.replace("/etc/hosts", p.to_str().expect("E:utf8-path")) }
    fn sh(c: &str, path: Option<&str>) -> i32 {
        let mut s = std::process::Command::new("/bin/sh");
        s.arg("-c").arg(c);
        if let Some(p) = path { s.env("PATH", p); }
        s.output().expect("E:/bin/sh").status.code().expect("E:signalled")
    }
    fn pn(p: &Path) -> String { rt(&LxcScriptRunner::f4(P), p) }
    fn up(p: &Path) -> String { rt(&LxcScriptRunner::f6(), p) }

    #[test] fn x0() {
        let z = Z::n("keeps"); z.w(O);
        let c = sh(&pn(&z.h()), None); let a = z.r();
        assert_eq!(c, 0, "E:pin-readable-ok");
        for l in O.lines() { assert!(a.contains(l), "E:dropped {l:?}\n{a}"); }
        assert!(a.contains(&format!("{P} {K0}")), "E:pin-absent\n{a}");
    }
    #[test] fn x1() {
        let z = Z::n("repin"); z.w(O);
        assert_eq!(sh(&pn(&z.h()), None), 0); assert_eq!(sh(&pn(&z.h()), None), 0);
        let a = z.r();
        assert_eq!(a.matches(K0).count(), 1, "E:repin-stacks\n{a}");
        assert!(a.contains("10.0.0.9 build.internal"), "E:repin-dropped-unrelated\n{a}");
    }
    #[test] fn x2() {
        let z = Z::n("failread"); z.w(O); let p = z.g(2);
        let c = sh(&pn(&z.h()), Some(&p));
        assert_eq!(z.r(), O, "E:I3-truncated-on-failed-read");
        assert_ne!(c, 0, "E:I4-must-fail");
    }
    #[test] fn x3() {
        let z = Z::n("nogrep"); z.w(O); let p = z.e();
        let c = sh(&pn(&z.h()), Some(&p));
        assert_eq!(z.r(), O, "E:I4-127-truncated");
        assert_ne!(c, 0, "E:I4-127-must-fail");
    }
    #[test] fn x4() {
        let z = Z::n("failunpin"); z.w(O); let p = z.g(2);
        let c = sh(&up(&z.h()), Some(&p));
        assert_eq!(z.r(), O, "E:I3-unpin-emptied");
        assert_ne!(c, 0, "E:I4-unpin-must-fail");
    }
    #[test] fn x5() {
        let z = Z::n("allmarked"); z.w(&format!("10.0.0.4 proxy.example.com {K0}\n"));
        let c = sh(&pn(&z.h()), None);
        assert_eq!(c, 0, "E:I4-status1-is-an-outcome");
        assert_eq!(z.r().trim(), format!("{P} {K0}"), "E:stale-replaced");
    }
    #[test] fn x6() {
        let z = Z::n("nofile");
        assert_eq!(sh(&pn(&z.h()), None), 0, "E:I4-absent-is-not-unreadable");
        assert_eq!(z.r().trim(), format!("{P} {K0}"));
    }
    #[test] fn x7() {
        let z = Z::n("unpin"); z.w(O); assert_eq!(sh(&pn(&z.h()), None), 0);
        let c = sh(&up(&z.h()), None); let a = z.r();
        assert_eq!(c, 0, "E:unpin-ok");
        assert!(!a.contains(K0), "E:pin-survived\n{a}");
        for l in O.lines() { assert!(a.contains(l), "E:unpin-dropped {l:?}\n{a}"); }
    }
    #[test] fn x8() {
        let z = Z::n("dangling"); let t = z.dir.join("attacker-named");
        std::os::unix::fs::symlink(&t, z.h()).expect("E:symlink");
        assert_ne!(sh(&pn(&z.h()), None), 0, "E:I5-dangling");
        assert!(!t.exists(), "E:I5-created {}", t.display());
    }
    #[test] fn x9() {
        let z = Z::n("symlink"); let t = z.dir.join("elsewhere");
        std::fs::write(&t, O).expect("E:write-target");
        std::os::unix::fs::symlink(&t, z.h()).expect("E:symlink");
        assert_ne!(sh(&pn(&z.h()), None), 0, "E:I5");
        assert_eq!(std::fs::read_to_string(&t).expect("E:read-target"), O, "E:I5-wrote-through");
    }
    #[test] fn x10() {
        let z = Z::n("unpinsymlink"); let t = z.dir.join("elsewhere");
        std::fs::write(&t, O).expect("E:write-target");
        std::os::unix::fs::symlink(&t, z.h()).expect("E:symlink");
        assert_ne!(sh(&up(&z.h()), None), 0, "E:I5-unpin");
        assert_eq!(std::fs::read_to_string(&t).expect("E:read-target"), O, "E:I5-unpin-emptied-through");
    }
    #[test] fn x11() {
        let z = Z::n("symlinkmsg"); let t = z.dir.join("elsewhere");
        std::os::unix::fs::symlink(&t, z.h()).expect("E:symlink");
        let o = std::process::Command::new("/bin/sh").arg("-c").arg(pn(&z.h())).output().expect("E:/bin/sh");
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(e.contains("symbolic link"), "E:I5-no-reason\n{e}");
    }
}
