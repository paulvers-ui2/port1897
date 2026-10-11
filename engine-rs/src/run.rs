// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The engine's run, in the order of main_windows.go's run() and
//! stopTunnel. The order encodes fixed bugs (PRs #26 and #28, the Proton
//! VPN case), so it is kept step for step:
//!
//! start: flags the engine cannot serve yet are refused, the API is checked
//! (before anything changes on the PC), a network is waited for, the MTU is
//! planned, the adapter made, the NRPT rule set (before the adapter gets its
//! DNS server), the adapter configured, the kill switch set (before the
//! engine opens a socket of its own), the stack and DNS started, conflicts
//! looked for, the NRPT nudge sent, the routes added, and the API served.
//!
//! stop: the NRPT rule and the adapter's DNS server go first, then the
//! tunnel and the adapter (waited for), and the kill switch last, so a stop
//! cut short leaves the PC blocked rather than open.
//!
//! What changes the system is behind `Sys`, so the order is tested with a
//! fake.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::api::{self, ApiServer, RunInfo};
use crate::dns::dns53::Dns53;
use crate::dns::doh::Doh;
use crate::dns::dot::{self, Dot};
use crate::dns::fake::DEFAULT;
use crate::dns::tls::Trust;
use crate::dns::{FakeDns, Transport};
use crate::engine::{Engine, FAKEDNS4, Owners, PREFERRED, SYSTEM};
use crate::flags::{self, Options};
use crate::golike;
use crate::killswitch::{Firewall, KillSwitch, WfpOptions};
use crate::mtu::{self, MtuPlan};
use crate::net::dial::{Direct, Protect};
use crate::exit::{EXIT_PROXY, exit_name};
use crate::net::forward::Forwarder;
use crate::net::proxy::{ProxyExit, ProxyUrl};
use crate::net::stack::StackConfig;
use crate::net::tunnel::{Device, Tunnel};
use crate::rules;

/// How long a start waits for a network (Go's networkWait): the app
/// resumes protection as Windows signs in, before Wi-Fi is up.
pub const NETWORK_WAIT: Duration = Duration::from_secs(30);

/// Why the engine stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    CtrlC,
    App,
    Service,
}

/// The adapter, once made.
pub trait Adapter: Send + Sync {
    fn name(&self) -> String;
    fn luid(&self) -> u64;
    fn index(&self) -> u32;
    /// Its packets, for the stack.
    fn device(&self) -> Arc<dyn Device>;
    /// Removes it; returns once it is gone.
    fn close(self: Box<Self>);
}

/// The network outside the tunnel (win/ifbind's Binder).
pub trait Phys: Send + Sync {
    /// The IPv4 and IPv6 default-route interfaces outside the tunnel.
    fn indexes(&self) -> (u32, u32);
    /// What keeps the engine's sockets out of the tunnel.
    fn protect(&self) -> Option<Arc<dyn Protect>>;
    /// The physical adapter's DNS servers (the System transport).
    fn dns_servers(&self) -> Vec<Ipv4Addr>;
}

/// Everything the run changes or reads on the PC.
pub trait Sys: Send + Sync {
    /// A line for stdout (and so the -logfile).
    fn say(&self, line: &str);
    /// A line for stderr (the same file with -logfile).
    fn warn(&self, line: &str);
    /// The interface of the IPv4 default route, 0 if none.
    fn default_route4(&self) -> u32;
    /// The network's MTU and what it comes from (before the adapter).
    fn link_mtu(&self) -> (i64, String);
    fn create_adapter(&self, name: &str) -> Result<Box<dyn Adapter>, String>;
    fn nrpt_add(&self) -> Result<(), String>;
    /// Removes the rule and starts the DNS Client nudge without waiting.
    fn nrpt_drop(&self) -> Result<(), String>;
    /// The rule's backup: ipconfig /registerdns, not waited for.
    fn nrpt_nudge(&self) -> Result<(), String>;
    /// Other catch-all NRPT rules, "DisplayName (Comment)".
    fn nrpt_others(&self) -> Vec<String>;
    fn configure(&self, name: &str, luid: u64, set_dns: bool) -> Result<(), String>;
    fn clear_dns(&self, luid: u64) -> Result<(), String>;
    fn add_routes(&self, name: &str, luid: u64) -> Result<(), String>;
    fn phys(&self, tun_index: u32) -> Arc<dyn Phys>;
    fn firewall(&self) -> Arc<dyn Firewall>;
    fn owners(&self) -> Arc<dyn Owners>;
    /// An interface's name, description and whether it looks like a VPN.
    fn describe(&self, idx: u32) -> (String, String, bool);
    /// -cleanup: the NRPT rule and the kill switch, left or not.
    fn cleanup(&self) -> Result<(), String>;
    /// A file of the app's, read with the user's rights.
    fn read_user_file(&self, path: &str) -> Result<Vec<u8>, String>;
}

/// Refuses what this engine cannot do yet, before it touches the system,
/// so the app shows why rather than running half an engine. The checks of
/// values Go makes later (dial strategy and retry) come first, worded as
/// Go's.
pub fn check_supported(o: &Options) -> Result<(), String> {
    if ![flags::DIAL_NEVER, flags::DIAL_AUTO, flags::DIAL_SPLIT_TCP, flags::DIAL_SPLIT_TLS].contains(&o.dial_strategy.as_str()) {
        return Err(format!("-dial-strategy must be never, auto, split-tcp or split-tls, not {}", golike::quote(&o.dial_strategy)));
    }
    if !["", "never", "split", "plain"].contains(&o.dial_retry.as_str()) {
        return Err(format!("-dial-retry must be never, split or plain, not {}", golike::quote(&o.dial_retry)));
    }
    // Go's prepareExit makes this check; it comes first here so that two
    // exits read as in Go even where one of them is not supported yet
    let exits = [!o.wg.is_empty(), o.warp, !o.proxy.is_empty(), o.masque, !o.chain.is_empty()];
    if exits.iter().filter(|&&on| on).count() > 1 {
        return Err("choose one of -wg, -warp, -proxy, -masque and -chain".into());
    }
    let not_yet = |what: &str| Err(format!("{what} is not supported by this engine yet (fswin-rs); use fswin.exe"));
    let set = [
        (!o.wg.is_empty(), "-wg"),
        (o.warp, "-warp"),
        (o.masque, "-masque"),
        (!o.chain.is_empty(), "-chain"),
        (!o.routes_file.is_empty(), "-routes"),
        (!o.pcap_file.is_empty(), "-pcap"),
        (!o.blocklist_dir.is_empty() || !o.blocklist_stamp.is_empty(), "-blocklists"),
        (o.undelegated, "-undelegated"),
        (o.dial_strategy != flags::DIAL_NEVER, "-dial-strategy other than never"),
        (o.keep_alive, "-tcp-keepalive"),
        (o.eim, "-eim"),
        (o.dns_type == flags::DNS_DNSCRYPT, "-dns dnscrypt"),
        (o.dns_type == flags::DNS_ODOH, "-dns odoh"),
    ];
    for (on, what) in set {
        if on {
            return not_yet(what);
        }
    }
    Ok(())
}

/// Go's prepareExit for the exits this engine has: the exit's id ("" for
/// direct), its config, and for -proxy its URL and addresses. The proxy's
/// name is looked up here, before the tunnel takes the PC's DNS. Errors
/// past the scheme check read as Go's from AddProxy.
pub async fn prepare_exit(o: &Options) -> Result<(String, String, Option<(ProxyUrl, Vec<SocketAddr>)>), String> {
    if o.proxy.is_empty() {
        return Ok((String::new(), String::new(), None));
    }
    let url = ProxyUrl::parse(&o.proxy).map_err(|e| if e.starts_with("-proxy") { e } else { format!("add exit {EXIT_PROXY}: {e}") })?;
    let servers = url.resolve().await.map_err(|e| format!("add exit {EXIT_PROXY}: {e}"))?;
    Ok((EXIT_PROXY.to_string(), o.proxy.clone(), Some((url, servers))))
}

/// Go's apiPreflight: fail before changing anything on the PC if the app
/// could not reach us anyway.
pub fn api_preflight(sys: &dyn Sys, addr: &str, token_file: &str) -> Result<(SocketAddr, Vec<u8>), String> {
    let a = api::check_addr(addr)?;
    let tok = sys.read_user_file(token_file).map_err(|e| format!("-token-file: {e}"))?;
    let tok = api::token_from(&tok)?;
    let l = std::net::TcpListener::bind(a).map_err(|e| format!("listen tcp {addr}: {e} (is another engine still running?)"))?;
    drop(l);
    Ok((a, tok))
}

/// "1.1.1.1,2606:4700::1111" for -doh-ips and the like, kept as the DoH
/// transport reads it (bare IPs get the URL's port).
fn csv(ips: &[Ipv4Addr]) -> String {
    ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",")
}

/// Go's setupDNS: registers the transports for -dns and returns the id
/// queries go to and the label the status shows. The System transport is
/// added whenever the physical adapter's DNS servers are known.
pub fn setup_dns(fake: &FakeDns, o: &Options, sys_servers: &[Ipv4Addr], dialer: Arc<dyn crate::dns::Dialer>, say: &dyn Fn(&str)) -> Result<(String, String), String> {
    if !sys_servers.is_empty() {
        match Dns53::new(SYSTEM, &csv(sys_servers), dialer.clone()) {
            Ok(t) => fake.add(Arc::new(t)),
            Err(e) => say(&format!("fswin: system dns {sys_servers:?}: {e}")),
        }
    }
    let add = |t: Result<Arc<dyn Transport>, String>| t.map(|t| fake.add(t));
    match o.dns_type.as_str() {
        "" | flags::DNS_DOH => {
            add(Doh::new(PREFERRED, &o.doh, &o.doh_ips, &Trust::System, dialer).map(|t| Arc::new(t) as Arc<dyn Transport>))?;
            Ok((PREFERRED.into(), o.doh.clone()))
        }
        flags::DNS_DOT => {
            if o.dot.is_empty() {
                return Err("-dns dot needs -dot".into());
            }
            let d = dot::normalize(&o.dot);
            add(Dot::new(PREFERRED, &d, &o.dot_ips, &Trust::System, dialer).map(|t| Arc::new(t) as Arc<dyn Transport>))?;
            Ok((PREFERRED.into(), d))
        }
        flags::DNS_PROXY => {
            if o.dns_proxy.is_empty() {
                return Err("-dns proxy needs -dns-proxy ip:port".into());
            }
            add(Dns53::new(PREFERRED, &o.dns_proxy, dialer).map(|t| Arc::new(t) as Arc<dyn Transport>))?;
            Ok((PREFERRED.into(), format!("DNS proxy {}", o.dns_proxy)))
        }
        flags::DNS_SYSTEM => {
            if sys_servers.is_empty() {
                return Err("-dns system: no DNS servers found on the network adapter".into());
            }
            let list = sys_servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
            Ok((SYSTEM.into(), format!("System DNS ({list})")))
        }
        t => Err(format!("-dns must be doh, dot, dnscrypt, odoh, proxy or system, not {}", golike::quote(t))),
    }
}

/// Go's findConflicts: another VPN's catch-all NRPT rule, and our own
/// traffic leaving through another VPN's adapter.
pub fn find_conflicts(sys: &dyn Sys, phys4: u32) -> Vec<String> {
    let mut out: Vec<String> = sys.nrpt_others().into_iter().map(|r| format!("another VPN sends all DNS elsewhere: {r}")).collect();
    let (name, desc, vpn) = sys.describe(phys4);
    if vpn {
        out.push(format!("internet traffic leaves through another VPN's adapter: {name} ({desc})"));
    }
    out
}

/// Asks the run to stop; the first reason given is kept.
pub fn request_stop(tx: &watch::Sender<Option<StopReason>>, why: StopReason) {
    tx.send_if_modified(|s| {
        if s.is_some() {
            return false;
        }
        *s = Some(why);
        true
    });
}

/// What is up, for the stop to take down in its order.
#[derive(Default)]
struct Up {
    adapter: Option<Box<dyn Adapter>>,
    luid: u64,
    nrpt: bool,
    kill: Option<Arc<KillSwitch>>,
    tunnel: Option<Tunnel>,
    api: Option<ApiServer>,
    /// the options as the status shows them; the conflicts change
    shared: Option<Arc<Mutex<Options>>>,
    stop_at: Option<Instant>,
}

/// Logs how long a step of the start took (Go's startStep).
fn start_step(sys: &dyn Sys, began: Instant, what: &str) {
    sys.say(&format!("fswin: start: {what} after {} ms", began.elapsed().as_millis()));
}

fn stop_step(sys: &dyn Sys, up: &Up, what: &str) {
    if let Some(at) = up.stop_at {
        sys.say(&format!("fswin: stop: {what} after {} ms", at.elapsed().as_millis()));
    }
}

/// Waits up to d for an IPv4 default route; false if none came or a stop
/// came first.
async fn wait_for_network(sys: &dyn Sys, d: Duration, stops: &mut watch::Receiver<Option<StopReason>>) -> bool {
    if sys.default_route4() != 0 {
        return true;
    }
    sys.say(&format!("fswin: start: no network yet (no IPv4 default route); waiting up to {}s", d.as_secs()));
    let began = Instant::now();
    let deadline = tokio::time::sleep(d);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = &mut deadline => return false,
            _ = stops.wait_for(|s| s.is_some()) => return false,
            _ = tick.tick() => {
                if sys.default_route4() != 0 {
                    sys.say(&format!("fswin: start: network up after {} ms", began.elapsed().as_millis()));
                    return true;
                }
            }
        }
    }
}

/// Runs the engine until a stop: from the app's API, the service's event
/// or Ctrl+C (all through stops). An error is a start that failed; what it
/// set up is undone before it returns.
pub async fn run(o: Options, sys: Arc<dyn Sys>, version: &str, stop_tx: Arc<watch::Sender<Option<StopReason>>>) -> Result<(), String> {
    let mut stops = stop_tx.subscribe();
    let began = Instant::now();
    if !crate::service::valid_adapter_name(&o.name) {
        return Err(format!("-name {}: up to 64 letters, digits, spaces, dots, dashes or underscores", golike::quote(&o.name)));
    }
    if o.cleanup {
        sys.cleanup()?;
        sys.say("fswin: removed fswin's NRPT rule and kill switch, if any");
        return Ok(());
    }
    check_supported(&o)?;
    crate::logline::set_level(o.golog);

    let mut up = Up::default();
    let r = start(&o, sys.as_ref(), version, &stop_tx, &mut stops, began, &mut up).await;
    let r = match r {
        Ok(true) => {
            let why = serve(sys.as_ref(), &mut stops, &up).await;
            sys.say(match why {
                StopReason::CtrlC => "fswin: stopping",
                StopReason::App => "fswin: stopping (requested by the app)",
                StopReason::Service => "fswin: stopping (requested by AuroraVPN Service)",
            });
            up.stop_at = Some(Instant::now());
            Ok(())
        }
        Ok(false) => {
            sys.say("fswin: stopping (requested by AuroraVPN Service)");
            Ok(())
        }
        Err(e) => Err(e),
    };
    stop(sys.as_ref(), &o, &mut up).await;
    stop_step(sys.as_ref(), &up, "stopped");
    r
}

/// The start. Ok(false): the service asked for a stop while it waited for a
/// network.
async fn start(o: &Options, sys: &dyn Sys, version: &str, stop_tx: &Arc<watch::Sender<Option<StopReason>>>, stops: &mut watch::Receiver<Option<StopReason>>, began: Instant, up: &mut Up) -> Result<bool, String> {
    let mut o = o.clone();
    let api_ok = if o.api.is_empty() { None } else { Some(api_preflight(sys, &o.api, &o.token_file).map_err(|e| format!("api: {e}"))?) };

    // all traffic in the tunnel needs a network outside it from the start
    if (o.full || o.kill) && !wait_for_network(sys, NETWORK_WAIT, stops).await && stops.borrow().is_some() {
        return Ok(false);
    }
    // Go's prepareExit: -proxy is the only exit check_supported lets by
    let (exit_id, exit_cfg, proxy) = prepare_exit(&o).await?;
    let (link, link_why) = sys.link_mtu();
    let plan: MtuPlan = mtu::plan_mtu(link, &link_why, &exit_id, &exit_cfg, None, o.mtu);
    sys.say(&format!("fswin: MTU: {plan}"));
    if !exit_id.is_empty() || o.kill {
        o.full = true; // a VPN exit and the kill switch need all traffic in the tunnel
    }
    if !o.block.is_empty() && !o.full {
        sys.say("fswin: -block needs -full: without it only DNS goes through the tunnel, and DNS is answered for every app");
    }

    let adapter = sys.create_adapter(&o.name).map_err(|e| format!("create wintun adapter (run as admin, wintun.dll next to the exe?): {e}"))?;
    start_step(sys, began, "adapter created");
    let (name, luid, index) = (adapter.name(), adapter.luid(), adapter.index());
    let dev = adapter.device();
    up.adapter = Some(adapter);
    up.luid = luid;
    // before the adapter gets its DNS server: the DNS Client reloads its
    // settings, NRPT rules among them, when that changes
    if o.nrpt {
        sys.nrpt_add()?;
        up.nrpt = true;
        start_step(sys, began, "NRPT rule set");
    }
    sys.configure(&name, luid, o.set_dns)?;
    let phys = sys.phys(index);
    let (phys4, _) = phys.indexes();
    if o.full && phys4 == 0 {
        return Err("-full: no IPv4 default route outside the tunnel to send firestack's own traffic over".into());
    }
    start_step(sys, began, "adapter configured");

    // the kill switch goes on before the engine opens a socket of its own
    let fw = sys.firewall();
    let kill = Arc::new(KillSwitch::new(fw.clone(), WfpOptions { tun_luid: luid, allow: vec![], persistent: true, allow_lan: o.allow_lan }, o.full));
    up.kill = Some(kill.clone());
    let mut kill_mode = "";
    if o.kill {
        // protection still runs without it; the status carries the error
        if let Err(e) = kill.set(true, o.allow_lan) {
            sys.say(&format!("fswin: warning: -killswitch: not on: {e}"));
            kill_mode = "; kill switch FAILED";
        } else {
            kill_mode = "; kill switch on";
        }
        start_step(sys, began, "kill switch set");
    } else {
        match fw.active() {
            Ok(true) => match fw.disable() {
                Ok(()) => sys.say("fswin: removed the kill switch an earlier run left on"),
                Err(e) => sys.say(&format!("fswin: warning: a kill switch left by an earlier run may still block: {e}")),
            },
            Ok(false) => {}
            Err(e) => sys.say(&format!("fswin: warning: a kill switch left by an earlier run may still block: {e}")),
        }
    }

    let mut initial = None;
    if !o.rules_file.is_empty() {
        let data = sys.read_user_file(&o.rules_file).map_err(|e| format!("-rules: {e}"))?;
        let (r, skipped) = rules::load(&data).map_err(|e| format!("-rules: {}: {e}", o.rules_file))?;
        if let Some(s) = skipped {
            sys.say(&format!("fswin: -rules: skipped: {s}"));
        }
        initial = Some(r);
    }
    let mut e = Engine::new(initial, &o.block);
    e.kill = Some(kill.clone());
    e.dns_direct = o.dns_direct;
    e.dns_cache = o.dns_cache;
    e.dnssec = o.dnssec;
    let engine = Arc::new(e);

    let direct = Arc::new(Direct::new(phys.protect()));
    // the exit is there before the first flow, so none waits for it or
    // leaves direct; DNS transports dial through it for the queries given it
    let exit = proxy.map(|(url, servers)| Arc::new(ProxyExit::new(&exit_id, url, servers, (*direct).clone())));
    let dns_dialer: Arc<dyn crate::dns::Dialer> = match &exit {
        Some(x) => x.clone(),
        None => direct.clone(),
    };
    if let Some(x) = &exit {
        engine.set_exit(&exit_id);
        engine.set_proxies(x.clone());
    }
    let fake = Arc::new(FakeDns::new(engine.clone()));
    let (fb_url, fb_ips) = if o.fallback_doh.is_empty() { (o.doh.clone(), o.doh_ips.clone()) } else { (o.fallback_doh.clone(), o.fallback_ips.clone()) };
    let dtr = Doh::new(DEFAULT, &fb_url, &fb_ips, &Trust::System, dns_dialer.clone()).map_err(|e| format!("default dns: {e}"))?;
    fake.add(Arc::new(dtr));
    fake.set_fallback(o.dns_fallback);

    let fwd = Arc::new(Forwarder::new(engine.clone(), sys.owners(), direct.clone(), fake.clone()));
    if let Some(x) = &exit {
        fwd.add_exit(&exit_id, x.clone());
    }
    engine.set_closer(fwd.clone().closer());
    let cfg = StackConfig { mtu: plan.adapter.max(mtu::MIN_MTU) as usize, ..Default::default() };
    up.tunnel = Some(Tunnel::start(dev, cfg, fwd));
    crate::logline::log(crate::logline::INFO, "netstack", &format!("up on {name}, mtu {}", plan.adapter));
    if !o.filetag.is_empty() {
        sys.say("fswin: blocklists: remote filetag names are not supported by this engine yet");
    }

    let (tid, dns_label) = setup_dns(&fake, &o, &phys.dns_servers(), dns_dialer, &|l| sys.say(l)).map_err(|e| format!("dns: {e}"))?;
    engine.set_dns(&tid);
    start_step(sys, began, "tunnel and DNS ready");

    let (pname, pdesc, _) = sys.describe(phys4);
    sys.say(&format!("fswin: firestack's own traffic leaves via interface #{phys4} {pname} ({pdesc})"));
    let conflicts = find_conflicts(sys, phys4);
    for c in &conflicts {
        sys.say(&format!("fswin: warning: {c}; disconnect that VPN"));
    }
    o.conflicts = conflicts;

    // the NRPT rule's backup, after the DNS setup as in Go 0.2.22
    if up.nrpt
        && let Err(e) = sys.nrpt_nudge()
    {
        sys.say(&format!("fswin: warning: the NRPT rule is set, but Windows may apply it late: {e}"));
    }

    let mut mode = "DNS only".to_string();
    if o.full {
        sys.add_routes(&name, luid)?;
        mode = format!("all IPv4; firestack's own traffic leaves via interface #{phys4}");
    }
    mode += kill_mode;
    if !exit_id.is_empty() {
        mode += &format!("; exit: {}", exit_name(&exit_id));
    }
    sys.say(&format!(
        "fswin {version}: up on {} in {} ms ({mode}); DNS {FAKEDNS4}:53 -> {dns_label}. Ctrl+C to stop.",
        golike::quote(&name),
        began.elapsed().as_millis()
    ));
    let blocked = engine.blocked_list();
    if !blocked.is_empty() {
        sys.say(&format!("fswin: blocking {blocked}"));
    }

    if let Some((addr, token)) = api_ok {
        let started = crate::events::now_ms();
        let shared = Arc::new(Mutex::new(o.clone()));
        up.shared = Some(shared.clone());
        let run = RunInfo { version: version.to_string(), started_ms: started, exit_id, dns_label, mtu: Some(plan), ..Default::default() };
        let (e2, o2) = (engine.clone(), shared.clone());
        let info: api::InfoFn = Arc::new(move || api::status_of(&e2, &o2.lock().unwrap_or_else(|e| e.into_inner()), &run));
        let tx = stop_tx.clone();
        let app_stop: api::StopFn = Arc::new(move || request_stop(&tx, StopReason::App));
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("api: listen tcp {addr}: {e}"))?;
        up.api = Some(ApiServer::start(listener, &token, engine.clone(), info, app_stop).map_err(|e| format!("api: {e}"))?);
        sys.say(&format!("fswin: control API on {}", o.api));
    }
    Ok(true)
}

/// Waits for a stop, re-checking for VPNs that broke ours every 15 s.
async fn serve(sys: &dyn Sys, stops: &mut watch::Receiver<Option<StopReason>>, up: &Up) -> StopReason {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(15), Duration::from_secs(15));
    let phys = up.adapter.as_ref().map(|a| sys.phys(a.index()));
    loop {
        tokio::select! {
            r = stops.wait_for(|s| s.is_some()) => {
                return r.ok().and_then(|s| *s).unwrap_or(StopReason::CtrlC);
            }
            _ = tick.tick() => {
                let Some(p) = &phys else { continue };
                let now = find_conflicts(sys, p.indexes().0);
                if let Some(shared) = &up.shared {
                    let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
                    for c in now.iter().filter(|c| !g.conflicts.contains(c)) {
                        sys.say(&format!("fswin: warning: {c}; disconnect that VPN"));
                    }
                    g.conflicts = now;
                }
            }
        }
    }
}

/// Go's stopTunnel, after the API: in an order that lets nothing out of
/// the tunnel while it is up and waits on nothing it need not.
async fn stop(sys: &dyn Sys, o: &Options, up: &mut Up) {
    if let Some(a) = up.api.take() {
        a.close();
    }
    if up.nrpt {
        up.nrpt = false;
        if let Err(e) = sys.nrpt_drop() {
            sys.warn(&format!("fswin: stop: NRPT rule (if DNS fails, run fswin -cleanup): {e}"));
        }
        if up.luid != 0 && o.set_dns
            && let Err(e) = sys.clear_dns(up.luid)
        {
            sys.warn(&format!("fswin: clear the adapter's DNS server: {e}"));
        }
        stop_step(sys, up, "NRPT rule removed");
    }
    let adapter = up.adapter.take();
    match up.tunnel.take() {
        Some(t) => {
            t.stop(move || {
                if let Some(a) = adapter {
                    a.close();
                }
            })
            .await
        }
        None => {
            if let Some(a) = adapter {
                let _ = tokio::task::spawn_blocking(move || a.close()).await;
            }
        }
    }
    if up.luid != 0 {
        stop_step(sys, up, "tunnel and adapter removed");
    }
    if let Some(k) = up.kill.take()
        && k.is_on()
    {
        if let Err(e) = k.set(false, false) {
            sys.warn(&format!("fswin: remove kill switch (run fswin -cleanup): {e}"));
        }
        stop_step(sys, up, "kill switch removed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::forward::NoOwners;
    use crate::net::tunnel::tests::MemDevice;
    use std::sync::mpsc as smpsc;

    /// A system that records what it is asked, in order.
    #[derive(Default)]
    struct Fake {
        steps: Mutex<Vec<String>>,
        lines: Mutex<Vec<String>>,
        fail_configure: bool,
        no_route: bool,
        /// the adapter's packets: what the "programs" send, what they get
        wire: Mutex<Option<Wire>>,
    }

    type Wire = (smpsc::Sender<Vec<u8>>, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>);

    impl Fake {
        fn step(&self, s: &str) {
            self.steps.lock().unwrap().push(s.to_string());
        }
        fn steps(&self) -> Vec<String> {
            self.steps.lock().unwrap().clone()
        }
        fn has_line(&self, part: &str) -> bool {
            self.lines.lock().unwrap().iter().any(|l| l.contains(part))
        }
    }

    struct FakeAdapter {
        sys: Arc<Fake>,
        dev: Arc<MemDevice>,
        input: Mutex<Option<smpsc::Sender<Vec<u8>>>>,
    }

    impl Adapter for FakeAdapter {
        fn name(&self) -> String {
            "AuroraVPN".into()
        }
        fn luid(&self) -> u64 {
            7
        }
        fn index(&self) -> u32 {
            42
        }
        fn device(&self) -> Arc<dyn Device> {
            self.dev.clone()
        }
        fn close(self: Box<Self>) {
            // the device's reader ends when its input does
            self.input.lock().unwrap().take();
            self.sys.wire.lock().unwrap().take();
            self.sys.step("adapter closed");
        }
    }

    struct FakePhys;
    impl Phys for FakePhys {
        fn indexes(&self) -> (u32, u32) {
            (3, 0)
        }
        fn protect(&self) -> Option<Arc<dyn Protect>> {
            None
        }
        fn dns_servers(&self) -> Vec<Ipv4Addr> {
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        }
    }

    struct FakeFw(Arc<Fake>, Mutex<bool>);
    impl Firewall for FakeFw {
        fn enable(&self, _o: &WfpOptions) -> Result<(), String> {
            self.0.step("kill on");
            *self.1.lock().unwrap() = true;
            Ok(())
        }
        fn disable(&self) -> Result<(), String> {
            self.0.step("kill off");
            *self.1.lock().unwrap() = false;
            Ok(())
        }
        fn active(&self) -> Result<bool, String> {
            Ok(*self.1.lock().unwrap())
        }
    }

    /// Sys over an Arc<Fake>, so the adapter can record its close.
    struct S(Arc<Fake>);

    impl Sys for S {
        fn say(&self, line: &str) {
            self.0.lines.lock().unwrap().push(line.to_string());
        }
        fn warn(&self, line: &str) {
            self.say(line);
        }
        fn default_route4(&self) -> u32 {
            if self.0.no_route { 0 } else { 3 }
        }
        fn link_mtu(&self) -> (i64, String) {
            (1500, "Ethernet 1500".into())
        }
        fn create_adapter(&self, _name: &str) -> Result<Box<dyn Adapter>, String> {
            self.0.step("adapter");
            let (dev, input, out) = MemDevice::new();
            *self.0.wire.lock().unwrap() = Some((input.clone(), out));
            Ok(Box::new(FakeAdapter { sys: self.0.clone(), dev, input: Mutex::new(Some(input)) }))
        }
        fn nrpt_add(&self) -> Result<(), String> {
            self.0.step("nrpt add");
            Ok(())
        }
        fn nrpt_drop(&self) -> Result<(), String> {
            self.0.step("nrpt drop");
            Ok(())
        }
        fn nrpt_nudge(&self) -> Result<(), String> {
            self.0.step("nudge");
            Ok(())
        }
        fn nrpt_others(&self) -> Vec<String> {
            vec!["Sim VPN (Force all DNS)".into()]
        }
        fn configure(&self, _name: &str, _luid: u64, _set_dns: bool) -> Result<(), String> {
            self.0.step("configure");
            if self.0.fail_configure { Err("ipconf: no".into()) } else { Ok(()) }
        }
        fn clear_dns(&self, _luid: u64) -> Result<(), String> {
            self.0.step("clear dns");
            Ok(())
        }
        fn add_routes(&self, _name: &str, _luid: u64) -> Result<(), String> {
            self.0.step("routes");
            Ok(())
        }
        fn phys(&self, _tun_index: u32) -> Arc<dyn Phys> {
            Arc::new(FakePhys)
        }
        fn firewall(&self) -> Arc<dyn Firewall> {
            Arc::new(FakeFw(self.0.clone(), Mutex::new(false)))
        }
        fn owners(&self) -> Arc<dyn Owners> {
            Arc::new(NoOwners)
        }
        fn describe(&self, idx: u32) -> (String, String, bool) {
            (format!("Ethernet{idx}"), "Intel".into(), false)
        }
        fn cleanup(&self) -> Result<(), String> {
            self.0.step("cleanup");
            Ok(())
        }
        fn read_user_file(&self, path: &str) -> Result<Vec<u8>, String> {
            if path == "token" { Ok(b"0123456789abcdef0123".to_vec()) } else { Err(format!("open {path}: not found")) }
        }
    }

    fn opts(args: &[&str]) -> Options {
        crate::flags::parse(args).unwrap().opts
    }

    async fn run_until_up(f: Arc<Fake>, o: Options) -> Result<(), String> {
        run_while_up(f, o, async |_| {}).await
    }

    /// Runs the engine, does during once it is up, then stops it.
    async fn run_while_up(f: Arc<Fake>, o: Options, during: impl AsyncFnOnce(Arc<Fake>)) -> Result<(), String> {
        let tx = Arc::new(watch::channel(None).0);
        let sys: Arc<dyn Sys> = Arc::new(S(f.clone()));
        let h = tokio::spawn({
            let tx = tx.clone();
            async move { run(o, sys, "test", tx).await }
        });
        for _ in 0..500 {
            if f.has_line(": up on ") || h.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !h.is_finished() {
            during(f.clone()).await;
        }
        request_stop(&tx, StopReason::App);
        tokio::time::timeout(Duration::from_secs(10), h).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn start_and_stop_in_gos_order() {
        let f = Arc::new(Fake::default());
        let o = opts(&["-full", "-nrpt", "-killswitch", "-api", "127.0.0.1:0", "-token-file", "token"]);
        run_until_up(f.clone(), o).await.unwrap();
        assert_eq!(
            f.steps(),
            ["adapter", "nrpt add", "configure", "kill on", "nudge", "routes", "nrpt drop", "clear dns", "adapter closed", "kill off"]
        );
        for want in [
            "fswin: MTU: adapter 1500 (automatic), from Ethernet 1500",
            "fswin: firestack's own traffic leaves via interface #3 Ethernet3 (Intel)",
            "fswin: warning: another VPN sends all DNS elsewhere: Sim VPN (Force all DNS); disconnect that VPN",
            "fswin test: up on \"AuroraVPN\" in ",
            "(all IPv4; firestack's own traffic leaves via interface #3; kill switch on); DNS 10.111.222.3:53 -> https://cloudflare-dns.com/dns-query. Ctrl+C to stop.",
            "fswin: control API on 127.0.0.1:0",
            "fswin: stopping (requested by the app)",
            "fswin: stop: NRPT rule removed after ",
            "fswin: stop: tunnel and adapter removed after ",
            "fswin: stop: kill switch removed after ",
            "fswin: stop: stopped after ",
        ] {
            assert!(f.has_line(want), "no line {want:?} in {:#?}", f.lines.lock().unwrap());
        }
    }

    #[tokio::test]
    async fn dns_only_has_no_routes_and_leaves_no_kill_switch() {
        let f = Arc::new(Fake::default());
        run_until_up(f.clone(), opts(&["-dns", "proxy", "-dns-proxy", "127.0.0.1:25353"])).await.unwrap();
        assert_eq!(f.steps(), ["adapter", "configure", "adapter closed"]);
        assert!(f.has_line("(DNS only); DNS 10.111.222.3:53 -> DNS proxy 127.0.0.1:25353."));
    }

    #[tokio::test]
    async fn failed_start_undoes_what_it_did() {
        let f = Arc::new(Fake { fail_configure: true, ..Default::default() });
        let e = run_until_up(f.clone(), opts(&["-nrpt", "-killswitch"])).await.unwrap_err();
        assert_eq!(e, "ipconf: no");
        assert_eq!(f.steps(), ["adapter", "nrpt add", "configure", "nrpt drop", "clear dns", "adapter closed"]);
        // a stop was never asked for: no stop timings
        assert!(!f.has_line("fswin: stop:"));
    }

    #[tokio::test]
    async fn unsupported_flags_are_refused_before_anything_changes() {
        for (args, want) in [
            (&["-wg", "x.conf"][..], "-wg is not supported by this engine yet (fswin-rs); use fswin.exe"),
            (&["-warp"][..], "-warp is not supported"),
            (&["-dns", "odoh"][..], "-dns odoh is not supported"),
            (&["-dial-strategy", "split-tls"][..], "-dial-strategy other than never is not supported"),
            (&["-dial-strategy", "fast"][..], "-dial-strategy must be never, auto, split-tcp or split-tls, not \"fast\""),
            (&["-dial-retry", "x"][..], "-dial-retry must be never, split or plain, not \"x\""),
            (&["-name", "bad/name"][..], "-name \"bad/name\": up to 64"),
        ] {
            let f = Arc::new(Fake::default());
            let e = run_until_up(f.clone(), opts(args)).await.unwrap_err();
            assert!(e.starts_with(want), "{args:?}: {e}");
            assert!(f.steps().is_empty(), "{args:?}: {:?}", f.steps());
        }
    }

    /// -proxy: all traffic goes to the tunnel (it implies -full) and
    /// leaves by the proxy; the status line names the exit.
    #[tokio::test]
    async fn proxy_exit_starts_full_and_says_so() {
        use crate::net::proxy::tests::{Behaviour, echo_udp, socks_server};
        use crate::net::stack::{Parsed, build_udp, parse};
        let b = Behaviour { auth: Some(("u", "p")), ..Default::default() };
        let px = socks_server(b.clone()).await;
        let echo = echo_udp().await;
        let f = Arc::new(Fake::default());
        let o = opts(&["-proxy", &format!("socks5://u:p@{px}"), "-api", "127.0.0.1:0", "-token-file", "token"]);
        run_while_up(f.clone(), o, async |f: Arc<Fake>| {
            // a program's datagram goes out by the proxy and its answer back
            let (input, mut out) = f.wire.lock().unwrap().take().unwrap();
            let me: SocketAddr = "10.111.222.1:7000".parse().unwrap();
            input.send(build_udp(me, echo, b"through").unwrap()).unwrap();
            let p = tokio::time::timeout(Duration::from_secs(5), out.recv()).await.unwrap().unwrap();
            let Parsed::Udp { src, payload, .. } = parse(&p) else { panic!("not udp") };
            assert_eq!((src, &p[payload]), (echo, &b"through"[..]));
        })
        .await
        .unwrap();
        assert_eq!(b.conns.load(std::sync::atomic::Ordering::Relaxed), 1, "the association's connection");
        assert_eq!(f.steps(), ["adapter", "configure", "routes", "adapter closed"]);
        for want in [
            "fswin: MTU: adapter 1500 (automatic), from Ethernet 1500",
            "(all IPv4; firestack's own traffic leaves via interface #3; exit: proxy); DNS 10.111.222.3:53 -> https://cloudflare-dns.com/dns-query.",
        ] {
            assert!(f.has_line(want), "no line {want:?} in {:#?}", f.lines.lock().unwrap());
        }
    }

    #[tokio::test]
    async fn proxy_urls_are_checked_before_the_adapter() {
        for (args, want) in [
            (&["-proxy", "https://1.2.3.4:443"][..], "-proxy must start with socks5:// or http://"),
            (&["-proxy", "socks5://1.2.3.4"][..], "add exit socks: parse \"socks5://1.2.3.4\": missing port"),
            (&["-proxy", "socks5://1.2.3.4:1", "-wg", "x.conf"][..], "choose one of -wg, -warp, -proxy, -masque and -chain"),
            (&["-proxy", "http://1.2.3.4:1", "-masque"][..], "choose one of -wg, -warp, -proxy, -masque and -chain"),
        ] {
            let f = Arc::new(Fake::default());
            let e = run_until_up(f.clone(), opts(args)).await.unwrap_err();
            assert_eq!(e, want, "{args:?}");
            assert!(f.steps().is_empty(), "{args:?}: {:?}", f.steps());
        }
    }

    #[tokio::test]
    async fn prepare_exit_gives_the_proxy() {
        let (id, cfg, px) = prepare_exit(&opts(&["-proxy", "http://127.0.0.1:3128"])).await.unwrap();
        assert_eq!((id.as_str(), cfg.as_str()), ("socks", "http://127.0.0.1:3128"));
        assert_eq!(px.unwrap().1, vec!["127.0.0.1:3128".parse::<SocketAddr>().unwrap()]);
        let (id, _, px) = prepare_exit(&opts(&[])).await.unwrap();
        assert!(id.is_empty() && px.is_none());
    }

    #[tokio::test]
    async fn api_checks_come_before_the_adapter() {
        let f = Arc::new(Fake::default());
        let e = run_until_up(f.clone(), opts(&["-api", "127.0.0.1:0", "-token-file", "nope"])).await.unwrap_err();
        assert_eq!(e, "api: -token-file: open nope: not found");
        let e = run_until_up(f.clone(), opts(&["-api", "10.0.0.1:47897", "-token-file", "token"])).await.unwrap_err();
        assert_eq!(e, "api: -api must be a loopback address like 127.0.0.1:47897");
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = busy.local_addr().unwrap().to_string();
        let e = run_until_up(f.clone(), opts(&["-api", &a, "-token-file", "token"])).await.unwrap_err();
        assert!(e.ends_with("(is another engine still running?)"), "{e}");
        assert!(f.steps().is_empty());
    }

    #[tokio::test]
    async fn cleanup_only_cleans_up() {
        let f = Arc::new(Fake::default());
        run_until_up(f.clone(), opts(&["-cleanup", "-wg", "x"])).await.unwrap();
        assert_eq!(f.steps(), ["cleanup"]);
        assert!(f.has_line("fswin: removed fswin's NRPT rule and kill switch, if any"));
    }

    #[tokio::test]
    async fn no_network_outside_the_tunnel_fails_full() {
        let f = Arc::new(Fake { no_route: true, ..Default::default() });
        let tx = Arc::new(watch::channel(None).0);
        let sys: Arc<dyn Sys> = Arc::new(S(f.clone()));
        // the service's stop during the wait for a network ends the start
        let h = tokio::spawn({
            let tx = tx.clone();
            async move { run(opts(&["-full"]), sys, "t", tx).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        request_stop(&tx, StopReason::Service);
        tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap().unwrap();
        assert!(f.steps().is_empty());
        assert!(f.has_line("fswin: start: no network yet"));
        assert!(f.has_line("fswin: stopping (requested by AuroraVPN Service)"));
    }
}
