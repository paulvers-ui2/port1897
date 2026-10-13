// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Connect automatically, and reconnect: the app presses Start by itself.
//!
//! With "Connect automatically" (setting autoConnect) on, protection starts
//! when Windows starts (the app runs at sign-in, with --autostart) and when
//! the PC connects to a network: from none to one, or to another one.
//!
//! With "Reconnect if the connection drops" (autoRecover) on, while
//! protection runs with a VPN exit, the app checks every 10 s that the
//! internet answers through the tunnel; after two misses in a row it presses
//! Stop, waits 1 second and presses Start, as one would by hand. An engine
//! that ends by itself is started again 1 second later.
//!
//! A Stop by the user (window, tray, automation, the 11-hour WARP timer) is
//! kept: nothing starts protection again until the next network or the next
//! start of Windows. The loop lives in the app's backend, so it works with
//! the window closed and the app in the tray.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::AppHandle;

use crate::{applog, engine, live, net, settings};

/// How often the loop looks at the network and the engine.
const TICK: Duration = Duration::from_secs(1);
/// The pause between Stop and Start, and before starting an engine that ended
/// by itself.
const RESTART_PAUSE: Duration = Duration::from_secs(1);
/// How often the internet is checked through the tunnel.
const PROBE_EVERY: Duration = Duration::from_secs(10);
/// Misses in a row that mean the connection is gone.
const PROBE_MISSES: u32 = 2;
/// The shortest and longest wait between two reconnects while the internet
/// stays unreachable: it doubles each time, and starts over once it answers.
const RECOVER_MIN: Duration = Duration::from_secs(20);
const RECOVER_MAX: Duration = Duration::from_secs(300);
/// Retries of a start that failed: doubling up to a minute.
const RETRY_MIN: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(60);
/// An engine that ends this long after a stop was asked for ended because of
/// it, not by itself.
const STOP_GRACE: Duration = Duration::from_secs(30);
/// After protection stops, the routes settle (the tunnel's go, the
/// network's come back): network changes meanwhile are ours, not a new
/// network.
const SETTLE: Duration = Duration::from_secs(5);

/// Protection should be on: set by every start, cleared by a Stop of the user.
static WANT_ON: AtomicBool = AtomicBool::new(false);
/// Counts the user's Stops, so a start planned before one is dropped.
static STOPS: AtomicU64 = AtomicU64::new(0);
/// When a stop was last asked for (any: the user's, a reconnect, Quit).
static LAST_STOP: Mutex<Option<Instant>> = Mutex::new(None);

/// engine::start calls this once the engine runs.
pub fn started() {
    WANT_ON.store(true, Ordering::Relaxed);
}

/// engine::stop calls this before asking the engine to stop.
pub fn stopping(by_user: bool) {
    *LAST_STOP.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    if by_user {
        WANT_ON.store(false, Ordering::Relaxed);
        STOPS.fetch_add(1, Ordering::Relaxed);
    }
}

fn stopped_recently(now: Instant) -> bool {
    LAST_STOP.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|t| now.duration_since(t) < STOP_GRACE)
}

/// The network this PC would use to reach the internet, as the address it
/// would send from: None without one. Connecting a UDP socket only looks up
/// the route, so nothing is sent. Loopback, link-local (169.254.x, a network
/// with no DHCP answer yet) and the engine's own tunnel (10.111.222.0/24,
/// cmd/fswin ifaddr4) are not a network to connect over.
pub fn network_path() -> Option<String> {
    for (bind, to) in [("0.0.0.0:0", "1.1.1.1:53"), ("[::]:0", "[2606:4700:4700::1111]:53")] {
        let Ok(sock) = std::net::UdpSocket::bind(bind) else { continue };
        if sock.connect(to).is_err() {
            continue;
        }
        if let Ok(a) = sock.local_addr()
            && usable(a.ip())
        {
            return Some(a.ip().to_string());
        }
    }
    None
}

fn usable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_loopback() || v4.is_link_local() || v4.octets()[..3] == [10, 111, 222]),
        std::net::IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// What the loop sees on one tick.
#[derive(Clone, Debug, Default)]
pub struct Seen {
    /// The engine runs (its API answers).
    pub on: bool,
    /// A start or stop is in progress.
    pub busy: bool,
    /// The network path (network_path), looked at while protection is off.
    pub net: Option<String>,
    pub auto_connect: bool,
    pub auto_recover: bool,
    /// Protection should be on (WANT_ON).
    pub want_on: bool,
    /// The user's Stops so far (STOPS).
    pub stops: u64,
    /// The engine runs with a VPN exit (the only case the internet check
    /// tells the tunnel apart from the network).
    pub has_exit: bool,
    pub paused: bool,
    /// A stop was asked for within STOP_GRACE.
    pub stopped_recently: bool,
}

/// What the loop should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Act {
    Wait,
    /// Press Start.
    Start(String),
    /// Check the internet through the tunnel, then report with probed.
    Probe,
    /// Press Stop, wait RESTART_PAUSE, press Start.
    Restart(String),
}

struct Pending {
    why: String,
    at: Instant,
    retry: Duration,
    /// Planned before this many user Stops; a later Stop drops it.
    stops: u64,
}

/// The decisions, kept apart from Windows and the engine so they can be
/// tested.
pub struct Guard {
    first: bool,
    boot: bool,
    was_on: bool,
    prev_net: Option<String>,
    pending: Option<Pending>,
    misses: u32,
    probing: bool,
    next_probe: Option<Instant>,
    next_recover: Option<Instant>,
    recover_wait: Duration,
    settle_until: Option<Instant>,
}

impl Guard {
    /// boot: the app was started with Windows (--autostart).
    pub fn new(boot: bool) -> Self {
        Guard { first: true, boot, was_on: false, prev_net: None, pending: None, misses: 0, probing: false, next_probe: None, next_recover: None, recover_wait: RECOVER_MIN, settle_until: None }
    }

    fn plan(&mut self, why: &str, at: Instant, stops: u64) {
        if self.pending.is_none() {
            self.pending = Some(Pending { why: why.to_string(), at, retry: RETRY_MIN, stops });
        }
    }

    pub fn tick(&mut self, s: &Seen, now: Instant) -> Act {
        if s.busy {
            return Act::Wait;
        }
        if self.first {
            self.first = false;
            self.was_on = s.on;
            self.prev_net = if s.on { None } else { s.net.clone() };
            if s.on {
                self.next_probe = Some(now + PROBE_EVERY);
            }
            if self.boot && s.auto_connect && !s.on {
                self.plan("Windows started", now, s.stops);
            }
        }
        if self.pending.as_ref().is_some_and(|p| p.stops != s.stops) {
            self.pending = None; // the user pressed Stop since
        }

        if self.was_on && !s.on {
            // our own stop changes the path from the tunnel's back to the
            // network's: that is not a new network
            self.prev_net = s.net.clone();
            self.settle_until = Some(now + SETTLE);
            self.probing = false;
            if s.want_on && s.auto_recover && !s.stopped_recently {
                self.plan("protection stopped by itself", now + RESTART_PAUSE, s.stops);
            }
        } else if !self.was_on && s.on {
            self.pending = None;
            self.misses = 0;
            self.next_probe = Some(now + PROBE_EVERY);
        }
        self.was_on = s.on;

        if !s.on {
            if self.settle_until.is_some_and(|t| now < t) {
                self.prev_net = s.net.clone();
            }
            match (&self.prev_net, &s.net) {
                (_, None) => self.prev_net = None,
                (prev, Some(n)) => {
                    let why = match prev {
                        None => Some("connected to a network"),
                        Some(p) if p != n => Some("connected to another network"),
                        _ => None,
                    };
                    if let Some(why) = why
                        && s.auto_connect
                    {
                        self.plan(why, now, s.stops);
                    }
                    self.prev_net = Some(n.clone());
                }
            }
            if let Some(p) = &self.pending
                && now >= p.at
                && s.net.is_some()
            {
                return Act::Start(p.why.clone());
            }
            return Act::Wait;
        }

        if s.auto_recover && s.want_on && s.has_exit && !s.paused && !self.probing && self.next_probe.is_none_or(|t| now >= t) {
            self.probing = true;
            return Act::Probe;
        }
        Act::Wait
    }

    /// The result of Act::Start.
    pub fn start_done(&mut self, ok: bool, now: Instant) {
        if ok {
            self.pending = None;
        } else if let Some(p) = &mut self.pending {
            p.at = now + p.retry;
            p.retry = (p.retry * 2).min(RETRY_MAX);
        }
    }

    /// The result of Act::Probe: whether the internet answered.
    pub fn probed(&mut self, ok: bool, now: Instant) -> Act {
        self.probing = false;
        self.next_probe = Some(now + PROBE_EVERY);
        if ok {
            self.misses = 0;
            self.recover_wait = RECOVER_MIN;
            return Act::Wait;
        }
        self.misses += 1;
        if self.misses < PROBE_MISSES || self.next_recover.is_some_and(|t| now < t) {
            return Act::Wait;
        }
        self.misses = 0;
        self.next_recover = Some(now + self.recover_wait);
        self.recover_wait = (self.recover_wait * 2).min(RECOVER_MAX);
        Act::Restart("the connection dropped".into())
    }
}

fn seen(now: Instant) -> Seen {
    let s = settings::read();
    let st = live::last();
    let on = st.is_some();
    let busy = engine::OP.try_lock().is_err();
    let exit = st.as_ref().and_then(|v| v.get("exit")).and_then(Value::as_str).unwrap_or("");
    Seen {
        on,
        busy,
        net: if on { None } else { network_path() },
        auto_connect: settings::bool(&s, "autoConnect"),
        auto_recover: settings::bool(&s, "autoRecover"),
        want_on: WANT_ON.load(Ordering::Relaxed),
        stops: STOPS.load(Ordering::Relaxed),
        has_exit: !exit.is_empty(),
        paused: settings::num(&s, "pausedUntil") > applog::now_ms() as f64,
        stopped_recently: stopped_recently(now),
    }
}

fn ok(r: &Value) -> bool {
    r.get("ok").and_then(Value::as_bool) == Some(true)
}

fn error(r: &Value) -> &str {
    r.get("error").and_then(Value::as_str).unwrap_or("")
}

fn notify(app: &AppHandle, body: &str) {
    if settings::bool(&settings::read(), "notify") {
        live::notify(app, body);
    } else {
        applog!("notice (not shown): {body}");
    }
}

/// The internet through the tunnel: Cloudflare's trace answers.
async fn internet_answers() -> bool {
    let r = net::check_exit().await;
    r.get("error").is_none() && r.get("ip").and_then(Value::as_str).is_some_and(|ip| ip != "?")
}

/// Runs the loop until Quit. boot: the app was started with Windows.
pub fn spawn(app: AppHandle, boot: bool) {
    tauri::async_runtime::spawn(async move {
        let mut g = Guard::new(boot);
        let mut failed_once = false;
        loop {
            tokio::time::sleep(TICK).await;
            if crate::quitting() {
                return;
            }
            let now = Instant::now();
            match g.tick(&seen(now), now) {
                Act::Wait => {}
                Act::Start(why) => {
                    applog!("auto-connect: {why}; starting protection");
                    let r = engine::start().await;
                    live::refresh(&app).await;
                    g.start_done(ok(&r), Instant::now());
                    if ok(&r) {
                        failed_once = false;
                    } else {
                        applog!("auto-connect: start failed ({}); trying again", error(&r));
                        if !failed_once {
                            failed_once = true;
                            notify(&app, &format!("Could not start protection: {}. Trying again.", error(&r)));
                        }
                    }
                }
                Act::Probe => {
                    let answered = internet_answers().await;
                    if let Act::Restart(why) = g.probed(answered, Instant::now()) {
                        reconnect(&app, &why).await;
                    }
                }
                Act::Restart(why) => reconnect(&app, &why).await,
            }
        }
    });
}

/// Stop, a 1-second pause, Start: what one would do by hand.
async fn reconnect(app: &AppHandle, why: &str) {
    let stops = STOPS.load(Ordering::Relaxed);
    applog!("auto-reconnect: {why}; stopping, then starting again in {} s", RESTART_PAUSE.as_secs());
    engine::stop(false).await;
    tokio::time::sleep(RESTART_PAUSE).await;
    if crate::quitting() || STOPS.load(Ordering::Relaxed) != stops {
        return; // Quit, or the user pressed Stop meanwhile
    }
    let r = engine::start().await;
    live::refresh(app).await;
    if ok(&r) {
        notify(app, "The connection dropped: protection restarted.");
    } else {
        applog!("auto-reconnect: start failed ({})", error(&r));
        notify(app, &format!("The connection dropped and protection could not start again: {}", error(&r)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn off(net: Option<&str>) -> Seen {
        Seen { net: net.map(str::to_string), auto_connect: true, auto_recover: true, ..Default::default() }
    }

    fn on() -> Seen {
        Seen { on: true, auto_connect: true, auto_recover: true, want_on: true, has_exit: true, ..Default::default() }
    }

    #[test]
    fn starts_when_windows_starts_and_waits_for_a_network() {
        let t = Instant::now();
        let mut g = Guard::new(true);
        assert_eq!(g.tick(&off(None), t), Act::Wait); // no network yet
        assert_eq!(g.tick(&off(Some("192.168.1.5")), t + TICK), Act::Start("Windows started".into()));
    }

    #[test]
    fn a_launch_by_hand_does_not_start() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        assert_eq!(g.tick(&off(Some("192.168.1.5")), t), Act::Wait);
        assert_eq!(g.tick(&off(Some("192.168.1.5")), t + TICK), Act::Wait);
    }

    #[test]
    fn starts_on_a_network_and_on_another_network() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        g.tick(&off(None), t);
        assert_eq!(g.tick(&off(Some("10.0.0.2")), t + TICK), Act::Start("connected to a network".into()));
        g.start_done(true, t + TICK);
        assert_eq!(g.tick(&off(Some("10.0.0.2")), t + TICK * 2), Act::Wait);
        assert_eq!(g.tick(&off(Some("100.64.3.9")), t + TICK * 3), Act::Start("connected to another network".into()));
    }

    #[test]
    fn nothing_without_the_setting() {
        let t = Instant::now();
        let mut g = Guard::new(true);
        let mut s = off(None);
        s.auto_connect = false;
        g.tick(&s, t);
        s.net = Some("10.0.0.2".into());
        assert_eq!(g.tick(&s, t + TICK), Act::Wait);
    }

    #[test]
    fn a_failed_start_is_retried_later() {
        let t = Instant::now();
        let mut g = Guard::new(true);
        assert!(matches!(g.tick(&off(Some("10.0.0.2")), t), Act::Start(_)));
        g.start_done(false, t);
        assert_eq!(g.tick(&off(Some("10.0.0.2")), t + Duration::from_secs(1)), Act::Wait);
        assert!(matches!(g.tick(&off(Some("10.0.0.2")), t + RETRY_MIN), Act::Start(_)));
    }

    #[test]
    fn the_users_stop_is_kept_until_the_next_network() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        g.tick(&on(), t);
        // the user pressed Stop: WANT_ON off, a stop just now
        let mut s = off(Some("10.0.0.2"));
        s.stops = 1;
        s.stopped_recently = true;
        assert_eq!(g.tick(&s, t + TICK), Act::Wait);
        assert_eq!(g.tick(&s, t + TICK * 2 + SETTLE), Act::Wait);
        s.net = Some("100.64.3.9".into());
        assert!(matches!(g.tick(&s, t + TICK * 3 + SETTLE), Act::Start(_)));
    }

    #[test]
    fn a_stop_drops_a_planned_start() {
        let t = Instant::now();
        let mut g = Guard::new(true);
        g.tick(&off(None), t); // planned, waiting for a network
        let mut s = off(Some("10.0.0.2"));
        s.stops = 1; // then the user pressed Stop
        assert_eq!(g.tick(&s, t + TICK), Act::Start("connected to a network".into())); // the network itself still counts
        g.start_done(true, t + TICK);
        let mut g = Guard::new(true);
        g.tick(&off(None), t);
        let mut s = off(None);
        s.stops = 1;
        assert_eq!(g.tick(&s, t + TICK), Act::Wait);
        assert!(g.pending.is_none());
    }

    #[test]
    fn routes_settling_after_a_stop_are_not_a_new_network() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        g.tick(&on(), t);
        let mut s = off(None); // the tunnel's route is gone, the network's not back yet
        s.stops = 1;
        s.stopped_recently = true;
        assert_eq!(g.tick(&s, t + TICK), Act::Wait);
        s.net = Some("192.168.1.5".into());
        assert_eq!(g.tick(&s, t + TICK * 2), Act::Wait);
        assert_eq!(g.tick(&s, t + TICK * 2 + SETTLE), Act::Wait);
        s.net = Some("100.64.3.9".into()); // a real change, later
        assert!(matches!(g.tick(&s, t + TICK * 3 + SETTLE), Act::Start(_)));
    }

    #[test]
    fn an_engine_that_ends_by_itself_starts_again_a_second_later() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        g.tick(&on(), t);
        let mut s = off(Some("10.0.0.2"));
        s.want_on = true;
        assert_eq!(g.tick(&s, t + TICK), Act::Wait); // the 1-second pause
        assert_eq!(g.tick(&s, t + TICK + RESTART_PAUSE), Act::Start("protection stopped by itself".into()));
    }

    #[test]
    fn two_misses_in_a_row_restart_then_the_wait_grows() {
        let t = Instant::now();
        let mut g = Guard::new(false);
        g.tick(&on(), t);
        assert_eq!(g.tick(&on(), t + PROBE_EVERY), Act::Probe);
        assert_eq!(g.probed(false, t + PROBE_EVERY), Act::Wait);
        assert_eq!(g.tick(&on(), t + PROBE_EVERY * 2), Act::Probe);
        assert_eq!(g.probed(false, t + PROBE_EVERY * 2), Act::Restart("the connection dropped".into()));
        // still down right after: no second restart within RECOVER_MIN
        let t2 = t + PROBE_EVERY * 2;
        assert_eq!(g.probed(false, t2 + Duration::from_secs(5)), Act::Wait);
        assert_eq!(g.probed(false, t2 + Duration::from_secs(10)), Act::Wait);
        assert!(matches!(g.probed(false, t2 + RECOVER_MIN + Duration::from_secs(5)), Act::Restart(_)));
        assert_eq!(g.recover_wait, RECOVER_MIN * 4);
        // answering again resets it
        assert_eq!(g.probed(true, t2 + RECOVER_MIN * 3), Act::Wait);
        assert_eq!(g.recover_wait, RECOVER_MIN);
    }

    #[test]
    fn no_check_while_paused_without_an_exit_or_with_reconnect_off() {
        let t = Instant::now();
        let changes: [fn(&mut Seen); 4] = [|s| s.paused = true, |s| s.has_exit = false, |s| s.auto_recover = false, |s| s.want_on = false];
        for change in changes {
            let mut g = Guard::new(false);
            let mut s = on();
            change(&mut s);
            g.tick(&s, t);
            assert_eq!(g.tick(&s, t + PROBE_EVERY), Act::Wait);
        }
    }

    #[test]
    fn busy_waits() {
        let t = Instant::now();
        let mut g = Guard::new(true);
        let mut s = off(Some("10.0.0.2"));
        s.busy = true;
        assert_eq!(g.tick(&s, t), Act::Wait);
    }

    #[test]
    fn network_path_is_this_pcs_address_or_none() {
        // on a PC (or CI runner) with a network: the address it sends from
        if let Some(a) = network_path() {
            println!("network path: {a}");
            assert!(usable(a.parse().unwrap()));
        }
    }

    #[test]
    fn link_local_is_no_network() {
        assert!(!usable("169.254.10.1".parse().unwrap()));
        assert!(!usable("fe80::1".parse().unwrap()));
        assert!(!usable("127.0.0.1".parse().unwrap()));
        assert!(!usable("10.111.222.1".parse().unwrap())); // the engine's tunnel
        assert!(usable("192.168.1.5".parse().unwrap()));
        assert!(usable("2001:db8::5".parse().unwrap()));
    }
}
