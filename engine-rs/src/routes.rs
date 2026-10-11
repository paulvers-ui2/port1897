// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! -routes (routes_windows.go): per-app routes, like the Android app's
//! WireGuard "advanced" mode and its proxy app lists: extra WireGuard
//! tunnels or SOCKS5 / HTTP proxies that the apps given them
//! (appRule.Route) use instead of the main exit. The ids come from the app
//! (wgapp<N> for WireGuard, pxsocks and pxhttp for proxies); as in Go the
//! engine only checks that WireGuard ids start with wgapp.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::engine::{Proxies, ProxyInfo, ROUTE_WG_PREFIX};
use crate::exit;
use crate::gojson::{self, JValue, Obj};
use crate::golike;
use crate::net::dial::{Dialer, Direct};
use crate::net::proxy::{ProxyExit, ProxyUrl};

/// One entry of the routes file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    pub id: String,
    pub name: String,
    /// "wg" or "proxy"
    pub kind: String,
    /// wg-quick .conf, for wg
    pub file: String,
    /// socks5://... or http://..., for proxy
    pub url: String,
}

/// The routes file as Go's json.Unmarshal reads it into []route.
pub fn parse(data: &[u8]) -> Result<Vec<Route>, String> {
    let v = gojson::unmarshal(data)?;
    let items = match &v {
        JValue::Null => return Ok(Vec::new()),
        JValue::Array(a) => a,
        other => return Err(format!("json: cannot unmarshal {} into Go value of type []main.route", other.kind())),
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let o = match it {
            // a null element is a zero route, as in Go
            JValue::Null => None,
            JValue::Object(_) => Obj::of(it, "route")?,
            other => return Err(format!("json: cannot unmarshal {} into Go value of type main.route", other.kind())),
        };
        let Some(o) = o else {
            out.push(Route::default());
            continue;
        };
        out.push(Route { id: o.string("id")?, name: o.string("name")?, kind: o.string("kind")?, file: o.string("file")?, url: o.string("url")? });
    }
    Ok(out)
}

/// What a route adds: WireGuard's config (UAPI text) or a proxy URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCfg {
    Wg(String),
    Proxy(String),
}

/// A loaded route's exit: what dials its flows and what reports its state.
#[derive(Clone)]
pub struct RouteExit {
    pub dialer: Arc<dyn Dialer>,
    pub proxies: Arc<dyn Proxies>,
}

/// The routes that loaded: names by id (for the engine) and their exits in
/// file order (a later id replaces an earlier one, as firestack's AddProxy
/// does).
#[derive(Default)]
pub struct Loaded {
    pub names: HashMap<String, String>,
    pub exits: Vec<(String, RouteExit)>,
}

/// Go's loadRoutes: reads path with the user's rights, adds each route and
/// returns those that loaded. Routes that fail are skipped and reported in
/// the error, one per line as Go's errors.Join puts them.
pub async fn load(read: &(dyn Fn(&str) -> Result<Vec<u8>, String> + Sync), path: &str, direct: &Direct) -> (Loaded, Option<String>) {
    let mut loaded = Loaded::default();
    let data = match read(path) {
        Ok(d) => d,
        Err(e) => return (loaded, Some(e)),
    };
    let rs = match parse(&data) {
        Ok(rs) => rs,
        Err(e) => return (loaded, Some(format!("{path}: {e}"))),
    };
    let mut errs = Vec::new();
    for r in rs {
        let cfg = match check(read, &r) {
            Ok(c) => c,
            Err(e) => {
                errs.push(e);
                continue;
            }
        };
        let x = match add(&r.id, &cfg, direct).await {
            Ok(x) => x,
            Err(e) => {
                errs.push(format!("route {}: {e}", r.id));
                continue;
            }
        };
        let name = if r.name.is_empty() { r.id.clone() } else { r.name.clone() };
        loaded.names.insert(r.id.clone(), name);
        loaded.exits.push((r.id, x));
    }
    (loaded, (!errs.is_empty()).then(|| errs.join("\n")))
}

/// loadRoutes' checks of one entry, before it is added; the errors read
/// as Go's.
fn check(read: &(dyn Fn(&str) -> Result<Vec<u8>, String> + Sync), r: &Route) -> Result<RouteCfg, String> {
    match r.kind.as_str() {
        "wg" => {
            if !r.id.starts_with(ROUTE_WG_PREFIX) {
                return Err(format!("route {}: WireGuard ids start with {ROUTE_WG_PREFIX}", r.id));
            }
            let conf = read(&r.file).map_err(|e| format!("route {}: {e}", r.id))?;
            let uapi = exit::wg_quick_to_uapi(&String::from_utf8_lossy(&conf)).map_err(|e| format!("route {}: {e}", r.id))?;
            Ok(RouteCfg::Wg(uapi))
        }
        "proxy" => {
            if !r.url.starts_with("socks5://") && !r.url.starts_with("http://") {
                return Err(format!("route {}: proxy url must start with socks5:// or http://", r.id));
            }
            Ok(RouteCfg::Proxy(r.url.clone()))
        }
        k => Err(format!("route {}: kind must be wg or proxy, not {}", r.id, golike::quote(k))),
    }
}

/// firestack's AddProxy for a route: its refusals by id first, then the
/// exit. A proxy's host is looked up now, as -proxy's is, since the exit
/// dials addresses.
async fn add(id: &str, cfg: &RouteCfg, direct: &Direct) -> Result<RouteExit, String> {
    if id.contains("rpn") {
        return Err("proxy: cannot add rpn proxy".into());
    }
    if id.is_empty() {
        return Err("proxy: add failed".into());
    }
    match cfg {
        // the WireGuard exit is not in this engine yet; the config is
        // ready for it
        RouteCfg::Wg(_) => Err("WireGuard routes are not supported by this engine yet".into()),
        RouteCfg::Proxy(url) => {
            // firestack takes any id starting with wg (or gsro) for
            // WireGuard and reads the URL as a WireGuard config
            if id.starts_with("wg") || id.starts_with("gsro") {
                return Err(if url.contains('=') { "proxy: invalid config".into() } else { format!("proxy: wg: {id} failed to parse line {}", golike::quote(url)) });
            }
            let u = ProxyUrl::parse(url)?;
            let servers = u.resolve().await?;
            let x = Arc::new(ProxyExit::new(id, u, servers, direct.clone()));
            Ok(RouteExit { dialer: x.clone(), proxies: x })
        }
    }
}

/// The stack's exits and routes by id (firestack's GetProxies), for
/// /api/proxies: each id answers with its own exit's state.
#[derive(Default)]
pub struct ProxyTable {
    m: RwLock<HashMap<String, Arc<dyn Proxies>>>,
}

impl ProxyTable {
    /// Adds p as id, replacing what id was.
    pub fn add(&self, id: &str, p: Arc<dyn Proxies>) {
        self.m.write().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), p);
    }
}

impl Proxies for ProxyTable {
    fn get(&self, id: &str) -> Option<ProxyInfo> {
        let p = self.m.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()?;
        p.get(id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::engine::{Engine, Owners, TZZ};
    use crate::exit::EXIT_PROXY;
    use crate::net::proxy::tests::{Behaviour, echo_tcp, exit as proxy_exit, socks_server};
    use std::net::SocketAddr;

    const WG_CONF: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";

    fn files(name: &'static str, data: &'static str) -> impl Fn(&str) -> Result<Vec<u8>, String> + Sync {
        move |p: &str| match p {
            "wg.conf" => Ok(WG_CONF.as_bytes().to_vec()),
            p if p == name => Ok(data.as_bytes().to_vec()),
            p => Err(format!("open {p}: The system cannot find the file specified.")),
        }
    }

    async fn load_str(data: &'static str) -> (Loaded, Option<String>) {
        load(&files("routes.json", data), "routes.json", &Direct::new(None)).await
    }

    #[test]
    fn parse_reads_as_go_does() {
        let rs = parse(br#"[{"ID":"pxsocks","Name":"Home","kind":"proxy","url":"socks5://127.0.0.1:1080","extra":1},null,{"id":"a","id":"b"}]"#).unwrap();
        assert_eq!(rs[0], Route { id: "pxsocks".into(), name: "Home".into(), kind: "proxy".into(), url: "socks5://127.0.0.1:1080".into(), ..Default::default() });
        assert_eq!(rs[1], Route::default());
        assert_eq!(rs[2].id, "b", "a later duplicate key wins");
        assert!(parse(b"null").unwrap().is_empty());
        assert!(parse(b" [] ").unwrap().is_empty());
        for (data, want) in [
            (&br#"{"id":"x"}"#[..], "json: cannot unmarshal object into Go value of type []main.route"),
            (br#"["x"]"#, "json: cannot unmarshal string into Go value of type main.route"),
            (br#"[{"id":5}]"#, "json: cannot unmarshal number into Go struct field route.id of type string"),
            (br#"[{"kind":true}]"#, "json: cannot unmarshal bool into Go struct field route.kind of type string"),
        ] {
            assert_eq!(parse(data).unwrap_err(), want);
        }
        assert!(parse(b"[").is_err());
    }

    #[tokio::test]
    async fn bad_routes_are_skipped_with_gos_wording() {
        let (l, err) = load_str(
            r#"[
            {"id":"pxsocks","name":"Home proxy","kind":"proxy","url":"socks5://127.0.0.1:1080"},
            {"id":"pxhttp","kind":"proxy","url":"http://127.0.0.1:3128"},
            {"id":"pxbad","kind":"proxy","url":"https://127.0.0.1:443"},
            {"id":"pxnoport","kind":"proxy","url":"socks5://127.0.0.1"},
            {"id":"office","kind":"wg","file":"wg.conf"},
            {"id":"wgapp1","name":"Office","kind":"wg","file":"missing.conf"},
            {"id":"wgapp2","name":"Away","kind":"wg","file":"wg.conf"},
            {"id":"wgx","kind":"proxy","url":"socks5://127.0.0.1:1"},
            {"id":"pxrpn","kind":"proxy","url":"socks5://127.0.0.1:1"},
            {"id":"","kind":"proxy","url":"socks5://127.0.0.1:1"},
            {"id":"x","kind":"WG"}
        ]"#,
        )
        .await;
        assert_eq!(
            err.unwrap(),
            [
                "route pxbad: proxy url must start with socks5:// or http://",
                "route pxnoport: parse \"socks5://127.0.0.1\": missing port",
                "route office: WireGuard ids start with wgapp",
                "route wgapp1: open missing.conf: The system cannot find the file specified.",
                "route wgapp2: WireGuard routes are not supported by this engine yet",
                "route wgx: proxy: wg: wgx failed to parse line \"socks5://127.0.0.1:1\"",
                "route pxrpn: proxy: cannot add rpn proxy",
                "route : proxy: add failed",
                "route x: kind must be wg or proxy, not \"WG\"",
            ]
            .join("\n")
        );
        // names default to the id
        assert_eq!(l.names, HashMap::from([("pxsocks".to_string(), "Home proxy".to_string()), ("pxhttp".to_string(), "pxhttp".to_string())]));
        let ids: Vec<&str> = l.exits.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["pxsocks", "pxhttp"]);
        assert_eq!(l.exits[0].1.proxies.get("pxsocks").unwrap().status, TZZ);
    }

    #[tokio::test]
    async fn unreadable_or_bad_files_load_nothing() {
        let (l, err) = load(&files("x", ""), "routes.json", &Direct::new(None)).await;
        assert!(l.names.is_empty() && l.exits.is_empty());
        assert_eq!(err.unwrap(), "open routes.json: The system cannot find the file specified.");
        let (l, err) = load_str(r#"{"id":"x"}"#).await;
        assert!(l.names.is_empty());
        assert_eq!(err.unwrap(), "routes.json: json: cannot unmarshal object into Go value of type []main.route");
        let (l, err) = load_str("null").await;
        assert!(l.names.is_empty() && err.is_none());
    }

    #[test]
    fn wg_routes_get_their_config_ready() {
        let r = Route { id: "wgapp1".into(), kind: "wg".into(), file: "wg.conf".into(), ..Default::default() };
        let Ok(RouteCfg::Wg(uapi)) = check(&files("", ""), &r) else { panic!("not a wg config") };
        assert!(uapi.contains("endpoint=192.0.2.1:51820"), "{uapi}");
    }

    /// GET /api/proxies lists the exit and the routes, each with its own
    /// state, sorted by name.
    #[tokio::test]
    async fn the_table_answers_for_the_exit_and_every_route() {
        let (l, err) = load_str(r#"[{"id":"pxsocks","name":"Home proxy","kind":"proxy","url":"socks5://127.0.0.1:1080"},{"id":"pxhttp","name":"Away","kind":"proxy","url":"http://127.0.0.1:3128"},{"id":"wgapp1","name":"Office","kind":"wg","file":"wg.conf"}]"#).await;
        assert!(err.unwrap().starts_with("route wgapp1: "));
        let t = Arc::new(ProxyTable::default());
        t.add(EXIT_PROXY, Arc::new(proxy_exit("socks5://127.0.0.1:1", "127.0.0.1:1".parse().unwrap())));
        for (id, x) in &l.exits {
            t.add(id, x.proxies.clone());
        }
        assert!(t.get("wgapp1").is_none() && t.get("Base").is_none());
        let e = Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {}));
        e.set_exit(EXIT_PROXY);
        e.set_proxies(t);
        e.set_routes(l.names);
        let st = e.proxy_stats();
        let v = serde_json::to_value(&st).unwrap();
        let rows: Vec<(String, String, String)> = v.as_array().unwrap().iter().map(|r| (r["id"].as_str().unwrap().into(), r["name"].as_str().unwrap().into(), r["status"].as_str().unwrap().into())).collect();
        assert_eq!(
            rows,
            [("pxhttp".into(), "Away".into(), "idle".into()), ("pxsocks".into(), "Home proxy".into(), "idle".into()), (EXIT_PROXY.to_string(), "proxy".into(), "idle".into())]
        );
        // the keys in Go's order; no addrs or lastOK before a good dial
        for (s, (id, name, _)) in st.iter().zip(&rows) {
            let j = serde_json::to_string(s).unwrap();
            let head = format!(r#"{{"id":"{id}","name":"{name}","status":"idle","rx":0,"tx":0,"since":"#);
            assert!(j.starts_with(&head) && j.ends_with('}') && !j[head.len()..].contains(','), "{j}");
        }
    }

    /// Every flow comes from C:\Apps\app.exe.
    pub(crate) struct OneApp;
    impl Owners for OneApp {
        fn tcp4(&self, _: SocketAddr, _: SocketAddr) -> Result<u32, String> {
            Ok(4242)
        }
        fn udp4(&self, _: SocketAddr) -> Result<u32, String> {
            Ok(4242)
        }
        fn exe_path(&self, _: u32) -> Result<String, String> {
            Ok(r"C:\Apps\app.exe".into())
        }
    }

    /// An app whose rule names a loaded route goes through that route's
    /// proxy, not the exit; the journal names the route.
    #[tokio::test]
    async fn an_apps_route_carries_its_flows() {
        use crate::net::forward::Forwarder;
        use crate::net::stack::tests::{Host, drive};
        use crate::net::stack::{Stack, StackConfig};
        use crate::rules::{AppRule, RuleSet};
        use tokio::sync::mpsc;

        let echo = echo_tcp().await;
        let b = Behaviour::default();
        let px = socks_server(b.clone()).await;
        let data: &'static str = Box::leak(format!(r#"[{{"id":"pxsocks","name":"Home proxy","kind":"proxy","url":"socks5://{px}"}}]"#).into_boxed_str());
        let (l, err) = load_str(data).await;
        assert!(err.is_none(), "{err:?}");

        let e = Arc::new(Engine::with_self(None, "", "C:\\fswin.exe", Box::new(|_| {})));
        let mut rs = RuleSet::default();
        rs.apps.insert("app.exe".into(), AppRule { route: "pxsocks".into(), ..Default::default() });
        e.set_rules(rs);
        let t = Arc::new(ProxyTable::default());
        let (st, io) = Stack::new(StackConfig::default());
        let (to_stack, rx) = mpsc::channel(1024);
        tokio::spawn(st.run(rx));
        let mut from_stack = io.out;
        let f = Arc::new(Forwarder::new(e.clone(), Arc::new(OneApp), Arc::new(Direct::new(None)), Arc::new(crate::dns::FakeDns::new(e.clone()))));
        for (id, x) in &l.exits {
            f.add_exit(id, x.dialer.clone());
            t.add(id, x.proxies.clone());
        }
        e.set_proxies(t);
        e.set_routes(l.names);
        tokio::spawn(f.clone().run(io.flows));

        let mut host = Host::new();
        let h = host.connect(42001, echo);
        drive(&mut host, &to_stack, &mut from_stack, |h2| h2.tcp(h).may_send()).await;
        host.tcp(h).send_slice(b"by route").unwrap();
        let mut got = Vec::new();
        drive(&mut host, &to_stack, &mut from_stack, |h2| {
            let s = h2.tcp(h);
            while s.can_recv() {
                let mut buf = [0u8; 64];
                let n = s.recv_slice(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            got.len() == 8
        })
        .await;
        assert_eq!(got, b"by route");
        assert_eq!(b.conns.load(std::sync::atomic::Ordering::Relaxed), 1, "the flow went through the route's proxy");
        let flow = e.log.since(0, 100).into_iter().find(|v| v.kind == "flow").unwrap();
        assert_eq!(flow.via, "Home proxy");
        let st = e.proxy_stats();
        assert_eq!((st[0].id.as_str(), st[0].status.as_str(), st[0].rx, st[0].tx), ("pxsocks", "connected", 8, 8));
    }
}
