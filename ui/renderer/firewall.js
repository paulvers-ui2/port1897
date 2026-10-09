// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// The firewall screens of the Android app: Universal firewall rules, IP and
// domain rules (for all apps or one), App info, the connection and DNS log
// details, the mode chooser, pause, and allowed DNS record types. Rules
// apply at once (no restart): App.setRules hands them to the engine.

'use strict';

// App modes, as on Android's App info screen. "block" is the switch.
const APP_MODES = [
  ['isolate', 'Isolate', 'ic_firewall_lockdown_off', 'Block everything except the IPs and domains you trust for this app.'],
  ['bypass', 'Bypass DNS & Firewall', 'ic_firewall_bypass_off', 'Never firewall this app.'],
  ['bypassUniversal', 'Bypass Universal', 'universal_firewall', 'Skip the universal rules for this app; its own rules still apply.'],
  ['exclude', 'Exclude', 'ic_firewall_exclude_off', 'Never firewall this app, and never send it through the VPN or proxy.'],
];

const MODE_LABEL = {
  block: 'Blocked',
  allow: 'Allowed',
  isolate: 'Isolated',
  bypass: 'Bypass DNS & Firewall',
  bypassUniversal: 'Bypass Universal',
  exclude: 'Excluded',
};

// DNS record types (Android's ResourceRecordTypes).
const RR_TYPES = [
  [1, 'A', 'IPv4'], [28, 'AAAA', 'IPv6'], [5, 'CNAME', 'Canonical Name'], [65, 'HTTPS', 'HTTP Service Binding'],
  [64, 'SVCB', 'General Service Binding'], [45, 'IPSECKEY', 'IPSECKEY'], [15, 'MX', 'Mail Exchange'], [16, 'TXT', 'Text Strings'],
  [2, 'NS', 'Authoritative Name Server'], [6, 'SOA', 'Start of a zone of Authority'], [12, 'PTR', 'Domain Name Pointer'],
  [33, 'SRV', 'Server Selection'], [257, 'CAA', 'Certification Authority Restriction'], [35, 'NAPTR', 'Naming Authority Pointer'],
  [43, 'DS', 'Delegation Signer'], [48, 'DNSKEY', 'DNSKEY'], [46, 'RRSIG', 'RRSIG'], [47, 'NSEC', 'NSEC'], [50, 'NSEC3', 'NSEC3'],
  [52, 'TLSA', 'TLSA'], [53, 'SMIMEA', 'S/MIME cert association'], [44, 'SSHFP', 'SSH Key Fingerprint'], [39, 'DNAME', 'DNAME'],
  [13, 'HINFO', 'Host Information'], [17, 'RP', 'Responsible Person'], [29, 'LOC', 'Location Information'], [37, 'CERT', 'CERT'],
  [59, 'CDS', 'Child DS'], [60, 'CDNSKEY', 'DNSKEY(s)'], [61, 'OPENPGPKEY', 'OpenPGP Key'], [256, 'URI', 'URI'],
  [99, 'SPF', 'SPF'], [255, 'ANY', 'Any'], [252, 'AXFR', 'Transfer entire zone'], [251, 'IXFR', 'Incremental transfer'],
];

const rrName = (t) => (RR_TYPES.find((r) => r[0] === t) || [t, 'TYPE' + t])[1];

// ---------- rule helpers ----------

function appRuleOf(name) {
  return (App.settings.rules.apps || {})[String(name || '').toLowerCase()] || {};
}

function blockedNames() {
  return Object.entries(App.settings.rules.apps || {})
    .filter(([, a]) => a.mode === 'block')
    .map(([n]) => n)
    .sort();
}

function appStatusText(name) {
  const a = appRuleOf(name);
  if (a.allowUntil > Date.now()) return 'Allowed for ' + Math.ceil((a.allowUntil - Date.now()) / 60000) + ' min';
  const label = MODE_LABEL[a.mode] || 'Allowed';
  return a.noProxy && a.mode !== 'exclude' ? label + ' · no proxy' : label;
}

async function setAppRule(name, patch) {
  const key = String(name).toLowerCase();
  const apps = { ...App.settings.rules.apps };
  const a = { ...apps[key], ...patch };
  for (const k of Object.keys(a)) if (a[k] === undefined || a[k] === '' || a[k] === false || a[k] === 0) delete a[k];
  if (Object.keys(a).length) apps[key] = a;
  else delete apps[key];
  await App.setRules({ rules: { ...App.settings.rules, apps } });
}

async function addRule(kind, rule) {
  const list = (App.settings.rules[kind] || []).filter((r) => !sameRule(kind, r, rule));
  list.push(rule);
  await App.setRules({ rules: { ...App.settings.rules, [kind]: list } });
  toast(`${rule.action === 'block' ? 'Blocked' : 'Trusted'} ${kind === 'ips' ? ipText(rule) : rule.domain}${rule.app ? ' for ' + rule.app : ''}`);
}

async function removeRule(kind, rule) {
  const list = (App.settings.rules[kind] || []).filter((r) => !sameRule(kind, r, rule));
  await App.setRules({ rules: { ...App.settings.rules, [kind]: list } });
}

function sameRule(kind, a, b) {
  if ((a.app || '') !== (b.app || '')) return false;
  if (kind === 'ips') return a.ip === b.ip && (a.port || 0) === (b.port || 0);
  return a.domain.toLowerCase() === b.domain.toLowerCase();
}

function findRule(kind, app, value, port) {
  return (App.settings.rules[kind] || []).find((r) => (r.app || '') === (app || '') && (kind === 'ips' ? r.ip === value && (r.port || 0) === (port || 0) : r.domain === value));
}

const ipText = (r) => (r.port ? (r.ip.includes(':') ? `[${r.ip}]:${r.port}` : `${r.ip || '*'}:${r.port}`) : r.ip);

// "10.0.0.1", "10.1.1.*", "10.2.0.0/16", "ffff::/104", "[::]:80",
// "[10.1.0.0/16]:80", "*:80", as the Android dialog accepts.
function parseIpRule(text) {
  let t = String(text || '').trim();
  let port = 0;
  let m = /^\[(.+)\]:(\d{1,5})$/.exec(t);
  if (m) {
    t = m[1];
    port = Number(m[2]);
  } else if ((m = /^([^:]*):(\d{1,5})$/.exec(t))) {
    t = m[1] || '*';
    port = Number(m[2]);
  }
  if (port > 65535) return null;
  if (t === '*' || t === '*.*' || t === '*.*.*.*') return port ? { ip: '*', port } : null;
  const v4 = /^(\d{1,3}|\*)(\.(\d{1,3}|\*)){0,3}(\/\d{1,2})?$/;
  const v6 = /^[0-9a-f:.]+(\/\d{1,3})?$/i;
  if (v4.test(t)) {
    const parts = t.split('/')[0].split('.');
    if (parts.some((p) => p !== '*' && Number(p) > 255)) return null;
    if (!t.includes('*') && !t.includes('/') && parts.length !== 4) return null;
    return { ip: t, port };
  }
  if (t.includes(':') && v6.test(t)) return { ip: t, port };
  return null;
}

function validDomain(d) {
  return /^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i.test(String(d || '').trim());
}

// ---------- Firewall ----------

PAGES.firewall = () => {
  const s = App.settings;
  const blocked = blockedNames();
  return screen(
    'Firewall',
    card(
      row({ ico: 'ic_dns_firewall', title: 'Mode', sub: MODES.find((m) => m[0] === s.mode)[1] + (s.mode === 'dns' ? ' · the firewall is off' : ''), right: chevron(), onclick: chooseMode }),
      switchRow({ ico: 'ic_firewall_shield', title: 'Kill switch', sub: 'Block the internet outside AuroraVPN, at once. If the app crashes, the internet stays blocked until you start it again.', value: killSwitchOn(), onchange: (v) => setKillSwitch(v) }),
      switchRow({ ico: 'universal_firewall', title: 'Allow outgoing only', sub: 'Every program may connect out and is added to your allowed apps the moment it does; incoming connections are blocked.', value: !!s.universal.outgoingOnly, onchange: (v) => App.setRules({ universal: { ...App.settings.universal, outgoingOnly: v } }).then(() => App.render()) })
    ),
    sectionLabel('Universal'),
    card(
      row({ ico: 'universal_firewall', title: 'Universal firewall rules', sub: 'Apply firewall rules on all applications based on PC events, for example, when the PC is locked.', right: chevron(), onclick: () => App.go('universal') }),
      row({ ico: 'universal_ip_rule', title: 'IP & Port rules', sub: 'Modify blocked or trusted Domain, IP / Port rules.', right: chevron(), onclick: () => App.go('custom-rules', {}) })
    ),
    sectionLabel('Per app'),
    card(row({ ico: 'ic_ip_address', title: 'Per app IP / Domain rules', sub: 'Modify per app IP / Domain rules.', right: chevron(), onclick: () => App.go('apps') })),
    sectionLabel('Blocked apps'),
    card(
      blocked.length
        ? blocked.map((app) => row({ ico: 'firewall_home_screen', title: app, sub: 'Blocked', right: h('div', { class: 'actions' }, btn('App info', () => App.go('app-info', { app })), btn('Unblock', () => App.block(app, false).then(() => App.render()))) }))
        : h('div', { class: 'pad' }, note('No apps blocked yet. Block them in Apps or from the Logs.'))
    ),
    s.mode === 'dns' ? note('The firewall only sees DNS in DNS mode. Choose "DNS and Firewall" or "Firewall" to firewall apps.', 'bad') : null
  );
};

// ---------- Mode (Android: "Choose mode" on the home screen) ----------

const MODES = [
  ['dns', 'DNS (battery saver)', 'Monitor, block, and encrypt DNS requests.', 'dns_home_screen'],
  ['firewall', 'Firewall', 'Monitor network activity and firewall any app or IP address. DNS goes to your network adapter’s DNS.', 'firewall_home_screen'],
  ['both', 'DNS and Firewall (default)', 'All of the above + bypass Internet censorship.', 'ic_dns_firewall'],
];

async function chooseMode() {
  let pick = App.settings.mode;
  const body = h(
    'div',
    {},
    MODES.map(([id, title, sub, ico]) => {
      const r = h('input', { type: 'radio', name: 'mode', checked: id === pick });
      r.addEventListener('change', () => (pick = id));
      return h('label', { class: 'pick-row' }, icon(ico, 'row-ico'), h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: title }), h('span', { class: 'row-sub', text: sub })), r);
    }),
    App.settings.exit !== 'none' || App.settings.killSwitch ? note('A VPN, proxy or the kill switch needs all traffic in the tunnel, so the firewall stays on with them.') : null
  );
  if (!(await dialog({ title: 'Choose mode', body, ok: 'Save' }))) return;
  if (pick !== App.settings.mode) await save({ mode: pick, full: pick !== 'dns' });
}

// ---------- Universal firewall rules ----------

PAGES.universal = () => {
  const u = App.settings.universal;
  const set = (k) => (v) => App.setRules({ universal: { ...App.settings.universal, [k]: v } });
  return screen(
    'Universal firewall',
    note('Apply firewall rules on all applications based on PC events, for example, firewall when the PC is locked or when a program connects without a DNS lookup.'),
    card(
      switchRow({ ico: 'universal_firewall', title: 'Allow outgoing only', sub: 'Every program may connect out. A program’s first connection is allowed at once and the program is added to Apps as allowed (Bypass Universal), so the rules below never block it. Incoming connections are blocked. Your Block and Isolate choices, IP and domain rules, Lockdown and “PC locked” still apply.', value: !!u.outgoingOnly, onchange: (v) => set('outgoingOnly')(v).then(() => App.render()) })
    ),
    u.outgoingOnly ? note('Allow outgoing only is on: the rules below, except Lockdown and “PC locked”, do not block outgoing connections.') : null,
    card(
      switchRow({ ico: 'ic_device_lock', title: 'Block all apps when the PC is locked', sub: 'While Windows shows the lock screen, no app reaches the internet.', value: u.locked, onchange: set('locked') }),
      switchRow({ ico: 'ic_unknown_app', title: 'Block when source app is unknown', sub: 'Block connections whose program Windows cannot tell (some system services).', value: u.unknown, onchange: set('unknown') }),
      switchRow({ ico: 'ic_udp', title: 'Block UDP except DNS and NTP', sub: 'Blocks QUIC (HTTP/3), most games and calls; DNS (53) and time sync (123) still work.', value: u.udp, onchange: set('udp') }),
      switchRow({ ico: 'ic_network', title: 'Block ICMP (ping)', sub: 'Drops ICMP echo (ping) through the tunnel. On by default to prevent apps from using ICMP as a covert channel. Turn off if you need ping or traceroute.', value: u.icmp, onchange: set('icmp') }),
      switchRow({ ico: 'ic_prevent_dns_leaks', title: 'Block when DNS is bypassed', sub: 'Block connections to IPs that were not looked up through this app’s DNS, like apps with their own DNS-over-HTTPS.', value: u.dnsBypass, onchange: set('dnsBypass') }),
      switchRow({ ico: 'ic_app_info', title: 'Block newly installed apps by default', sub: 'Programs that connect for the first time are blocked until you allow them in Apps.', value: u.newApps, onchange: async (v) => {
        if (v) {
          // everything seen so far counts as known
          const st = await App.port.stats('7d');
          const known = new Set(App.settings.knownApps);
          for (const a of st.allowedApps.concat(st.blockedApps)) known.add(a.name.toLowerCase());
          await App.setRules({ knownApps: [...known].sort(), universal: { ...App.settings.universal, newApps: true } });
        } else set('newApps')(false);
      } }),
      switchRow({ ico: 'ic_http', title: 'Block port 80 (insecure HTTP) traffic', sub: 'Unencrypted websites stop loading; HTTPS is not affected.', value: u.http, onchange: set('http') }),
      switchRow({ ico: 'ic_global_lockdown', title: 'Block all except bypassed apps and IPs', sub: 'Lockdown: only apps set to Bypass or Exclude, and trusted IPs and domains, reach the internet.', value: u.lockdown, onchange: set('lockdown') })
    ),
    note('Android-only rules are left out: block apps not in use, block IPv4 in IPv6, and block on metered networks.'),
    App.settings.mode === 'dns' ? note('These rules need the firewall: choose "DNS and Firewall" or "Firewall" mode.', 'bad') : null
  );
};

// ---------- IP & domain rules ----------

let rulesTab = 'domains';

PAGES['custom-rules'] = ({ app }) => {
  app = app || '';
  const tabs = h(
    'div',
    { class: 'seg-wrap' },
    h('div', { class: 'seg' }, [['domains', 'Domain'], ['ips', 'IP']].map(([id, name]) => h('button', { class: rulesTab === id ? 'on' : '', type: 'button', text: name, onclick: () => {
      rulesTab = id;
      App.render();
    } })))
  );
  const kind = rulesTab;
  const list = (App.settings.rules[kind] || []).filter((r) => (r.app || '') === app);
  const rows = list.map((r) => {
    const text = kind === 'ips' ? ipText(r) : r.domain;
    const tag = h('button', { class: 'tag ' + (r.action === 'block' ? 'bad' : 'good'), type: 'button', title: 'Switch between block and trust', text: r.action === 'block' ? 'B' : 'T', onclick: () => addRule(kind, { ...r, action: r.action === 'block' ? 'trust' : 'block' }).then(() => App.render()) });
    return h(
      'div',
      { class: 'row' },
      tag,
      h('span', { class: 'row-text' }, h('span', { class: 'row-title', text }), h('span', { class: 'row-sub', text: r.action === 'block' ? 'Blocked' : 'Trusted' })),
      h('button', { class: 'info-btn', type: 'button', title: 'Delete', onclick: () => removeRule(kind, r).then(() => App.render()) }, icon('ic_delete'))
    );
  });
  return screen(
    app ? `${app}: rules` : 'IP & domain rules',
    tabs,
    note(kind === 'ips'
      ? 'Trust (allow, skipping the other rules) or block an IP address, subnet or port. Examples: 10.10.10.10, 10.1.1.*, 10.2.0.0/16, ffff::/104, [::]:80, [10.1.0.0/16]:80, *:80'
      : 'Trust or block a domain. *.example.com also covers its subdomains. Rules for all apps also apply to DNS: blocked domains get no answer.'),
    card(rows.length ? rows : h('p', { class: 'empty', text: kind === 'ips' ? 'No IP or Port rules.' : 'No domain rules.' })),
    h('div', { class: 'actions' }, btn(kind === 'ips' ? '+ Add IP / Port rule' : '+ Add domain rule', () => addRuleDialog(kind, app), { primary: true }))
  );
};

async function addRuleDialog(kind, app) {
  const input = field({ label: kind === 'ips' ? 'IP address, subnet or port' : 'Domain', placeholder: kind === 'ips' ? '10.1.1.* or [::]:80' : 'ads.example.com or *.example.com' });
  let action = 'block';
  const radios = h(
    'div',
    { class: 'radio-row' },
    [['block', 'Block'], ['trust', 'Trust']].map(([id, name]) => {
      const r = h('input', { type: 'radio', name: 'act', checked: id === action });
      r.addEventListener('change', () => (action = id));
      return h('label', {}, r, ' ' + name);
    })
  );
  const ok = await dialog({ title: kind === 'ips' ? 'Add IP / Port Rule' : 'Add domain rule', body: h('div', {}, input, radios, app ? note('Only for ' + app) : note('For all apps')), ok: 'Add' });
  if (!ok) return;
  const v = input.input.value.trim();
  if (kind === 'ips') {
    const p = parseIpRule(v);
    if (!p) return toast('Invalid IP address, subnet or port.');
    await addRule('ips', { app: app || undefined, ip: p.ip, port: p.port || undefined, action });
  } else {
    if (!validDomain(v)) return toast('Invalid domain');
    await addRule('domains', { app: app || undefined, domain: v.toLowerCase(), action });
  }
  App.render();
}

// ---------- App info ----------

PAGES['app-info'] = ({ app }) => {
  const a = appRuleOf(app);
  const blocked = a.mode === 'block';
  const tempAllowed = a.allowUntil > Date.now();
  const stats = h('div', {}, note('Loading…'));
  const connsBox = h('div', {}, note('Loading…'));
  const loadConns = async () => {
    const list = App.status ? await App.port.conns(app) : [];
    connsBox.replaceChildren(
      list.length
        ? card(list.slice(0, 50).map((c) => row({ ico: 'ic_network', title: c.domain || c.dst, sub: `${c.proto} ${c.dst}${c.country ? ' · ' + countryName(c.country) : ''} · since ${fmtTime(c.since)}` })))
        : note(App.status ? 'No open connections.' : 'Start protection to see open connections.')
    );
  };
  loadConns();
  PAGE_TICK['app-info'] = () => {};
  App.port.appStats(app).then((st) => {
    const list = (title, items, kind) =>
      h(
        'div',
        {},
        sectionLabel(title),
        items.length
          ? card(items.slice(0, 15).map((d) => {
              const r = kind === 'ips' ? findRule('ips', app, d.name, 0) : findRule('domains', app, d.name);
              return row({ ico: kind === 'ips' ? 'ic_ip_address' : 'dns_home_screen', title: d.name, sub: `${d.n} connection${d.n === 1 ? '' : 's'}${d.blocked ? ` · ${d.blocked} blocked` : ''}${r ? ' · ' + (r.action === 'block' ? 'blocked for this app' : 'trusted for this app') : ''}`, onclick: () => ruleSheet(kind, app, d.name) });
            }))
          : note('Nothing yet.')
      );
    stats.replaceChildren(list('Most contacted domains', st.domains, 'domains'), list('Most contacted IPs', st.ips, 'ips'));
  });

  const chips = h(
    'div',
    { class: 'chips' },
    APP_MODES.map(([id, title, ico, sub]) =>
      h('button', { class: 'chip' + (a.mode === id ? ' on' : ''), type: 'button', title: sub, onclick: () => setAppRule(app, { mode: a.mode === id ? undefined : id, allowUntil: undefined }).then(() => App.render()) }, icon(ico, 'chip-ico'), h('span', { text: title }))
    )
  );
  const mode = APP_MODES.find((m) => m[0] === a.mode);
  return screen(
    'App info',
    h('div', { class: 'app-head' }, avatar(app), h('div', {}, h('h2', { text: app }), h('p', { class: 'row-sub', text: appStatusText(app) }))),
    sectionLabel('Firewall rules for this app'),
    card(
      row({ ico: 'firewall_home_screen', title: 'Allow internet', sub: blocked ? (tempAllowed ? 'Blocked, but allowed for now' : 'Blocked') : 'Allowed', right: toggle(!blocked, (on) => App.block(app, !on).then(() => App.render()), 'Allow ' + app) }),
      h('div', { class: 'pad' }, chips, note(mode ? mode[3] : 'Tap a mode to apply it; tap it again to clear it.')),
      blocked || a.mode === 'isolate'
        ? row({ ico: 'ic_idle_timeout', title: 'Allow for 15 minutes', sub: tempAllowed ? `Allowed until ${fmtTime(a.allowUntil)}` : 'Temporarily allow this app. Auto-reverts after 15 minutes.', right: btn(tempAllowed ? 'Stop' : 'Allow', () => setAppRule(app, { allowUntil: tempAllowed ? undefined : Date.now() + 15 * 60000 }).then(() => App.render())) })
        : null,
      row({ ico: 'ic_ip_address', title: 'IP Rules', sub: countRules('ips', app), right: chevron(), onclick: () => ((rulesTab = 'ips'), App.go('custom-rules', { app })) }),
      row({ ico: 'dns_home_screen', title: 'Domain Rules', sub: countRules('domains', app), right: chevron(), onclick: () => ((rulesTab = 'domains'), App.go('custom-rules', { app })) }),
      switchRow({ ico: 'ic_proxy_white', title: 'Bypass app from all proxies', sub: 'Connect directly, not through the WARP, WireGuard or proxy exit.', value: !!a.noProxy || a.mode === 'exclude', onchange: (v) => setAppRule(app, { noProxy: v }).then(() => App.render()) }),
      a.noProxy || a.mode === 'exclude' ? null : routeRow(app, a)
    ),
    h('div', { class: 'stat-head' }, h('h3', { text: 'Top active connections' }), h('div', { class: 'actions' }, btn('Refresh', loadConns), btn('Close All', async () => {
      const r = await App.port.closeConns(app);
      toast(`Closed ${r.closed || 0} connections`);
      loadConns();
    }))),
    connsBox,
    stats
  );
};

// Per-app route (Android: WireGuard advanced mode, proxy app lists): this
// app leaves through its own WireGuard config or proxy, the rest through
// the main exit.
function routeRow(app, a) {
  const s = App.settings;
  const sel = h('select', { class: 'fld-input', 'aria-label': 'Route' }, h('option', { value: '', text: 'Main VPN / proxy (default)' }));
  if (s.socks && s.socks.host) sel.append(h('option', { value: 'socks', text: `SOCKS5 ${s.socks.host}:${s.socks.port}` }));
  if (s.http && s.http.host) sel.append(h('option', { value: 'http', text: `HTTP ${s.http.host}:${s.http.port}` }));
  sel.value = a.route || '';
  App.port.wg.list().then((wgs) => {
    for (const w of wgs) sel.append(h('option', { value: 'wg:' + w.id, text: 'WireGuard: ' + w.name }));
    sel.value = a.route || '';
  });
  sel.addEventListener('change', async () => {
    await setAppRule(app, { route: sel.value || undefined });
    App.restartNeeded = true;
    toast(App.status ? 'Saved. Restart protection to use the new route.' : 'Saved');
    App.render();
  });
  return row({ ico: 'ic_wireguard_icon', title: 'Route through', sub: 'Send this app through its own WireGuard config or proxy instead of the main one (split tunnel).', right: sel });
}

function countRules(kind, app) {
  const n = (App.settings.rules[kind] || []).filter((r) => (r.app || '') === app).length;
  return n ? `${n} rule${n === 1 ? '' : 's'}` : 'No rules';
}

// Block or trust an IP or domain, for one app (app) or all apps ('').
function ruleSheet(kind, app, value, port) {
  const label = kind === 'ips' ? 'IP' : 'domain';
  const mine = findRule(kind, app, value, port || 0);
  const all = findRule(kind, '', value, port || 0);
  const rule = (forApp, action) => (kind === 'ips' ? { app: forApp || undefined, ip: value, port: port || undefined, action } : { app: forApp || undefined, domain: value, action });
  const acts = [];
  if (app) {
    acts.push(mine && mine.action === 'block' ? null : { text: `Block this ${label} for ${app}`, onclick: () => addRule(kind, rule(app, 'block')).then(() => App.render()) });
    acts.push(mine && mine.action === 'trust' ? null : { text: `Trust this ${label} for ${app}`, onclick: () => addRule(kind, rule(app, 'trust')).then(() => App.render()) });
    if (mine) acts.push({ text: `Remove the rule for ${app}`, onclick: () => removeRule(kind, mine).then(() => App.render()) });
  }
  acts.push(all && all.action === 'block' ? null : { text: `Block this ${label} for all apps`, onclick: () => addRule(kind, rule('', 'block')).then(() => App.render()) });
  acts.push(all && all.action === 'trust' ? null : { text: `Trust this ${label} for all apps`, onclick: () => addRule(kind, rule('', 'trust')).then(() => App.render()) });
  if (all) acts.push({ text: 'Remove the rule for all apps', onclick: () => removeRule(kind, all).then(() => App.render()) });
  sheet({ title: value + (port ? ':' + port : ''), body: h('div', {}, mine ? kv('For ' + app, mine.action === 'block' ? 'Blocked' : 'Trusted') : null, all ? kv('For all apps', all.action === 'block' ? 'Blocked' : 'Trusted') : null), actions: acts });
}

// ---------- log details (Android: connection and DNS log bottom sheets) ----------

function connDetails(e) {
  const app = e.app && e.app !== '?' ? e.app : '';
  const [ip, port] = splitHostPort(e.dst);
  sheet({
    title: e.domain || e.dst,
    body: h(
      'div',
      {},
      app ? h('div', { class: 'app-head small' }, avatar(app), h('div', {}, h('b', { text: app }), h('p', { class: 'row-sub', text: appStatusText(app) }))) : null,
      kv('Time', new Date(e.at).toLocaleString()),
      kv('Destination', `${e.proto} ${e.dst}`),
      e.domain ? kv('Domain', e.domain) : null,
      e.country ? kv('Country', countryName(e.country)) : null,
      kv('Via', e.via),
      kv(e.blocked ? 'Blocked by' : 'Rule', e.rule || (e.blocked ? 'app blocked' : 'none'))
    ),
    actions: [
      app ? { text: 'App info: block, bypass, exclude, isolate this app', primary: true, onclick: () => App.go('app-info', { app }) } : null,
      !app ? { text: 'Universal firewall: block when source app is unknown', onclick: () => App.go('universal') } : null,
      ip ? { text: `Block or trust this IP${app ? ' for this app' : ''}…`, onclick: () => ruleSheet('ips', app, ip, 0) } : null,
      ip && port ? { text: `Block or trust ${ip}:${port}…`, onclick: () => ruleSheet('ips', app, ip, Number(port)) } : null,
      e.domain ? { text: `Block or trust this domain${app ? ' for this app' : ''}…`, onclick: () => ruleSheet('domains', app, e.domain) } : null,
    ],
  });
}

// An open connection from the Logs screen's Active list.
function activeDetails(c) {
  const app = c.app && c.app !== '?' ? c.app : '';
  const [ip, port] = splitHostPort(c.dst);
  sheet({
    title: c.domain || c.dst,
    body: h(
      'div',
      {},
      app ? h('div', { class: 'app-head small' }, avatar(app), h('div', {}, h('b', { text: app }), h('p', { class: 'row-sub', text: appStatusText(app) }))) : null,
      kv('Destination', `${c.proto} ${c.dst}`),
      c.domain ? kv('Domain', c.domain) : null,
      kv('Country', c.country ? countryName(c.country) : 'unknown: a private or unassigned address'),
      kv('Open since', `${new Date(c.since).toLocaleString()} (${fmtAge(Date.now() - c.since)})`),
      kv('Via', c.via || 'direct')
    ),
    actions: [
      {
        text: 'Close this connection',
        primary: true,
        onclick: async () => {
          const r = await App.port.closeConn(c.cid);
          toast(r.closed ? 'Connection closed' : 'It had already closed');
          App.render();
        },
      },
      app ? { text: 'App info: block, bypass, exclude, isolate this app', onclick: () => App.go('app-info', { app }) } : null,
      ip ? { text: `Block or trust this IP${app ? ' for this app' : ''}…`, onclick: () => ruleSheet('ips', app, ip, 0) } : null,
      ip && port ? { text: `Block or trust ${ip}:${port}…`, onclick: () => ruleSheet('ips', app, ip, Number(port)) } : null,
      c.domain ? { text: `Block or trust this domain${app ? ' for this app' : ''}…`, onclick: () => ruleSheet('domains', app, c.domain) } : null,
    ],
  });
}

function dnsDetails(e) {
  const r = findRule('domains', '', e.domain);
  sheet({
    title: e.domain,
    body: h(
      'div',
      {},
      kv('Time', new Date(e.at).toLocaleString()),
      kv('Query type', e.qtype ? `${rrName(e.qtype)} (${e.qtype})` : ''),
      kv('Answer', e.answer || 'no answer'),
      e.country ? kv('Country', countryName(e.country)) : null,
      e.error ? kv('Failed', e.error) : null,
      kv('Resolver', e.via),
      kv('Latency', `${e.latencyMs} ms`),
      kv('DNSSEC', e.secure ? 'verified (AD)' : 'not verified'),
      e.cached ? kv('Cache', 'answered from the DNS booster cache') : null,
      e.blocked || e.rule ? kv('Blocked by', e.rule || 'blocklist') : null,
      r ? kv('Your rule', r.action === 'block' ? 'Blocked' : 'Trusted') : null
    ),
    actions: [
      !r || r.action !== 'block' ? { text: 'Block this domain', primary: true, onclick: () => addRule('domains', { domain: e.domain, action: 'block' }).then(() => App.render()) } : null,
      !r || r.action !== 'trust' ? { text: 'Trust this domain', onclick: () => addRule('domains', { domain: e.domain, action: 'trust' }).then(() => App.render()) } : null,
      r ? { text: 'Remove the rule', onclick: () => removeRule('domains', r).then(() => App.render()) } : null,
      { text: 'Block *.' + baseDomain(e.domain) + ' and its subdomains', onclick: () => addRule('domains', { domain: '*.' + baseDomain(e.domain), action: 'block' }).then(() => App.render()) },
    ],
  });
}

function splitHostPort(s) {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(s || ''));
  return m ? [m[1], m[2]] : [s, ''];
}

function baseDomain(d) {
  const p = String(d || '').split('.');
  return p.slice(-2).join('.');
}

// ---------- allowed DNS record types ----------

function recordTypesSummary() {
  const s = App.settings;
  if (s.dnsTypesAuto) return 'Auto (All types)';
  return s.dnsTypes.map(rrName).join(', ') || 'None: every lookup fails';
}

async function chooseRecordTypes() {
  const s = App.settings;
  let auto = s.dnsTypesAuto;
  const picked = new Set(s.dnsTypes);
  const boxes = h(
    'div',
    { class: 'rr-list' },
    RR_TYPES.map(([id, name, desc]) => {
      const c = h('input', { type: 'checkbox', checked: picked.has(id), disabled: auto });
      c.addEventListener('change', () => (c.checked ? picked.add(id) : picked.delete(id)));
      return h('label', { class: 'pick-row' }, c, h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: name }), h('span', { class: 'row-sub', text: desc })));
    })
  );
  const autoSw = toggle(auto, (v) => {
    auto = v;
    boxes.querySelectorAll('input').forEach((i) => (i.disabled = v));
  }, 'Auto');
  const body = h('div', {}, h('div', { class: 'row' }, h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: 'Auto (All types)' }), h('span', { class: 'row-sub', text: 'Allow every DNS record type.' })), autoSw), boxes);
  if (!(await dialog({ title: 'Allowed DNS record types', body, ok: 'Save' }))) return;
  await App.setRules({ dnsTypesAuto: auto, dnsTypes: [...picked].sort((a, b) => a - b) });
  App.render();
}

// ---------- pause (Android: PauseActivity) ----------

const pauseLeft = () => Math.max(0, (App.settings.pausedUntil || 0) - Date.now());

function fmtLeft(ms) {
  const t = Math.ceil(ms / 1000);
  const m = Math.floor(t / 60);
  return `${String(m).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
}

PAGES.pause = () => {
  const clock = h('div', { class: 'big-timer', text: fmtLeft(pauseLeft()) });
  const adjust = async (mins) => {
    const left = pauseLeft();
    const next = Math.max(1, Math.round(left / 60000) + mins);
    App.settings = await App.port.pause(next);
    clock.textContent = fmtLeft(pauseLeft());
  };
  PAGE_TICK.pause = () => {
    const left = pauseLeft();
    clock.textContent = fmtLeft(left);
    if (!left) App.back();
  };
  const n = blockedNames().length;
  return screen(
    'Paused',
    h(
      'div',
      { class: 'pause-page' },
      brandHeader('taking a nap…'),
      h('p', { class: 'pause-label', text: 'paused' }),
      clock,
      h(
        'div',
        { class: 'timer-row' },
        h('button', { class: 'round-btn', type: 'button', 'aria-label': 'One minute less', onclick: () => adjust(-1) }, icon('ic_minus')),
        h('button', { class: 'round-btn stop', type: 'button', 'aria-label': 'Resume', title: 'Resume', onclick: async () => {
          App.settings = await App.port.pause(0);
          App.back();
        } }, icon('ic_stop')),
        h('button', { class: 'round-btn', type: 'button', 'aria-label': 'One minute more', onclick: () => adjust(1) }, icon('ic_plus'))
      ),
      note(`Note: ${n} blocked app${n === 1 ? '' : 's'} will continue to be firewalled. Other rules, and DNS rules, are off while paused.`)
    )
  );
};

async function pauseProtection() {
  if (!App.status) return toast('Cannot pause: protection is not on');
  if (pauseLeft() <= 0) App.settings = await App.port.pause(15);
  App.go('pause');
}
