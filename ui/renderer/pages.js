// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// The screens behind the bottom navigation and the Configure list, ported
// from the Android app (AuroraVPN / Rethink): Configure, Apps, DNS, Firewall,
// Proxy, WireGuard, Chain mode, Network, Settings, Logs, Stats, About.
// Each PAGES entry returns the screen's element; PAGE_TICK entries refresh
// live data in place on every poll.

'use strict';

const PAGES = {};
const PAGE_TICK = {};

// In the Android app's order.
const DNS_TYPES = [
  { id: 'doh', title: 'DoH', sub: 'DNS-over-HTTPS' },
  { id: 'dnscrypt', title: 'DNSCrypt', sub: 'DNSCrypt' },
  { id: 'proxy', title: 'DNS Proxy', sub: 'Plain DNS to an IP and port' },
  { id: 'rdns', title: 'RethinkDNS', sub: 'Blocklists, by RethinkDNS' },
  { id: 'dot', title: 'DoT', sub: 'DNS-over-TLS' },
  { id: 'odoh', title: 'ODoH', sub: 'Oblivious DNS-over-HTTPS' },
];

const EXIT_LABEL = {
  none: 'Off',
  masque: 'Cloudflare WARP (MASQUE)',
  chain: 'WARP chain',
  warp: 'Cloudflare WARP (WireGuard)',
  wg: 'WireGuard',
  socks: 'SOCKS5 proxy',
  http: 'HTTP(S) proxy',
};

const DEFAULT_SNI = 'consumer-masque.cloudflareclient.com';

// ---------- shared pieces ----------

function topbar(title) {
  return h('div', { class: 'topbar' }, h('button', { class: 'back', type: 'button', 'aria-label': 'Back', onclick: () => App.back(), text: '←' }), h('h1', { text: title }));
}

function screen(title, ...content) {
  return h('div', {}, title ? topbar(title) : null, restartBanner(), ...content);
}

// Settings take effect when the engine starts; offer a restart if it runs.
function restartBanner() {
  if (!App.restartNeeded || !App.status) return null;
  return h(
    'div',
    { class: 'group pad' },
    note('Changes apply when protection restarts.'),
    h('div', { class: 'actions' }, btn('Restart now', () => App.restart(), { primary: true }))
  );
}

async function save(patch, quiet) {
  await App.save(patch);
  if (!quiet) toast(App.status ? 'Saved. Restart protection to apply.' : 'Saved');
  App.render();
}

function switchRow(o) {
  return row({ ico: o.ico, title: o.title, sub: o.sub, right: toggle(o.value, o.onchange, o.title) });
}

function brandHeader(sub) {
  return h('div', { class: 'brand-left' }, h('h1', { class: 'brand-title', text: 'port1897' }), h('p', { class: 'brand-sub', text: sub }));
}

// ---------- Configure (screenshot: "A highly customizable DNS and Firewall") ----------

PAGES.configure = () =>
  h(
    'div',
    { class: 'nav-list' },
    brandHeader('A highly customizable DNS and Firewall'),
    [
      ['apps', 'ic_app_info_accent', 'Apps'],
      ['dns', 'dns_home_screen', 'DNS'],
      ['firewall', 'firewall_home_screen', 'Firewall'],
      ['proxy', 'ic_proxy', 'Proxy'],
      ['network', 'ic_network_tunnel', 'Network'],
      ['settings', 'ic_other_settings', 'Settings'],
      ['logs', 'ic_logs_accent', 'Logs'],
    ].map(([p, ico, title]) => card(row({ ico, title, right: chevron(), onclick: () => App.go(p) })))
  );

// ---------- Apps ----------

let appsFilter = 'all';
PAGES.apps = () => {
  const list = h('div', { class: 'group' }, note('Loading…'));
  const search = field({ placeholder: 'Search apps', oninput: () => fill() });
  let apps = [];
  const filters = h(
    'div',
    { class: 'seg-wrap' },
    h('div', { class: 'seg' }, [['all', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked'], ['rules', 'With rules']].map(([id, name]) => h('button', { class: appsFilter === id ? 'on' : '', type: 'button', text: name, onclick: () => {
      appsFilter = id;
      filters.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.textContent === name));
      fill();
    } })))
  );
  const keep = (a) => {
    const r = appRuleOf(a.name);
    if (appsFilter === 'allowed') return r.mode !== 'block';
    if (appsFilter === 'blocked') return r.mode === 'block';
    if (appsFilter === 'rules') return !!Object.keys(r).length || ['ips', 'domains'].some((k) => App.settings.rules[k].some((x) => x.app === a.name.toLowerCase()));
    return true;
  };
  const fill = () => {
    const q = search.input.value.trim().toLowerCase();
    const rows = apps.filter((a) => (!q || a.name.toLowerCase().includes(q)) && keep(a));
    list.replaceChildren();
    if (!rows.length) {
      list.append(h('p', { class: 'empty', text: App.status ? 'No apps yet. Use the internet and they show up here.' : 'Start protection to see the apps that use the internet.' }));
      return;
    }
    for (const a of rows) {
      const isBlocked = appRuleOf(a.name).mode === 'block';
      list.append(
        h(
          'div',
          { class: 'row clickable' + (isBlocked ? ' blocked' : ''), tabindex: '0', onclick: () => App.go('app-info', { app: a.name.toLowerCase() }), onkeydown: (e) => e.key === 'Enter' && App.go('app-info', { app: a.name.toLowerCase() }) },
          avatar(a.name),
          h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: a.name }), h('span', { class: 'row-sub', text: `${appStatusText(a.name)} · ${a.n || 0} connections · ${fmtBytes(a.rx)} ▼ / ${fmtBytes(a.tx)} ▲` })),
          toggle(!isBlocked, async (allow) => {
            await App.block(a.name, !allow);
            fill();
          }, 'Allow ' + a.name)
        )
      );
    }
  };
  App.port.stats('7d').then((st) => {
    const seen = new Map();
    for (const a of st.allowedApps.concat(st.blockedApps)) {
      const k = a.name.toLowerCase();
      const prev = seen.get(k) || { name: a.name, n: 0, rx: 0, tx: 0 };
      prev.n += a.n || 0;
      prev.rx += a.rx || 0;
      prev.tx += a.tx || 0;
      seen.set(k, prev);
    }
    for (const b of Object.keys(App.settings.rules.apps)) if (!seen.has(b)) seen.set(b, { name: b, n: 0, rx: 0, tx: 0 });
    apps = [...seen.values()].filter((a) => a.name !== '?').sort((x, y) => y.n - x.n || x.name.localeCompare(y.name));
    fill();
  });
  return screen('Apps', note('Switch an app off to block it from the internet. Tap an app for its rules: isolate, bypass, exclude, IP and domain rules. Rules apply immediately.'), filters, h('div', { class: 'field-row' }, search), list);
};

// ---------- DNS ----------

function dnsCurrent() {
  const s = App.settings;
  switch (s.dnsType) {
    case 'system':
      return { name: 'System DNS', kind: 'Your network adapter’s DNS' };
    case 'dot':
      return { name: s.dotName || s.dot, kind: 'DNS over TLS' };
    case 'dnscrypt':
      return { name: s.dnscryptName || 'DNSCrypt', kind: s.dnscryptRelays.length ? 'DNSCrypt via relays' : 'DNSCrypt' };
    case 'odoh':
      return { name: s.odohName || hostOf(s.odoh), kind: s.odohRelay ? 'Oblivious DoH via ' + hostOf(s.odohRelay) : 'Oblivious DoH' };
    case 'proxy':
      return { name: s.dnsProxyName || s.dnsProxy, kind: 'DNS proxy (unencrypted)' };
    case 'rdns':
      return { name: s.dohName || 'RethinkDNS', kind: 'DNS over HTTPS (RethinkDNS)' };
    default:
      return { name: s.dohName || hostOf(s.doh), kind: 'DNS over HTTPS' };
  }
}

PAGES.dns = () => {
  const s = App.settings;
  const cur = dnsCurrent();
  const lat = App.status && App.status.dns.queries ? `(${App.status.dns.avgMs || App.status.dns.lastMs}ms) ` : '';
  const radio = (checked, onchange) => {
    const r = h('input', { type: 'radio', name: 'dnstype', checked });
    r.addEventListener('change', onchange);
    return r;
  };
  return screen(
    'DNS',
    sectionLabel('Type'),
    card(
      h('label', { class: 'pick-row' }, radio(s.dnsType === 'system', () => save({ dnsType: 'system' })), h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: 'System DNS' }), h('span', { class: 'row-sub', text: 'The DNS servers of your Wi-Fi or Ethernet adapter, used through the app' }))),
      h(
        'div',
        { class: 'pick-row' },
        radio(s.dnsType !== 'system', () => save({ dnsType: s.lastOtherType || 'doh' })),
        h('span', { class: 'row-text', onclick: () => App.go('dns-type') }, h('span', { class: 'row-title', text: 'Other DNS' })),
        h('button', { class: 'info-btn', type: 'button', onclick: () => App.go('dns-type') }, chevron())
      ),
      h('div', { class: 'row' }, h('span', { class: 'row-ico' }), h('span', { class: 'row-text' }, h('span', { class: 'row-sub', text: s.dnsType === 'system' ? '' : cur.name })), h('span', { class: 'row-sub', text: s.dnsType === 'system' ? '' : lat + cur.kind }))
    ),
    sectionLabel('Advanced'),
    card(
      switchRow({ ico: 'ic_fav_icon', title: 'Show website icon in DNS logs (experimental)', sub: 'Fetches website icons from duckduckgo.com, which then sees the sites you look up.', value: s.favicons, onchange: (v) => save({ favicons: v }, true) }),
      switchRow({ ico: 'ic_auto_start', title: 'DNS booster', sub: 'Coalesce requests, cache responses, resilient error handling. Cached answers skip the DNSSEC check.', value: s.dnsCache, onchange: (v) => save({ dnsCache: v }) }),
      switchRow({ ico: 'ic_prevent_dns_leaks', title: 'Enable DNSSEC', sub: 'Block DNS answers with forged or bogus (bogon) addresses: a public site pointing at a private, loopback or test address is a sign of DNS poisoning. Verified answers show DNSSEC ✓ in the logs.', value: s.dnssec, onchange: (v) => save({ dnssec: v }) }),
      switchRow({ ico: 'ic_prevent_dns_proxy', title: 'Never proxy DNS', sub: 'Do not send DNS over the WireGuard, WARP, SOCKS5 or HTTP proxy; it still goes encrypted to your DNS server', value: s.dnsDirect, onchange: (v) => save({ dnsDirect: v }) }),
      switchRow({ ico: 'ic_prevent_dns_leaks', title: 'Prevent DNS leaks', sub: 'Force every DNS lookup on this PC through the app, even when another app or VPN sets its own DNS', value: s.nrpt, onchange: (v) => save({ nrpt: v }) }),
      switchRow({ ico: 'ic_use_fallback_bypass', title: 'Use fallback DNS', sub: 'When your chosen DNS fails, answer with the fallback DNS (Network → Choose fallback DNS)', value: s.dnsFallback, onchange: (v) => save({ dnsFallback: v }) }),
      switchRow({ ico: 'ic_undelegated_domain', title: 'Use System DNS for undelegated domains', sub: 'Use System DNS for undelegated domains like .lan, .internal, etc.', value: s.undelegated, onchange: (v) => save({ undelegated: v }) }),
      row({ ico: 'ic_filter', title: 'Allowed DNS record types', sub: 'Select which DNS resource record types to allow. Now: ' + recordTypesSummary(), right: chevron(), onclick: chooseRecordTypes })
    ),
    sectionLabel('Blocklists'),
    blocklistsCard(),
    sectionLabel('Rules'),
    card(row({ ico: 'dns_home_screen', title: 'Domain rules', sub: countRules('domains', '') + ' for all apps. Blocked domains get no DNS answer.', right: chevron(), onclick: () => ((rulesTab = 'domains'), App.go('custom-rules', {})) }))
  );
};

PAGES['dns-type'] = () => {
  const cur = App.settings.dnsType;
  return screen(
    'Other DNS',
    h(
      'div',
      { class: 'type-grid' },
      DNS_TYPES.map((t) =>
        h('button', { class: 'type-card' + (cur === t.id ? ' sel' : ''), type: 'button', onclick: () => App.go('dns-list', { type: t.id }) }, h('b', { text: t.title }), h('small', { text: t.sub }))
      )
    )
  );
};

// Settings patch that selects DNS entry e of type.
function dnsPatch(type, e) {
  switch (type) {
    case 'dot':
      return { dnsType: 'dot', dot: e.url, dotName: e.name, lastOtherType: 'dot' };
    case 'dnscrypt':
      return { dnsType: 'dnscrypt', dnscrypt: e.url, dnscryptName: e.name, lastOtherType: 'dnscrypt' };
    case 'odoh':
      return { dnsType: 'odoh', odoh: e.url, odohRelay: e.relay || '', odohName: e.name, lastOtherType: 'odoh' };
    case 'proxy':
      return { dnsType: 'proxy', dnsProxy: e.url, dnsProxyName: e.name, lastOtherType: 'proxy' };
    default:
      return { dnsType: type, doh: e.url, dohIps: e.ips || '', dohName: e.name, lastOtherType: type };
  }
}

function dnsSelected(type, e) {
  const s = App.settings;
  if (s.dnsType !== type) return false;
  if (type === 'dot') return s.dot === e.url;
  if (type === 'dnscrypt') return s.dnscrypt === e.url;
  if (type === 'odoh') return s.odoh === e.url && (s.odohRelay || '') === (e.relay || '');
  if (type === 'proxy') return s.dnsProxy === e.url;
  return s.doh === e.url;
}

PAGES['dns-list'] = ({ type }) => {
  const meta = DNS_TYPES.find((t) => t.id === type);
  const custom = (App.settings.customDns || {})[type] || [];
  const entries = (DNS_LISTS[type] || []).concat(custom.map((c) => ({ ...c, custom: true })));
  const list = card(
    entries.map((e) => {
      const sel = dnsSelected(type, e);
      const desc = h('span', { class: 'row-sub', hidden: true, text: e.desc || e.url });
      const box = h('input', { type: 'checkbox', checked: sel, 'aria-label': 'Use ' + e.name });
      box.addEventListener('change', () => (box.checked ? save(dnsPatch(type, e)) : (box.checked = true)));
      return h(
        'div',
        { class: 'pick-row' },
        h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: e.name }), sel ? h('span', { class: 'row-sub', text: App.status ? 'Connected' : 'Selected' }) : null, desc),
        e.custom
          ? h('button', { class: 'info-btn', type: 'button', title: 'Delete', onclick: () => removeCustomDns(type, e) }, icon('ic_delete'))
          : null,
        h('button', { class: 'info-btn', type: 'button', title: 'Details', onclick: () => (desc.hidden = !desc.hidden) }, icon('ic_info_white_16')),
        box
      );
    })
  );
  return screen(
    meta ? meta.sub : 'DNS',
    type === 'rdns' ? card(row({ ico: 'ic_configure', title: 'Configure 195+ blocklists', sub: App.settings.remoteFlags.length ? `${App.settings.remoteFlags.length} blocklists on the RethinkDNS server` : 'Pick what the RethinkDNS server blocks for you', right: chevron(), onclick: () => App.go('blocklists', { kind: 'remote' }) })) : null,
    type === 'proxy' ? note('Plain DNS is not encrypted: your network can see and change it. Use it for a local DNS forwarder, like Tor’s DNSPort.', 'bad') : null,
    type === 'odoh' ? note('Oblivious DoH: a relay hides your IP address from the DNS server, and the server’s encryption hides your lookups from the relay. Add a server with a relay below; without one, queries go to the server directly.') : null,
    list,
    type === 'dnscrypt' ? relaysCard() : null,
    h('div', { class: 'actions' }, btn('+ Add custom', () => addCustomDns(type)))
  );
};

// DNSCrypt relays (Android: DNSCrypt relays dialog): anonymized DNSCrypt
// sends queries through a relay, which never sees what you look up.
function relaysCard() {
  const s = App.settings;
  const custom = (s.customDns || {}).relay || [];
  const all = DNSCRYPT_RELAYS.concat(custom.map((c) => ({ ...c, custom: true })));
  return h(
    'div',
    {},
    sectionLabel('Relays'),
    note('Anonymized DNSCrypt: queries go through a relay, so the DNS server does not see your IP address. Pick one or more.'),
    card(
      all.map((r) => {
        const c = h('input', { type: 'checkbox', checked: s.dnscryptRelays.includes(r.url), 'aria-label': r.name });
        c.addEventListener('change', () => {
          const set = new Set(App.settings.dnscryptRelays);
          if (c.checked) set.add(r.url);
          else set.delete(r.url);
          save({ dnscryptRelays: [...set] });
        });
        return h('label', { class: 'pick-row' }, h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: r.name }), h('span', { class: 'row-sub', text: r.custom ? 'Custom relay' : 'DNSCrypt relay' })), c);
      })
    ),
    h('div', { class: 'actions' }, btn('+ Add relay', async () => {
      const name = field({ label: 'Name', placeholder: 'My relay' });
      const url = field({ label: 'Relay stamp', placeholder: 'sdns://g...' });
      if (!(await dialog({ title: 'Add DNSCrypt relay', body: h('div', {}, name, url), ok: 'Add' }))) return;
      const v = url.input.value.trim();
      if (!v.startsWith('sdns://')) return toast('A relay stamp starts with sdns://');
      const list = { ...(App.settings.customDns || {}) };
      list.relay = (list.relay || []).concat({ name: name.input.value.trim() || 'Relay', url: v });
      await save({ customDns: list, dnscryptRelays: [...new Set(App.settings.dnscryptRelays.concat(v))] });
    }))
  );
}

async function addCustomDns(type) {
  const name = field({ label: 'Name', placeholder: 'My DNS' });
  const url = field({
    label: type === 'dnscrypt' ? 'Stamp' : type === 'proxy' ? 'IP address and port' : type === 'odoh' ? 'Server (target) URL' : 'URL',
    placeholder: type === 'dot' ? 'tls://dns.example.com' : type === 'dnscrypt' ? 'sdns://...' : type === 'proxy' ? '9.9.9.9:53' : 'https://dns.example.com/dns-query',
  });
  const ips = field({ label: 'IP addresses (optional)', placeholder: '1.2.3.4,5.6.7.8' });
  const relay = field({ label: 'Relay URL (optional)', placeholder: 'https://odoh-relay.example.com/proxy' });
  const ok = await dialog({ title: 'Add DNS', body: h('div', {}, name, url, type === 'doh' || type === 'rdns' ? ips : null, type === 'odoh' ? relay : null), ok: 'Add' });
  if (!ok) return;
  const e = { name: name.input.value.trim() || url.input.value.trim(), url: url.input.value.trim(), ips: ips.input.value.trim(), relay: relay.input.value.trim(), desc: 'Custom' };
  const valid = type === 'dot' ? /^(tls:\/\/)?[a-z0-9.-]+(:\d+)?$/i.test(e.url) : type === 'dnscrypt' ? e.url.startsWith('sdns://') : type === 'proxy' ? /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/.test(e.url) : /^https:\/\/\S+$/.test(e.url) && (!e.relay || /^https:\/\/\S+$/.test(e.relay));
  if (!valid) return toast('That address does not look right');
  const all = { ...(App.settings.customDns || {}) };
  all[type] = (all[type] || []).concat(e);
  await save({ customDns: all, ...dnsPatch(type, e) });
}

async function removeCustomDns(type, e) {
  const all = { ...(App.settings.customDns || {}) };
  all[type] = (all[type] || []).filter((c) => c.url !== e.url);
  await save({ customDns: all }, true);
}

// ---------- Proxy (WARP, WireGuard, SOCKS5, HTTP) ----------

function warpStatusText(reg) {
  const s = App.settings;
  if (App.status && s.exit === 'masque') return 'Connected · routing via Cloudflare WARP';
  if (!reg.warp1.registered) return 'Not registered';
  return 'Registered · switch on to connect';
}

PAGES.proxy = () => {
  const s = App.settings;
  const warpCard = h('div', { class: 'group pad' }, note('Loading…'));
  App.port.usque.status().then((reg) => {
    const sni = field({ label: 'SNI (ClientHello)', value: s.warpSni, placeholder: DEFAULT_SNI });
    warpCard.replaceChildren(
      h(
        'div',
        { class: 'hop-head' },
        icon('ic_vpn', 'row-ico'),
        h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: 'WARP Tunnel' }), h('span', { class: 'row-sub', text: warpStatusText(reg) })),
        toggle(s.exit === 'masque', async (on) => {
          if (on && !reg.warp1.registered) {
            toast('Register with WARP first');
            return App.render();
          }
          await save({ exit: on ? 'masque' : 'none' });
        }, 'WARP Tunnel')
      ),
      btn('Chain mode (WARP → WG → WARP)', () => App.go('chain'), { wide: true, cls: 'big' }),
      h('div', { class: 'field-row' }, sni, btn('Save', () => saveSni('warpSni', sni.input.value)), btn('Reset', () => saveSni('warpSni', ''))),
      h('div', { class: 'actions center' }, btn(reg.warp1.registered ? 'Re-register with WARP' : 'Register with WARP', () => registerWarp('warp1', reg.warp1.registered))),
      expander('Advanced: config and usque flags', () => advancedWarp('warp1', 'masqueFlags', '-i 1350 --http2-fallback-after 2')),
      switchRow({ ico: 'ic_auto_start', title: 'Auto-disable after 11 hours', sub: 'Turns WARP off on its own if it has been running continuously for 11 hours straight.', value: s.warpAutoDisable, onchange: (v) => save({ warpAutoDisable: v }, true) })
    );
  });

  const live = h('div', {});
  const drawLive = async () => {
    const list = App.status ? await App.port.proxies() : [];
    live.replaceChildren(
      list.length
        ? card(
            list.map((p) => {
              const ok = p.status === 'connected' || p.status === 'up';
              const seen = p.lastOK > 1e12 ? ` · last handshake ${Math.max(0, Math.round((Date.now() - p.lastOK) / 1000))}s ago` : '';
              return h(
                'div',
                { class: 'row' },
                dot(ok ? 'on' : p.status === 'idle' ? 'warn' : 'off'),
                h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: p.name }), h('span', { class: 'row-sub', text: `${p.status}${seen} · ${fmtBytes(p.rx)} ▼ / ${fmtBytes(p.tx)} ▲` }))
              );
            })
          )
        : ''
    );
  };
  drawLive();
  PAGE_TICK.proxy = drawLive;
  return screen(
    'Proxy',
    live,
    warpCard,
    card(row({ ico: 'ic_wireguard_icon', title: 'Setup WireGuard', sub: 'WireGuard as a proxy.', right: chevron(), onclick: () => App.go('wireguard') })),
    sectionLabel('Other'),
    card(
      row({ ico: 'ic_socks5', title: 'Setup SOCKS5 Proxy', sub: s.exit === 'socks' ? `On: ${s.socks.host}:${s.socks.port}` : 'Forward connections to SOCKS5 endpoint.', onclick: () => proxyDialog('socks'), right: toggle(s.exit === 'socks', (on) => (on ? proxyDialog('socks') : save({ exit: 'none' }))) }),
      row({ ico: 'ic_http', title: 'Setup HTTP(S) CONNECT Proxy', sub: s.exit === 'http' ? `On: ${s.http.host}:${s.http.port}` : 'Forward connections to HTTP(S) CONNECT endpoint.', onclick: () => proxyDialog('http'), right: toggle(s.exit === 'http', (on) => (on ? proxyDialog('http') : save({ exit: 'none' }))) })
    ),
    note('One VPN or proxy is used at a time: switching one on switches the others off.')
  );
};

async function saveSni(key, v) {
  v = v.trim();
  if (v && !/^[a-z0-9.-]+$/i.test(v)) return toast('Invalid SNI: letters, digits, dots and hyphens only');
  await save({ [key]: v }, true);
  toast(v ? `SNI saved: ${v}` : `SNI reset to ${DEFAULT_SNI}`);
}

async function registerWarp(which, already) {
  if (already) {
    const ok = await confirmDialog(
      'Re-register',
      'This identity is already registered. Registering again requests a brand new key from Cloudflare and discards the current one.',
      'Re-register'
    );
    if (!ok) return;
  }
  toast('Registering…');
  const r = await App.port.usque.register(which, !!already);
  toast(r.ok ? 'Registered' : 'Registration failed. Cloudflare may rate-limit a second registration; see the log.');
  App.render();
}

// Advanced: identity file editor + extra usque flags, as on Android.
function advancedWarp(which, flagsKey, example) {
  const s = App.settings;
  const cfg = field({ label: which === 'warp2' ? 'WARP2 identity (warp2.json)' : 'WARP identity (warp1.json)', multiline: true, mono: true });
  const load = () => App.port.usque.readConfig(which).then((t) => (cfg.input.value = t || ''));
  load();
  const flags = field({ label: 'usque flags', value: s[flagsKey], placeholder: example, mono: true });
  const eff = h('p', { class: 'cmd' });
  const showEff = () => (eff.textContent = 'Effective (next start): ' + (flags.input.value.trim() || '(none)'));
  flags.input.addEventListener('input', showEff);
  showEff();
  return [
    note('Holds the private key of this WARP identity: keep it private. Changes apply when protection restarts.'),
    cfg,
    h(
      'div',
      { class: 'actions' },
      btn('Reload', load),
      btn('Save', async () => {
        const r = await App.port.usque.saveConfig(which, cfg.input.value);
        toast(r.ok ? 'Saved' : r.error);
      })
    ),
    note('Advanced. Space-separated usque flags added after the fixed core. {sni} is the SNI above. Not allowed: -b -p -u -w -c --wg --exit-config.'),
    flags,
    eff,
    h(
      'div',
      { class: 'actions' },
      btn('Reset', async () => {
        flags.input.value = '';
        showEff();
        await save({ [flagsKey]: '' }, true);
      }),
      btn('Save', async () => {
        const bad = badFlag(flags.input.value);
        if (bad) return toast(`Not saved: ${bad} belongs to the fixed core`);
        await save({ [flagsKey]: flags.input.value.trim() });
      })
    ),
  ];
}

function badFlag(text) {
  const core = ['-b', '--bind', '-p', '--port', '-u', '--username', '-w', '--password', '-c', '--config', '--wg', '--exit-config'];
  for (const a of text.split(/\s+/)) {
    const n = a.split('=')[0];
    if (core.includes(n)) return n;
    if (['socks', 'chain', 'register'].includes(a)) return a;
  }
  return '';
}

async function proxyDialog(kind) {
  const cur = App.settings[kind];
  const host = field({ label: 'Host or IP', value: cur.host, placeholder: '127.0.0.1' });
  const port = field({ label: 'Port', value: String(cur.port || ''), type: 'number' });
  const user = field({ label: 'Username (optional)', value: cur.user });
  const pass = field({ label: 'Password (optional)', value: cur.pass, type: 'password' });
  const ok = await dialog({ title: kind === 'socks' ? 'SOCKS5 proxy' : 'HTTP(S) CONNECT proxy', body: h('div', {}, host, port, user, pass), ok: 'Use this proxy' });
  if (!ok) return App.render();
  const p = { host: host.input.value.trim(), port: Number(port.input.value), user: user.input.value, pass: pass.input.value };
  if (!p.host || !(p.port > 0 && p.port < 65536)) {
    toast('Enter a host and a port');
    return App.render();
  }
  await save({ [kind]: p, exit: kind });
}

// ---------- WireGuard ----------

PAGES.wireguard = () => {
  const s = App.settings;
  const list = h('div', {}, note('Loading…'));
  App.port.wg.list().then((items) => {
    list.replaceChildren(
      card(
        row({
          ico: 'ic_wireguard_icon',
          title: 'Cloudflare WARP (free)',
          sub: 'WireGuard to Cloudflare. Registers an anonymous account on first use.',
          right: toggle(s.exit === 'warp', (on) => save({ exit: on ? 'warp' : 'none' })),
        })
      ),
      items.length
        ? card(
            items.map((w) =>
              row({
                ico: 'ic_wireguard_icon',
                title: w.name,
                sub: (w.endpoint ? `Endpoint ${w.endpoint}` : 'WireGuard') + wgUsers(w.id),
                onclick: () => App.go('wg-edit', { id: w.id }),
                right: toggle(s.exit === 'wg' && s.wgActive === w.id, (on) => save(on ? { exit: 'wg', wgActive: w.id } : { exit: 'none' })),
              })
            )
          )
        : h('p', { class: 'empty', text: 'No WireGuard VPNs. Add some to get started.' })
    );
  });

  const menu = h(
    'div',
    { class: 'fab-area' },
    h('div', { class: 'fab-items', hidden: true },
      h('button', { class: 'fab-item', type: 'button', onclick: importWg }, 'Import'),
      h('button', { class: 'fab-item', type: 'button', onclick: () => App.go('wg-edit', {}) }, 'Create')
    ),
    h('button', { class: 'fab', type: 'button', 'aria-label': 'Add', text: '+', onclick: (e) => {
      const items = menu.querySelector('.fab-items');
      items.hidden = !items.hidden;
      items.style.display = items.hidden ? 'none' : 'flex';
      items.style.flexDirection = 'column';
      items.style.alignItems = 'flex-end';
      items.style.gap = '14px';
    } })
  );
  return screen('WireGuard', list, note('Free WireGuard configs: Proton VPN’s free plan and many providers let you download a .conf file.'), note('Split tunnel: to send only some apps through a config, open the app (Apps → app → Route through). The switch here makes a config the main VPN for every other app.'), menu);
};

// Apps routed through WireGuard config id (App info → Route through).
function wgUsers(id) {
  const users = Object.entries(App.settings.rules.apps)
    .filter(([, r]) => r.route === 'wg:' + id)
    .map(([n]) => n);
  return users.length ? ` · used by ${users.join(', ')}` : '';
}

async function importWg() {
  const r = await App.port.wg.importFile();
  if (r && r.error) return toast(r.error);
  if (r && r.id) {
    toast('Imported ' + r.name);
    App.render();
  }
}

PAGES['wg-edit'] = ({ id }) => {
  const name = field({ label: 'Name', placeholder: 'My WireGuard' });
  const text = field({ label: 'Config (.conf)', multiline: true, mono: true, placeholder: '[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nEndpoint = ...\nAllowedIPs = 0.0.0.0/0' });
  if (id) App.port.wg.get(id).then((w) => {
    if (w) {
      name.input.value = w.name;
      text.input.value = w.text;
    }
  });
  return screen(
    id ? 'Edit WireGuard' : 'Create WireGuard',
    h('div', { class: 'group pad' }, name, text),
    h(
      'div',
      { class: 'actions' },
      id ? btn('Delete', async () => {
        if (!(await confirmDialog('Delete', 'Delete this WireGuard config?', 'Delete'))) return;
        await App.port.wg.remove(id);
        if (App.settings.wgActive === id) await App.save({ exit: App.settings.exit === 'wg' ? 'none' : App.settings.exit, wgActive: '' });
        App.back();
      }) : null,
      btn('Save', async () => {
        const r = await App.port.wg.save({ id, name: name.input.value.trim(), text: text.input.value });
        if (r.error) return toast(r.error);
        toast('Saved');
        App.back();
      }, { primary: true })
    )
  );
};

// ---------- Chain mode (WARP1 → wg0 → WARP2) ----------

function wgMtu(text) {
  const m = /^\s*MTU\s*=\s*(\d+)/im.exec(text || '');
  return m ? Number(m[1]) : 0;
}

function flagVal(flags, names, dflt) {
  const f = (flags || '').split(/\s+/);
  for (let i = 0; i < f.length; i++) {
    const [n, v] = f[i].split('=');
    if (names.includes(n)) return Number(v !== undefined ? v : f[i + 1]) || dflt;
  }
  return dflt;
}

PAGES.chain = () => {
  const s = App.settings;
  const root = h('div', {}, note('Loading…'));
  App.port.usque.status().then((reg) => {
    const ready = reg.warp1.registered && reg.warp2.registered && reg.wg0.present;
    const on = s.exit === 'chain';
    const connected = on && !!App.status;
    const m1 = flagVal(s.warp1Flags, ['-m', '--mtu'], 1280);
    const wgm = reg.wg0.present ? Math.min(flagVal(s.wgFlags, ['--wg-mtu'], 0) || wgMtu(reg.wg0.text) || m1 - 60, m1 - 60) : null;
    const m2 = flagVal(s.warp2Flags, ['--exit-mtu'], 1280);
    const statusText = connected ? 'Connected' : ready ? 'Ready — not connected' : 'Setup incomplete';
    const exitOut = h('p', { class: 'cmd', text: 'Not checked yet' });

    const hop = (title, sub, registered, which, sniKey, sniLabel, flagsKey, flagsExample) => {
      const sni = field({ label: sniLabel, value: s[sniKey], placeholder: DEFAULT_SNI });
      return h(
        'div',
        { class: 'hop' },
        h('div', { class: 'hop-head' }, dot(registered ? 'on' : 'off'), h('h2', { text: title })),
        note(sub),
        h('div', { class: 'hop-status' }, h('span', { text: registered ? 'Registered' : 'Not registered' }), btn(registered ? 'Re-register' : which === 'warp1' ? 'Register WARP1' : 'Register WARP2', () => registerWarp(which, registered))),
        h('div', { class: 'field-row' }, sni, btn('Save', () => saveSni(sniKey, sni.input.value)), btn('Reset', () => saveSni(sniKey, ''))),
        expander('Advanced: config and usque flags', () => advancedWarp(which, flagsKey, flagsExample))
      );
    };

    const wgText = field({ label: 'wg0.conf', multiline: true, mono: true, value: reg.wg0.text });
    const wgHop = h(
      'div',
      { class: 'hop' },
      h('div', { class: 'hop-head' }, dot(reg.wg0.present ? 'on' : 'off'), h('h2', { text: 'wg0 · WireGuard' })),
      note('Gives the new location. Runs inside WARP1.'),
      h('p', { text: reg.wg0.present ? 'wg0.conf loaded' : 'No wg0.conf yet' }),
      wgText,
      note('Paste your wg0.conf (plain WireGuard; AmneziaWG is not supported)'),
      h(
        'div',
        { class: 'actions' },
        btn('Import .conf', async () => {
          const r = await App.port.usque.importWg0();
          if (r.error) return toast(r.error);
          if (r.ok) {
            toast('wg0.conf imported');
            App.render();
          }
        }),
        btn('Reload', () => App.render()),
        btn('Save', async () => {
          const r = await App.port.usque.saveWg0(wgText.input.value);
          toast(r.ok ? 'wg0.conf saved' : r.error);
          if (r.ok) App.render();
        })
      ),
      expander('Advanced: usque flags', () => {
        const f = field({ label: 'wg0 flags (only --wg-*)', value: s.wgFlags, placeholder: '--wg-mtu 0 --wg-keepalive 25', mono: true });
        return [
          note('Only --wg-* flags. --wg-mtu 0 uses the MTU from wg0.conf; usque always caps it to WARP1 MTU − 60. --wg-keepalive applies when wg0.conf sets none.'),
          f,
          h('div', { class: 'actions' }, btn('Reset', () => save({ wgFlags: '' })), btn('Save', () => {
            if (f.input.value.split(/\s+/).some((a) => a && a.startsWith('-') && !a.startsWith('--wg-'))) return toast('Not saved: only --wg-* flags here');
            save({ wgFlags: f.input.value.trim() });
          })),
        ];
      })
    );

    const coreCmd = 'usque -c warp1.json chain --wg wg0.conf --exit-config warp2.json -b 127.0.0.1 -p {random} -u {random} -w {random}';
    const extra = chainFlags(s);
    const logBox = h('pre', { class: 'logbox', text: 'Loading…' });
    const loadLog = () => App.port.engineLog('usque').then((t) => (logBox.textContent = t || 'Empty. Connect the chain to see usque’s output here.'));
    loadLog();

    root.replaceChildren(
      note('Nest three tunnels in one process: WARP1 hides you from your ISP, a WireGuard hop gives a new location, and WARP2 washes it into a Cloudflare IP. Set up each step, then connect.'),
      h(
        'div',
        { class: 'hop' },
        h(
          'div',
          { class: 'hop-head' },
          dot(connected ? 'on' : ready ? 'warn' : 'off'),
          h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: statusText }), h('span', { class: 'row-sub', text: on ? 'Chain enabled' : 'Chain disabled' })),
          toggle(on, (v) => {
            if (v && !ready) {
              toast('Finish steps 1–3 first');
              return App.render();
            }
            save({ exit: v ? 'chain' : 'none' });
          }, 'Chain enabled')
        ),
        h('p', { class: 'cmd', text: `MTU: WARP1 ${m1} → wg0 ${wgm || '—'} → WARP2 ${m2} (HTTP/2)` }),
        btn(connected ? 'Disconnect' : 'Connect chain', async () => {
          if (connected) return App.stopEngine();
          if (!ready) return toast('Finish steps 1–3 first');
          await App.save({ exit: 'chain' });
          App.startEngine();
        }, { wide: true, cls: 'big', disabled: !ready && !connected }),
          h('div', { class: 'actions' }, btn('Check exit IP', async () => {
          if (!App.status) return (exitOut.textContent = 'Connect first');
          exitOut.textContent = 'Asking Cloudflare…';
          const t = await App.port.checkExit();
          exitOut.textContent = t.error
            ? `• failed: ${t.error}`
            : `• ip ${t.ip} · loc ${t.loc} · colo ${t.colo} · warp=${t.warp}\n${t.warp === 'on' || t.warp === 'plus' ? 'Traffic leaves through Cloudflare WARP. With the chain, colo and loc should match the wg0 server’s location, not yours.' : 'warp=off: traffic is not leaving through WARP.'}`;
        }, { wide: true })),
        note('Asks Cloudflare what it sees from this PC. Through the chain, the colo (Cloudflare data center) should be near your wg0 server, not near you.'),
        exitOut
      ),
      hop('WARP1 · entry', 'Hides you from your ISP. The only hop on your network: its SNI is what the ISP sees.', reg.warp1.registered, 'warp1', 'warpSni', 'SNI (ClientHello, seen by your ISP)', 'warp1Flags', '-m 1280 -i 1350 -P 443 -k 30s -r 1s --http2-fallback-after 2'),
      wgHop,
      hop('WARP2 · exit', 'Cloudflare egress IP. Runs inside wg0, over HTTP/2 because QUIC does not fit there.', reg.warp2.registered, 'warp2', 'exitSni', 'Exit SNI (inside wg0, hidden from your ISP)', 'warp2Flags', '--exit-transport auto --exit-mtu 1280 --exit-connect-port 443'),
      h('div', { class: 'hop' }, h('h2', { text: 'usque command' }), note('Fixed core (the VPN tunnel is routed to this SOCKS port; port and password are new every start):'), h('p', { class: 'cmd', text: coreCmd }), note('Full command (next start):'), h('p', { class: 'cmd', text: coreCmd + (extra ? ' ' + extra : '') })),
      h(
        'div',
        { class: 'hop' },
        h('h2', { text: 'Verbose log' }),
        logBox,
        h('div', { class: 'actions' }, btn('Refresh', loadLog), btn('Clear', async () => {
          await App.port.clearLog();
          loadLog();
        }), btn('Copy', () => App.port.copy(logBox.textContent).then(() => toast('Copied'))))
      )
    );
  });
  return screen('Chain mode (WARP → WG → WARP)', root);
};

// Mirrors the main process's chain flag assembly, for the preview.
function chainFlags(s) {
  const out = [];
  if (s.warpSni) out.push('-s', s.warpSni);
  if (s.warp1Flags) out.push(s.warp1Flags.replaceAll('{sni}', s.warpSni || DEFAULT_SNI));
  if (s.wgFlags) out.push(s.wgFlags);
  if (s.exitSni) out.push('--exit-sni', s.exitSni);
  if (s.warp2Flags) out.push(s.warp2Flags.replaceAll('{exit_sni}', s.exitSni || DEFAULT_SNI));
  return out.join(' ');
}

// ---------- Network ----------

PAGES.network = () => {
  const s = App.settings;
  return screen(
    'Network',
    sectionLabel('Network'),
    card(
      switchRow({ ico: 'ic_firewall_shield', title: 'Kill switch', sub: 'Block the internet outside the app. If the app crashes, the internet stays blocked until you start it again or release the kill switch below.', value: s.killSwitch, onchange: (v) => save({ killSwitch: v }) }),
      switchRow({ ico: 'ic_private_network', title: 'Do not route Private IPs', sub: 'Let LAN, link-local and multicast traffic (printers, file shares, casting) through the kill switch.', value: s.allowLan, onchange: (v) => save({ allowLan: v }) }),
      row({ ico: 'ic_loopback', title: 'Release kill switch', sub: 'Removes a kill switch left behind by a crash. Asks Windows for permission.', right: chevron(), onclick: async () => {
        const r = await App.port.cleanup();
        toast(r.ok ? 'Released. The internet works without the app again.' : r.error);
      } })
    ),
    card(
      row({ ico: 'ic_fallback', title: 'Choose fallback DNS', sub: `In rare cases when your chosen DNS can't be reached, fallback DNS is used. Now: ${s.fallbackName}`, right: chevron(), onclick: chooseFallback }),
      row({ ico: 'ic_connectivity_checks', title: 'Ping test', sub: 'Check what this PC can reach: an IP, a DNS lookup and a website.', right: chevron(), onclick: () => App.go('ping') }),
      row({ ico: 'ic_ip_network', title: 'Choose IP version', sub: 'IPv4 (IPv6 support comes later; IPv6 is blocked while the kill switch is on)', right: chevron(), onclick: () => toast('IPv4 only for now') })
    ),
    sectionLabel('Anti-censorship'),
    card(
      row({ ico: 'ic_firewall_shield', title: 'Dial strategy', sub: 'How connections leave this PC. Splitting the first packet or the TLS ClientHello (which carries the site name) gets past many DPI firewalls that block sites by name. Off on Android.', right: selectBox(DIAL_STRATEGIES, s.dialStrategy, (v) => save({ dialStrategy: v }), 'Dial strategy') }),
      row({ ico: 'ic_refresh_white', title: 'Retry', sub: 'When a connection fails: retry it as-is, or retry with a split.', right: selectBox(DIAL_RETRIES, s.dialRetry, (v) => save({ dialRetry: v }), 'Retry') })
    ),
    note('Also against censorship: WARP over MASQUE with a custom SNI (Proxy → WARP Tunnel), and the WARP chain.'),
    sectionLabel('TCP'),
    card(
      switchRow({ ico: 'ic_tcp_keep_alive', title: 'Shorter TCP keep alive', sub: 'Quickly close TCP sockets with no recent activity.', value: s.tcpKeepAlive, onchange: (v) => save({ tcpKeepAlive: v }) }),
      switchRow({ ico: 'ic_endpoint_independent', title: 'Endpoint-Independent mapping', sub: 'UDP sockets keep a fixed address and port for all destinations. Helps games, calls and peer-to-peer apps.', value: s.eim, onchange: (v) => save({ eim: v }) }),
      row({ ico: 'ic_idle_timeout', title: 'Idle timeout', sub: 'Close idle TCP and UDP sockets after this duration.', right: selectBox(IDLE_TIMEOUTS, String(s.dialTimeout || 0), (v) => save({ dialTimeout: Number(v) }), 'Idle timeout') })
    )
  );
};

const DIAL_STRATEGIES = [
  ['never', 'Off (as-is)'],
  ['auto', 'Auto'],
  ['split-tcp', 'Split TCP'],
  ['split-tls', 'Split TLS ClientHello'],
];

const DIAL_RETRIES = [
  ['', 'Auto'],
  ['never', 'Never'],
  ['plain', 'Retry as-is'],
  ['split', 'Retry with split'],
];

const IDLE_TIMEOUTS = [
  ['0', 'Default'],
  ['60', '1 minute'],
  ['300', '5 minutes'],
  ['900', '15 minutes'],
  ['3600', '1 hour'],
];

function selectBox(options, value, onchange, label) {
  const sel = h('select', { class: 'fld-input', 'aria-label': label, onclick: (e) => e.stopPropagation() }, options.map(([v, n]) => h('option', { value: v, text: n })));
  sel.value = value || options[0][0];
  sel.addEventListener('change', () => onchange(sel.value));
  return sel;
}

async function chooseFallback() {
  const opts = DNS_LISTS.doh.filter((d) => d.ips);
  let pick = App.settings.fallbackDoh;
  const body = h(
    'div',
    {},
    opts.map((d) => {
      const r = h('input', { type: 'radio', name: 'fb', checked: d.url === pick });
      r.addEventListener('change', () => (pick = d.url));
      return h('label', { class: 'pick-row' }, r, h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: d.name }), h('span', { class: 'row-sub', text: d.ips })));
    })
  );
  if (!(await dialog({ title: 'Choose fallback DNS', body, ok: 'Save' }))) return;
  const d = opts.find((o) => o.url === pick);
  if (d) save({ fallbackDoh: d.url, fallbackIps: d.ips, fallbackName: d.name });
}

// ---------- Settings ----------

const THEMES = [
  ['darkplus', 'Dark Plus'],
  ['trueblack', 'True Black'],
  ['dark', 'Dark'],
  ['light', 'Light'],
];

const LOG_LEVELS = [
  [0, 'Very verbose'],
  [1, 'Verbose'],
  [2, 'Debug'],
  [3, 'Info'],
  [4, 'Warning'],
  [5, 'Error'],
  [8, 'None'],
];

PAGES.settings = () => {
  const s = App.settings;
  const level = h('select', { class: 'fld-input', 'aria-label': 'Log level' }, LOG_LEVELS.map(([v, n]) => h('option', { value: String(v), text: n })));
  level.value = String(s.logLevel);
  level.addEventListener('change', () => save({ logLevel: Number(level.value) }));
  return screen(
    'Settings',
    sectionLabel('General'),
    card(
      h(
        'div',
        { class: 'row' },
        icon('ic_backup_restore', 'row-ico'),
        h(
          'span',
          { class: 'row-text' },
          h('span', { class: 'row-title', text: 'Backup & Restore' }),
          h('span', { class: 'row-sub', text: 'Manually back up or restore app data and settings. Backups include WireGuard and WARP keys: keep them private.' }),
          h('div', { class: 'actions' }, btn('Backup', async () => {
            const r = await App.port.backup();
            if (r.ok) toast('Backup saved');
            else if (r.error) toast(r.error);
          }), btn('Restore', async () => {
            if (!(await confirmDialog('Restore', 'Replace the current settings, WireGuard configs and WARP identities with the backup?', 'Restore'))) return;
            const r = await App.port.restore();
            if (r.ok) {
              await App.reload();
              toast('Restored');
            } else if (r.error) toast(r.error);
          }))
        )
      )
    ),
    card(
      row({ ico: 'ic_refresh_white', title: 'Check for app updates', sub: 'Automatically check for app updates once a week, on github.com.', right: h('div', { class: 'actions' }, btn('Check now', checkUpdateNow), toggle(s.checkUpdates, (v) => save({ checkUpdates: v }, true), 'Check for app updates')) })
    ),
    sectionLabel('Logs'),
    card(
      switchRow({ ico: 'ic_logs', title: 'Enable on-device logging', sub: 'Store DNS and firewall logs and stats on this PC (7 days), for the Stats and Logs screens.', value: s.history, onchange: (v) => save({ history: v }, true) }),
      row({ ico: 'ic_log_level', title: 'Log level', sub: 'How much the engine writes to its log', right: level }),
      row({ ico: 'ic_app_log', title: 'App Logs', sub: 'For debugging purposes', right: chevron(), onclick: () => App.go('applogs') }),
      row({ ico: 'ic_app_log', title: 'Save debug logs', sub: 'One zip with the engine, WireGuard, WARP and usque logs, settings, recent activity and this PC’s network setup. Private keys and passwords are left out.', right: btn('Save zip', saveDebugZip) }),
      row({ ico: 'ic_network', title: 'Packet capture', sub: 'Write every packet in the tunnel to capture.pcap (open it with Wireshark). Grows fast; turn it off when done. Applies on the next start.', right: h('div', { class: 'actions' }, btn('Open folder', () => App.port.openPcapFolder()), toggle(s.pcap, (v) => save({ pcap: v }), 'Packet capture')) })
    ),
    sectionLabel('Notification'),
    card(
      switchRow({ ico: 'show_notification', title: 'App Notification', sub: 'Show Windows notifications when protection starts, stops or fails', value: s.notify, onchange: (v) => save({ notify: v }, true) }),
      switchRow({ ico: 'ic_notification', title: 'Network status alerts', sub: 'Play a sound when the tunnel, proxy, or network status changes', value: s.statusAlerts, onchange: (v) => save({ statusAlerts: v }, true) })
    ),
    sectionLabel('Customize'),
    card(
      row({ ico: 'ic_appearance', title: 'Appearance', sub: 'Current theme: ' + (THEMES.find((t) => t[0] === s.theme) || THEMES[0])[1], right: chevron(), onclick: chooseTheme }),
      switchRow({ ico: 'ic_tun_nw_policy', title: 'Automation', sub: 'Let scripts and the Task Scheduler control protection: port1897.exe --start, --stop, --pause=15 or --resume.', value: s.automation, onchange: (v) => save({ automation: v }, true) }),
      switchRow({ ico: 'ic_auto_start', title: 'Auto-start on power-up', sub: 'On sign-in, start the app in the tray, and start protection if it was running before shut down (asks for admin permission).', value: s.autostart, onchange: (v) => App.port.setAutostart(v).then(() => save({ autostart: v }, true)) })
    )
  );
};

async function chooseTheme() {
  let pick = App.settings.theme;
  const body = h(
    'div',
    {},
    THEMES.map(([id, name]) => {
      const r = h('input', { type: 'radio', name: 'theme', checked: id === pick });
      r.addEventListener('change', () => {
        pick = id;
        document.documentElement.dataset.theme = id;
      });
      return h('label', { class: 'pick-row' }, r, h('span', { class: 'row-title', text: name }));
    })
  );
  const ok = await dialog({ title: 'Appearance', body, ok: 'Save' });
  if (ok) await save({ theme: pick }, true);
  App.applyTheme();
}

PAGES.applogs = () => {
  const box = h('pre', { class: 'logbox', text: 'Loading…' });
  const load = () => App.port.engineLog('').then((t) => (box.textContent = t || 'The engine has not written anything yet.'));
  load();
  return screen('App Logs', box, h('div', { class: 'actions' }, btn('Refresh', load), btn('Copy', () => App.port.copy(box.textContent).then(() => toast('Copied'))), btn('Open file', () => App.port.openLog()), btn('Save debug zip', saveDebugZip, { primary: true })));
};

let savingZip = false;
async function saveDebugZip() {
  if (savingZip) return;
  savingZip = true;
  toast('Collecting logs…');
  try {
    const r = await App.port.debugZip();
    if (r.ok) toast('Debug logs saved');
    else if (r.error) toast('Could not save the zip: ' + r.error);
  } finally {
    savingZip = false;
  }
}

// ---------- Logs ----------

let logFilter = 'flow';
let logShow = 'all';
PAGES.logs = () => {
  const list = h('div', { class: 'group' });
  const search = field({ placeholder: 'Search app or domain', oninput: () => fillLog(list, search.input.value) });
  const tabs = h(
    'div',
    { class: 'seg-wrap' },
    h(
      'div',
      { class: 'seg' },
      [
        ['flow', 'Network'],
        ['dns', 'DNS'],
      ].map(([id, name]) =>
        h('button', { class: logFilter === id ? 'on' : '', type: 'button', onclick: () => {
          logFilter = id;
          App.render();
        }, text: name })
      )
    )
  );
  const shows = h(
    'div',
    { class: 'chips center' },
    [['all', 'All'], ['allowed', 'Allowed'], ['blocked', 'Blocked']].map(([id, name]) => h('button', { class: 'chip' + (logShow === id ? ' on' : ''), type: 'button', text: name, onclick: () => {
      logShow = id;
      shows.querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', c.textContent === name));
      fillLog(list, search.input.value);
    } }))
  );
  PAGE_TICK.logs = () => fillLog(list, search.input.value);
  fillLog(list, '');
  return screen('Logs', tabs, shows, h('div', { class: 'field-row' }, search), list, h('div', { class: 'actions' }, btn('Save debug zip', saveDebugZip)));
};

// Website icon from DuckDuckGo when "Show website icon" is on; else the DNS
// globe. Only well-formed host names go into the URL.
function siteIcon(domain) {
  const d = String(domain || '').toLowerCase();
  if (!App.settings.favicons || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) return icon('dns_home_screen', 'row-ico');
  const parts = d.split('.');
  const site = parts.slice(-2).join('.');
  const img = h('img', { class: 'row-ico favicon', alt: '', referrerpolicy: 'no-referrer', loading: 'lazy', src: `https://icons.duckduckgo.com/ip3/${encodeURIComponent(site)}.ico` });
  img.addEventListener('error', () => img.replaceWith(icon('dns_home_screen', 'row-ico')));
  return img;
}

function fillLog(list, q) {
  q = (q || '').trim().toLowerCase();
  const rows = App.events
    .filter((e) => e.kind === logFilter && (logShow === 'all' || (logShow === 'blocked') === !!e.blocked))
    .filter((e) => !q || (e.app || '').toLowerCase().includes(q) || (e.domain || '').toLowerCase().includes(q) || (e.dst || '').includes(q))
    .slice(-300)
    .reverse();
  list.replaceChildren();
  if (!rows.length) {
    list.append(h('p', { class: 'empty', text: App.status ? 'Nothing yet. Use the internet and connections show up here.' : 'Start protection to see connections.' }));
    return;
  }
  const open = (f) => ({ class: 'row clickable', tabindex: '0', onclick: f, onkeydown: (ev) => ev.key === 'Enter' && f() });
  for (const e of rows) {
    if (e.kind === 'flow') {
      const o = open(() => connDetails(e));
      o.class += e.blocked ? ' blocked' : '';
      list.append(
        h(
          'div',
          o,
          avatar(e.app),
          h(
            'span',
            { class: 'row-text' },
            h('span', { class: 'row-title', text: (e.domain || e.dst) + (e.blocked ? '  · blocked' : '') }),
            h('span', { class: 'row-sub', text: `${fmtTime(e.at)} · ${e.app || '?'} · ${e.proto} ${e.dst}${e.via && e.via !== 'direct' && e.via !== 'blocked' ? ' · via ' + e.via : ''}${e.blocked && e.rule ? ' · ' + e.rule : ''}` })
          )
        )
      );
    } else {
      const marks = [e.secure ? 'DNSSEC ✓' : '', e.cached ? 'cached' : '', e.blocked ? 'blocked' + (e.rule ? ': ' + e.rule : '') : ''].filter(Boolean).join(' · ');
      const o = open(() => dnsDetails(e));
      o.class += e.blocked ? ' blocked' : '';
      list.append(
        h(
          'div',
          o,
          siteIcon(e.domain),
          h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: e.domain || '' }), h('span', { class: 'row-sub', text: `${fmtTime(e.at)} · ${e.qtype ? rrName(e.qtype) + ' · ' : ''}${e.answer || 'no answer'}${e.error ? ' (' + e.error + ')' : ''} · ${e.latencyMs} ms${marks ? ' · ' + marks : ''}` }))
        )
      );
    }
  }
}

// ---------- Stats ----------

let statsRange = '1h';
let statsAll = {};
PAGES.stats = () => {
  const root = h('div', {}, note('Loading…'));
  const draw = async () => {
    const st = await App.port.stats(statsRange);
    const total = st.rx + st.tx;
    const section = (key, title, items, render) => {
      const limit = statsAll[key] ? 50 : 5;
      return h(
        'div',
        {},
        h('div', { class: 'stat-head' }, h('h3', { text: title }), items.length > 5 ? btn(statsAll[key] ? 'Show less' : 'Show all', () => {
          statsAll[key] = !statsAll[key];
          draw();
        }) : null),
        items.length ? items.slice(0, limit).map(render) : note('Nothing yet.')
      );
    };
    const maxOf = (items, f) => Math.max(1, ...items.map(f));
    const appRow = (max, f) => (a) =>
      h(
        'div',
        { class: 'stat-row' },
        avatar(a.name),
        h(
          'span',
          { class: 'row-text' },
          f === 'bytes' ? h('span', { class: 'bytes' }, `${fmtBytes(a.tx)} `, h('span', { class: 'arrow-up', text: '▲' }), ` / ${fmtBytes(a.rx)} `, h('span', { class: 'arrow-up', text: '▼' })) : null,
          h('span', { class: 'row-sub', text: a.name }),
          (() => {
            const b = h('span', { class: 'mini-bar' });
            b.style.width = `${(100 * (f === 'bytes' ? a.rx + a.tx || a.n : a.blocked || a.n)) / max}%`;
            return b;
          })()
        ),
        h('span', { class: 'count', text: String(f === 'blocked' ? a.blocked : a.n) })
      );
    const domRow = (max, blocked) => (d) =>
      h(
        'div',
        { class: 'stat-row' },
        icon('dns_home_screen', 'row-ico'),
        h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: d.name }), (() => {
          const b = h('span', { class: 'mini-bar' });
          b.style.width = `${(100 * (blocked ? d.blocked : d.n)) / max}%`;
          return b;
        })()),
        h('span', { class: 'count', text: String(blocked ? d.blocked : d.n) })
      );
    const bar = h('div', { class: 'usage-bar' }, (() => {
      const a = h('span');
      a.style.width = total ? `${(100 * st.tx) / total}%` : '0';
      return a;
    })(), (() => {
      const b = h('span');
      b.style.width = total ? `${(100 * st.rx) / total}%` : '0';
      return b;
    })());
    root.replaceChildren(
      h(
        'div',
        { class: 'seg-wrap' },
        h(
          'div',
          { class: 'seg' },
          [
            ['1h', '1 hr'],
            ['24h', '24 hr'],
            ['7d', '7 day'],
          ].map(([id, name]) => h('button', { class: statsRange === id ? 'on' : '', type: 'button', text: name, onclick: () => {
            statsRange = id;
            draw();
          } }))
        )
      ),
      h(
        'div',
        { class: 'usage' },
        bar,
        h(
          'div',
          { class: 'usage-row' },
          h('div', {}, h('span', { class: 'legend' }, h('i'), `Upload: ${fmtBytes(st.tx)}`), h('span', { class: 'legend' }, h('i', { class: 'dim' }), `Download: ${fmtBytes(st.rx)}`)),
          h('div', {}, h('span', { text: `Overall: ${fmtBytes(total)}` }), h('span', { text: `${st.flows} connections` }))
        )
      ),
      st.history ? '' : note('On-device logging is off (Settings → Logs), so stats cover only the current session.'),
      section('apps', 'Most allowed apps', st.allowedApps, appRow(maxOf(st.allowedApps, (a) => a.rx + a.tx || a.n), 'bytes')),
      section('blocked', 'Most blocked apps', st.blockedApps, appRow(maxOf(st.blockedApps, (a) => a.blocked), 'blocked')),
      section('domains', 'Most contacted domains', st.domains, domRow(maxOf(st.domains, (d) => d.n), false)),
      section('bdomains', 'Most blocked domains', st.blockedDomains, domRow(maxOf(st.blockedDomains, (d) => d.blocked), true))
    );
  };
  draw();
  PAGE_TICK.stats = () => {};
  return h('div', {}, brandHeader('Detect and block network security threats'), root);
};

// ---------- About ----------

PAGES.about = () =>
  h(
    'div',
    {},
    brandHeader('Firewall, encrypted DNS and free VPN for Windows'),
    h(
      'div',
      { class: 'group pad' },
      h('p', { class: 'desc', text: 'Built on firestack, the open-source engine of the Rethink DNS + Firewall Android app, with usque for WARP over MASQUE.' }),
      h('p', { class: 'desc', text: 'Early test software. Unofficial: not affiliated with Celzero (Rethink), Cloudflare, WireGuard LLC or Microsoft.' }),
      h('p', { class: 'desc', text: 'Engine: ' + (App.status ? `fswin ${App.status.version}, running` : 'not running') }),
      h('div', { class: 'actions' }, btn('Source code', () => App.port.openUrl('https://github.com/wowjes92jsj2oe0-star/port1897')), btn('Send a test report', () => App.port.openUrl('https://github.com/wowjes92jsj2oe0-star/port1897/issues/new?template=test_report.yml')))
    ),
    h('div', { class: 'group pad' }, h('h2', { class: 'modal-title', text: 'Licenses' }), h('p', { class: 'desc', text: 'Mozilla Public License 2.0. Icons, layout and DNS lists from the Rethink Android app (Apache-2.0). usque (MIT). Kill switch rules adapted from WireGuard for Windows (MIT). Wintun © WireGuard LLC, prebuilt-binaries license.' }))
  );
