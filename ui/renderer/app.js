// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Renderer: draws the screens and polls the engine through window.port
// (preload.js). Names of apps and domains come from the network, so they are
// only ever set with textContent, never as HTML.

'use strict';

const DNS_PRESETS = [
  { id: 'cloudflare', name: 'Cloudflare', note: '1.1.1.1, fast', url: 'https://cloudflare-dns.com/dns-query', ips: '1.1.1.1,1.0.0.1' },
  { id: 'quad9', name: 'Quad9', note: 'Blocks malware sites', url: 'https://dns.quad9.net/dns-query', ips: '9.9.9.9,149.112.112.112' },
  { id: 'adguard', name: 'AdGuard', note: 'Blocks ads and trackers', url: 'https://dns.adguard-dns.com/dns-query', ips: '94.140.14.14,94.140.15.15' },
  { id: 'mullvad', name: 'Mullvad', note: 'No logging', url: 'https://dns.mullvad.net/dns-query', ips: '194.242.2.2' },
  { id: 'google', name: 'Google', note: '8.8.8.8', url: 'https://dns.google/dns-query', ips: '8.8.8.8,8.8.4.4' },
];

const EXIT_NAMES = { none: 'Off', warp: 'Cloudflare WARP', masque: 'WARP (MASQUE)', chain: 'WARP chain', wg: 'WireGuard', proxy: 'Proxy' };

const $ = (id) => document.getElementById(id);
const port = window.port || demoPort();

let settings = null;
let status = null;
let busy = false;
let page = 'home';
let lastEventId = 0;
let events = [];
let logFilter = 'flow';
let restartNeeded = false;

// ---------- helpers ----------

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// ---------- navigation ----------

function showPage(name) {
  page = name;
  document.querySelectorAll('.page').forEach((p) => (p.hidden = p.dataset.page !== name));
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.nav === name));
  $('pages').scrollTop = 0;
  if (name === 'stats') refreshStats();
  if (name === 'logs') renderLog();
  if (name === 'configure') renderConfigure();
}

// ---------- home ----------

function renderHome() {
  const s = status;
  const on = !!s;

  // DNS
  if (on) {
    const q = s.dns.queries;
    setText('dns-main', q ? `${s.dns.avgMs || s.dns.lastMs} ms` : 'Waiting for lookups…');
    setText('dns-sub', q ? `${q} lookups${s.dns.failed ? `, ${s.dns.failed} failed` : ''}` : '');
    setText('dns-foot', hostOf(s.dns.server));
  } else {
    setText('dns-main', 'Enable DNS mode.');
    setText('dns-sub', '');
    setText('dns-foot', '');
  }

  // Firewall
  if (on && s.mode === 'full') {
    const n = s.firewall.blockedApps.length;
    setText('fw-main', `${n} app${n === 1 ? '' : 's'} blocked`);
    setText('fw-sub', `${s.firewall.blocked} connections blocked`);
    setText('fw-foot', 'Active');
  } else if (on) {
    setText('fw-main', 'DNS only');
    setText('fw-sub', '');
    setText('fw-foot', '"Firewall all apps" is off');
  } else {
    setText('fw-main', 'Enable firewall mode.');
    setText('fw-sub', '');
    setText('fw-foot', 'Disabled');
  }

  // Proxy
  const planned = settings ? EXIT_NAMES[settings.exit] : 'Off';
  if (on) {
    setText('px-main', s.exit || 'Direct');
    setText('px-sub', '');
    setText('px-foot', s.exit ? 'Active' : 'No VPN');
  } else {
    setText('px-main', 'Inactive');
    setText('px-sub', settings && settings.exit !== 'none' ? planned : '');
    setText('px-foot', 'Disabled');
  }

  // Logs
  if (on) {
    setText('logs-main', `Network logs: ${s.firewall.flows}`);
    setText('logs-sub', `DNS logs: ${s.dns.queries}`);
  } else {
    setText('logs-main', 'Enable firewall mode.');
    setText('logs-sub', 'Disabled');
  }

  // Apps
  setText('apps-seen', on ? String(s.firewall.appsSeen) : '0');
  setText('apps-blocked', String(on ? s.firewall.blockedApps.length : (settings ? settings.blocked.length : 0)));
  setText('apps-flows', on ? String(s.firewall.flows) : '0');
  setText('apps-blocked-flows', on ? String(s.firewall.blocked) : '0');
  setText('apps-traffic', on ? fmtBytes(s.traffic.rx + s.traffic.tx) : '0 B');

  // Start button and protection line
  const btn = $('start-btn');
  btn.classList.toggle('running', on);
  btn.disabled = busy;
  setText('start-label', busy ? (on ? 'STOPPING…' : 'STARTING…') : on ? 'STOP' : 'START');

  const prot = $('protection');
  prot.classList.toggle('on', on);
  if (on) {
    const parts = ['encrypted DNS'];
    if (s.mode === 'full') parts.push('firewall');
    if (s.exit) parts.push(s.exit);
    if (s.killSwitch) parts.push('kill switch');
    prot.textContent = 'Protected: ' + parts.join(' · ');
  } else {
    prot.textContent = 'Not protected';
  }

  setText('about-engine', on ? `fswin ${s.version}, running` : 'not running');
}

async function toggleEngine() {
  if (busy) return;
  busy = true;
  $('start-error').hidden = true;
  renderHome();
  const r = status ? await port.stop() : await port.start();
  busy = false;
  if (!r.ok) {
    const err = $('start-error');
    err.textContent = r.error + (r.log ? '\n\n' + r.log : '');
    err.hidden = false;
  } else {
    restartNeeded = false;
    $('cfg-restart').hidden = true;
  }
  await poll();
}

// ---------- logs ----------

async function pullEvents() {
  if (!status) return;
  const fresh = await port.events(lastEventId);
  if (fresh.length) {
    lastEventId = fresh[fresh.length - 1].id;
    events = events.concat(fresh).slice(-1500);
    if (page === 'logs') renderLog();
  }
}

function renderLog() {
  const list = $('log');
  const q = $('log-search').value.trim().toLowerCase();
  const blocked = new Set(settings ? settings.blocked : []);
  const rows = events
    .filter((e) => e.kind === logFilter)
    .filter((e) => !q || (e.app || '').toLowerCase().includes(q) || (e.domain || '').toLowerCase().includes(q) || (e.dst || '').includes(q))
    .slice(-300)
    .reverse();

  list.replaceChildren();
  for (const e of rows) {
    const li = el('li');
    li.append(el('span', 't', fmtTime(e.at)));
    if (e.kind === 'flow') {
      li.append(el('span', 'a', e.app || '?'));
      const d = el('span', 'd');
      if (e.domain) d.append(el('b', '', e.domain), ' ');
      d.append(`${e.proto} ${e.dst}${e.via && e.via !== 'direct' && e.via !== 'blocked' ? ' via ' + e.via : ''}`);
      li.append(d);
      if (e.app && e.app !== '?') {
        const isBlocked = blocked.has(e.app.toLowerCase());
        const b = el('button', 'act' + (isBlocked ? ' blocked' : ''), isBlocked ? 'Unblock' : 'Block');
        b.addEventListener('click', () => setBlocked(e.app, !isBlocked));
        li.append(b);
      } else {
        li.append(el('span'));
      }
    } else {
      li.append(el('span', 'a', e.domain || ''));
      li.append(el('span', 'd', `${e.answer || 'no answer'} · ${e.latencyMs} ms`));
      li.append(el('span'));
    }
    if (e.blocked) li.classList.add('blocked');
    list.append(li);
  }
  $('log-hint').hidden = rows.length > 0;
  $('log-hint').textContent = status ? 'Nothing yet. Use the internet and connections show up here.' : 'Start protection to see connections.';
}

async function setBlocked(app, block) {
  const list = await port.block(app, block);
  settings.blocked = list;
  renderLog();
  renderBlocked();
  renderHome();
}

// ---------- stats ----------

async function refreshStats() {
  if (!status) {
    $('stats-hint').hidden = false;
    $('top-apps').replaceChildren();
    $('top-domains').replaceChildren();
    return;
  }
  const st = await port.stats();
  $('stats-hint').hidden = st.apps.length + st.domains.length > 0;
  fillBars($('top-apps'), st.apps);
  fillBars($('top-domains'), st.domains);
}

function fillBars(ol, items) {
  const max = Math.max(1, ...items.map((i) => i.count));
  ol.replaceChildren();
  for (const i of items) {
    const li = el('li');
    const bar = el('span', 'bar');
    bar.style.width = `${(100 * i.count) / max}%`;
    li.append(bar, el('span', '', i.name), el('span', '', String(i.count)));
    ol.append(li);
  }
}

// ---------- configure ----------

function renderConfigure() {
  if (!settings) return;

  const dnsBox = $('dns-choices');
  dnsBox.replaceChildren();
  const preset = DNS_PRESETS.find((p) => p.url === settings.doh);
  for (const p of [...DNS_PRESETS, { id: 'custom', name: 'Custom', note: 'Your own DoH server' }]) {
    const label = el('label', 'choice');
    const input = el('input');
    input.type = 'radio';
    input.name = 'dns';
    input.value = p.id;
    input.checked = preset ? preset.id === p.id : p.id === 'custom';
    input.addEventListener('change', () => chooseDns(p));
    const span = el('span');
    span.append(el('b', '', p.name), el('small', '', p.note));
    label.append(input, span);
    dnsBox.append(label);
  }
  $('dns-custom').hidden = !!preset;
  $('doh-url').value = settings.doh;
  $('doh-ips').value = settings.dohIps;

  document.querySelectorAll('input[name="exit"]').forEach((r) => (r.checked = r.value === settings.exit));
  $('wg-row').hidden = settings.exit !== 'wg' && settings.exit !== 'chain';
  $('proxy-row').hidden = settings.exit !== 'proxy';
  $('wg-file').textContent = settings.wgFile || 'No file chosen';
  $('proxy-url').value = settings.proxy;

  $('opt-full').checked = settings.full;
  $('opt-nrpt').checked = settings.nrpt;
  $('opt-kill').checked = !!settings.killSwitch;
  $('cfg-restart').hidden = !(restartNeeded && status);
  renderBlocked();
}

function renderBlocked() {
  const ul = $('blocked-list');
  ul.replaceChildren();
  if (!settings.blocked.length) {
    ul.append(el('li', 'empty', 'No apps blocked. Block them here or from the Logs.'));
    return;
  }
  for (const app of settings.blocked) {
    const li = el('li', '', app);
    const x = el('button', '', '×');
    x.title = 'Unblock ' + app;
    x.addEventListener('click', () => setBlocked(app, false));
    li.append(x);
    ul.append(li);
  }
}

async function save(patch) {
  settings = await port.setSettings(patch);
  restartNeeded = true;
  renderConfigure();
  renderHome();
}

function chooseDns(p) {
  if (p.id === 'custom') {
    $('dns-custom').hidden = false;
    return;
  }
  save({ doh: p.url, dohIps: p.ips });
}

// ---------- polling ----------

async function poll() {
  const was = !!status;
  status = await port.status();
  if (!was && status) {
    events = [];
    lastEventId = 0;
  }
  renderHome();
  await pullEvents();
}

// ---------- wiring ----------

function wire() {
  document.querySelectorAll('[data-icon]').forEach((e) => {
    e.innerHTML = ICONS[e.dataset.icon] || ''; // static icon markup only
  });
  document.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => showPage(b.dataset.nav)));
  document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => showPage(b.dataset.go)));
  document.querySelectorAll('[data-url]').forEach((b) => b.addEventListener('click', () => port.openUrl(b.dataset.url)));
  $('start-btn').addEventListener('click', toggleEngine);

  document.querySelectorAll('.tab').forEach((t) =>
    t.addEventListener('click', () => {
      logFilter = t.dataset.filter;
      document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
      renderLog();
    })
  );
  $('log-search').addEventListener('input', renderLog);

  $('doh-url').addEventListener('change', () => save({ doh: $('doh-url').value.trim() }));
  $('doh-ips').addEventListener('change', () => save({ dohIps: $('doh-ips').value.trim() }));
  document.querySelectorAll('input[name="exit"]').forEach((r) => r.addEventListener('change', () => save({ exit: r.value })));
  $('wg-pick').addEventListener('click', async () => {
    const f = await port.pickWgFile();
    if (f) save({ wgFile: f });
  });
  $('proxy-url').addEventListener('change', () => save({ proxy: $('proxy-url').value.trim() }));
  $('opt-full').addEventListener('change', () => save({ full: $('opt-full').checked }));
  $('opt-nrpt').addEventListener('change', () => save({ nrpt: $('opt-nrpt').checked }));
  $('opt-kill').addEventListener('change', () => save({ killSwitch: $('opt-kill').checked }));
  $('kill-release').addEventListener('click', async () => {
    setText('kill-msg', 'Asking Windows for permission…');
    const r = await port.cleanup();
    setText('kill-msg', r.ok ? 'Released. The internet works without the app again.' : r.error);
  });
  $('block-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = $('block-name').value.trim();
    if (name) setBlocked(name, true);
    $('block-name').value = '';
  });
  $('open-log').addEventListener('click', () => port.openLog());
}

async function main() {
  wire();
  settings = await port.getSettings();
  await poll();
  setInterval(poll, 1000);
  setInterval(() => page === 'stats' && refreshStats(), 3000);
}

main();

// ---------- demo mode (no engine, e.g. opened in a browser) ----------

function demoPort() {
  let s = { doh: DNS_PRESETS[0].url, dohIps: DNS_PRESETS[0].ips, exit: 'warp', wgFile: '', proxy: '', full: true, nrpt: true, blocked: ['notepad.exe'] };
  let running = false;
  let id = 0;
  let flows = 0;
  let queries = 0;
  const apps = ['msedge.exe', 'chrome.exe', 'discord.exe', 'spotify.exe', 'svchost.exe', 'notepad.exe'];
  const doms = ['example.com', 'github.com', 'discord.gg', 'spotify.com', 'windowsupdate.com', 'cloudflare.com'];
  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  return {
    getSettings: async () => ({ ...s }),
    setSettings: async (p) => (s = { ...s, ...p }),
    start: async () => ((running = true), { ok: true }),
    cleanup: async () => ({ ok: true }),
    stop: async () => ((running = false), { ok: true }),
    status: async () => {
      if (!running) return null;
      flows += 3;
      queries += 2;
      return {
        version: 'demo', startedAt: Date.now(), mode: s.full ? 'full' : 'dns', nrpt: s.nrpt, killSwitch: !!s.killSwitch,
        exit: s.exit === 'none' ? '' : EXIT_NAMES[s.exit],
        dns: { server: s.doh, queries, failed: 0, lastMs: 18, avgMs: 21 },
        firewall: { flows, blocked: Math.floor(flows / 9), blockedApps: s.blocked, appsSeen: 6 },
        traffic: { rx: flows * 48000, tx: flows * 9000 },
      };
    },
    events: async () => {
      if (!running) return [];
      const out = [];
      for (let i = 0; i < 3; i++) {
        const app = pick(apps);
        const dom = pick(doms);
        out.push({ id: ++id, at: Date.now(), kind: 'dns', domain: dom, answer: '104.16.0.1', latencyMs: 20 });
        out.push({ id: ++id, at: Date.now(), kind: 'flow', app, proto: 'tcp', dst: '104.16.0.1:443', domain: dom, via: 'Cloudflare WARP', blocked: s.blocked.includes(app) });
      }
      return out;
    },
    stats: async () => ({ apps: apps.map((a, i) => ({ name: a, count: 60 - i * 9 })), domains: doms.map((d, i) => ({ name: d, count: 40 - i * 6 })) }),
    block: async (app, b) => {
      s.blocked = b ? [...new Set([...s.blocked, app.toLowerCase()])] : s.blocked.filter((x) => x !== app.toLowerCase());
      return s.blocked;
    },
    pickWgFile: async () => '',
    openUrl: async () => {},
    openLog: async () => {},
  };
}
