// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Renderer core: settings, navigation (a back stack like Android's), the
// home screen, and polling the engine through window.port (preload.js).
// Without window.port (opened in a browser) it runs on demo data.

'use strict';

const $ = (id) => document.getElementById(id);

const App = {
  port: window.port || demoPort(),
  settings: null,
  status: null,
  events: [],
  lastEventId: 0,
  stack: [{ name: 'home' }],
  busy: false,
  restartNeeded: false,

  go(name, params) {
    this.stack.push({ name, params: params || {} });
    this.render(true);
  },
  back() {
    if (this.stack.length > 1) this.stack.pop();
    this.render(true);
  },
  root(name) {
    this.stack = [{ name }];
    this.render(true);
  },

  render(scrollTop) {
    const top = this.stack[this.stack.length - 1];
    const home = top.name === 'home';
    $('page-home').hidden = !home;
    const view = $('page-view');
    view.hidden = home;
    for (const k of Object.keys(PAGE_TICK)) delete PAGE_TICK[k];
    if (!home) {
      const build = PAGES[top.name];
      view.replaceChildren(build ? build(top.params || {}) : h('p', { text: 'Not found' }));
    }
    const rootName = this.stack[0].name;
    document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.nav === rootName));
    if (scrollTop) $('pages').scrollTop = 0;
    renderHome();
  },

  async save(patch) {
    this.settings = await this.port.setSettings(patch);
    this.restartNeeded = true;
    this.applyTheme();
  },
  async reload() {
    this.settings = await this.port.getSettings();
    this.applyTheme();
    this.render();
  },
  async block(app, block) {
    this.settings = await this.port.block(app, block);
    renderHome();
  },
  // Firewall rules apply at once; no restart needed.
  async setRules(patch) {
    const r = await this.port.setRules(patch);
    this.settings = r.settings;
    if (r.warnings) toast('Some rules were skipped: ' + r.warnings);
    renderHome();
  },
  applyTheme() {
    document.documentElement.dataset.theme = (this.settings && this.settings.theme) || 'darkplus';
  },

  async startEngine() {
    return toggleEngine(true);
  },
  async stopEngine() {
    return toggleEngine(false);
  },
  async restart() {
    if (this.status) await toggleEngine(false);
    await toggleEngine(true);
  },
};

// ---------- home ----------

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function renderHome() {
  const s = App.status;
  const cfg = App.settings || {};
  const on = !!s;

  if (on) {
    const q = s.dns.queries;
    setText('dns-main', q ? `${s.dns.avgMs || s.dns.lastMs} ms` : 'Waiting for lookups…');
    setText('dns-sub', q ? `${q} lookups${s.dns.failed ? `, ${s.dns.failed} failed` : ''}${s.dns.bogus ? `, ${s.dns.bogus} bogus blocked` : ''}` : '');
    setText('dns-foot', dnsCurrent().name);
  } else {
    setText('dns-main', 'Enable DNS mode.');
    setText('dns-sub', '');
    setText('dns-foot', '');
  }

  if (on && s.mode === 'full') {
    const n = s.firewall.blockedApps.length;
    setText('fw-main', `${n} app${n === 1 ? '' : 's'} blocked`);
    setText('fw-sub', `${s.firewall.blocked} connections blocked`);
    setText('fw-foot', s.killSwitch ? 'Active · kill switch on' : 'Active');
  } else if (on) {
    setText('fw-main', 'DNS only');
    setText('fw-sub', '');
    setText('fw-foot', '"Firewall all apps" is off');
  } else {
    setText('fw-main', 'Enable firewall mode.');
    setText('fw-sub', '');
    setText('fw-foot', 'Disabled');
  }

  if (on) {
    setText('px-main', s.exit || 'Direct');
    setText('px-sub', '');
    setText('px-foot', s.exit ? 'Active' : 'No VPN');
  } else {
    setText('px-main', 'Inactive');
    setText('px-sub', cfg.exit && cfg.exit !== 'none' ? EXIT_LABEL[cfg.exit] : '');
    setText('px-foot', 'Disabled');
  }

  if (on) {
    setText('logs-main', `Network logs: ${s.firewall.flows}`);
    setText('logs-sub', `DNS logs: ${s.dns.queries}`);
  } else {
    setText('logs-main', 'Enable firewall mode.');
    setText('logs-sub', 'Disabled');
  }

  setText('apps-seen', on ? String(s.firewall.appsSeen) : '0');
  setText('apps-blocked', String(on ? s.firewall.blockedApps.length : cfg.rules ? blockedNames().length : 0));
  setText('apps-flows', on ? String(s.firewall.flows) : '0');
  setText('apps-blocked-flows', on ? String(s.firewall.blocked) : '0');
  setText('apps-traffic', on ? fmtBytes(s.traffic.rx + s.traffic.tx) : '0 B');

  const btnEl = $('start-btn');
  btnEl.classList.toggle('running', on);
  btnEl.classList.toggle('busy', App.busy);
  $('start-main').disabled = App.busy;
  setText('start-label', App.busy ? (on ? 'STOPPING…' : 'STARTING…') : on ? 'STOP' : 'START');
  const paused = on && cfg.pausedUntil > Date.now();
  $('pause-btn').title = paused ? 'Paused: open' : 'Pause';

  const kill = killSwitchOn();
  const killBtn = $('kill-btn');
  killBtn.classList.toggle('on', kill);
  killBtn.setAttribute('aria-pressed', String(kill));
  setText('kill-label', kill ? 'Kill switch on' : 'Kill switch off');
  killBtn.title = kill ? 'Only port1897 reaches the internet. Click to turn off.' : 'Block the internet outside port1897. Click to turn on.';

  const prot = $('protection');
  prot.classList.toggle('on', on && !paused);
  if (paused) {
    prot.textContent = `Paused · ${fmtLeft(cfg.pausedUntil - Date.now())} left`;
  } else if (on) {
    const parts = ['encrypted DNS'];
    if (s.mode === 'full') parts.push('firewall');
    if (s.exit) parts.push(s.exit);
    if (s.killSwitch) parts.push('kill switch');
    prot.textContent = 'Protected: ' + parts.join(' · ');
  } else {
    prot.textContent = 'Not protected';
  }

  // another VPN (Proton VPN, say) claiming all DNS or traffic breaks ours
  const conflicts = (on && s.conflicts) || [];
  const warn = $('conflict-warn');
  warn.hidden = !conflicts.length;
  warn.textContent = conflicts.length ? `Another VPN is connected and DNS will fail. Disconnect it, then restart protection. (${conflicts.join('; ')})` : '';
}

async function toggleEngine(wantOn) {
  if (App.busy) return;
  if (wantOn === undefined) wantOn = !App.status;
  App.busy = true;
  $('start-error').hidden = true;
  renderHome();
  const r = wantOn ? await App.port.start() : await App.port.stop();
  App.busy = false;
  if (!r.ok) {
    const err = $('start-error');
    err.textContent = r.error + (r.log ? '\n\n' + r.log : '');
    err.hidden = false;
    if (App.stack[App.stack.length - 1].name !== 'home') toast(r.error);
  } else {
    App.restartNeeded = false;
  }
  await poll();
  App.render();
}

// ---------- polling ----------

async function poll() {
  const was = !!App.status;
  App.status = await App.port.status();
  if (was !== !!App.status) {
    App.events = [];
    App.lastEventId = 0;
  }
  const fresh = await App.port.events(App.lastEventId);
  if (fresh.length) {
    App.lastEventId = fresh[fresh.length - 1].id;
    App.events = App.events.concat(fresh.filter((e) => e.kind !== 'close')).slice(-1500);
  }
  renderHome();
  const top = App.stack[App.stack.length - 1].name;
  if (PAGE_TICK[top]) PAGE_TICK[top]();
  if (was !== !!App.status && top !== 'home') App.render();
}

// ---------- wiring ----------

async function main() {
  document.querySelectorAll('[data-icon]').forEach((e) => {
    e.innerHTML = ICONS[e.dataset.icon] || ''; // static icon markup only
  });
  document.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('click', () => App.root(b.dataset.nav)));
  document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => App.go(b.dataset.go)));
  $('start-main').addEventListener('click', () => toggleEngine());
  $('pause-btn').addEventListener('click', () => pauseProtection());
  $('mode-btn').addEventListener('click', () => chooseMode());
  $('kill-btn').addEventListener('click', () => setKillSwitch(!killSwitchOn()));
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !document.querySelector('.modal-back')) App.back();
  });

  App.settings = await App.port.getSettings();
  App.applyTheme();
  await poll();
  App.render();
  setInterval(poll, 1000);
  if (!App.settings.welcomed) showWelcome();
}

main();

// ---------- demo mode (no engine, e.g. opened in a browser) ----------

function demoPort() {
  let s = {
    dnsType: 'doh', doh: 'https://cloudflare-dns.com/dns-query', dohIps: '1.1.1.1,1.0.0.1', dohName: 'Cloudflare',
    dot: '', dotName: '', dnscrypt: '', dnscryptName: '', lastOtherType: 'doh', customDns: {},
    dnsDirect: false, dnsCache: false, dnssec: true, favicons: false, undelegated: false, dnsFallback: false, nrpt: true,
    fallbackDoh: 'https://cloudflare-dns.com/dns-query', fallbackIps: '1.1.1.1,1.0.0.1', fallbackName: 'Cloudflare',
    exit: 'masque', wgActive: '', socks: { host: '127.0.0.1', port: 1080, user: '', pass: '' }, http: { host: '', port: 8080, user: '', pass: '' },
    warpSni: '', exitSni: '', masqueFlags: '', warp1Flags: '', wgFlags: '', warp2Flags: '', warpAutoDisable: false,
    mode: 'both', full: true, killSwitch: false, allowLan: true,
    rules: { apps: { 'notepad.exe': { mode: 'block' } }, ips: [], domains: [{ domain: 'ads.example.com', action: 'block' }] },
    universal: { udp: false, icmp: true, http: false, unknown: false, dnsBypass: false, newApps: false, locked: false, lockdown: false },
    dnsTypesAuto: true, dnsTypes: [1, 28, 5, 65, 64, 45], knownApps: [], pausedUntil: 0,
    dialStrategy: 'never', dialRetry: '', dialTimeout: 0, tcpKeepAlive: false, eim: false,
    odoh: '', odohRelay: '', odohName: '', dnsProxy: '', dnsProxyName: '', dnscryptRelays: [],
    blocklistsLocal: false, localFlags: [], localStamp: '', remoteFlags: [], remoteStamp: '',
    history: true, logLevel: 3, notify: true, statusAlerts: true, theme: 'darkplus', autostart: false,
  };
  let running = false;
  let id = 0;
  let flows = 0;
  let queries = 0;
  const wgs = [];
  const apps = ['msedge.exe', 'chrome.exe', 'discord.exe', 'spotify.exe', 'svchost.exe', 'notepad.exe'];
  const doms = ['example.com', 'github.com', 'discord.gg', 'spotify.com', 'windowsupdate.com', 'cloudflare.com'];
  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  const reg = { warp1: { registered: true }, warp2: { registered: false }, wg0: { present: false, text: '' } };
  const isBlocked = (app) => (s.rules.apps[app] || {}).mode === 'block';
  let bl = false;
  return {
    getSettings: async () => ({ ...s }),
    setSettings: async (p) => (s = { ...s, ...p }),
    start: async () => ((running = true), { ok: true }),
    stop: async () => ((running = false), { ok: true }),
    cleanup: async () => ({ ok: true }),
    killSwitch: async (on) => ((s.killSwitch = !!on), { ok: true, applied: running ? 'now' : 'next start' }),
    status: async () => {
      if (!running) return null;
      flows += 3;
      queries += 2;
      return {
        version: 'demo', startedAt: Date.now(), mode: s.full ? 'full' : 'dns', nrpt: s.nrpt, killSwitch: s.killSwitch,
        exit: s.exit === 'none' ? '' : EXIT_LABEL[s.exit],
        dns: { server: s.doh, type: s.dnsType, queries, failed: 0, lastMs: 18, avgMs: 21 },
        firewall: { flows, blocked: Math.floor(flows / 9), blockedApps: apps.filter(isBlocked), appsSeen: 6 },
        traffic: { rx: flows * 48000, tx: flows * 9000 },
      };
    },
    events: async () => {
      if (!running) return [];
      const out = [];
      for (let i = 0; i < 3; i++) {
        const app = pick(apps);
        const dom = pick(doms);
        out.push({ id: ++id, at: Date.now(), kind: 'dns', domain: dom, answer: '104.16.0.1', latencyMs: 20, secure: dom.endsWith('.com'), qtype: 1 });
        out.push({ id: ++id, at: Date.now(), kind: 'flow', app, proto: 'tcp', dst: '104.16.0.1:443', domain: dom, via: 'Cloudflare WARP', blocked: isBlocked(app), rule: isBlocked(app) ? 'app blocked' : '', cid: String(id) });
      }
      return out;
    },
    stats: async () => ({
      history: true, rx: 5e7, tx: 9e6, flows: 1234,
      allowedApps: apps.map((a, i) => ({ name: a, n: 60 - i * 9, rx: 4e6 / (i + 1), tx: 6e5 / (i + 1), blocked: 0 })),
      blockedApps: [{ name: 'notepad.exe', n: 0, blocked: 12, rx: 0, tx: 0 }],
      domains: doms.map((d, i) => ({ name: d, n: 40 - i * 6, blocked: 0 })),
      blockedDomains: [{ name: 'ads.example.com', n: 9, blocked: 9 }],
    }),
    appStats: async () => ({ domains: doms.map((d, i) => ({ name: d, n: 30 - i * 4, blocked: 0 })), ips: [{ name: '104.16.0.1', n: 22, blocked: 0 }] }),
    block: async (app, b) => {
      const a = { ...s.rules.apps[app.toLowerCase()] };
      if (b) a.mode = 'block';
      else if (a.mode === 'block') delete a.mode;
      s.rules = { ...s.rules, apps: { ...s.rules.apps, [app.toLowerCase()]: a } };
      return { ...s };
    },
    setRules: async (p) => ((s = { ...s, ...p }), { settings: { ...s }, warnings: '' }),
    pause: async (m) => ((s = { ...s, pausedUntil: m ? Date.now() + m * 60000 : 0 }), { ...s }),
    proxies: async () => (running ? [{ id: 'masque', name: 'Cloudflare WARP (MASQUE)', status: 'connected', rx: 5e7, tx: 4e6, lastOK: Date.now() - 12000 }] : []),
    conns: async () => (running ? [{ cid: '1', app: 'chrome.exe', proto: 'tcp', dst: '104.16.0.1:443', domain: 'github.com', since: Date.now() - 5000 }] : []),
    closeConns: async () => ({ closed: running ? 1 : 0 }),
    blocklists: {
      status: async () => ({ local: bl ? { timestamp: Date.now() - 864e5, size: 61e6 } : null, filetag: true, job: null }),
      filetag: async () => ({
        ok: true,
        lists: [
          { value: 0, vname: 'OISD (full)', group: 'privacy', subg: '', entries: 260000, pack: ['liteprivacy'], level: [0] },
          { value: 3, vname: 'AdGuard DNS filter', group: 'privacy', subg: 'rethinkdns-recommended', entries: 70000, pack: ['recommended'], level: [0] },
          { value: 17, vname: '1Hosts (Pro)', group: 'privacy', subg: '', entries: 400000, pack: ['aggressiveprivacy'], level: [1] },
          { value: 95, vname: 'URLhaus', group: 'security', subg: 'threat-intelligence-feeds', entries: 3000, pack: ['malware'], level: [0] },
          { value: 103, vname: 'Phishing Army', group: 'security', subg: 'threat-intelligence-feeds', entries: 140000, pack: ['scams & phishing'], level: [1] },
          { value: 146, vname: 'StevenBlack Porn', group: 'parentalcontrol', subg: 'porn', entries: 76000, pack: ['adult'], level: [0] },
          { value: 170, vname: 'Gambling list', group: 'parentalcontrol', subg: 'gambling', entries: 9000, pack: ['gambling'], level: [2] },
        ],
      }),
      download: async () => ((bl = true), { ok: true }),
      latest: async () => ({ ok: true, timestamp: Date.now() }),
      remove: async () => ((bl = false), { ok: true }),
    },
    usque: {
      status: async () => reg,
      register: async (w) => ((reg[w].registered = true), { ok: true }),
      readConfig: async () => '{\n  "private_key": "(demo)"\n}',
      saveConfig: async () => ({ ok: true }),
      saveWg0: async (t) => ((reg.wg0 = { present: !!t.trim(), text: t }), { ok: true }),
      importWg0: async () => ({}),
    },
    wg: {
      list: async () => wgs,
      get: async (i) => wgs.find((w) => w.id === i),
      save: async (w) => {
        const id2 = w.id || String(Date.now());
        const i = wgs.findIndex((x) => x.id === id2);
        const e = { id: id2, name: w.name || 'WireGuard', text: w.text, endpoint: '' };
        if (i >= 0) wgs[i] = e;
        else wgs.push(e);
        return { id: id2 };
      },
      remove: async (i) => wgs.splice(wgs.findIndex((w) => w.id === i), 1),
      importFile: async () => ({}),
    },
    checkExit: async () => ({ ip: '104.28.0.1', loc: 'DE', colo: 'FRA', warp: 'on' }),
    ping: async () => ({ ip: { ok: true, ms: 18 }, host: { ok: true, ms: 9, answer: '142.250.74.36' }, url: { ok: false, ms: 10000, error: 'timed out' } }),
    checkUpdate: async () => ({ ok: true, current: '0.1.0', latest: '', newer: false }),
    engineLog: async () => 'usque: demo log line',
    clearLog: async () => {},
    copy: async () => {},
    backup: async () => ({ ok: true }),
    restore: async () => ({ ok: false }),
    setAutostart: async () => {},
    openUrl: async () => {},
    openLog: async () => {},
    debugZip: async () => ({ ok: true }),
  };
}
