// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Electron main process. The window has no Node access; it asks this process
// (through preload.js) to start and stop the engine (fswin.exe), to call the
// engine's loopback control API, and to manage files: WARP identities (usque),
// WireGuard configs, stats history, backups. The engine needs admin rights,
// so it is started through a UAC prompt; this process and the window never are.

'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, Menu, Tray, nativeImage, Notification, clipboard, net, powerMonitor } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const http = require('node:http');
const { execFile } = require('node:child_process');

const API_HOST = '127.0.0.1';
const API_PORT = 47897;
const HOUR = 3600 * 1000;

const DEFAULTS = {
  // DNS (Android: DNS screen)
  dnsType: 'doh', // doh | rdns | dot | dnscrypt | system
  doh: 'https://cloudflare-dns.com/dns-query',
  dohIps: '1.1.1.1,1.0.0.1',
  dohName: 'Cloudflare',
  dot: '',
  dotName: '',
  dnscrypt: '',
  dnscryptName: '',
  odoh: '',
  odohRelay: '',
  odohName: '',
  dnsProxy: '',
  dnsProxyName: '',
  dnscryptRelays: [], // relay stamps
  lastOtherType: 'doh',
  customDns: {},
  // RethinkDNS blocklists: on-device (downloaded) and on the server (stamp in the URL)
  blocklistsLocal: false,
  localFlags: [],
  localStamp: '',
  remoteFlags: [],
  remoteStamp: '',
  dnsDirect: false,
  dnsCache: false, // "DNS booster"
  dnssec: true, // block bogus answers, as on Android
  favicons: false, // website icons in DNS logs, from DuckDuckGo
  undelegated: false,
  dnsFallback: false,
  nrpt: true,
  fallbackDoh: 'https://cloudflare-dns.com/dns-query',
  fallbackIps: '1.1.1.1,1.0.0.1',
  fallbackName: 'Cloudflare',
  // Proxy (Android: Proxy and Chain mode screens); one exit at a time
  exit: 'none', // none | masque | chain | warp | wg | socks | http
  wgActive: '',
  socks: { host: '127.0.0.1', port: 1080, user: '', pass: '' },
  http: { host: '', port: 8080, user: '', pass: '' },
  warpSni: '',
  exitSni: '',
  masqueFlags: '',
  warp1Flags: '',
  wgFlags: '',
  warp2Flags: '',
  warpAutoDisable: false,
  // Network and firewall
  mode: 'both', // dns | firewall | both (Android: "Choose mode")
  full: true,
  killSwitch: false,
  allowLan: true,
  // Firewall rules (Android: App info, Universal firewall, IP & domain rules)
  rules: { apps: {}, ips: [], domains: [] },
  universal: { udp: false, icmp: true, http: false, unknown: false, dnsBypass: false, newApps: false, locked: false, lockdown: false },
  dnsTypesAuto: true,
  dnsTypes: [1, 28, 5, 65, 64, 45], // A, AAAA, CNAME, HTTPS, SVCB, IPSECKEY: Android's defaults
  knownApps: [],
  pausedUntil: 0,
  // Anti-censorship and sockets (Network)
  dialStrategy: 'never', // never | auto | split-tcp | split-tls
  dialRetry: '',
  dialTimeout: 0,
  tcpKeepAlive: false,
  eim: false,
  // Settings
  history: true,
  logLevel: 3,
  notify: true,
  statusAlerts: true,
  theme: 'darkplus',
  autostart: false,
  wasRunning: false,
};

let win = null;
let tray = null;
let token = null;
let quitting = false;
let lastStatus = null;

const dataDir = () => app.getPath('userData');
const tokenFile = () => path.join(dataDir(), 'api-token');
const settingsFile = () => path.join(dataDir(), 'settings.json');
const logFile = () => path.join(dataDir(), 'engine.log');
const usqueDir = () => path.join(dataDir(), 'usque');
const usqueLog = () => path.join(usqueDir(), 'usque.log');
const wgDir = () => path.join(dataDir(), 'wireguard');
const histDir = () => path.join(dataDir(), 'history');
const rulesFile = () => path.join(dataDir(), 'rules.json');

function enginePath() {
  if (app.isPackaged) return path.join(process.resourcesPath, 'engine', 'fswin.exe');
  return process.env.FSWIN_PATH || path.join(__dirname, 'engine', 'fswin.exe');
}

function usquePath() {
  return path.join(path.dirname(enginePath()), 'usque.exe');
}

// ---------- settings ----------

function readSettings() {
  let s;
  try {
    const raw = JSON.parse(fs.readFileSync(settingsFile(), 'utf8'));
    if (!('mode' in raw)) raw.mode = raw.full === false ? 'dns' : 'both'; // before modes
    s = { ...DEFAULTS, ...raw };
  } catch {
    s = { ...DEFAULTS };
  }
  return migrate(s);
}

function writeSettings(s) {
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(settingsFile(), JSON.stringify(s, null, 2));
}

// Settings from 0.1.0: exit "proxy" with a URL, and a single wgFile.
function migrate(s) {
  let changed = false;
  if (s.exit === 'proxy' && s.proxy) {
    try {
      const u = new URL(s.proxy);
      const kind = u.protocol === 'http:' ? 'http' : 'socks';
      s[kind] = { host: u.hostname, port: Number(u.port) || (kind === 'http' ? 8080 : 1080), user: decodeURIComponent(u.username), pass: decodeURIComponent(u.password) };
      s.exit = kind;
    } catch {
      s.exit = 'none';
    }
    changed = true;
  }
  if (s.wgFile) {
    try {
      const text = fs.readFileSync(s.wgFile, 'utf8');
      if (s.exit === 'chain' && !fs.existsSync(path.join(usqueDir(), 'wg0.conf'))) {
        fs.mkdirSync(usqueDir(), { recursive: true });
        fs.writeFileSync(path.join(usqueDir(), 'wg0.conf'), text);
      } else if (s.exit === 'wg') {
        s.wgActive = wgSave({ name: path.basename(s.wgFile, '.conf'), text }).id || '';
      }
    } catch {
      // the old file is gone
    }
    changed = true;
  }
  if (changed) {
    delete s.proxy;
    delete s.wgFile;
    if (s.exit === 'proxy') s.exit = 'none';
    try {
      writeSettings(s);
    } catch {
      // read-only; try again next time
    }
  }
  // 0.1: a list of blocked apps; now a mode per app
  if (Array.isArray(s.blocked)) {
    s.rules = { ...DEFAULTS.rules, ...s.rules, apps: { ...(s.rules && s.rules.apps) } };
    for (const name of s.blocked) s.rules.apps[String(name).toLowerCase()] = { ...s.rules.apps[name], mode: 'block' };
    delete s.blocked;
    try {
      writeSettings(s);
    } catch {
      // read-only; try again next time
    }
  }
  s.rules = { apps: {}, ips: [], domains: [], ...s.rules };
  s.universal = { ...DEFAULTS.universal, ...s.universal };
  for (const k of ['knownApps', 'dnscryptRelays', 'localFlags', 'remoteFlags']) if (!Array.isArray(s[k])) s[k] = [];
  return s;
}

// ---------- firewall rules ----------

let screenLocked = false;

// The rule set fswin applies (cmd/fswin/rules_windows.go).
function ruleSet(s) {
  return {
    apps: s.rules.apps,
    ips: s.rules.ips,
    domains: s.rules.domains,
    universal: s.universal,
    known: s.knownApps,
    dnsTypes: s.dnsTypesAuto ? [] : s.dnsTypes,
    pausedUntil: s.pausedUntil > Date.now() ? s.pausedUntil : 0,
    screenLocked,
  };
}

function writeRules(s) {
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(rulesFile(), JSON.stringify(ruleSet(s)));
}

// Rules apply at once: the file for the next start, the API for now.
async function pushRules(s) {
  writeRules(s);
  try {
    const r = await api('POST', '/api/rules', ruleSet(s));
    return { ok: true, warnings: r.warnings || '' };
  } catch {
    return { ok: true, warnings: '' }; // not running; applies on next start
  }
}

const RULE_KEYS = ['rules', 'universal', 'dnsTypesAuto', 'dnsTypes', 'knownApps', 'pausedUntil'];

// Apps seen for the first time: remembered, and blocked when "Block newly
// installed apps" is on (fswin already blocked them; this makes it a rule
// the user can see and undo).
function learnApps(evs) {
  let s = null;
  let known = null;
  const fresh = [];
  for (const e of evs) {
    if (e.kind !== 'flow' || !e.app || e.app === '?' || /^pid\d+$/.test(e.app)) continue;
    if (!s) {
      s = readSettings();
      known = new Set(s.knownApps);
    }
    const name = e.app.toLowerCase();
    if (known.has(name)) continue;
    known.add(name);
    fresh.push({ name, blocked: e.rule === 'universal: new app' });
  }
  if (!fresh.length) return;
  s.knownApps = [...known].sort();
  const blocked = fresh.filter((f) => f.blocked && !s.rules.apps[f.name]);
  for (const f of blocked) s.rules.apps[f.name] = { mode: 'block' };
  writeSettings(s);
  writeRules(s);
  if (blocked.length) {
    pushRules(s);
    if (s.notify) notify(`New app blocked: ${blocked.map((f) => f.name).join(', ')}. Allow it in Apps.`);
  }
}


// ---------- RethinkDNS blocklists (Android: "Configure 195+ blocklists") ----------

const blDir = () => path.join(dataDir(), 'blocklists');
const BL_BASE = 'https://dl.rethinkdns.com';
// what the Android app downloads; "?compressed" is served brotli-encoded
const BL_FILES = [
  ['basicconfig', 'basicconfig.json', 'cfgmd5'],
  ['blocklists', 'filetag.json', 'ftmd5'],
  ['rank?compressed', 'rd.txt', 'rdmd5'],
  ['trie?compressed', 'td.txt', 'tdmd5'],
];
const BL_NEEDED = ['td.txt', 'rd.txt', 'basicconfig.json', 'filetag.json'];
let blJob = null; // { file, done, total } while downloading; { error } after a failure

// The newest complete on-device download, or ''.
function blLocalDir() {
  const root = path.join(blDir(), 'local');
  try {
    const dirs = fs.readdirSync(root).filter((d) => /^\d+$/.test(d)).sort((a, b) => Number(b) - Number(a));
    for (const d of dirs) {
      const p = path.join(root, d);
      if (BL_NEEDED.every((f) => fs.existsSync(path.join(p, f)))) return p;
    }
  } catch {
    // nothing downloaded
  }
  return '';
}

async function fetchTo(url, file, onBytes) {
  const res = await net.fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const total = Number(res.headers.get('content-length')) || 0;
  const out = fs.createWriteStream(file);
  const hash = crypto.createHash('md5');
  const reader = res.body.getReader();
  let done = 0;
  try {
    for (;;) {
      const { value, done: end } = await reader.read();
      if (end) break;
      const buf = Buffer.from(value);
      hash.update(buf);
      done += buf.length;
      onBytes(done, total);
      if (!out.write(buf)) await new Promise((r) => out.once('drain', r));
    }
  } finally {
    await new Promise((r) => out.end(r));
  }
  return hash.digest('hex');
}

// basicconfig's timestamp looks like "2026/1790903143399".
function blTimestamp(cfg) {
  const m = /(\d{10,})/.exec(String(cfg.timestamp || ''));
  return m ? m[1] : '';
}

async function blLatest() {
  const res = await net.fetch(`${BL_BASE}/basicconfig`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return blTimestamp(await res.json());
}

function blStatus() {
  const dir = blLocalDir();
  let size = 0;
  if (dir) for (const f of BL_NEEDED) size += fs.statSync(path.join(dir, f)).size;
  return {
    local: dir ? { timestamp: Number(path.basename(dir)), size } : null,
    filetag: fs.existsSync(path.join(blDir(), 'filetag.json')),
    job: blJob,
  };
}

// Only the filetag (the list of lists, ~50 KB), for RethinkDNS servers.
async function blFiletag() {
  const f = path.join(blDir(), 'filetag.json');
  if (!fs.existsSync(f)) {
    fs.mkdirSync(blDir(), { recursive: true });
    await fetchTo(`${BL_BASE}/blocklists`, f + '.part', () => {});
    fs.renameSync(f + '.part', f);
  }
  const ft = JSON.parse(fs.readFileSync(f, 'utf8'));
  return Object.values(ft).map((v) => ({
    value: v.value,
    vname: v.vname,
    group: v.group,
    subg: v.subg,
    url: Array.isArray(v.url) ? v.url[0] : v.url,
    entries: v.entries,
    pack: v.pack || [],
    level: v.level || [],
  }));
}

async function blDownload() {
  if (blJob && !blJob.error) return { ok: false, error: 'Already downloading' };
  blJob = { file: 'basicconfig.json', done: 0, total: 0 };
  const tmp = path.join(blDir(), 'tmp-' + Date.now());
  try {
    fs.mkdirSync(tmp, { recursive: true });
    const sums = {};
    for (const [u, f, key] of BL_FILES) {
      blJob = { file: f, done: 0, total: 0 };
      sums[key] = await fetchTo(`${BL_BASE}/${u}`, path.join(tmp, f), (d, t) => {
        blJob.done = d;
        blJob.total = t;
      });
    }
    const cfg = JSON.parse(fs.readFileSync(path.join(tmp, 'basicconfig.json'), 'utf8'));
    for (const [, f, key] of BL_FILES) {
      if (cfg[key] && cfg[key] !== sums[key]) throw new Error(`${f}: integrity check failed; try again`);
    }
    const ts = blTimestamp(cfg) || String(Date.now());
    const dest = path.join(blDir(), 'local', ts);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.rmSync(dest, { recursive: true, force: true });
    fs.renameSync(tmp, dest);
    fs.copyFileSync(path.join(dest, 'filetag.json'), path.join(blDir(), 'filetag.json'));
    for (const d of fs.readdirSync(path.dirname(dest))) {
      if (d === ts) continue;
      try {
        fs.rmSync(path.join(path.dirname(dest), d), { recursive: true, force: true });
      } catch {
        // still loaded by a running engine; removed next time
      }
    }
    blJob = null;
    return { ok: true, timestamp: Number(ts) };
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    blJob = { error: e.message };
    return { ok: false, error: e.message };
  }
}

// ---------- engine API ----------

// The token stays the same while an engine may be running, so a reopened
// window can still talk to it.
function ensureToken() {
  if (token) return token;
  try {
    token = fs.readFileSync(tokenFile(), 'utf8').trim();
  } catch {
    token = '';
  }
  if (token.length < 32) {
    token = crypto.randomBytes(32).toString('hex');
    fs.mkdirSync(dataDir(), { recursive: true });
    fs.writeFileSync(tokenFile(), token, { mode: 0o600 });
  }
  return token;
}

function api(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const headers = { Authorization: 'Bearer ' + ensureToken() };
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    const req = http.request({ host: API_HOST, port: API_PORT, method, path: urlPath, headers, timeout: 3000 }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (buf += c));
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`${res.statusCode} ${buf.trim()}`));
        try {
          resolve(JSON.parse(buf));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function engineStatus() {
  try {
    return await api('GET', '/api/status');
  } catch {
    return null;
  }
}

const split = (s) => String(s || '').split(/\s+/).filter(Boolean);

function masqueFlags(s) {
  const sni = s.warpSni || 'consumer-masque.cloudflareclient.com';
  const out = s.warpSni ? ['-s', s.warpSni] : [];
  return out.concat(split(s.masqueFlags.replaceAll('{sni}', sni))).join(' ');
}

function chainFlags(s) {
  const sni = s.warpSni || 'consumer-masque.cloudflareclient.com';
  const xsni = s.exitSni || 'consumer-masque.cloudflareclient.com';
  const out = s.warpSni ? ['-s', s.warpSni] : [];
  out.push(...split(s.warp1Flags.replaceAll('{sni}', sni)), ...split(s.wgFlags));
  if (s.exitSni) out.push('--exit-sni', s.exitSni);
  out.push(...split(s.warp2Flags.replaceAll('{exit_sni}', xsni)));
  return out.join(' ');
}

function proxyURL(kind, p) {
  const auth = p.user ? `${encodeURIComponent(p.user)}:${encodeURIComponent(p.pass || '')}@` : '';
  return `${kind === 'http' ? 'http' : 'socks5'}://${auth}${p.host}:${p.port}`;
}

function engineArgs(s) {
  const a = [
    '-api', `${API_HOST}:${API_PORT}`,
    '-token-file', tokenFile(),
    '-logfile', logFile(),
    '-warp-file', path.join(dataDir(), 'warp.json'),
    '-log', String(s.logLevel),
    '-fallback-doh', s.fallbackDoh,
    '-fallback-ips', s.fallbackIps,
  ];
  // Firewall mode leaves DNS to the network adapter's servers, as on Android
  const type = s.mode === 'firewall' ? 'system' : s.dnsType === 'rdns' ? 'doh' : s.dnsType;
  a.push('-dns', type);
  if (type === 'doh') a.push('-doh', s.doh, '-doh-ips', s.dohIps || '');
  if (type === 'dot') a.push('-dot', s.dot);
  if (type === 'dnscrypt') {
    a.push('-dnscrypt', s.dnscrypt);
    if (s.dnscryptRelays.length) a.push('-dnscrypt-relays', s.dnscryptRelays.join(','));
  }
  if (type === 'odoh') {
    a.push('-odoh', s.odoh);
    if (s.odohRelay) a.push('-odoh-relay', s.odohRelay);
  }
  if (type === 'proxy') a.push('-dns-proxy', s.dnsProxy);
  const bl = blLocalDir();
  if (s.blocklistsLocal && s.localStamp && bl) a.push('-blocklists', bl, '-blocklist-stamp', s.localStamp);
  if (fs.existsSync(path.join(blDir(), 'filetag.json'))) a.push('-filetag', path.join(blDir(), 'filetag.json'));
  if (s.dnsDirect) a.push('-dns-direct');
  if (s.dnsCache) a.push('-dns-cache');
  if (s.dnssec) a.push('-dnssec');
  if (s.undelegated) a.push('-undelegated');
  if (s.dnsFallback) a.push('-dns-fallback');
  if (s.mode !== 'dns') a.push('-full');
  if (s.nrpt) a.push('-nrpt');
  if (s.killSwitch) {
    a.push('-killswitch');
    if (s.allowLan) a.push('-allow-lan');
  }
  switch (s.exit) {
    case 'masque':
      a.push('-masque', '-usque-dir', usqueDir());
      if (masqueFlags(s)) a.push('-usque-flags', masqueFlags(s));
      break;
    case 'chain':
      a.push('-chain', path.join(usqueDir(), 'wg0.conf'), '-usque-dir', usqueDir());
      if (chainFlags(s)) a.push('-usque-flags', chainFlags(s));
      break;
    case 'warp':
      a.push('-warp');
      break;
    case 'wg': {
      const f = wgFile(s.wgActive);
      if (f) a.push('-wg', f);
      break;
    }
    case 'socks':
    case 'http':
      if (s[s.exit].host) a.push('-proxy', proxyURL(s.exit, s[s.exit]));
      break;
  }
  writeRules(s);
  a.push('-rules', rulesFile());
  a.push('-dial-strategy', s.dialStrategy || 'never');
  if (s.dialRetry) a.push('-dial-retry', s.dialRetry);
  if (s.dialTimeout > 0) a.push('-dial-timeout', String(s.dialTimeout));
  if (s.tcpKeepAlive) a.push('-tcp-keepalive');
  if (s.eim) a.push('-eim');
  return a;
}

// Quote one argument for the Windows command line (CommandLineToArgvW rules).
function winQuote(arg) {
  if (arg !== '' && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let slashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      slashes++;
    } else if (ch === '"') {
      out += '\\'.repeat(slashes * 2 + 1) + '"';
      slashes = 0;
    } else {
      out += '\\'.repeat(slashes) + ch;
      slashes = 0;
    }
  }
  return out + '\\'.repeat(slashes * 2) + '"';
}

const psQuote = (s) => "'" + s.replace(/'/g, "''") + "'";

function launchElevated(exe, args) {
  const cmd = `Start-Process -FilePath ${psQuote(exe)} -Verb RunAs -WindowStyle Hidden -ArgumentList ${psQuote(args.map(winQuote).join(' '))}`;
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { windowsHide: true }, (err, _stdout, stderr) => {
      if (!err) return resolve();
      const msg = String(stderr || err.message);
      reject(new Error(/cancel/i.test(msg) ? 'Admin permission was declined.' : msg.trim()));
    });
  });
}

function lastLogLines(n) {
  try {
    const lines = fs.readFileSync(logFile(), 'utf8').trim().split(/\r?\n/);
    return lines.slice(-n).join('\n');
  } catch {
    return '';
  }
}

let expectedStop = false;

async function startEngine() {
  if (await engineStatus()) return { ok: true };
  const exe = enginePath();
  if (!fs.existsSync(exe)) return { ok: false, error: `Engine not found at ${exe}` };
  const s = readSettings();
  if (s.exit === 'chain' && !fs.existsSync(path.join(usqueDir(), 'wg0.conf'))) return { ok: false, error: 'Chain mode needs a wg0.conf (Proxy → Chain mode).' };
  if (s.exit === 'wg' && !wgFile(s.wgActive)) return { ok: false, error: 'Choose a WireGuard config first (Proxy → Setup WireGuard).' };
  ensureToken();
  logOffset = 0;
  try {
    await launchElevated(exe, engineArgs(s));
  } catch (e) {
    return { ok: false, error: e.message };
  }
  // WARP registration and the usque chain can take a while on first use
  for (let i = 0; i < 120; i++) {
    await new Promise((r) => setTimeout(r, 500));
    if (await engineStatus()) {
      writeSettings({ ...readSettings(), wasRunning: true });
      return { ok: true };
    }
  }
  return { ok: false, error: 'The engine did not start.', log: lastLogLines(15) };
}

async function stopEngine(byUser = true) {
  expectedStop = true;
  try {
    await api('POST', '/api/stop');
  } catch {
    return { ok: true }; // not running
  }
  if (byUser) writeSettings({ ...readSettings(), wasRunning: false });
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 250));
    if (!(await engineStatus())) return { ok: true };
  }
  return { ok: false, error: 'The engine is still running.' };
}

// ---------- WARP identities and wg0 for usque ----------

function usqueFile(which) {
  if (which !== 'warp1' && which !== 'warp2') throw new Error('bad identity');
  return path.join(usqueDir(), which + '.json');
}

function registered(which) {
  try {
    return !!JSON.parse(fs.readFileSync(usqueFile(which), 'utf8')).private_key;
  } catch {
    return false;
  }
}

function usqueStatus() {
  let wg0 = '';
  try {
    wg0 = fs.readFileSync(path.join(usqueDir(), 'wg0.conf'), 'utf8');
  } catch {
    // none yet
  }
  return { warp1: { registered: registered('warp1') }, warp2: { registered: registered('warp2') }, wg0: { present: !!wg0.trim(), text: wg0 } };
}

function appendUsqueLog(text) {
  try {
    fs.mkdirSync(usqueDir(), { recursive: true });
    fs.appendFileSync(usqueLog(), `${new Date().toISOString()} ${text.trim()}\n`);
  } catch {
    // best effort
  }
}

function usqueRegister(which, force) {
  return new Promise((resolve) => {
    const exe = usquePath();
    if (!fs.existsSync(exe)) return resolve({ ok: false, error: `usque.exe not found at ${exe}` });
    const file = usqueFile(which);
    fs.mkdirSync(usqueDir(), { recursive: true });
    if (fs.existsSync(file)) {
      if (!force) return resolve({ ok: true });
      fs.renameSync(file, file + '.bak');
    }
    appendUsqueLog(`register ${which}: start`);
    execFile(exe, ['-c', file, 'register', '--accept-tos'], { cwd: usqueDir(), windowsHide: true, timeout: 60000 }, (err, stdout, stderr) => {
      appendUsqueLog(`register ${which}: ${err ? 'failed: ' + err.message : 'done'}\n${stdout}${stderr}`);
      const ok = registered(which);
      if (!ok && force && fs.existsSync(file + '.bak')) fs.renameSync(file + '.bak', file);
      resolve({ ok, error: ok ? '' : 'Registration failed — see the log.' });
    });
  });
}

function validWg(text, needEndpoint) {
  const t = String(text || '');
  if (!/^\s*\[Interface\]/im.test(t) || !/^\s*PrivateKey\s*=/im.test(t) || !/^\s*\[Peer\]/im.test(t) || !/^\s*PublicKey\s*=/im.test(t)) return false;
  if (/^\s*(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)\s*=/im.test(t)) return false; // AmneziaWG
  return !needEndpoint || /^\s*Endpoint\s*=/im.test(t);
}

async function openConf(title) {
  const r = await dialog.showOpenDialog(win, { title, filters: [{ name: 'WireGuard config', extensions: ['conf'] }], properties: ['openFile'] });
  if (r.canceled) return null;
  const p = r.filePaths[0];
  return { name: path.basename(p, path.extname(p)), text: fs.readFileSync(p, 'utf8') };
}

// ---------- WireGuard configs ----------

function wgIndex() {
  try {
    return JSON.parse(fs.readFileSync(path.join(wgDir(), 'index.json'), 'utf8'));
  } catch {
    return [];
  }
}

function wgFile(id) {
  if (!/^[a-f0-9]{16}$/.test(String(id))) return '';
  const f = path.join(wgDir(), id + '.conf');
  return fs.existsSync(f) ? f : '';
}

function wgSave({ id, name, text }) {
  if (!validWg(text, true)) return { error: 'Invalid config: needs [Interface] PrivateKey and a [Peer] with PublicKey and Endpoint (plain WireGuard; AmneziaWG is not supported)' };
  fs.mkdirSync(wgDir(), { recursive: true });
  const idx = wgIndex();
  if (!id || !wgFile(id)) id = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(path.join(wgDir(), id + '.conf'), text, { mode: 0o600 });
  const entry = { id, name: name || 'WireGuard' };
  const i = idx.findIndex((e) => e.id === id);
  if (i >= 0) idx[i] = entry;
  else idx.push(entry);
  fs.writeFileSync(path.join(wgDir(), 'index.json'), JSON.stringify(idx, null, 2));
  return { id, name: entry.name };
}

function wgList() {
  return wgIndex()
    .filter((e) => wgFile(e.id))
    .map((e) => {
      const m = /^\s*Endpoint\s*=\s*(\S+)/im.exec(fs.readFileSync(wgFile(e.id), 'utf8'));
      return { id: e.id, name: e.name, endpoint: m ? m[1] : '' };
    });
}

// ---------- history: events and hourly stats (Stats and Logs screens) ----------

const hist = { buf: [], seq: 0, engineLast: 0, engineStarted: 0, buckets: new Map(), dirty: false };

function loadBuckets() {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(histDir(), 'buckets.json'), 'utf8'));
    for (const [k, v] of Object.entries(raw)) hist.buckets.set(Number(k), v);
  } catch {
    // no history yet
  }
}

function bucket(at) {
  const k = Math.floor(at / HOUR) * HOUR;
  let b = hist.buckets.get(k);
  if (!b) {
    b = { rx: 0, tx: 0, flows: 0, apps: {}, domains: {} };
    hist.buckets.set(k, b);
  }
  return b;
}

function addEvent(e) {
  const b = bucket(e.at);
  const app = (b.apps[e.app || '?'] ||= { n: 0, blocked: 0, rx: 0, tx: 0 });
  if (e.kind === 'flow') {
    b.flows++;
    if (e.blocked) app.blocked++;
    else app.n++;
    if (e.blocked && e.domain) (b.domains[e.domain] ||= { n: 0, blocked: 0 }).blocked++;
  } else if (e.kind === 'dns' && e.domain) {
    const d = (b.domains[e.domain] ||= { n: 0, blocked: 0 });
    d.n++;
    if (e.blocked) d.blocked++;
  } else if (e.kind === 'close') {
    app.rx += e.rx || 0;
    app.tx += e.tx || 0;
    b.rx += e.rx || 0;
    b.tx += e.tx || 0;
  }
  hist.dirty = true;
}

async function pumpEvents(st, s) {
  if (!st) return;
  if (st.startedAt !== hist.engineStarted) {
    hist.engineStarted = st.startedAt;
    hist.engineLast = 0;
  }
  let evs;
  try {
    evs = await api('GET', `/api/events?after=${hist.engineLast}&max=1000`);
  } catch {
    return;
  }
  learnApps(evs);
  const lines = [];
  for (const e of evs) {
    hist.engineLast = e.id;
    const m = { ...e, id: ++hist.seq };
    hist.buf.push(m);
    addEvent(m);
    if (s.history && m.kind !== 'close') lines.push(JSON.stringify(m));
  }
  if (hist.buf.length > 3000) hist.buf.splice(0, hist.buf.length - 3000);
  if (lines.length) {
    const day = new Date().toISOString().slice(0, 10);
    fs.mkdir(histDir(), { recursive: true }, () => fs.appendFile(path.join(histDir(), `events-${day}.jsonl`), lines.join('\n') + '\n', () => {}));
  }
}

function stats(range) {
  const hours = range === '7d' ? 168 : range === '24h' ? 24 : 1;
  const cutoff = Date.now() - hours * HOUR;
  const apps = {};
  const domains = {};
  let rx = 0;
  let tx = 0;
  let flows = 0;
  for (const [k, b] of hist.buckets) {
    if (k + HOUR <= cutoff) continue;
    rx += b.rx;
    tx += b.tx;
    flows += b.flows;
    for (const [name, a] of Object.entries(b.apps)) {
      const t = (apps[name] ||= { n: 0, blocked: 0, rx: 0, tx: 0 });
      t.n += a.n;
      t.blocked += a.blocked;
      t.rx += a.rx;
      t.tx += a.tx;
    }
    for (const [name, d] of Object.entries(b.domains)) {
      const t = (domains[name] ||= { n: 0, blocked: 0 });
      t.n += d.n;
      t.blocked += d.blocked;
    }
  }
  const list = (obj, keep, key) =>
    Object.entries(obj)
      .map(([name, v]) => ({ name, ...v }))
      .filter((x) => x.name !== '?' && keep(x))
      .sort((a, b) => key(b) - key(a))
      .slice(0, 50);
  return {
    history: readSettings().history,
    rx,
    tx,
    flows,
    allowedApps: list(apps, (a) => a.n > 0, (a) => a.rx + a.tx + a.n),
    blockedApps: list(apps, (a) => a.blocked > 0, (a) => a.blocked),
    domains: list(domains, (d) => d.n > 0, (d) => d.n),
    blockedDomains: list(domains, (d) => d.blocked > 0, (d) => d.blocked),
  };
}

// Most contacted domains and IPs of one app, from recent events (memory and
// the last two days of event files), for App info.
function appStats(appName) {
  const want = String(appName || '').toLowerCase();
  const domains = {};
  const ips = {};
  const seen = new Set();
  const take = (e) => {
    if (e.kind !== 'flow' || String(e.app || '').toLowerCase() !== want) return;
    const key = `${e.at}|${e.dst}|${e.cid || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    const ip = String(e.dst || '').replace(/^\[?([^\]]+?)\]?:\d+$/, '$1');
    for (const [obj, name] of [[domains, e.domain], [ips, ip]]) {
      if (!name) continue;
      const t = (obj[name] ||= { n: 0, blocked: 0 });
      t.n++;
      if (e.blocked) t.blocked++;
    }
  };
  for (let d = 1; d >= 0; d--) {
    const day = new Date(Date.now() - d * 24 * HOUR).toISOString().slice(0, 10);
    try {
      const text = fs.readFileSync(path.join(histDir(), `events-${day}.jsonl`), 'utf8');
      if (text.length > 64 * 1024 * 1024) continue;
      for (const line of text.split(/\r?\n/)) {
        if (!line || !line.toLowerCase().includes(want)) continue;
        try {
          take(JSON.parse(line));
        } catch {
          // a torn line
        }
      }
    } catch {
      // no file that day
    }
  }
  for (const e of hist.buf) take(e);
  const top = (obj) => Object.entries(obj).map(([name, v]) => ({ name, ...v })).sort((a, b) => b.n + b.blocked - (a.n + a.blocked)).slice(0, 30);
  return { domains: top(domains), ips: top(ips) };
}

function saveBuckets(s) {
  const cutoff = Date.now() - 168 * HOUR;
  for (const k of hist.buckets.keys()) if (k < cutoff) hist.buckets.delete(k);
  if (!s.history || !hist.dirty) return;
  hist.dirty = false;
  const trim = (obj, n, key) => Object.fromEntries(Object.entries(obj).sort((a, b) => key(b[1]) - key(a[1])).slice(0, n));
  const out = {};
  for (const [k, b] of hist.buckets) {
    out[k] = { ...b, apps: trim(b.apps, 300, (a) => a.n + a.blocked + a.rx), domains: trim(b.domains, 1000, (d) => d.n + d.blocked) };
  }
  fs.mkdir(histDir(), { recursive: true }, () => fs.writeFile(path.join(histDir(), 'buckets.json'), JSON.stringify(out), () => {}));
  // keep a week of raw event files
  fs.readdir(histDir(), (err, files) => {
    if (err) return;
    const oldest = new Date(cutoff).toISOString().slice(0, 10);
    for (const f of files) {
      const m = /^events-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(f);
      if (m && m[1] < oldest) fs.unlink(path.join(histDir(), f), () => {});
    }
  });
}

// ---------- notifications and the status loop ----------

function notify(body) {
  if (Notification.isSupported()) new Notification({ title: 'port1897', body, icon: path.join(__dirname, 'build', 'icon.png') }).show();
}

let autoDisabledFor = 0;

async function statusLoop() {
  const st = await engineStatus();
  const s = readSettings();
  const was = !!lastStatus;
  lastStatus = st;
  updateTray(st);
  if (was && !st) {
    if (!expectedStop && s.notify) notify('Protection stopped unexpectedly.' + (s.killSwitch ? ' The kill switch keeps the internet blocked until you start it again.' : ''));
    else if (s.statusAlerts) notify('Protection is off.');
  } else if (!was && st && s.statusAlerts) {
    notify('Protected' + (st.exit ? ` via ${st.exit}` : '') + '.');
  }
  if (!st) expectedStop = false;
  await pumpEvents(st, s);

  if (st && s.warpAutoDisable && (s.exit === 'masque' || s.exit === 'warp') && Date.now() - st.startedAt > 11 * HOUR && autoDisabledFor !== st.startedAt) {
    autoDisabledFor = st.startedAt;
    await stopEngine();
    notify('WARP was turned off after running for 11 hours.');
  }
}

// ---------- logs ----------

let logOffset = 0;

function engineLogText(filter) {
  let text = '';
  try {
    const all = fs.readFileSync(logFile(), 'utf8');
    text = all.slice(Math.min(logOffset, all.length));
  } catch {
    // no log yet
  }
  let lines = text.split(/\r?\n/);
  if (filter === 'usque') {
    lines = lines.filter((l) => /usque|chain|warp|masque/i.test(l));
    try {
      lines = fs.readFileSync(usqueLog(), 'utf8').split(/\r?\n/).concat(lines);
    } catch {
      // no registrations yet
    }
  }
  return lines.filter(Boolean).slice(-400).join('\n');
}

// ---------- window and tray ----------

function createWindow(show = true) {
  win = new BrowserWindow({
    width: 1100,
    height: 820,
    minWidth: 720,
    minHeight: 600,
    show,
    backgroundColor: '#0E1B21',
    title: 'port1897',
    icon: path.join(__dirname, 'build', 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // nothing in the window may navigate away or open new windows
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  // the close button hides to the tray; Quit (tray menu) turns protection off
  win.on('close', (e) => {
    if (!quitting) {
      e.preventDefault();
      win.hide();
    }
  });
}

function showWindow() {
  if (!win) createWindow();
  win.show();
  win.focus();
}

const trayIcons = {};
function trayIcon(on) {
  const key = on ? 'on' : 'off';
  if (!trayIcons[key]) trayIcons[key] = nativeImage.createFromPath(path.join(__dirname, 'assets', `tray-${key}.png`));
  return trayIcons[key];
}

let trayState = null;
let trayBusy = false;
let trayPaused = false;
function updateTray(st, force) {
  const on = !!st;
  const paused = readSettings().pausedUntil > Date.now();
  if (!tray || (trayState === on && trayPaused === paused && !trayBusy && !force)) return;
  trayState = on;
  trayPaused = paused;
  const pause = async (m) => {
    const s = readSettings();
    s.pausedUntil = m ? Date.now() + m * 60 * 1000 : 0;
    writeSettings(s);
    await pushRules(s);
    updateTray(lastStatus, true);
  };
  tray.setImage(trayIcon(on));
  tray.setToolTip(on ? `port1897: protected${st.exit ? ' via ' + st.exit : ''}` : 'port1897: not protected');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: on ? 'Protected' + (st.exit ? ` (${st.exit})` : '') : 'Not protected', enabled: false },
      { type: 'separator' },
      {
        label: on ? 'Stop protection' : 'Start protection',
        enabled: !trayBusy,
        click: async () => {
          trayBusy = true;
          updateTray(st);
          const r = on ? await stopEngine() : await startEngine();
          trayBusy = false;
          trayState = null;
          updateTray(await engineStatus());
          if (!r.ok) {
            showWindow();
            dialog.showErrorBox('port1897', r.error + (r.log ? '\n\n' + r.log : ''));
          }
        },
      },
      on && !paused ? { label: 'Pause for 15 minutes', click: () => pause(15) } : null,
      on && paused ? { label: 'Resume (paused)', click: () => pause(0) } : null,
      { label: 'Open port1897', click: showWindow },
      { type: 'separator' },
      { label: 'Quit (turns protection off)', click: () => app.quit() },
    ].filter(Boolean))
  );
}

function createTray() {
  tray = new Tray(trayIcon(false));
  tray.on('click', showWindow);
  trayState = null;
  updateTray(null);
}

// ---------- IPC ----------

ipcMain.handle('settings:get', () => readSettings());
ipcMain.handle('settings:set', async (_e, patch) => {
  const merged = migrate({ ...readSettings(), ...patch });
  writeSettings(merged);
  if (RULE_KEYS.some((k) => k in patch)) await pushRules(merged);
  return merged;
});
// Rule changes apply at once, without a restart.
ipcMain.handle('rules:set', async (_e, patch) => {
  const s = migrate({ ...readSettings(), ...patch });
  writeSettings(s);
  const r = await pushRules(s);
  return { settings: s, warnings: r.warnings };
});
ipcMain.handle('engine:pause', async (_e, minutes) => {
  const s = readSettings();
  const m = Number(minutes) || 0;
  s.pausedUntil = m > 0 ? Date.now() + m * 60 * 1000 : 0;
  writeSettings(s);
  await pushRules(s);
  updateTray(lastStatus, true);
  return s;
});
ipcMain.handle('conns:list', async (_e, appName) => {
  try {
    return await api('GET', '/api/conns?app=' + encodeURIComponent(String(appName || '')));
  } catch {
    return [];
  }
});
ipcMain.handle('conns:close', async (_e, appName) => {
  try {
    return await api('POST', '/api/close', { app: String(appName || '') });
  } catch {
    return { closed: 0 };
  }
});
ipcMain.handle('engine:start', () => startEngine());
ipcMain.handle('engine:stop', () => stopEngine());
// Removes a kill switch (and DNS rule) left behind if the engine crashed.
ipcMain.handle('engine:cleanup', async () => {
  if (await engineStatus()) return { ok: false, error: 'Stop protection first.' };
  try {
    await launchElevated(enginePath(), ['-cleanup']);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});
ipcMain.handle('engine:status', () => engineStatus());
ipcMain.handle('engine:events', (_e, after) => {
  const a = Number(after) || 0;
  return hist.buf.filter((e) => e.id > a).slice(-300);
});
ipcMain.handle('engine:stats', (_e, range) => stats(String(range)));
ipcMain.handle('engine:appStats', (_e, appName) => appStats(appName));
ipcMain.handle('bl:status', () => blStatus());
ipcMain.handle('bl:filetag', async () => {
  try {
    return { ok: true, lists: await blFiletag() };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});
ipcMain.handle('bl:download', () => blDownload());
ipcMain.handle('bl:latest', async () => {
  try {
    return { ok: true, timestamp: Number(await blLatest()) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});
ipcMain.handle('bl:delete', async () => {
  if (await engineStatus()) return { ok: false, error: 'Stop protection first: the engine has the blocklists open.' };
  fs.rmSync(path.join(blDir(), 'local'), { recursive: true, force: true });
  const s = readSettings();
  s.blocklistsLocal = false;
  writeSettings(s);
  return { ok: true };
});
ipcMain.handle('engine:block', async (_e, appName, block) => {
  const name = String(appName).trim().toLowerCase();
  const s = readSettings();
  if (!name) return s;
  const a = { ...s.rules.apps[name] };
  if (block) a.mode = 'block';
  else if (a.mode === 'block') delete a.mode;
  delete a.allowUntil;
  if (Object.keys(a).length) s.rules.apps[name] = a;
  else delete s.rules.apps[name];
  writeSettings(s);
  await pushRules(s);
  return s;
});

ipcMain.handle('usque:status', () => usqueStatus());
ipcMain.handle('usque:register', (_e, which, force) => usqueRegister(String(which), !!force));
ipcMain.handle('usque:readConfig', (_e, which) => {
  try {
    return fs.readFileSync(usqueFile(String(which)), 'utf8');
  } catch {
    return '';
  }
});
ipcMain.handle('usque:saveConfig', (_e, which, text) => {
  try {
    const j = JSON.parse(String(text));
    if (!j || typeof j !== 'object' || !j.private_key) throw new Error();
  } catch {
    return { ok: false, error: 'Invalid config: needs a JSON object with private_key. Not saved.' };
  }
  fs.mkdirSync(usqueDir(), { recursive: true });
  fs.writeFileSync(usqueFile(String(which)), String(text), { mode: 0o600 });
  return { ok: true };
});
ipcMain.handle('usque:saveWg0', (_e, text) => {
  const f = path.join(usqueDir(), 'wg0.conf');
  if (!String(text).trim()) {
    fs.rmSync(f, { force: true });
    return { ok: true };
  }
  if (!validWg(text, true)) return { ok: false, error: 'Invalid wg0.conf — needs [Interface] PrivateKey and [Peer] Endpoint (plain WireGuard; AmneziaWG is not supported)' };
  fs.mkdirSync(usqueDir(), { recursive: true });
  fs.writeFileSync(f, String(text), { mode: 0o600 });
  return { ok: true };
});
ipcMain.handle('usque:importWg0', async () => {
  const c = await openConf('Import wg0.conf');
  if (!c) return {};
  if (!validWg(c.text, true)) return { error: 'Invalid wg0.conf — needs [Interface] PrivateKey and [Peer] Endpoint (plain WireGuard; AmneziaWG is not supported)' };
  fs.mkdirSync(usqueDir(), { recursive: true });
  fs.writeFileSync(path.join(usqueDir(), 'wg0.conf'), c.text, { mode: 0o600 });
  return { ok: true };
});

ipcMain.handle('wg:list', () => wgList());
ipcMain.handle('wg:get', (_e, id) => {
  const f = wgFile(id);
  if (!f) return null;
  const e = wgIndex().find((x) => x.id === id);
  return { id, name: e ? e.name : 'WireGuard', text: fs.readFileSync(f, 'utf8') };
});
ipcMain.handle('wg:save', (_e, w) => wgSave({ id: w.id, name: String(w.name || '').slice(0, 80), text: String(w.text || '') }));
ipcMain.handle('wg:remove', (_e, id) => {
  const f = wgFile(id);
  if (f) fs.rmSync(f, { force: true });
  const idx = wgIndex().filter((e) => e.id !== id);
  fs.mkdirSync(wgDir(), { recursive: true });
  fs.writeFileSync(path.join(wgDir(), 'index.json'), JSON.stringify(idx, null, 2));
  return true;
});
ipcMain.handle('wg:importFile', async () => {
  const c = await openConf('Import a WireGuard config');
  if (!c) return {};
  return wgSave(c);
});

ipcMain.handle('net:checkExit', async () => {
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 10000);
    const res = await net.fetch('https://www.cloudflare.com/cdn-cgi/trace', { signal: ac.signal, cache: 'no-store' });
    clearTimeout(t);
    const kv = Object.fromEntries((await res.text()).split('\n').map((l) => l.split('=')).filter((p) => p.length === 2));
    return { ip: kv.ip || '?', loc: kv.loc || '?', colo: kv.colo || '?', warp: kv.warp || '?' };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('log:engine', (_e, filter) => engineLogText(String(filter || '')));
ipcMain.handle('log:clear', () => {
  try {
    logOffset = fs.statSync(logFile()).size;
  } catch {
    logOffset = 0;
  }
  fs.rmSync(usqueLog(), { force: true });
});
ipcMain.handle('clip:copy', (_e, text) => clipboard.writeText(String(text)));

ipcMain.handle('backup:save', async () => {
  const day = new Date().toISOString().slice(0, 10);
  const r = await dialog.showSaveDialog(win, { title: 'Back up port1897', defaultPath: `port1897-backup-${day}.json`, filters: [{ name: 'Backup', extensions: ['json'] }] });
  if (r.canceled) return { ok: false };
  const read = (f) => {
    try {
      return fs.readFileSync(f, 'utf8');
    } catch {
      return '';
    }
  };
  const out = {
    app: 'port1897',
    version: 1,
    created: new Date().toISOString(),
    settings: readSettings(),
    wireguard: wgIndex().filter((e) => wgFile(e.id)).map((e) => ({ id: e.id, name: e.name, text: read(wgFile(e.id)) })),
    usque: { warp1: read(usqueFile('warp1')), warp2: read(usqueFile('warp2')), wg0: read(path.join(usqueDir(), 'wg0.conf')) },
    warp: read(path.join(dataDir(), 'warp.json')),
  };
  fs.writeFileSync(r.filePath, JSON.stringify(out, null, 2), { mode: 0o600 });
  return { ok: true };
});
ipcMain.handle('backup:restore', async () => {
  const r = await dialog.showOpenDialog(win, { title: 'Restore port1897', filters: [{ name: 'Backup', extensions: ['json'] }], properties: ['openFile'] });
  if (r.canceled) return { ok: false };
  let b;
  try {
    b = JSON.parse(fs.readFileSync(r.filePaths[0], 'utf8'));
    if (b.app !== 'port1897' || typeof b.settings !== 'object') throw new Error();
  } catch {
    return { ok: false, error: 'That is not a port1897 backup.' };
  }
  if (await engineStatus()) return { ok: false, error: 'Stop protection first.' };
  fs.rmSync(wgDir(), { recursive: true, force: true });
  fs.mkdirSync(wgDir(), { recursive: true });
  const idx = [];
  for (const w of b.wireguard || []) {
    if (!/^[a-f0-9]{16}$/.test(String(w.id)) || !validWg(w.text, true)) continue;
    fs.writeFileSync(path.join(wgDir(), w.id + '.conf'), w.text, { mode: 0o600 });
    idx.push({ id: w.id, name: String(w.name || 'WireGuard') });
  }
  fs.writeFileSync(path.join(wgDir(), 'index.json'), JSON.stringify(idx, null, 2));
  fs.mkdirSync(usqueDir(), { recursive: true });
  const put = (f, t) => (t ? fs.writeFileSync(f, t, { mode: 0o600 }) : null);
  put(usqueFile('warp1'), b.usque && b.usque.warp1);
  put(usqueFile('warp2'), b.usque && b.usque.warp2);
  put(path.join(usqueDir(), 'wg0.conf'), b.usque && b.usque.wg0);
  put(path.join(dataDir(), 'warp.json'), b.warp);
  const s = { ...DEFAULTS, ...b.settings, wasRunning: false };
  if (s.exit === 'wg' && !wgFile(s.wgActive)) s.exit = 'none';
  writeSettings(s);
  return { ok: true };
});

ipcMain.handle('app:setAutostart', (_e, on) => {
  app.setLoginItemSettings({ openAtLogin: !!on, args: ['--autostart'] });
});
ipcMain.handle('open:url', (_e, url) => {
  if (/^https:\/\/[^\s]+$/.test(String(url))) shell.openExternal(String(url));
});
ipcMain.handle('open:log', () => shell.openPath(logFile()));

// ---------- startup and quit ----------

// one copy only; a second launch brings the first one forward
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', showWindow);
  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null);
    loadBuckets();
    const autostart = process.argv.includes('--autostart');
    createWindow(!autostart);
    createTray();
    // "Block all apps when the PC is locked"
    const onLock = (locked) => {
      screenLocked = locked;
      const s = readSettings();
      if (s.universal.locked) pushRules(s);
    };
    powerMonitor.on('lock-screen', () => onLock(true));
    powerMonitor.on('unlock-screen', () => onLock(false));
    setInterval(statusLoop, 1500);
    setInterval(() => saveBuckets(readSettings()), 60 * 1000);
    if (autostart && readSettings().wasRunning) {
      const r = await startEngine();
      if (!r.ok) notify('Could not resume protection: ' + r.error);
    }
  });
}

// Quitting turns protection off, so no engine is left running unseen.
let stopped = false;
app.on('before-quit', async (e) => {
  quitting = true;
  if (stopped) return;
  e.preventDefault();
  saveBuckets(readSettings());
  await stopEngine(false);
  stopped = true;
  app.quit();
});
app.on('window-all-closed', () => {}); // keep running in the tray
