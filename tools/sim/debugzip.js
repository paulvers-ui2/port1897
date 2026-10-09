// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Runs the app's real "Save debug zip" handler (ui/main.js, debug:zip) with
// Electron stubbed out, against a data folder full of planted secrets, and
// checks the zip: every expected file is there, no secret is, and the parts
// meant for debugging survive. Windows only (the handler uses PowerShell).
//
//   node tools/sim/debugzip.js

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { execFileSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'p1897-zipsim-'));
const userData = path.join(root, 'userData');
const desktop = path.join(root, 'Desk top'); // a space, as in many real paths
fs.mkdirSync(userData, { recursive: true });
fs.mkdirSync(desktop, { recursive: true });

// ---------- planted data ----------

const SECRETS = {
  socksPass: 'SECRET-socks-pass',
  httpPass: 'SECRET-http-pass',
  legacyProxyPass: 'SECRET-legacy-proxy',
  dohUrlPass: 'SECRET-doh-userinfo',
  wgPriv: 'SECRET-wg-private-key=',
  wgPsk: 'SECRET-wg-preshared-key=',
  wgPrivCrlf: 'SECRET-wg-crlf-key=',
  warpPriv: 'SECRET-warp-private-key',
  warpToken: 'SECRET-warp-token',
  warpLicense: 'SECRET-warp-license',
  usquePriv: 'SECRET-usque-private-key',
  usqueToken: 'SECRET-usque-access-token',
  logProxyPass: 'SECRET-log-proxy-pass',
  apiToken: 'SECRET-api-token-0123456789',
  appLogProxyPass: 'SECRET-app-log-pass',
};
const WG_ID = 'a1b2c3d4e5f60718';

const write = (rel, text) => {
  const f = path.join(userData, rel);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, text);
};

write('api-token', SECRETS.apiToken);
write(
  'settings.json',
  JSON.stringify({
    dnsType: 'doh',
    doh: 'https://cloudflare-dns.com/dns-query',
    customDns: { doh: [{ name: 'mine', url: `https://me:${SECRETS.dohUrlPass}@dns.example/dns-query` }] },
    socks: { host: '127.0.0.1', port: 1080, user: 'bob', pass: SECRETS.socksPass },
    http: { host: 'proxy.lan', port: 8080, user: 'amy', pass: SECRETS.httpPass },
    proxy: `socks5://bob:${SECRETS.legacyProxyPass}@10.0.0.1:1080`,
    universal: { dnsBypass: true, udp: false },
    wgActive: WG_ID,
    logLevel: 3,
  })
);
write('rules.json', JSON.stringify({ apps: { 'chrome.exe': { action: 'block' } }, universal: { dnsBypass: true } }));
write('warp.json', JSON.stringify({ id: 'device-id-ok', private_key: SECRETS.warpPriv, token: SECRETS.warpToken, account: { license: SECRETS.warpLicense } }));
write('usque/warp1.json', JSON.stringify({ private_key: SECRETS.usquePriv, access_token: SECRETS.usqueToken, endpoint_v4: '162.159.198.1', id: 'usque-id-ok' }));
write('usque/wg0.conf', `[Interface]\r\nPrivateKey = ${SECRETS.wgPrivCrlf}\r\nAddress = 10.8.0.2/32\r\n\r\n[Peer]\r\nPublicKey = PUBLICkeyIsFineToKeep=\r\nEndpoint = 203.0.113.7:51820\r\n`);
write('usque/usque.log', 'usque chain: connected\n');
write('wireguard/index.json', JSON.stringify([{ id: WG_ID, name: 'Home WG' }]));
write(`wireguard/${WG_ID}.conf`, `[Interface]\nPrivateKey=${SECRETS.wgPriv}\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = PeerPublicKeyOk=\n  presharedkey  =  ${SECRETS.wgPsk}\nEndpoint = 198.51.100.9:51820\n`);
write('engine.log', `fswin up\n   1.000s flow  #1 tcp chrome.exe -> 1.1.1.1:443 via socks5://bob:${SECRETS.logProxyPass}@10.0.0.1:1080\n`);
write('engine.prev.log', 'previous run\n');
write('app.log', `2026-10-08T10:00:00Z engine did not start: proxy socks5://amy:${SECRETS.appLogProxyPass}@10.0.0.9:1080 refused\n`);
const crashDumps = path.join(root, 'Crashpad');
fs.mkdirSync(path.join(crashDumps, 'reports'), { recursive: true });
fs.writeFileSync(path.join(crashDumps, 'reports', 'abc123.dmp'), 'MDMP fake dump with SECRET-in-dump');
const day = new Date().toISOString().slice(0, 10);
write(`history/events-${day}.jsonl`, '{"id":1,"kind":"dns","domain":"example.com"}\n');

const before = snapshot(userData);
const tempBefore = new Set(fs.readdirSync(os.tmpdir()).filter((d) => d.startsWith('auroravpn-debug-')));

// ---------- stub Electron and load the real main.js ----------

const handlers = {};
let savedTo = '';
const noop = () => stub;
const stub = new Proxy(function () {}, { get: (_t, k) => (k === 'then' ? undefined : noop), apply: () => stub });
const electron = new Proxy(
  {
    app: new Proxy(
      {
        getPath: (name) => ({ userData, desktop, temp: os.tmpdir(), home: root, crashDumps })[name] || root,
        getVersion: () => '0.0.0-sim',
        requestSingleInstanceLock: () => false, // main.js then skips window, tray and timers
        isPackaged: false,
      },
      { get: (t, k) => (k in t ? t[k] : noop) }
    ),
    ipcMain: { handle: (name, fn) => (handlers[name] = fn), on: noop },
    dialog: { showSaveDialog: async (_w, o) => ({ canceled: false, filePath: (savedTo = savedTo || o.defaultPath) }) },
    shell: { showItemInFolder: () => {}, openPath: async () => '', openExternal: async () => {} },
  },
  { get: (t, k) => (k in t ? t[k] : stub) }
);
const resolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  return req === 'electron' ? 'electron' : resolve.call(this, req, ...rest);
};
require.cache.electron = { id: 'electron', filename: 'electron', loaded: true, exports: electron };
require(path.join(__dirname, '..', '..', 'ui', 'main.js'));

// ---------- run and check ----------

const results = [];
const check = (what, ok, detail = '') => {
  results.push({ what, ok: !!ok, detail });
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${what}${detail ? ' -- ' + detail : ''}`);
};

// an IPC call as the window makes it: from the app's own page (main.js
// refuses calls from anywhere else)
const fromApp = { senderFrame: { parent: null, url: pathToFileURL(path.join(__dirname, '..', '..', 'ui', 'renderer', 'index.html')).href } };

(async () => {
  try {
    if (!handlers['debug:zip']) throw new Error('main.js registered no debug:zip handler');
    const r = await handlers['debug:zip'](fromApp);
    check('the handler reports success', r && r.ok, JSON.stringify(r));
    check('the zip is where the save dialog pointed (a folder with a space)', savedTo && fs.existsSync(savedTo), savedTo);

    const out = path.join(root, 'unzipped');
    const q = (s) => "'" + s.replace(/'/g, "''") + "'";
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath ${q(savedTo)} -DestinationPath ${q(out)} -Force`]);
    const files = listFiles(out);
    console.log('zip contents:', files.join(', '));
    for (const want of ['engine.log', 'engine.prev.log', 'settings.json', 'rules.json', 'warp.json', 'usque/warp1.json', 'usque/wg0.conf', 'usque/usque.log', 'wireguard/index.json', `wireguard/${WG_ID}.conf`, `history/events-${day}.jsonl`, 'status.json', 'system.txt', 'README.txt', 'app.log', 'crash-dumps.txt']) {
      check(`zip has ${want}`, files.includes(want));
    }
    check('zip leaves out the API token', !files.some((f) => /api-token/i.test(f)));
    check('no missing usque/warp2.json invented', !files.includes('usque/warp2.json'));

    const all = files.map((f) => [f, fs.readFileSync(path.join(out, f), 'utf8')]);
    for (const [name, secret] of Object.entries(SECRETS)) {
      const leaks = all.filter(([, t]) => t.includes(secret)).map(([f]) => f);
      check(`secret ${name} is not in the zip`, leaks.length === 0, leaks.join(', '));
    }

    const read = (f) => fs.readFileSync(path.join(out, f), 'utf8');
    const settings = JSON.parse(read('settings.json'));
    check('settings keep the non-secret dnsBypass switch', settings.universal && settings.universal.dnsBypass === true, JSON.stringify(settings.universal));
    check('settings keep proxy hosts and users for debugging', settings.socks.host === '127.0.0.1' && settings.socks.user === 'bob' && settings.http.host === 'proxy.lan');
    check('settings keep the DoH URL host', /dns\.example\/dns-query/.test(settings.customDns.doh[0].url), settings.customDns.doh[0].url);
    check('wg configs keep public keys and endpoints', /PublicKey = PeerPublicKeyOk=/.test(read(`wireguard/${WG_ID}.conf`)) && /Endpoint = 203\.0\.113\.7/.test(read('usque/wg0.conf')));
    check('a CRLF wg config keeps its line after the hidden key', /PrivateKey = \(hidden\)\r\nAddress = 10\.8\.0\.2/.test(read('usque/wg0.conf')), JSON.stringify(read('usque/wg0.conf').slice(0, 60)));
    check('ids that are not secrets stay', /device-id-ok/.test(read('warp.json')) && /usque-id-ok/.test(read('usque/warp1.json')));
    check('engine.log keeps the flow, password hidden', /flow {2}#1 tcp chrome\.exe/.test(read('engine.log')) && /bob:\(hidden\)@10\.0\.0\.1/.test(read('engine.log')));
    check('README warns that logs list domains', /engine\.log, engine\.prev\.log and history\//.test(read('README.txt')));
    check('app.log keeps the error, password hidden', /engine did not start/.test(read('app.log')) && /amy:\(hidden\)@/.test(read('app.log')));
    check('crash-dumps.txt names the dump but leaves its contents out', /abc123\.dmp/.test(read('crash-dumps.txt')) && !all.some(([, t]) => t.includes('SECRET-in-dump')));
    check('system.txt has versions, Windows Firewall and crash sections', /Electron \S+, Chromium \S+, Node \d/.test(read('system.txt')) && /===== Windows Firewall profiles =====/.test(read('system.txt')) && /===== Crashes of AuroraVPN/.test(read('system.txt')));
    check('system.txt has the network report', /===== Adapters =====/.test(read('system.txt')) && /===== NRPT rules/.test(read('system.txt')));
    check('status.json says the engine is not running', /"running": false/.test(read('status.json')));

    const after = snapshot(userData);
    const changed = Object.keys(before).filter((f) => f !== 'api-token' && before[f] !== after[f]);
    check('the data folder is left untouched', changed.length === 0, changed.join(', '));
    const leftovers = fs.readdirSync(os.tmpdir()).filter((d) => d.startsWith('auroravpn-debug-') && !tempBefore.has(d));
    check('no temp folder or temp zip is left behind', leftovers.length === 0, leftovers.join(', '));

    // a second save over the same file replaces it
    const r2 = await handlers['debug:zip'](fromApp);
    check('saving again over the same file replaces it', r2 && r2.ok && r2.file === savedTo && fs.statSync(savedTo).size > 0, JSON.stringify(r2));

    // last: the refusal is logged to app.log, in the data folder
    const refused = await handlers['debug:zip']({ senderFrame: { parent: null, url: 'https://example.com/' } }).then(() => false, (e) => /refused/.test(e.message));
    check('a call from another page is refused', refused);
  } catch (e) {
    check('ran to the end', false, e.stack);
  } finally {
    const failed = results.filter((r) => !r.ok).length;
    const md = ['## Debug zip simulation', '', '| Check | Result | Detail |', '|---|---|---|', ...results.map((r) => `| ${r.what} | ${r.ok ? 'PASS' : 'FAIL'} | ${String(r.detail).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, 300)} |`)];
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md.join('\n') + '\n');
    console.log(`\n${results.length} checks, ${failed} failed`);
    fs.rmSync(root, { recursive: true, force: true });
    process.exit(failed ? 1 : 0);
  }
})();

function listFiles(dir, base = dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const f = path.join(dir, e.name);
    return e.isDirectory() ? listFiles(f, base) : [path.relative(base, f).split(path.sep).join('/')];
  });
}

function snapshot(dir) {
  return Object.fromEntries(listFiles(dir).map((f) => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
}
