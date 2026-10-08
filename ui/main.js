// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Electron main process. The window has no Node access; it asks this process
// (through preload.js) to start and stop the engine (fswin.exe) and to call
// the engine's loopback control API. The engine needs admin rights, so it is
// started through a UAC prompt; this process and the window never are.

'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const http = require('node:http');
const { execFile } = require('node:child_process');

const API_HOST = '127.0.0.1';
const API_PORT = 47897;

const DEFAULTS = {
  doh: 'https://cloudflare-dns.com/dns-query',
  dohIps: '1.1.1.1,1.0.0.1',
  exit: 'none', // none | warp | wg | proxy
  wgFile: '',
  proxy: '',
  full: true,
  nrpt: true,
  blocked: [],
};

let win = null;
let token = null;

const dataDir = () => app.getPath('userData');
const tokenFile = () => path.join(dataDir(), 'api-token');
const settingsFile = () => path.join(dataDir(), 'settings.json');
const logFile = () => path.join(dataDir(), 'engine.log');

function enginePath() {
  if (app.isPackaged) return path.join(process.resourcesPath, 'engine', 'fswin.exe');
  return process.env.FSWIN_PATH || path.join(__dirname, 'engine', 'fswin.exe');
}

function readSettings() {
  try {
    return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(settingsFile(), 'utf8')) };
  } catch {
    return { ...DEFAULTS };
  }
}

function writeSettings(s) {
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(settingsFile(), JSON.stringify(s, null, 2));
}

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
    const req = http.request(
      { host: API_HOST, port: API_PORT, method, path: urlPath, headers, timeout: 3000 },
      (res) => {
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
      }
    );
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

function engineArgs(s) {
  const a = [
    '-api', `${API_HOST}:${API_PORT}`,
    '-token-file', tokenFile(),
    '-logfile', logFile(),
    '-warp-file', path.join(dataDir(), 'warp.json'),
    '-doh', s.doh,
    '-doh-ips', s.dohIps,
  ];
  if (s.full) a.push('-full');
  if (s.nrpt) a.push('-nrpt');
  if (s.exit === 'warp') a.push('-warp');
  if (s.exit === 'wg' && s.wgFile) a.push('-wg', s.wgFile);
  if (s.exit === 'proxy' && s.proxy) a.push('-proxy', s.proxy);
  if (s.blocked.length) a.push('-block', s.blocked.join(','));
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
  const cmd =
    `Start-Process -FilePath ${psQuote(exe)} -Verb RunAs -WindowStyle Hidden ` +
    `-ArgumentList ${psQuote(args.map(winQuote).join(' '))}`;
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', cmd],
      { windowsHide: true },
      (err, _stdout, stderr) => {
        if (!err) return resolve();
        const msg = String(stderr || err.message);
        reject(new Error(/cancel/i.test(msg) ? 'Admin permission was declined.' : msg.trim()));
      }
    );
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

async function startEngine() {
  if (await engineStatus()) return { ok: true };
  const exe = enginePath();
  if (!fs.existsSync(exe)) return { ok: false, error: `Engine not found at ${exe}` };
  ensureToken();
  try {
    await launchElevated(exe, engineArgs(readSettings()));
  } catch (e) {
    return { ok: false, error: e.message };
  }
  // WARP registration on first use can take a few seconds
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 500));
    if (await engineStatus()) return { ok: true };
  }
  return { ok: false, error: 'The engine did not start.', log: lastLogLines(15) };
}

async function stopEngine() {
  try {
    await api('POST', '/api/stop');
  } catch {
    return { ok: true }; // not running
  }
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 250));
    if (!(await engineStatus())) return { ok: true };
  }
  return { ok: false, error: 'The engine is still running.' };
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 820,
    minWidth: 720,
    minHeight: 600,
    backgroundColor: '#0E1B21',
    title: 'port1897',
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
}

ipcMain.handle('settings:get', () => readSettings());
ipcMain.handle('settings:set', (_e, s) => {
  const merged = { ...readSettings(), ...s };
  merged.blocked = Array.isArray(merged.blocked) ? merged.blocked.map(String) : [];
  writeSettings(merged);
  return merged;
});
ipcMain.handle('engine:start', () => startEngine());
ipcMain.handle('engine:stop', () => stopEngine());
ipcMain.handle('engine:status', () => engineStatus());
ipcMain.handle('engine:events', async (_e, after) => {
  try {
    return await api('GET', `/api/events?after=${Number(after) || 0}&max=300`);
  } catch {
    return [];
  }
});
ipcMain.handle('engine:stats', async () => {
  try {
    return await api('GET', '/api/stats');
  } catch {
    return { apps: [], domains: [] };
  }
});
ipcMain.handle('engine:block', async (_e, appName, block) => {
  const name = String(appName).trim().toLowerCase();
  if (!name) return readSettings().blocked;
  const s = readSettings();
  const set = new Set(s.blocked);
  if (block) set.add(name);
  else set.delete(name);
  s.blocked = [...set].sort();
  writeSettings(s);
  try {
    await api('POST', '/api/block', { app: name, block: !!block });
  } catch {
    // not running; applies on next start
  }
  return s.blocked;
});
ipcMain.handle('pick:wgfile', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: 'Choose a WireGuard config',
    filters: [{ name: 'WireGuard config', extensions: ['conf'] }],
    properties: ['openFile'],
  });
  return r.canceled ? '' : r.filePaths[0];
});
ipcMain.handle('open:url', (_e, url) => {
  if (/^https:\/\/[^\s]+$/.test(String(url))) shell.openExternal(String(url));
});
ipcMain.handle('open:log', () => shell.openPath(logFile()));

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  createWindow();
});

// Closing the app turns protection off, so no engine is left running unseen.
let quitting = false;
app.on('before-quit', async (e) => {
  if (quitting) return;
  e.preventDefault();
  quitting = true;
  await stopEngine();
  app.quit();
});
app.on('window-all-closed', () => app.quit());
