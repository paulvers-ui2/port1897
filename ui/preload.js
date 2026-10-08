// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// The only bridge between the window and the main process: a fixed list of
// calls, no raw IPC.

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const call = (ch) => (...args) => ipcRenderer.invoke(ch, ...args);

contextBridge.exposeInMainWorld('port', {
  getSettings: call('settings:get'),
  setSettings: call('settings:set'),
  start: call('engine:start'),
  stop: call('engine:stop'),
  cleanup: call('engine:cleanup'),
  killSwitch: call('engine:killSwitch'),
  status: call('engine:status'),
  events: call('engine:events'),
  stats: call('engine:stats'),
  appStats: call('engine:appStats'),
  block: call('engine:block'),
  setRules: call('rules:set'),
  pause: call('engine:pause'),
  conns: call('conns:list'),
  proxies: call('engine:proxies'),
  closeConns: call('conns:close'),
  blocklists: {
    status: call('bl:status'),
    filetag: call('bl:filetag'),
    download: call('bl:download'),
    latest: call('bl:latest'),
    remove: call('bl:delete'),
  },
  usque: {
    status: call('usque:status'),
    register: call('usque:register'),
    readConfig: call('usque:readConfig'),
    saveConfig: call('usque:saveConfig'),
    saveWg0: call('usque:saveWg0'),
    importWg0: call('usque:importWg0'),
  },
  wg: {
    list: call('wg:list'),
    get: call('wg:get'),
    save: call('wg:save'),
    remove: call('wg:remove'),
    importFile: call('wg:importFile'),
  },
  checkExit: call('net:checkExit'),
  ping: call('net:ping'),
  checkUpdate: call('app:checkUpdate'),
  engineLog: call('log:engine'),
  clearLog: call('log:clear'),
  copy: call('clip:copy'),
  backup: call('backup:save'),
  restore: call('backup:restore'),
  setAutostart: call('app:setAutostart'),
  openUrl: call('open:url'),
  openLog: call('open:log'),
  debugZip: call('debug:zip'),
  openPcapFolder: call('open:pcapFolder'),
});
