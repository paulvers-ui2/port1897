// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// The only bridge between the window and the main process: a fixed list of
// calls, no raw IPC.

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('port', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (s) => ipcRenderer.invoke('settings:set', s),
  start: () => ipcRenderer.invoke('engine:start'),
  stop: () => ipcRenderer.invoke('engine:stop'),
  status: () => ipcRenderer.invoke('engine:status'),
  events: (after) => ipcRenderer.invoke('engine:events', after),
  stats: () => ipcRenderer.invoke('engine:stats'),
  block: (app, block) => ipcRenderer.invoke('engine:block', app, block),
  pickWgFile: () => ipcRenderer.invoke('pick:wgfile'),
  openUrl: (url) => ipcRenderer.invoke('open:url', url),
  openLog: () => ipcRenderer.invoke('open:log'),
});
