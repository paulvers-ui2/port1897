// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// window.port for the Tauri app (desktop/): the same fixed list of calls
// preload.js gives the Electron app, each one an app command
// (desktop/src/commands.rs). In Electron or a browser it does nothing.

'use strict';

(() => {
  const T = window.__TAURI__;
  if (window.port || !T || !T.core) return;
  // call('cmd', 'a', 'b')(x, y) invokes cmd with { a: x, b: y }
  const call =
    (cmd, ...names) =>
    (...args) =>
      T.core.invoke(cmd, Object.fromEntries(names.map((n, i) => [n, args[i] === undefined ? null : args[i]])));
  const port = {
    getSettings: call('settings_get'),
    setSettings: call('settings_set', 'patch'),
    start: call('engine_start'),
    stop: call('engine_stop'),
    cleanup: call('engine_cleanup'),
    killSwitch: call('engine_kill_switch', 'on'),
    status: call('engine_status'),
    events: call('engine_events', 'after'),
    stats: call('engine_stats', 'range'),
    appStats: call('engine_app_stats', 'app'),
    appPaths: call('engine_app_paths'),
    block: call('engine_block', 'app', 'block'),
    setRules: call('rules_set', 'patch'),
    pause: call('engine_pause', 'minutes'),
    conns: call('conns_list', 'app'),
    proxies: call('engine_proxies'),
    closeConns: call('conns_close', 'app'),
    closeConn: call('conns_close_one', 'cid'),
    blocklists: {
      status: call('bl_status'),
      filetag: call('bl_filetag'),
      download: call('bl_download'),
      latest: call('bl_latest'),
      remove: call('bl_delete'),
    },
    usque: {
      status: call('usque_status'),
      register: call('usque_register', 'which', 'force'),
      readConfig: call('usque_read_config', 'which'),
      saveConfig: call('usque_save_config', 'which', 'text'),
      saveWg0: call('usque_save_wg0', 'text'),
      importWg0: call('usque_import_wg0'),
    },
    wg: {
      list: call('wg_list'),
      get: call('wg_get', 'id'),
      save: call('wg_save', 'w'),
      remove: call('wg_remove', 'id'),
      importFile: call('wg_import_file'),
    },
    checkExit: call('net_check_exit'),
    ping: call('net_ping', 'q'),
    engineLog: call('log_engine', 'filter'),
    clearLog: call('log_clear'),
    copy: call('clip_copy', 'text'),
    setAutostart: call('app_set_autostart', 'on'),
    openUrl: call('open_url', 'url'),
    openLog: call('open_log'),
    debugZip: call('debug_zip'),
    openPcapFolder: call('open_pcap_folder'),
    // the app tells the window at once when something changed (src/live.rs)
    onTick: (cb) => T.event.listen('tick', () => cb()),
  };
  Object.defineProperty(window, 'port', { value: Object.freeze(port), writable: false, configurable: false });

  // the window's errors go to app.log, as Electron logged its console
  const report = (level, message) => {
    try {
      T.core.invoke('log_window', { level, message: String(message).slice(0, 2000) });
    } catch {
      // nothing more to do
    }
  };
  window.addEventListener('error', (e) => report('error', `${e.message} (${e.filename}:${e.lineno})`));
  window.addEventListener('unhandledrejection', (e) => report('error', `unhandled: ${e.reason && e.reason.stack ? e.reason.stack : e.reason}`));
})();
