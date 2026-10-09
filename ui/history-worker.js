// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Reads one app's flows out of the event files, on a worker thread: a scan of
// up to two days of history (up to 64 MB a day) never holds up the window or
// the status loop (main.js, appStats).

'use strict';

const fs = require('node:fs');
const { parentPort, workerData } = require('node:worker_threads');

const { files, want } = workerData;
const flows = [];
for (const f of files) {
  let text;
  try {
    text = fs.readFileSync(f, 'utf8');
  } catch {
    continue; // no file that day
  }
  if (text.length > 64 * 1024 * 1024) continue;
  for (const line of text.split(/\r?\n/)) {
    if (!line || !line.toLowerCase().includes(want)) continue;
    try {
      const e = JSON.parse(line);
      if (e.kind === 'flow' && String(e.app || '').toLowerCase() === want) {
        flows.push({ kind: e.kind, app: e.app, at: e.at, dst: e.dst, cid: e.cid, domain: e.domain, blocked: e.blocked });
      }
    } catch {
      // a torn line
    }
  }
}
parentPort.postMessage(flows);
