// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Smaller screens of the Android app: the ping test, the welcome slides
// shown on first start, and the app update check.

'use strict';

// ---------- ping test (Android: PingTestActivity) ----------

PAGES.ping = () => {
  const ip = field({ label: 'IP address (TCP port 443)', value: '1.1.1.1' });
  const host = field({ label: 'Host name (DNS lookup)', value: 'www.google.com' });
  const url = field({ label: 'Web address (HTTPS)', value: 'https://www.cloudflare.com/cdn-cgi/trace' });
  const results = h('div', {});
  const line = (title, r) =>
    r
      ? row({
          ico: r.ok ? 'ic_tick' : 'ic_cross',
          title,
          sub: r.ok ? `${r.answer ? r.answer + ' · ' : ''}${r.ms} ms` : `failed: ${r.error}${r.ms ? ' · ' + r.ms + ' ms' : ''}`,
          cls: r.ok ? '' : 'blocked',
        })
      : null;
  const run = async () => {
    results.replaceChildren(note('Testing…'));
    const r = await App.port.ping({ ip: ip.input.value, host: host.input.value, url: url.input.value });
    results.replaceChildren(card(line('IP: ' + ip.input.value, r.ip), line('DNS: ' + host.input.value, r.host), line('Web: ' + url.input.value, r.url)));
  };
  return screen(
    'Ping test',
    note('Checks what this PC can reach right now, through protection when it is on: a TCP connection to an IP, a DNS lookup, and a web request. Use it to tell a blocked site from a broken DNS or a down VPN.'),
    h('div', { class: 'group pad' }, ip, host, url, h('div', { class: 'actions' }, btn('Cancel', () => App.back()), btn('Test', run, { primary: true }))),
    results
  );
};

// ---------- welcome slides (Android: WelcomeActivity), first start only ----------

const WELCOME = [
  ['Welcome', 'port1897 is the easiest way to monitor network activity, bypass Internet censorship, and firewall apps on your PC.', 'ic_heart_accent'],
  ['Secure Internet with WireGuard', 'Encrypt your Internet traffic with WireGuard, or free Cloudflare WARP. Choose different routes for different apps.', 'ic_wireguard_icon'],
  ['Protect your PC with Firewall', 'Control app internet use; restrict connections based on app or network activity.', 'firewall_home_screen'],
  ['Block Ads & Malware with DNS', 'Choose from 190+ lists to stop ads, trackers, and malware.', 'dns_home_screen'],
];

function showWelcome() {
  let i = 0;
  const back = h('div', { class: 'modal-back' });
  const done = () => {
    back.remove();
    App.save({ welcomed: true }).then(() => (App.restartNeeded = false));
  };
  const draw = () => {
    const [title, text, ico] = WELCOME[i];
    const last = i === WELCOME.length - 1;
    back.replaceChildren(
      h(
        'div',
        { class: 'modal welcome', role: 'dialog' },
        icon(ico, 'welcome-ico'),
        h('h2', { class: 'modal-title', text: title }),
        h('p', { class: 'desc', text }),
        h('div', { class: 'welcome-dots' }, WELCOME.map((_, k) => h('span', { class: k === i ? 'on' : '' }))),
        h('div', { class: 'modal-actions' }, last ? null : btn('Skip', done), btn(last ? 'Get started' : 'Next', () => {
          if (last) return done();
          i++;
          draw();
        }, { primary: true }))
      )
    );
  };
  draw();
  document.body.append(back);
}

// ---------- app updates ----------

async function checkUpdateNow() {
  toast('Checking…');
  const r = await App.port.checkUpdate();
  if (!r.ok) return toast('Update check failed: ' + r.error);
  if (!r.latest) return toast(`No releases published yet (this is ${r.current})`);
  if (!r.newer) return toast(`You have the latest version (${r.current})`);
  if (await confirmDialog('Update available', `port1897 ${r.latest} is available (you have ${r.current}). Open the download page?`, 'Open')) App.port.openUrl(r.url);
}
