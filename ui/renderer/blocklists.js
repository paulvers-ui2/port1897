// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkDNS blocklists, as on Android: pick from 195+ lists (simple packs
// or every list), then block them on this PC (downloaded, ~60 MB) or on a
// RethinkDNS server (the choice goes in the DoH URL as a "stamp").

'use strict';

// flagsToStamp packs blocklist ids into a RethinkDNS stamp the way
// firestack's flagtostamp does (intra/dnsx/rethinkdns.go): a 16-bit header
// with one bit per group of 16 ids, then one 16-bit word per group,
// little-endian, base32 without padding, prefixed "1-".
function flagsToStamp(flags) {
  const groups = new Map();
  for (const v of flags) {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0 || n > 255) continue;
    const hi = Math.floor(n / 16);
    groups.set(hi, (groups.get(hi) || 0) | (1 << (15 - (n % 16))));
  }
  if (!groups.size) return '';
  const his = [...groups.keys()].sort((a, b) => a - b);
  let header = 0;
  for (const hi of his) header |= 1 << (15 - hi);
  const words = [header, ...his.map((hi) => groups.get(hi))];
  const bytes = [];
  for (const w of words) bytes.push(w & 0xff, (w >> 8) & 0xff);
  return '1-' + base32(bytes);
}

function base32(bytes) {
  const abc = 'abcdefghijklmnopqrstuvwxyz234567';
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += abc[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += abc[(acc << (5 - bits)) & 31];
  return out;
}

const RDNS_SERVER = 'https://sky.rethinkdns.com/';

const BL_GROUPS = [
  ['privacy', 'Privacy', 'Block attentionware, spyware, scareware.'],
  ['security', 'Security', 'Block malware, ransomware, cryptoware, phishers, and other threats.'],
  ['parentalcontrol', 'Parental Control', 'Block adult & pirated content, online gambling & dating, social media, and more.'],
  ['', 'Other', ''],
];

const LEVELS = ['Lite', 'Aggressive', 'Extreme'];

function packTitle(p) {
  const named = { liteprivacy: 'Privacy', aggressiveprivacy: 'Privacy (aggressive)', extremeprivacy: 'Privacy (extreme)', socialmedia: 'Social media', 'vpn & proxies': 'VPN & proxies' };
  if (named[p]) return named[p];
  return p.charAt(0).toUpperCase() + p.slice(1);
}

let blView = 'simple';
let blCache = null;

PAGES.blocklists = ({ kind }) => {
  const s = App.settings;
  const local = kind === 'local';
  const picked = new Set((local ? s.localFlags : s.remoteFlags).map(Number));
  const body = h('div', {}, note('Loading the list of blocklists…'));
  const count = h('p', { class: 'note' });
  const search = field({ placeholder: 'Search blocklists', oninput: () => draw() });
  let lists = [];

  const setCount = () => {
    const entries = lists.filter((l) => picked.has(l.value)).reduce((n, l) => n + (l.entries || 0), 0);
    count.textContent = `${picked.size} of ${lists.length} blocklists selected · ${entries.toLocaleString()} domains`;
  };

  const tabs = h(
    'div',
    { class: 'seg-wrap' },
    h('div', { class: 'seg' }, [['simple', 'Simple'], ['advanced', 'Advanced']].map(([id, name]) => h('button', { class: blView === id ? 'on' : '', type: 'button', text: name, onclick: () => {
      blView = id;
      tabs.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.textContent === name));
      draw();
    } })))
  );

  const drawSimple = () => {
    const packs = new Map();
    for (const l of lists) {
      l.pack.forEach((p, i) => {
        if (p === 'ignore') return;
        if (!packs.has(p)) packs.set(p, []);
        packs.get(p).push({ value: l.value, level: Number(l.level[i]) || 0 });
      });
    }
    const rows = [...packs.entries()].sort((a, b) => b[1].length - a[1].length).map(([p, members]) => {
      const levels = [...new Set(members.map((m) => m.level))].sort();
      const upTo = (lv) => members.filter((m) => m.level <= lv).map((m) => m.value);
      // the highest level whose lists are all picked
      let cur = -1;
      for (const lv of levels) if (upTo(lv).every((v) => picked.has(v))) cur = lv;
      const chip = (lv) =>
        h('button', { class: 'chip' + (cur === lv ? ' on' : ''), type: 'button', text: levels.length === 1 ? 'On' : LEVELS[lv] || 'Level ' + lv, onclick: () => {
          for (const m of members) picked.delete(m.value);
          if (cur !== lv) for (const v of upTo(lv)) picked.add(v);
          draw();
        } });
      return h(
        'div',
        { class: 'row' },
        h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: packTitle(p) }), h('span', { class: 'row-sub', text: `${members.length} list${members.length === 1 ? '' : 's'}` })),
        h('div', { class: 'chips' }, levels.map(chip))
      );
    });
    body.replaceChildren(note('Choose a pack and how hard it blocks. Lite is safest; Extreme may break some sites.'), card(rows));
  };

  const drawAdvanced = () => {
    const q = search.input.value.trim().toLowerCase();
    const parts = [h('div', { class: 'field-row' }, search)];
    for (const [g, title, desc] of BL_GROUPS) {
      const inGroup = lists.filter((l) => (BL_GROUPS.some((x) => x[0] === l.group) ? l.group === g : g === '') && (!q || l.vname.toLowerCase().includes(q) || (l.subg || '').includes(q)));
      if (!inGroup.length) continue;
      inGroup.sort((a, b) => (a.subg || '').localeCompare(b.subg || '') || a.vname.localeCompare(b.vname));
      parts.push(
        sectionLabel(title),
        desc ? note(desc) : null,
        card(
          inGroup.map((l) => {
            const c = h('input', { type: 'checkbox', checked: picked.has(l.value), 'aria-label': l.vname });
            c.addEventListener('change', () => {
              if (c.checked) picked.add(l.value);
              else picked.delete(l.value);
              setCount();
            });
            return h('label', { class: 'pick-row' }, c, h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: l.vname }), h('span', { class: 'row-sub', text: `${l.subg ? l.subg.replace(/-/g, ' ') + ' · ' : ''}${(l.entries || 0).toLocaleString()} domains` })));
          })
        )
      );
    }
    body.replaceChildren(...parts.filter(Boolean));
    search.input.focus();
  };

  const draw = () => {
    if (!lists.length) return;
    setCount();
    if (blView === 'simple') drawSimple();
    else drawAdvanced();
  };

  (blCache ? Promise.resolve({ ok: true, lists: blCache }) : App.port.blocklists.filetag()).then((r) => {
    if (!r.ok) {
      body.replaceChildren(note('Could not get the list of blocklists from dl.rethinkdns.com: ' + r.error, 'bad'));
      return;
    }
    blCache = r.lists;
    lists = r.lists;
    draw();
  });

  const apply = async () => {
    const flags = [...picked].sort((a, b) => a - b);
    const stamp = flagsToStamp(flags);
    if (local) {
      await save({ localFlags: flags, localStamp: stamp, blocklistsLocal: flags.length > 0 });
    } else {
      await save({
        remoteFlags: flags,
        remoteStamp: stamp,
        dnsType: 'rdns',
        doh: RDNS_SERVER + (stamp || 'dns-query'),
        dohIps: '',
        dohName: 'RethinkDNS (your blocklists)',
        lastOtherType: 'rdns',
      });
    }
    App.back();
  };

  return screen(
    local ? 'On-device blocklists' : 'RethinkDNS blocklists',
    note(local
      ? 'Blocked on this PC: lookups never leave it to be checked, and it works with any DNS.'
      : 'Blocked by the RethinkDNS server (sky.rethinkdns.com): your choice goes in its DoH URL. Nothing to download.'),
    tabs,
    count,
    body,
    h('div', { class: 'actions sticky-actions' }, btn('Discard', () => App.back()), btn('Apply', apply, { primary: true }))
  );
};

// ---------- the DNS screen's on-device blocklists card ----------

function blocklistsCard() {
  const s = App.settings;
  const box = h('div', {}, note('Loading…'));
  const draw = async () => {
    const st = await App.port.blocklists.status();
    const job = st.job;
    const n = s.localFlags.length;
    const parts = [];
    parts.push(
      switchRow({
        ico: 'ic_filter',
        title: 'On-device blocklists',
        sub: st.local ? (n ? `${n} blocklists selected` : 'No blocklists selected yet') : 'Download blocklists (around 60 MB) to use this feature.',
        value: s.blocklistsLocal && !!st.local,
        onchange: (v) => {
          if (v && !st.local) {
            toast('Download the blocklists first');
            return draw();
          }
          if (v && !n) {
            App.go('blocklists', { kind: 'local' });
            return;
          }
          save({ blocklistsLocal: v });
        },
      }),
      row({ ico: 'ic_configure', title: 'Configure 195+ blocklists', sub: n ? `${n} selected` : 'Disabled', right: chevron(), onclick: () => App.go('blocklists', { kind: 'local' }) })
    );
    if (job && !job.error) {
      const pct = job.total ? ` ${Math.floor((100 * job.done) / job.total)}%` : ` ${fmtBytes(job.done)}`;
      parts.push(h('div', { class: 'pad' }, note(`Downloading blocklists… ${job.file}${pct}`)));
      setTimeout(() => box.isConnected && draw(), 1000);
    } else {
      if (job && job.error) parts.push(h('div', { class: 'pad' }, note('Download failed: ' + job.error, 'bad')));
      parts.push(
        h(
          'div',
          { class: 'pad' },
          st.local ? note(`Downloaded ${new Date(st.local.timestamp).toLocaleDateString()} · ${fmtBytes(st.local.size)}`) : null,
          h(
            'div',
            { class: 'actions' },
            st.local
              ? btn('Check for update', async () => {
                  const r = await App.port.blocklists.latest();
                  if (!r.ok) return toast('Update check failed: ' + r.error);
                  toast(r.timestamp > st.local.timestamp ? 'Update available: tap Redownload' : 'Blocklists are up to date');
                })
              : null,
            btn(st.local ? 'Redownload' : 'Download blocklists', async () => {
              App.port.blocklists.download().then((r) => {
                toast(r.ok ? 'Blocklists downloaded' : 'Download failed: ' + r.error);
                if (box.isConnected) draw();
              });
              setTimeout(draw, 300);
            }, { primary: !st.local }),
            st.local
              ? btn('Delete', async () => {
                  if (!(await confirmDialog('Delete blocklists', 'Delete the downloaded blocklists?', 'Delete'))) return;
                  const r = await App.port.blocklists.remove();
                  if (!r.ok) return toast(r.error);
                  App.settings.blocklistsLocal = false;
                  draw();
                })
              : null
          )
        )
      );
    }
    box.replaceChildren(card(parts));
  };
  draw();
  return box;
}
