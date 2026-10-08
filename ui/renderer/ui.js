// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Small DOM builders that mimic the Android app's Material widgets: section
// labels, grouped cards with icon rows, switches, outlined buttons, fields.
// Text always goes in as text nodes; only ICONS (static) are set as HTML.

'use strict';

// ---------- translations ----------

// Texts are written in English; i18n/<lang>.js (built by ui/tools/i18n.py
// from the Android app's translations) maps them to the chosen language.
let I18N = null;

function i18nLoaded(_code, table) {
  I18N = table;
}

function tr(s) {
  if (!I18N || typeof s !== 'string') return s;
  return I18N[s] || I18N[s.trim()] || s;
}

function loadLanguage(code) {
  const lang = (typeof LANGUAGES !== 'undefined' ? LANGUAGES : []).find((l) => l[0] === code);
  document.documentElement.dir = lang && lang[3] ? 'rtl' : 'ltr';
  document.documentElement.lang = lang ? code.replace('-r', '-') : 'en';
  if (!lang) {
    I18N = null;
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = `i18n/${code}.js`;
    s.onload = resolve;
    s.onerror = resolve; // stays English
    document.head.append(s);
  });
}

// Translates the static texts of index.html once.
function translateStatic(root) {
  if (!I18N) return;
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walk.nextNode(); n; n = walk.nextNode()) {
    const t = n.nodeValue.trim();
    if (t && I18N[t]) n.nodeValue = n.nodeValue.replace(t, I18N[t]);
  }
}

const TR_ATTRS = new Set(['placeholder', 'title', 'aria-label']);

// h('div', {class: 'x', onclick: f}, child, 'text', ...)
function h(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = tr(v);
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else if (k === 'checked') e.checked = !!v;
    else e.setAttribute(k, v === true ? '' : TR_ATTRS.has(k) ? tr(v) : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(tr(String(c))));
  }
  return e;
}

function icon(name, cls) {
  const s = h('span', { class: 'ico ' + (cls || '') });
  s.innerHTML = ICONS[name] || ''; // static icon markup only
  return s;
}

function sectionLabel(text) {
  return h('h3', { class: 'section-label', text });
}

function card(...children) {
  return h('div', { class: 'group' }, ...children);
}

// A settings row: icon, title, subtitle, and something on the right.
function row({ ico, title, sub, right, onclick, cls }) {
  const r = h(
    onclick ? 'button' : 'div',
    { class: 'row ' + (cls || ''), onclick, type: onclick ? 'button' : undefined },
    ico ? icon(ico, 'row-ico') : h('span', { class: 'row-ico' }),
    h('span', { class: 'row-text' }, h('span', { class: 'row-title', text: title }), sub ? h('span', { class: 'row-sub', text: sub }) : null),
    right || null
  );
  return r;
}

function chevron() {
  return icon('ic_right_arrow_white', 'chev');
}

// Material-style switch. onchange gets the new value.
function toggle(checked, onchange, label) {
  const input = h('input', { type: 'checkbox', checked, 'aria-label': label || 'toggle' });
  input.addEventListener('change', (e) => {
    e.stopPropagation();
    onchange(input.checked);
  });
  const sw = h('label', { class: 'switch', onclick: (e) => e.stopPropagation() }, input, h('span', { class: 'track' }), h('span', { class: 'thumb' }));
  return sw;
}

function btn(text, onclick, opts) {
  opts = opts || {};
  return h('button', {
    class: 'obtn ' + (opts.primary ? 'primary ' : '') + (opts.wide ? 'wide ' : '') + (opts.cls || ''),
    onclick,
    type: 'button',
    disabled: opts.disabled,
    text,
  });
}

function field({ label, value, placeholder, multiline, mono, oninput, type }) {
  const input = multiline
    ? h('textarea', { class: 'fld-input' + (mono ? ' mono' : ''), placeholder, spellcheck: 'false', rows: 8 })
    : h('input', { class: 'fld-input' + (mono ? ' mono' : ''), type: type || 'text', placeholder, spellcheck: 'false' });
  input.value = value || '';
  if (oninput) input.addEventListener('input', () => oninput(input.value));
  const wrap = h('label', { class: 'fld' }, label ? h('span', { class: 'fld-label', text: label }) : null, input);
  wrap.input = input;
  return wrap;
}

function note(text, cls) {
  return h('p', { class: 'note ' + (cls || ''), text });
}

function dot(state) {
  return h('span', { class: 'dot ' + (state || '') });
}

// Collapsible "Advanced" section.
function expander(title, build) {
  const body = h('div', { class: 'exp-body', hidden: true });
  const head = h(
    'button',
    {
      class: 'exp-head',
      type: 'button',
      onclick: () => {
        const open = body.hidden;
        body.hidden = !open;
        head.classList.toggle('open', open);
        if (open && !body.childElementCount) body.append(...[build()].flat());
      },
    },
    h('span', { text: title }),
    icon('ic_keyboard_arrow_down', 'exp-arrow')
  );
  return h('div', { class: 'exp' }, head, body);
}

// Modal dialog; resolves with true (OK) or false.
function dialog({ title, body, ok, cancel }) {
  return new Promise((resolve) => {
    const close = (v) => {
      back.remove();
      resolve(v);
    };
    const back = h(
      'div',
      { class: 'modal-back', onclick: (e) => e.target === back && close(false) },
      h(
        'div',
        { class: 'modal', role: 'dialog' },
        h('h2', { class: 'modal-title', text: title }),
        h('div', { class: 'modal-body' }, body),
        h('div', { class: 'modal-actions' }, cancel === null ? null : btn(cancel || 'Cancel', () => close(false)), btn(ok || 'OK', () => close(true), { primary: true }))
      )
    );
    document.body.append(back);
    const first = back.querySelector('input, textarea, button.primary');
    if (first) first.focus();
  });
}

// Bottom-sheet menu (Android's bottom sheets): every action closes it.
function sheet({ title, body, actions }) {
  const close = () => back.remove();
  const back = h('div', { class: 'modal-back', onclick: (e) => e.target === back && close() });
  const acts = (actions || []).filter(Boolean).map((a) =>
    btn(a.text, () => {
      close();
      a.onclick();
    }, { primary: a.primary, wide: true, cls: a.cls })
  );
  back.append(
    h(
      'div',
      { class: 'modal sheet', role: 'dialog' },
      h('h2', { class: 'modal-title', text: title }),
      body ? h('div', { class: 'modal-body' }, body) : null,
      h('div', { class: 'sheet-actions' }, acts, btn('Close', close, { wide: true }))
    )
  );
  document.body.append(back);
  return close;
}

// A label and value line, for details.
function kv(label, value) {
  return h('div', { class: 'kv' }, h('span', { text: label }), h('b', { text: value === undefined || value === '' ? '—' : String(value) }));
}

function confirmDialog(title, text, ok) {
  return dialog({ title, body: h('p', { class: 'desc', text }), ok });
}

let toastTimer = 0;
function toast(text) {
  let t = document.getElementById('toast');
  if (!t) {
    t = h('div', { id: 'toast', class: 'toast' });
    document.body.append(t);
  }
  t.textContent = tr(text);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

// First letter avatar for an app (no real icons for Windows apps yet).
function avatar(name) {
  const n = String(name || '?').replace(/\.exe$/i, '');
  let hash = 0;
  for (const ch of n) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  const hue = Math.abs(hash) % 360;
  const a = h('span', { class: 'avatar', text: n.charAt(0).toUpperCase() || '?' });
  a.style.background = `hsl(${hue} 45% 32%)`;
  return a;
}
