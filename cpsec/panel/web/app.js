'use strict';
/* CP-Security panel. Plain JavaScript, no libraries. Everything shown to the user goes through
   text nodes, never raw HTML strings, so nothing from the server can inject markup. */
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const NS = 'http://www.w3.org/2000/svg';

  // ------------------------------------------------------------------ tiny DOM helper
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style') el.style.cssText = v;      // set through the style object: allowed by the strict content policy
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  const ICONS = {
    overview: 'M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z',
    blocked: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 2a8 8 0 016.3 12.9L7.1 5.7A7.9 7.9 0 0112 4zM5.7 7.1l11.2 11.2A8 8 0 015.7 7.1z',
    access: 'M12.65 10A5.99 5.99 0 007 6c-3.31 0-6 2.69-6 6s2.69 6 6 6a5.99 5.99 0 005.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z',
    firewall: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z',
    logins: 'M11 7L9.6 8.4l2.6 2.6H2v2h10.2l-2.6 2.6L11 17l5-5-5-5zm9 12h-8v2h8c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-8v2h8v14z',
    updates: 'M17.65 6.35A7.96 7.96 0 0012 4a8 8 0 108 8h-2a6 6 0 11-1.76-4.24L13 11h7V4l-2.35 2.35z',
    settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z',
    check: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z',
    alert: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z',
    info: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z',
    advisor: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z',
    ports: 'M7.77 6.76L6.23 5.48.82 12l5.41 6.52 1.54-1.28L3.42 12l4.35-5.24zM7 13h2v-2H7v2zm10-2h-2v2h2v-2zm-6 2h2v-2h-2v2zm6.77-7.52l-1.54 1.28L20.58 12l-4.35 5.24 1.54 1.28L23.18 12l-5.41-6.52z',
    headers: 'M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 14v2h8v-2h-8zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z',
    serverfw: 'M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zM4 10h5v4H4v-4zm0 6v-2h5v2H4zm0-10h5v2H4V6zm7 0h9v2h-9V6zm0 4h4v4h-4v-4zm6 0h3v4h-3v-4zm-6 6h9v2h-9v-2z',
    setup: 'M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z',
    more: 'M6 10c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm12 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm-6 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z',
  };
  function icon(name) {
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', ICONS[name]);
    svg.append(path);
    return svg;
  }

  // ------------------------------------------------------------------ state, talking to the server
  const S = { me: null, csrf: '', view: 'overview', problems: 0, drawId: 0, pollTimer: null, twofa: false, more: false, advice: 0, update: null };

  async function api(path, opts = {}) {
    const init = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
    if (opts.body !== undefined) {
      init.body = JSON.stringify(opts.body);
      init.headers['Content-Type'] = 'application/json';
    }
    if (init.method !== 'GET') init.headers['X-CSRF-Token'] = S.csrf;
    let res;
    try { res = await fetch(path, init); }
    catch (e) { return { status: 0, data: { ok: false, message: 'Cannot reach the panel. Check your connection.' } }; }
    let data = {};
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (res.status === 401 && data.code === 'signed_out' && S.me) { S.me = null; draw(); }
    return { status: res.status, data };
  }

  function toast(message, kind) {
    const box = $('#toasts');
    const t = h('div', { class: 'toast ' + (kind || ''), text: message, title: 'Click to dismiss', onclick: () => t.remove() });
    box.append(t);
    while (box.children.length > 3) box.firstChild.remove();       // never pile up
    setTimeout(() => t.remove(), kind === 'bad' ? 8000 : 4500);
  }

  async function withBusy(text, fn) {
    $('#busy-text').textContent = text;
    $('#busy').hidden = false;
    try { return await fn(); } finally { $('#busy').hidden = true; }
  }

  // an action that changes something: ask the server, show the answer, redraw
  async function act(path, body, busyText) {
    const run = () => api(path, { method: 'POST', body });
    const { data } = busyText ? await withBusy(busyText, run) : await run();
    toast(data.message || (data.ok ? 'Done.' : 'That did not work.'), data.ok ? 'ok' : 'bad');
    return data;
  }

  function dialog({ title, content, ok = 'OK', cancel = 'Cancel', danger = false, validate }) {
    return new Promise(resolve => {
      const dlg = $('#dialog');
      dlg.replaceChildren();
      const err = h('p', { class: 'error', role: 'alert' });
      const finish = value => { if (dlg.open) dlg.close(); resolve(value); };
      const okBtn = h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), type: 'button', text: ok, onclick: () => {
        const problem = validate ? validate() : null;
        if (problem) { err.textContent = problem; return; }
        finish(true);
      } });
      const noBtn = cancel ? h('button', { class: 'btn', type: 'button', text: cancel, onclick: () => finish(false) }) : null;
      dlg.addEventListener('cancel', () => resolve(false), { once: true });
      dlg.append(h('div', { class: 'body' }, h('h2', { text: title }), content, err), h('div', { class: 'buttons' }, noBtn, okBtn));
      dlg.showModal();
    });
  }
  const confirmBox = (title, text, ok, danger) => dialog({ title, content: h('p', { text }), ok, danger });

  // ------------------------------------------------------------------ small building blocks
  const badge = (text, kind) => h('span', { class: 'badge ' + (kind || ''), text });
  const card = (title, ...kids) => h('section', { class: 'card' }, title ? h('h2', { text: title }) : null, ...kids);
  const empty = text => h('div', { class: 'empty', text });
  const tile = (label, value) => h('div', { class: 'card tile' }, h('div', { class: 'label', text: label }), h('div', { class: 'value', text: String(value) }));
  const MODES = { off: 'Off', watch: 'Watch only', block: 'Blocking' };

  // each cell remembers its column heading: on a phone a table becomes a list and the heading is shown above the value
  function labelCells(headers, rows) {
    rows.forEach(r => { if (r && r.cells) Array.from(r.cells).forEach((c, i) => { if (headers[i]) c.setAttribute('data-label', headers[i]); }); });
    return rows;
  }

  function table(headers, rows, emptyText, wrapClass) {
    if (!rows.length) return empty(emptyText);
    labelCells(headers, rows);
    return h('div', { class: 'table-wrap' + (wrapClass ? ' ' + wrapClass : '') }, h('table', {},
      h('thead', {}, h('tr', {}, headers.map(x => h('th', { scope: 'col', text: x })))),
      h('tbody', {}, rows)));
  }

  function field(id, label, props) {
    return h('div', { class: 'field' }, h('label', { for: id, text: label }), h('input', Object.assign({ id, name: id }, props || {})));
  }

  // ------------------------------------------------------------------ sign in
  function viewLogin() {
    const error = h('p', { class: 'error', role: 'alert' });
    const form = h('form', { class: 'stack', autocomplete: 'on' },
      field('username', 'Username', { type: 'text', autocomplete: 'username', required: true, autofocus: true }),
      field('password', 'Password', { type: 'password', autocomplete: 'current-password', required: true }),
      // the code is only asked for when the owner switched the second step on
      S.twofa ? field('code', '6-digit code from your authenticator app', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]*', maxlength: 8, required: true }) : null,
      error,
      h('button', { class: 'btn primary', type: 'submit', text: 'Sign in', style: 'width:100%' }));
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      error.textContent = '';
      const btn = $('button', form); btn.disabled = true;
      const code = $('#code');
      const { data } = await api('/api/login', { method: 'POST', body: {
        username: $('#username').value, password: $('#password').value, code: code ? code.value : '' } });
      btn.disabled = false;
      if (data.ok) { await boot(); } else { error.textContent = data.message || 'Could not sign in.'; if (code) code.value = ''; }
    });
    return h('div', { class: 'login' }, h('div', { class: 'card' },
      h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), 'CP-Security'),
      h('p', { class: 'muted', text: 'Sign in to look after your server.' }), form,
      h('p', { class: 'muted small login-note', text: 'Locked out after a change of internet address? Run  security myip  on the server.' })));
  }

  // ------------------------------------------------------------------ the frame around every page
  // id, long name, icon, short name for the phone's bottom bar, menu group, shown in the phone's bottom bar
  const NAV = [
    ['overview', 'Overview', 'overview', 'Overview', 'Protection', true],
    ['advisor', 'Advisor', 'advisor', 'Advisor', 'Protection', true],
    ['blocked', 'Blocked', 'blocked', 'Blocked', 'Protection', true],
    ['access', 'Admin access', 'access', 'Access', 'Protection', false],
    ['ports', 'Open ports', 'ports', 'Ports', 'Protection', false],
    ['serverfw', 'Server firewall', 'serverfw', 'Server FW', 'Protection', false],
    ['headers', 'Security headers', 'headers', 'Headers', 'Protection', false],
    ['firewall', 'Web firewall', 'firewall', 'Firewall', 'Protection', true],
    ['updates', 'WP Updates', 'updates', 'WP Updates', 'Protection', false],
    ['logins', 'One-click login', 'logins', 'Login', 'Protection', false],
    ['setup', 'Setup', 'setup', 'Setup', 'Manage', false],
    ['settings', 'Settings', 'settings', 'Settings', 'Manage', false],
  ];
  const isSmall = () => matchMedia('(max-width:900px)').matches;

  function shell(main) {
    const small = isSmall();
    const link = ([id, label, ic, short]) =>
      h('a', { href: '#/' + id, 'aria-current': S.view === id ? 'page' : null, onclick: () => { S.more = false; } },
        icon(ic), h('span', { text: small ? short : label }),
        id === 'overview' && S.problems ? h('span', { class: 'dot', title: S.problems + ' need attention' }) : null,
        id === 'advisor' && S.advice ? h('span', { class: 'dot warn', title: S.advice + ' suggestions' }) : null);
    const signOut = () => h('button', { class: 'btn small', type: 'button', text: 'Sign out', onclick: async () => {
      await api('/api/logout', { method: 'POST', body: {} }); forgetAdvice(); S.advice = 0; S.me = null; S.more = false; draw(); } });

    let nav;
    if (small) {
      // phone: the four most used pages and a "More" button that opens the rest
      const rest = NAV.filter(n => !n[5]);
      const moreActive = rest.some(n => n[0] === S.view);
      nav = h('nav', { class: 'nav', 'aria-label': 'Main' }, NAV.filter(n => n[5]).map(link),
        h('button', { type: 'button', class: 'more-btn', 'aria-expanded': String(S.more), 'aria-controls': 'more-sheet', 'aria-current': moreActive ? 'page' : null,
          onclick: ev => {
            S.more = !S.more;
            $('#more-sheet').hidden = !S.more;
            ev.currentTarget.setAttribute('aria-expanded', String(S.more));
          } }, icon('more'), h('span', { text: 'More' })));
    } else {
      const groups = [...new Set(NAV.map(n => n[4]))];
      nav = h('nav', { class: 'nav', 'aria-label': 'Main' }, groups.map(g =>
        h('div', { class: 'nav-group' }, h('div', { class: 'nav-title', text: g }), NAV.filter(n => n[4] === g).map(link))));
    }
    const sheet = small
      ? h('div', { class: 'sheet', id: 'more-sheet', hidden: !S.more },
        NAV.filter(n => !n[5]).map(link),
        h('div', { class: 'sheet-foot' }, h('span', { class: 'muted small', text: 'Signed in as ' + S.me.user }), signOut()))
      : null;
    return h('div', {},
      h('div', { class: 'topbar' }, h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', width: 28, height: 28, alt: '' }), 'CP-Security'),
        S.me.demo ? badge('demo', 'warn') : null, h('span', { class: 'right' }, signOut())),
      h('div', { class: 'shell' },
        h('aside', { class: 'side' }, h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), 'CP-Security'), nav,
          h('div', { class: 'foot small muted' }, h('div', { text: 'Signed in as ' + S.me.user }),
            S.me.demo ? h('div', { text: 'DEMO – made-up data' }) : null,
            h('div', { class: 'row', style: 'margin-top:.5rem' }, signOut()))),
        h('main', { class: 'main', id: 'main' }, versionBar(), main)),
      sheet);
  }

  function pageHead(title, sub, ...actions) {
    return h('div', { class: 'page-head' }, h('div', {}, h('h1', { text: title }), sub ? h('div', { class: 'sub', text: sub }) : null),
      h('div', { class: 'right row' }, actions));
  }

  // ------------------------------------------------------------------ the panel's own version and updates
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  // a request that never touches the page: used while the panel restarts and answers nothing or "signed out"
  async function peek(path) {
    try {
      const res = await fetch(path, { credentials: 'same-origin' });
      let data = {};
      try { data = await res.json(); } catch (e) { /* not JSON */ }
      return { status: res.status, data };
    } catch (e) { return { status: 0, data: {} }; }
  }

  async function loadUpdate(check) {
    const r = check ? await api('/api/update/check', { method: 'POST', body: {} }) : await api('/api/update');
    const state = check ? r.data.state : r.data;
    if (state && state.current) S.update = state;
    return r;
  }

  function versionBar() {
    const u = S.update;
    const working = u && u.job && (u.job.status === 'working' || u.job.status === 'restarting');
    let chip;
    if (!u || !u.checked_at) chip = badge('not checked yet', '');
    else if (u.check_error) chip = badge('could not check', 'warn');
    else if (u.available) chip = badge('update available: v' + u.latest, 'warn');
    else chip = badge('up to date', 'ok');
    return h('div', { class: 'versionbar' },
      h('span', { class: 'ver', text: 'CP-Security v' + ((u && u.current) || S.me.version) }), chip,
      working ? h('span', { class: 'muted small', text: 'updating…' }) : null,
      h('button', { class: 'btn small right' + (u && u.available ? ' primary' : ''), type: 'button',
        text: u && u.available ? 'Update now…' : 'Check for updates', onclick: openUpdate }));
  }

  async function openUpdate() {
    const r = await withBusy('Looking for a newer version…', () => loadUpdate(true));
    const u = S.update;
    if (!u) { toast((r.data && r.data.message) || 'Could not check.', 'bad'); return; }
    const failed = u.last_result && u.last_result.ok === false;
    const content = h('div', { class: 'stack' },
      h('p', {}, 'You have ', h('strong', { text: 'v' + u.current }),
        u.available ? [', and ', h('strong', { text: 'v' + u.latest }), ' is available' + (u.published ? ' (published ' + u.published + ')' : '') + '.']
          : '. This is the newest version.'),
      u.check_error ? h('p', { class: 'error', text: u.check_error }) : null,
      failed ? h('div', { class: 'note warn', text: 'The last update (' + u.last_result.version + ', ' + u.last_result.when + ') did not start, so the old version was put back automatically.' }) : null,
      u.available && u.notes ? [h('p', { class: 'muted small', text: 'What is new:' }), h('pre', { class: 'log', text: u.notes })] : null,
      u.available ? h('p', { class: 'muted small', text: 'The panel restarts for a few seconds and you sign in again. The download is checked against its published fingerprint and tested before it is switched on; if the new version does not start, the old one comes back by itself. Your protection keeps running during the update.' }) : null);
    const go = await dialog({ title: u.available ? 'Update CP-Security?' : 'CP-Security is up to date', content,
      ok: u.available ? 'Update to v' + u.latest : 'Close', cancel: u.available ? 'Not now' : '' });
    if (go && u.available) await runUpdate(u.latest);
    else if (go !== undefined) redraw();
  }

  async function runUpdate(target) {
    const r = await api('/api/update/install', { method: 'POST', body: { version: target, confirm: true } });
    if (!r.data.ok) { toast(r.data.message, 'bad'); return; }
    const text = $('#busy-text');
    $('#busy').hidden = false;
    text.textContent = 'Starting the update…';
    const started = Date.now();
    let restarting = false;
    while (Date.now() - started < 180000) {
      await sleep(1500);
      const s = await peek('/api/update');
      if (s.status === 200 && s.data.job) {
        text.textContent = s.data.job.message || 'Working…';
        if (s.data.job.status === 'failed') { $('#busy').hidden = true; toast(s.data.job.message, 'bad'); await loadUpdate(false); redraw(); return; }
        if (s.data.job.status === 'done') { $('#busy').hidden = true; S.update = s.data; toast('Updated to v' + target + '.', 'ok'); redraw(); return; }
        if (s.data.job.status === 'restarting') restarting = true;
      } else {
        restarting = true;                               // no answer, or signed out: the panel is restarting
      }
      if (restarting) {
        text.textContent = 'The panel is restarting…';
        const me = await peek('/api/me');
        if (me.status === 200 && me.data.version === target) { location.reload(); return; }
      }
    }
    $('#busy').hidden = true;
    toast('The panel did not come back with the new version. It goes back to the old one by itself: reload this page in a minute.', 'bad');
  }

  // ------------------------------------------------------------------ overview
  // the advice card on the Overview, remembered between redraws (and reloads of this tab) so it never blinks
  const ADVICE_KEY = 'cps-advice';
  function savedAdvice() {
    if (S.adviceData) return S.adviceData;
    try {
      const v = JSON.parse(sessionStorage.getItem(ADVICE_KEY) || 'null');
      if (v && Array.isArray(v.todo) && typeof v.at === 'number') { S.adviceData = v; return v; }
    } catch (e) { /* storage unavailable or damaged: just ask again */ }
    return null;
  }
  function rememberAdvice(todo) {
    S.adviceData = { todo, at: Date.now() };
    try { sessionStorage.setItem(ADVICE_KEY, JSON.stringify(S.adviceData)); } catch (e) { /* not essential */ }
  }
  function forgetAdvice() {
    S.adviceData = null;
    try { sessionStorage.removeItem(ADVICE_KEY); } catch (e) { /* not essential */ }
  }
  function showAdvice(slot, todo) {
    if (!todo.length) {
      slot.replaceChildren();
      const old = document.querySelector('.nav a[href="#/advisor"] .dot');
      if (old) old.remove();
      return;
    }
    slot.replaceChildren(h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Advice for you' }), badge(todo.length + ' suggestion' + (todo.length > 1 ? 's' : ''), 'warn'),
        h('a', { class: 'btn small right', href: '#/advisor', text: 'See all advice' })),
      h('div', { class: 'mini-list' }, todo.slice(0, 3).map(f => h('div', { class: 'mini ' + f.level }, icon(f.level === 'bad' ? 'alert' : 'info'),
        h('div', {}, h('div', { class: 'what', text: f.title }), f.advice ? h('div', { class: 'text', text: f.advice }) : null))))));
    const dot = document.querySelector('.nav a[href="#/advisor"]');
    if (dot && !dot.querySelector('.dot')) dot.append(h('span', { class: 'dot warn', title: todo.length + ' suggestions' }));
  }

  async function viewOverview(refresh, soft) {
    const { data } = await api('/api/overview' + (refresh ? '?refresh=1' : ''));
    S.problems = data.problems || 0;
    const ok = S.problems === 0;
    const sites = data.sites || { sites: [], new_problems: [], old_problems: [] };
    const sorted = sites.sites.slice().sort((a, b) => Number(a.ok) - Number(b.ok) || a.domain.localeCompare(b.domain));
    // the websites are asked in the background (it takes several seconds): look again until the answers are in
    if (data.sites_checking) setTimeout(() => { if (S.view === 'overview') softRedraw(); }, 2500);
    // The advice takes a few seconds to gather, so the page does not wait for it. The last advice we saw is shown
    // at once (kept for the whole visit), and the fresh answer replaces it quietly, only if something changed.
    // Without this the card popped in late and pushed everything down, and vanished on every background refresh.
    const teaser = h('div', {});
    const cached = savedAdvice();
    if (cached) { showAdvice(teaser, cached.todo); S.advice = cached.todo.length; }
    const recent = cached && Date.now() - cached.at < 120000;
    if (refresh || !(soft && recent)) {
      api('/api/advisor' + (refresh ? '?refresh=1' : '')).then(({ data: a }) => {
        if (!a || !a.findings) return;
        const todo = a.findings.filter(f => f.level === 'bad' || f.level === 'warn').map(f => ({ level: f.level, title: f.title, advice: f.advice || '' }));
        const same = cached && JSON.stringify(cached.todo) === JSON.stringify(todo);
        rememberAdvice(todo);
        S.advice = todo.length;
        if (!same) showAdvice(teaser, todo);
      });
    }
    return h('div', { class: 'stack' },
      pageHead('Overview', 'Checked ' + data.checked_at, h('button', { class: 'btn', type: 'button', text: 'Check again', onclick: () => redraw(true) })),
      h('div', { class: 'banner ' + (ok ? 'ok' : 'bad') }, icon(ok ? 'check' : 'alert'),
        h('div', {}, h('div', { text: ok ? 'Everything looks fine' : S.problems + ' thing' + (S.problems > 1 ? 's' : '') + ' need attention' }),
          h('div', { class: 'sub', text: ok ? 'The protections are on and your websites are answering.' : 'Look at the items marked in red below.' }))),
      teaser,
      h('div', { class: 'grid tiles' },
        tile('Blocked in the last 24 hours', data.blocked_24h),
        tile('Web firewall', data.waf_mode ? MODES[data.waf_mode] : 'Not set up'),
        tile('Websites answering', data.sites_pending ? 'checking…' : sites.normal + ' of ' + sites.total)),
      h('div', { class: 'grid' }, data.rows.map(r =>
        h('div', { class: 'card status-row' }, h('span', { class: 'dot-s ' + r.status, 'aria-hidden': 'true' }),
          h('div', {}, h('div', { class: 'what', text: r.label }), h('div', { class: 'text', text: r.text }))))),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Websites' }),
          data.sites_pending ? badge('checking…', '') : sites.new_problems.length ? badge(sites.new_problems.length + ' new problem' + (sites.new_problems.length > 1 ? 's' : ''), 'bad') : badge('no new problems', 'ok'),
          data.sites_checking && !data.sites_pending ? badge('refreshing…', '') : null,
          data.sites_checked_at ? h('span', { class: 'muted small right', text: 'Last asked ' + data.sites_checked_at }) : null),
        table(['Website', 'Answer'], sorted.map(s => {
          const old = sites.old_problems.some(o => o.domain === s.domain);
          return h('tr', {}, h('td', { class: 'mono', text: s.domain }),
            h('td', {}, badge(s.code === '000' ? 'no answer' : s.code, s.ok ? 'ok' : 'bad'), old ? h('span', { class: 'muted small', text: '  already like this before' }) : null));
        }), data.sites_pending ? 'Asking every website… this takes a few seconds.' : 'No websites found.')));
  }

  // ------------------------------------------------------------------ blocked
  async function viewBlocked() {
    const { data } = await api('/api/blocked');
    const rows = data.rows || [];
    const sum = data.summary || { day: { blocks: 0, by_reason: [] }, week: { blocks: 0, by_reason: [] }, top_addresses: [] };
    const unblockForm = h('form', { class: 'inline-form' }, field('ub-ip', 'Let one address in', { type: 'text', placeholder: 'for example 45.60.0.99', required: true }),
      h('button', { class: 'btn', type: 'submit', text: 'Let in' }));
    unblockForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      await act('/api/blocked/unblock', { ip: $('#ub-ip').value });
      redraw();
    });
    return h('div', { class: 'stack' },
      pageHead('Blocked addresses', 'People and robots the server turned away because they kept guessing passwords.'),
      !data.running ? h('div', { class: 'banner bad' }, icon('alert'), h('div', {}, h('div', { text: 'Automatic blocking is switched off' }),
        h('div', { class: 'sub', text: 'Nobody is being blocked right now.' }))) : null,
      h('div', { class: 'grid tiles' }, tile('Blocked right now', rows.length), tile('Blocks in 24 hours', sum.day.blocks), tile('Blocks in 7 days', sum.week.blocks)),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Blocked right now' }),
          rows.length ? h('button', { class: 'btn small right', type: 'button', text: 'Let everybody back in', onclick: async () => {
            if (await confirmBox('Let everybody back in?', 'All ' + rows.length + ' blocked addresses will be able to try again immediately.', 'Let everybody in', true)) {
              await act('/api/blocked/unblock-all', {}); redraw(); } } }) : null),
        table(['Address', 'Why', 'Blocked'], rows.map(r => h('tr', {}, h('td', { class: 'mono', text: r.ip }), h('td', { text: r.why }),
          h('td', { text: r.until_text }),
          h('td', { class: 'actions' }, h('button', { class: 'btn small', type: 'button', text: 'Let back in', onclick: async () => {
            await act('/api/blocked/unblock', { ip: r.ip }); redraw(); } })))), 'Nobody is blocked right now.')),
      card('Let an address in', unblockForm,
        h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'If a customer or a member of staff cannot reach a website, ask them to search Google for "what is my IP" and let that address in here.' })),
      card('Why they were blocked (last 7 days)', sum.week.by_reason.length
        ? h('div', { class: 'stack' }, sum.week.by_reason.map(r => h('div', { class: 'row' }, h('span', { text: r.why }), h('span', { class: 'right' }, badge(String(r.count)))))) : empty('Nothing blocked yet.')),
      card('Emergency switch', h('p', { class: 'muted', text: 'Stops all automatic blocking at once. Use it only if you suspect the blocker is causing a problem. It starts again by itself after a reboot.' }),
        h('button', { class: 'btn ' + (data.running ? 'danger' : 'primary'), type: 'button', text: data.running ? 'Stop all automatic blocking' : 'Start automatic blocking', onclick: async () => {
          if (!data.running || await confirmBox('Stop all automatic blocking?', 'Everybody who is blocked can try again, and nobody new will be blocked until you start it again.', 'Stop blocking', true)) {
            await act('/api/blocked/engine', { running: !data.running }); redraw(); } } })));
  }

  // ------------------------------------------------------------------ admin access
  async function viewAccess() {
    const { data } = await api('/api/access');
    const mine = data.client_ip;
    const addForm = h('form', { class: 'inline-form' }, field('ac-addr', 'Address', { type: 'text', required: true, placeholder: 'for example 45.60.0.99' }),
      field('ac-label', 'Name', { type: 'text', placeholder: 'for example Office', maxlength: 60 }), h('button', { class: 'btn primary', type: 'submit', text: 'Add' }));
    addForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      const r = await act('/api/access/add', { address: $('#ac-addr').value, label: $('#ac-label').value }, 'Updating the lock…');
      if (r.ok) redraw();
    });
    const neverForm = h('form', { class: 'inline-form' }, field('nb-addr', 'Add an address that must never be blocked', { type: 'text', required: true, placeholder: 'for example 45.60.0.99' }),
      field('nb-label', 'Name', { type: 'text', placeholder: 'for example Monitoring', maxlength: 60 }), h('button', { class: 'btn', type: 'submit', text: 'Add' }));
    neverForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      const r = await act('/api/access/never/add', { address: $('#nb-addr').value, label: $('#nb-label').value }, 'Updating the blocker…');
      if (r.ok) redraw();
    });
    const remove = async t => {
      let confirmed = false;
      if (t.address === mine) {
        if (!await confirmBox('Remove the address you are using?', 'This is the address you are connected from right now. Removing it can lock you out of the admin pages.', 'Remove it', true)) return;
        confirmed = true;
      } else if (!await confirmBox('Remove ' + t.address + '?', t.label + ' will no longer be able to open the admin pages.', 'Remove', true)) return;
      await act('/api/access/remove', { address: t.address, confirmed }, 'Updating the lock…');
      redraw();
    };

    // 1. what the trusted list actually protects
    const doors = data.protects || [];
    const protects = h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'What only your trusted addresses can open' }), data.lock_live ? badge('lock is on', 'ok') : badge('lock is NOT on', 'bad'),
        h('button', { class: 'btn small right', type: 'button', text: 'Choose which doors', onclick: () => { location.hash = '#/ports'; } })),
      doors.length
        ? doors.map(d => h('div', { class: 'door' },
          h('div', { class: 'door-head' }, h('strong', { text: d.name }), h('span', { class: 'muted small mono', text: (d.ports.length > 1 ? 'ports ' : 'port ') + d.ports.join(', ') }), d.running ? null : badge('not running', '')),
          h('div', { class: 'muted small', style: 'margin-top:.25rem', text: d.why })))
        : empty('Nothing is limited right now: every door is open to everyone.'),
      h('div', { class: 'card-foot muted small', text: 'Anybody else is refused at these doors: they never even see a login page. Your websites are not affected. The attack blocker also never bans a trusted address.' }));

    // 2. the never-block list: entries with the same name are one line
    const neverRows = (data.never_groups || []).map(g => {
      const only = g.entries[0];
      const removeThem = async () => {
        const what = g.many ? 'all ' + g.entries.length + ' ' + g.label + ' ranges' : only.address;
        if (!await confirmBox('Remove ' + what + '?', 'The blocker will be allowed to ban ' + (g.many ? 'them' : 'it') + ' again if ' + (g.many ? 'they keep' : 'it keeps') + ' guessing passwords.', 'Remove', true)) return;
        await act('/api/access/never/remove', { addresses: g.entries.map(e => e.address) }, 'Updating the blocker…');
        redraw();
      };
      return h('tr', {},
        h('td', {}, h('strong', { text: g.label }), g.hint ? h('div', { class: 'muted small', text: g.hint }) : null,
          g.many ? h('details', { class: 'small', style: 'margin-top:.4rem' }, h('summary', { text: 'Show the ' + g.entries.length + ' ranges' }),
            h('ul', { class: 'plain' }, g.entries.map(e => h('li', {}, h('span', { class: 'mono', text: e.address }), h('span', { class: 'muted', text: '  \u2013 ' + e.size_text }))))) : null),
        h('td', {}, g.many ? h('span', { text: g.total_text }) : h('div', {}, h('span', { class: 'mono', text: only.address }), h('div', { class: 'muted small', text: only.size_text }))),
        h('td', { class: 'actions' }, h('button', { class: 'btn small danger', type: 'button', text: g.many ? 'Remove all' : 'Remove', onclick: removeThem })));
    });

    return h('div', { class: 'stack' },
      pageHead('Admin access', 'The trusted list decides who gets through to your private doors, such as CyberPanel. Everybody else is refused. Your websites are not affected.'),
      protects,
      h('section', { class: 'card' },
        h('h2', { text: 'Your address right now' }),
        h('p', {}, h('span', { class: 'mono', text: mine }), ' ', data.client_ip_trusted ? badge('trusted', 'ok') : badge('not on the list', 'warn')),
        h('p', { class: 'muted', text: 'If your home internet address changed and you cannot open CyberPanel, press the button. It replaces your old home address with this one.' }),
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', type: 'button', text: 'Use this as my home address', onclick: async () => {
            if (await confirmBox('Use ' + mine + ' as your home address?', 'CyberPanel and the other admin pages will open from this address. Your old home address stops working.', 'Use this address')) {
              await act('/api/access/home', {}, 'Updating the lock…'); redraw(); } } }),
          data.client_ip_trusted ? null : h('button', { class: 'btn', type: 'button', text: 'Also trust it (keep the others)', onclick: async () => {
            await act('/api/access/add', { address: mine, label: 'Added from the panel' }, 'Updating the lock…'); redraw(); } }))),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Trusted addresses' }), badge(String(data.trusted.length)),
          h('span', { class: 'muted small right', text: 'These get through the doors above.' })),
        table(['Address', 'Name', ''], data.trusted.map(t => h('tr', {}, h('td', { class: 'mono', text: t.address }),
          h('td', {}, t.label, t.address === mine ? [' ', badge('you', 'brand')] : null,
            t.is_server ? h('div', { class: 'muted small', text: 'The server itself. Leave it: the server\u2019s own programs sometimes reach the admin pages through this address.' }) : null),
          h('td', { class: 'actions' }, h('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: () => remove(t) })))), 'No trusted addresses.')),
      card('Add a trusted address', addForm,
        h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'Use the public address (search Google for "what is my IP"). Addresses like 192.168.x.x only exist inside a home network and do not work.' })),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Never banned by the attack blocker' }), badge(String((data.never_groups || []).length))),
        h('p', { class: 'muted', style: 'padding:1rem 1.25rem 0', text: 'The attack blocker bans an address for a while when it keeps guessing passwords. The addresses here are never banned, even if they misbehave (your trusted addresses are never banned either). Add one only when a ban would do harm: your office, a monitoring service, or Cloudflare.' }),
        h('p', { class: 'muted small', style: 'padding:.5rem 1.25rem 1rem', text: 'A line like 173.245.48.0/20 is not one address but a range: the whole block of 4,096 addresses that starts at 173.245.48.0.' }),
        table(['Name', 'What it covers', ''], neverRows, 'Nothing is on this list.'),
        h('div', { class: 'card-foot' }, neverForm)));
  }

  // ------------------------------------------------------------------ open ports
  const PORT_STATUS = {
    open: 'Open to everyone', refused: 'Refused by the server firewall', locked: 'Trusted addresses only', closed: 'This server only',
    private: 'Private network only', idle: 'Nothing running', mixed: 'Partly limited',
  };
  const LOCKED_BY = { default: 'Limited automatically, because this is an admin page.', you: 'You limited this door.', panel: 'Who may reach the panel is set on the Settings page.' };

  async function viewPorts() {
    const { data } = await api('/api/ports');
    const head = pageHead('Open ports', 'Every program on this server waits for visitors at a numbered \u201cdoor\u201d (a port). Here you see who uses each door today, and you can limit a door so that only your trusted addresses can use it.');
    if (!data.supported) return h('div', { class: 'stack' }, head, card(null, empty(data.message)));

    // doors that belong together are one line (80 and 443, or 465 and 587)
    const groups = [], index = {};
    data.ports.forEach(r => {
      if (!(r.group in index)) { index[r.group] = groups.length; groups.push({ key: r.group, rows: [] }); }
      groups[index[r.group]].rows.push(r);
    });
    const RANK = { bad: 0, warn: 1, info: 2, ok: 3 };
    groups.forEach(g => {
      g.head = g.rows[0];
      g.ports = g.rows.map(r => r.port).sort((a, b) => a - b);
      const statuses = new Set(g.rows.map(r => r.status));
      g.status = statuses.size === 1 ? g.rows[0].status : 'mixed';
      g.level = g.rows.map(r => r.level).sort((a, b) => RANK[a] - RANK[b])[0];
      g.lockable = g.rows.filter(r => r.can_lock);
      g.openable = g.rows.filter(r => r.can_open);
      g.acceptable = g.rows.filter(r => r.can_accept);
      g.ignored = g.rows.filter(r => r.ignored);
      g.reachable = g.rows.some(r => ['open', 'private', 'refused'].includes(r.status));
      g.limited = g.rows.some(r => r.status === 'locked' || r.status === 'idle');
    });
    const portsText = g => (g.ports.length > 1 ? 'ports ' : 'port ') + g.ports.join(', ');
    const attention = groups.filter(g => g.reachable && (g.level === 'bad' || g.level === 'warn'));
    const inUse = groups.filter(g => g.reachable && !attention.includes(g));
    const limited = groups.filter(g => !g.reachable && g.limited);
    const onlyHere = groups.filter(g => !g.reachable && !g.limited);

    const chips = () => data.trusted_list.map(t => h('span', { class: 'chip', title: t.label || '' }, t.label ? t.label + ' \u00b7 ' : '', h('span', { class: 'mono', text: t.address })));
    const notTrusted = () => data.client_ip_trusted ? null : h('p', { class: 'error', style: 'min-height:0', text: 'The address you are using now (' + data.client_ip + ') is not on the trusted list, so you would lose access to this too. Add it on the Admin access page first.' });

    const limit = async g => {
      const r = g.head;
      const content = h('div', {},
        h('p', {}, 'Only these addresses will be able to reach ', h('strong', { text: r.name }), ' (' + portsText(g) + '). Everybody else is refused.'),
        h('div', { class: 'chips', style: 'margin-bottom:.75rem' }, chips()),
        h('p', { class: 'small' }, h('strong', { text: 'Used today by: ' }), r.uses),
        h('p', { class: 'small' }, h('strong', { text: 'What would change: ' }), r.if_limited),
        notTrusted());
      if (!await dialog({ title: 'Limit ' + r.name + ' to your trusted addresses?', content, ok: 'Limit it', danger: !!r.warn && !r.nothing_stops })) return;
      for (const row of g.lockable) {
        const res = await act('/api/ports/lock', { port: row.port, confirmed: true }, 'Updating the lock\u2026');
        if (!res.ok) break;
      }
      redraw();
    };
    const openUp = async g => {
      const r = g.openable[0];
      if (!await confirmBox('Open ' + g.head.name + ' to everybody?', r.open_warning || (g.head.name + ' (' + portsText(g) + ') will be open to everybody again.'), 'Open it', true)) return;
      for (const row of g.openable) {
        const res = await act('/api/ports/unlock', { port: row.port, confirmed: true }, 'Updating the lock\u2026');
        if (!res.ok) break;
      }
      redraw();
    };
    const know = async (g, on) => {
      for (const row of (on ? g.acceptable : g.ignored)) await act('/api/ports/accept', { port: row.port, accepted: on });
      redraw();
    };

    const line = (label, text, cls) => h('div', { class: 'door-line' }, h('span', { class: 'lbl', text: label }), h('span', { class: cls || '', text }));
    const doorRow = (g, sectionSays) => {
      const r = g.head;
      const kind = g.level === 'bad' ? 'bad' : g.level === 'warn' ? 'warn' : ['locked', 'closed', 'refused'].includes(g.status) ? 'ok' : '';
      const buttons = [];
      if (g.lockable.length) buttons.push(h('button', { class: 'btn small' + (g.level === 'bad' || g.level === 'warn' ? ' primary' : ''), type: 'button', text: 'Limit to trusted addresses', onclick: () => limit(g) }));
      if (g.openable.length) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Open to everyone', onclick: () => openUp(g) }));
      if (g.ignored.length) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Warn me again', onclick: () => know(g, false) }));
      else if (g.acceptable.length) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'I know about this', onclick: () => know(g, true) }));
      const why = g.status === 'locked' && LOCKED_BY[r.locked_by] ? LOCKED_BY[r.locked_by] : '';
      return h('div', { class: 'door' },
        h('div', { class: 'door-head' }, h('strong', { text: r.name }), h('span', { class: 'muted small mono', text: portsText(g) }), sectionSays === g.status ? null : badge(PORT_STATUS[g.status] || g.status, kind)),
        line('Used by', r.uses),
        g.status === 'locked' || g.status === 'idle' ? null : line('If you limit it', r.if_limited, r.nothing_stops ? 'safe' : ''),
        why ? h('div', { class: 'muted small', style: 'margin-top:.35rem', text: why }) : null,
        g.status === 'refused' ? h('div', { class: 'muted small', style: 'margin-top:.35rem', text: r.status_text }) : null,
        r.advice && g.reachable ? h('div', { class: 'small', style: 'margin-top:.4rem', text: r.advice }) : null,
        !g.lockable.length && g.reachable && r.cannot_lock_reason && r.service !== 'web' ? h('div', { class: 'muted small', style: 'margin-top:.35rem', text: r.cannot_lock_reason }) : null,
        buttons.length ? h('div', { class: 'door-actions' }, buttons) : null);
    };
    const section = (title, sub, items, says) => items.length ? h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: title }), badge(String(items.length)), h('span', { class: 'muted small', text: sub })),
      items.map(g => doorRow(g, says))) : null;

    const banner = attention.length
      ? h('div', { class: 'banner ' + (attention.some(g => g.level === 'bad') ? 'bad' : 'warn') }, icon('alert'), h('div', {}, h('div', { text: attention.length + (attention.length === 1 ? ' door needs' : ' doors need') + ' a look' }), h('div', { class: 'sub', text: 'Open to the whole internet, and probably not meant to be.' })))
      : h('div', { class: 'banner ok' }, icon('check'), h('div', {}, h('div', { text: 'Nothing here looks wrong' }), h('div', { class: 'sub', text: 'Every door open to the internet is one a normal server uses.' })));

    const trustedCard = card(null,
      h('div', { class: 'row' }, h('strong', { text: 'Your trusted addresses' }), badge(String(data.trusted), data.trusted ? 'ok' : 'bad'),
        h('button', { class: 'btn small right', type: 'button', text: 'Change the list', onclick: () => { location.hash = '#/access'; } })),
      h('p', { class: 'muted', style: 'margin:.5rem 0 .75rem', text: 'When you limit a door, only these addresses get through. Everybody else is refused: customers, other servers, and you too if your own address is not on this list.' }),
      h('div', { class: 'chips' }, chips()),
      notTrusted());

    const hereCard = onlyHere.length ? h('section', { class: 'card flush' },
      h('details', { class: 'quiet' },
        h('summary', { text: onlyHere.length + (onlyHere.length === 1 ? ' door that only this server can reach' : ' doors that only this server can reach') + ' (nothing to decide)' }),
        h('ul', { class: 'plain', style: 'margin-top:.6rem' }, onlyHere.map(g => h('li', {}, h('span', { class: 'mono', text: g.ports.join(', ') }), ' ', h('strong', { text: g.head.name }), g.head.what ? h('span', { class: 'muted', text: ' \u2013 ' + g.head.what }) : null))))) : null;

    return h('div', { class: 'stack' }, head, banner, trustedCard,
      section('Worth a look', 'Open to everyone. Check that you want this.', attention),
      section('Open to everyone', 'Normal doors that people or other servers use. If a line says nothing would stop working, you can limit the door safely.', inUse, 'open'),
      section('Limited to your trusted addresses', 'Only the addresses on your list get through.', limited, 'locked'),
      hereCard,
      h('p', { class: 'muted small', text: 'This shows what the programs on the server allow. A firewall outside the server, such as your hosting company\u2019s, may close more' + (data.firewall ? ', and a firewall (' + data.firewall + ') is also switched on here' : '') + '. Only TCP doors are listed. You can undo every choice.' }));
  }

  // ------------------------------------------------------------------ server firewall
  const FW_SOURCE = { you: 'added by you', cyberpanel: 'copied from CyberPanel', 'in use': 'was in use', 'other firewall': 'allowed by another firewall rule' };
  const clockText = s => Math.floor(s / 60) + ':' + String(Math.max(0, s % 60)).padStart(2, '0');

  async function viewServerFw() {
    const { data } = await api('/api/serverfw');
    const t = data.truth, cp = t.cyberpanel;
    const small = isSmall();
    const head = pageHead('Server firewall', 'Which ports are open to the internet. While the firewall is on, only the ports on your list are open and everything else is refused.');
    clearInterval(S.fwTick);

    const run = async (path, body, busy) => { const r = await act(path, body, busy); redraw(); return r; };
    const turnOn = async () => {
      const addBox = h('input', { type: 'checkbox', id: 'fw-add', checked: true });
      const sug = data.suggestions;
      const content = h('div', {},
        h('p', { text: 'Only the ports on your list will stay open. The server login and the admin pages are always open, so you cannot lock yourself out.' }),
        sug.length ? h('div', {},
          h('p', { text: 'These are in use right now and are not on your list. Visitors and programs would be refused:' }),
          h('ul', { class: 'plain' }, sug.map(s => h('li', {}, h('span', { class: 'mono', text: s.port + ' ' + s.proto.toUpperCase() }), ' ' + s.name + (s.address ? ' (only from ' + s.address + ')' : '')))),
          tick('fw-add', addBox, 'Also allow these (recommended)')) : null,
        h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'Safety net: after you turn it on you have ' + (data.confirm_seconds / 60) + ' minutes to press "Keep it". If you do nothing, the firewall switches itself off again.' }));
      if (!await dialog({ title: 'Turn the firewall on?', content, ok: 'Turn on' })) return;
      await run('/api/serverfw/power', { action: 'on', add_in_use: addBox.checked, confirmed: true }, 'Turning the firewall on…');
    };
    const turnOff = async () => {
      if (!await confirmBox('Turn the firewall off?', 'Every port that has a program behind it can be reached from the internet again. The admin lock keeps working.', 'Turn off', true)) return;
      await run('/api/serverfw/power', { action: 'off' }, 'Turning the firewall off…');
    };
    const remove = async r => {
      if (!await confirmBox('Close ' + r.text + '?', data.enabled ? 'It is removed from the list and closed right away.' : 'It is removed from the list.', 'Remove', true)) return;
      let res = (await api('/api/serverfw/remove', { method: 'POST', body: { id: r.id } })).data;
      if (res.code === 'needs_confirm') {
        if (!await confirmBox('Close a port that is in use?', res.message, 'Close it anyway', true)) return;
        res = (await api('/api/serverfw/remove', { method: 'POST', body: { id: r.id, confirmed: true } })).data;
      }
      toast(res.message, res.ok ? 'ok' : 'bad');
      redraw();
    };

    // ---- the truth
    const buttons = h('div', { class: 'row', style: 'margin-top:1rem' },
      data.loaded
        ? [h('button', { class: 'btn', type: 'button', text: 'Reload', onclick: () => run('/api/serverfw/power', { action: 'reload' }, 'Reloading…') }),
           h('button', { class: 'btn danger', type: 'button', text: 'Turn off…', onclick: turnOff })]
        : h('button', { class: 'btn primary', type: 'button', text: 'Turn on…', onclick: turnOn }));
    const status = h('section', { class: 'card' },
      h('div', { class: 'row' }, h('h2', { text: data.loaded ? 'The firewall is ON' : 'The firewall is OFF' }), badge(data.loaded ? 'ON' : 'OFF', data.loaded ? 'ok' : 'bad')),
      h('p', { text: t.verdict.text }),
      cp.present ? h('div', { class: 'mini ' + (cp.level === 'bad' ? 'bad' : cp.level === 'ok' ? 'ok' : '') },
        icon(cp.level === 'bad' ? 'alert' : 'info'),
        h('div', {}, h('div', { class: 'what', text: 'What CyberPanel\u2019s own Firewall page says' }), h('div', { class: 'text', text: cp.text }))) : null,
      buttons);

    // ---- waiting for "Keep it"
    let waiting = null;
    if (data.pending) {
      const clock = h('strong', { text: clockText(data.pending.seconds_left) });
      let left = data.pending.seconds_left;
      const id = S.drawId;
      S.fwTick = setInterval(() => {
        if (id !== S.drawId || S.view !== 'serverfw') { clearInterval(S.fwTick); return; }
        left -= 1; clock.textContent = clockText(Math.max(0, left));
        if (left <= -2) { clearInterval(S.fwTick); softRedraw(); }
      }, 1000);
      waiting = h('section', { class: 'card', style: 'border-color:var(--warn)' },
        h('h2', { text: 'Is everything still working?' }),
        h('p', {}, 'The firewall is on but not confirmed yet. Check your websites, mail and anything else you use. In ', clock,
          ' it switches itself off again, unless you press Keep it.'),
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', type: 'button', text: 'Keep it', onclick: () => run('/api/serverfw/keep', {}, 'Saving…') }),
          h('button', { class: 'btn', type: 'button', text: 'Undo now', onclick: () => run('/api/serverfw/undo', {}, 'Undoing…') })));
    }

    // ---- what could be added
    const sug = data.suggestions;
    const sugCard = sug.length ? h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'In use but not on your list' }), badge(String(sug.length), 'warn'),
        h('button', { class: 'btn small primary right', type: 'button', text: 'Add them all', onclick: () => run('/api/serverfw/suggested', {}, 'Adding…') })),
      table(['Port', 'Name', 'Why'], sug.map(s => h('tr', {},
        h('td', {}, h('span', { class: 'mono', text: s.port }), ' ', badge(s.proto.toUpperCase(), '')),
        h('td', {}, s.name, s.address ? h('div', { class: 'muted small', text: 'only from ' + s.address }) : null),
        h('td', { class: 'muted small', text: s.why }))), ''),
      h('div', { class: 'card-foot muted small', text: 'When the firewall is on, anything that is not on the list is refused. Add what you use.' })) : null;
    const allow = async r => {
      if (!await confirmBox('Open ' + r.proto.toUpperCase() + ' ' + r.port + ' to everybody?', 'Anybody on the internet will be able to reach it. Only do this for something of yours that you know.', 'Open it')) return;
      await run('/api/serverfw/add', { name: 'Allowed from the refused list', proto: r.proto, address: '', port: String(r.port) }, 'Adding…');
    };
    const refusedCard = data.loaded ? (data.refused === null
      ? h('div', { class: 'note', text: 'This server\u2019s firewall program cannot count the ports it refuses.' })
      : h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Refused in the last hour' }), badge(String(data.refused.length), data.refused.length ? 'warn' : 'ok'),
          h('span', { class: 'muted small right', text: 'The counts start again when you change the list.' })),
        data.refused.length ? table(['Port', 'Tried', 'Program', ''], data.refused.map(r => h('tr', {},
          h('td', {}, h('span', { class: 'mono', text: r.port }), ' ', badge(r.proto.toUpperCase(), '')),
          h('td', { text: r.packets + (r.proto === 'tcp' ? (r.packets === 1 ? ' attempt' : ' attempts') : (r.packets === 1 ? ' packet' : ' packets')) }),
          h('td', { class: 'small', text: r.programs.length ? r.programs.join(', ') : 'nothing is listening' }),
          h('td', { class: 'actions' }, h('button', { class: 'btn small', type: 'button', text: 'Allow this port', onclick: () => allow(r) })))), '')
          : h('div', { class: 'empty', text: 'Nothing was refused in the last hour.' }),
        h('div', { class: 'card-foot muted small', text: 'If something of yours is on this list, it is not reaching the server: allow its port. If you do not know it, leave it closed. The internet is full of scanners knocking on doors.' }))) : null;
    const copyCard = data.cyberpanel_rules ? h('section', { class: 'card' },
      h('h2', { text: 'Start from CyberPanel\u2019s list' }),
      h('p', { class: 'muted', text: 'CyberPanel keeps a list of ' + data.cyberpanel_rules + ' rules. You can copy it here once, so you do not have to type it again. The server login and the admin pages are skipped: they are always open.' }),
      h('button', { class: 'btn', type: 'button', text: 'Copy CyberPanel\u2019s list', onclick: () => run('/api/serverfw/import', {}, 'Copying…') })) : null;

    // ---- the list
    const form = h('form', { class: 'inline-form' },
      field('fw-name', 'Name', { type: 'text', placeholder: 'for example My tunnel', maxlength: 40 }),
      h('div', { class: 'field' }, h('label', { for: 'fw-proto', text: 'Protocol' }), h('select', { id: 'fw-proto' }, h('option', { value: 'tcp', text: 'TCP' }), h('option', { value: 'udp', text: 'UDP' }))),
      field('fw-address', 'From (empty = everybody)', { type: 'text', placeholder: 'for example 203.0.113.25' }),
      field('fw-port', 'Port or range', { type: 'text', required: true, placeholder: '4445 or 40110-40210', inputmode: 'numeric' }),
      h('button', { class: 'btn primary', type: 'submit', text: 'Open this port' }));
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      const r = await act('/api/serverfw/add', { name: $('#fw-name').value, proto: $('#fw-proto').value, address: $('#fw-address').value, port: $('#fw-port').value }, 'Adding…');
      if (r.ok) redraw();
    });
    const ruleRows = data.rules.map(r => {
      const btn = h('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: () => remove(r) });
      return h('tr', {},
        h('td', {}, h('strong', { text: r.name }), h('div', { class: 'muted small', text: FW_SOURCE[r.source] || '' }),
          r.in_use ? badge('in use' + (r.used_by.length ? ': ' + r.used_by.join(', ') : ''), 'ok') : null, small ? h('div', { style: 'margin-top:.4rem' }, btn) : null),
        h('td', {}, badge(r.proto.toUpperCase(), ''), ' ', r.address ? r.address : 'everybody'),
        h('td', { class: 'mono', text: r.port }),
        small ? null : h('td', { class: 'actions' }, btn));
    });
    const always = data.builtin.map(b => h('tr', { class: 'muted' },
      h('td', {}, h('strong', { text: b.name }), h('div', { class: 'small', text: b.what }), badge('always open', '')),
      h('td', { text: 'everybody' }), h('td', { class: 'mono', text: b.port || '' }), small ? null : h('td', {})));
    const list = h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Your list' }), badge(data.rules.length + ' rule' + (data.rules.length === 1 ? '' : 's'), ''),
        h('span', { class: 'muted small right', text: data.loaded ? 'Changes apply at once.' : 'The firewall is off: changes apply when you turn it on.' })),
      table(small ? ['Name', 'Open to', 'Port'] : ['Name', 'Open to', 'Port', ''], ruleRows.concat(always), ''),
      h('div', { class: 'card-foot' }, form));

    return h('div', { class: 'stack' }, head, status, waiting, refusedCard, sugCard, copyCard, list,
      h('p', { class: 'muted small', text: 'Only incoming traffic is judged: what the server starts itself is never blocked. Ports published by Docker are not covered. TCP and UDP are separate, like on CyberPanel\u2019s page.' }));
  }

  // ------------------------------------------------------------------ security headers
  const SITE_BADGE = { applied: 'ok', outdated: 'warn', none: 'warn', own: '', off: '', excluded: '', error: 'bad' };
  const SOURCE_TEXT = { ours: 'sent by CP-Security', site: 'set by the website itself', other: 'sent by something else (a plugin, Cloudflare…)', none: 'not sent' };

  // a checkbox with its text beside it (the text wraps inside its own column)
  const tick = (id, input, text) => h('label', { class: 'tick', for: id }, input, h('span', { text }));

  async function viewHeaders() {
    const { data } = await api('/api/headers');
    const head = pageHead('Security headers', 'Small instructions every website sends to every visitor\u2019s browser. They protect your visitors and your site\u2019s reputation. They do not stop a break-in.');
    if (!data.supported) {
      return h('div', { class: 'stack' }, head, card('Not available on this web server yet',
        h('p', { text: 'This server runs ' + data.web_server + ', which ignores header lines in .htaccess. CP-Security will support it in a later version. Nothing has been changed.' })));
    }
    if (data.checking) {                          // the websites are being asked in the background: look again soon
      const id = S.drawId;
      setTimeout(() => { if (id === S.drawId && S.view === 'headers') softRedraw(); }, 2500);
    }
    const d = data.defaults;
    const small = isSmall();

    // ---- the choices
    const boxes = {};
    const choiceRow = it => {
      if (it.id === 'hsts') {
        const sel = h('select', { id: 'hd-hsts', 'aria-label': it.title }, data.hsts_choices.map(c => h('option', { value: String(c.seconds), text: c.seconds ? 'For ' + c.text : 'Off' })));
        sel.value = String(d.hsts);
        const sub = h('input', { type: 'checkbox', id: 'hd-hsts_subdomains', checked: !!d.hsts_subdomains });
        boxes.hsts = sel; boxes.hsts_subdomains = sub;
        return h('div', { class: 'check' }, h('div', { class: 'grow' },
          h('div', { class: 't', text: it.title }), h('div', { class: 'd', text: it.what }),
          h('div', { class: 'risk', text: 'Careful: ' + it.risk }),
          h('div', { class: 'row', style: 'margin-top:.5rem' }, sel,
            tick('hd-hsts_subdomains', sub, 'Also cover sub-domains (only if every sub-domain works with https://)'))));
      }
      const box = h('input', { type: 'checkbox', id: 'hd-' + it.id, checked: !!d[it.id] });
      boxes[it.id] = box;
      return h('label', { class: 'check', for: 'hd-' + it.id }, box, h('div', { class: 'grow' },
        h('div', { class: 't', text: it.title }), h('div', { class: 'd', text: it.what }),
        it.risk ? h('div', { class: 'risk', text: 'Careful: ' + it.risk }) : null,
        h('div', { class: 'muted small mono', text: it.name })));
    };
    const collect = () => {
      const out = {};
      for (const it of data.items) out[it.id] = it.id === 'hsts' ? parseInt(boxes.hsts.value, 10) : boxes[it.id].checked;
      out.hsts_subdomains = boxes.hsts_subdomains.checked;
      return out;
    };
    const saveChoices = async () => (await act('/api/headers/defaults', { changes: collect() }, 'Saving…')).ok;
    const ownNames = s => data.items.filter(i => s.own_headers.includes(i.name.toLowerCase())).map(i => i.name);

    const applyAll = async () => {
      const clash = data.sites.some(s => ownNames(s).length);
      const takeBox = h('input', { type: 'checkbox', id: 'ap-take' });
      const content = h('div', {},
        h('p', { text: 'The headers you chose will be added to your websites. Afterwards each website is asked for its home page. If one stops answering, or the web server ignores the headers, that website gets its file back exactly as it was. Websites you left alone are skipped.' }),
        clash ? tick('ap-take', takeBox, 'Also take over the headers some websites set themselves. Their own lines are switched off, not deleted, and come back if you remove CP-Security\u2019s.') : null);
      if (!await dialog({ title: 'Apply to all websites?', content, ok: 'Save and apply' })) return;
      if (!await saveChoices()) return;
      await act('/api/headers/apply', { all: true, take_over: takeBox.checked }, 'Applying… this can take a minute');
      redraw();
    };
    const removeAll = async () => {
      if (!await confirmBox('Remove from all websites?', 'CP-Security\u2019s lines are taken out of every website\u2019s .htaccess. Headers a website set itself stay. Lines that CP-Security switched off are switched back on.', 'Remove', true)) return;
      await act('/api/headers/remove', { all: true }, 'Removing…');
      redraw();
    };

    const customize = async s => {
      const o = s.overrides || {};
      const tri = (key, label) => {
        const sel = h('select', { id: 'cs-' + key },
          h('option', { value: '', text: 'Follow the default (' + (d[key] ? 'on' : 'off') + ')' }), h('option', { value: 'on', text: 'Always on' }), h('option', { value: 'off', text: 'Always off' }));
        sel.value = o[key] === true ? 'on' : (o[key] === false ? 'off' : '');
        return [h('div', { class: 'field' }, h('label', { for: 'cs-' + key, text: label }), sel), sel];
      };
      const sels = {}, fields = [];
      for (const it of data.items) {
        if (it.id === 'hsts') {
          const sel = h('select', { id: 'cs-hsts' }, h('option', { value: '', text: 'Follow the default (' + (d.hsts ? 'for ' + (data.hsts_choices.find(c => c.seconds === d.hsts) || {}).text : 'off') + ')' }),
            data.hsts_choices.map(c => h('option', { value: String(c.seconds), text: c.seconds ? 'For ' + c.text : 'Off' })));
          sel.value = o.hsts === undefined ? '' : String(o.hsts);
          sels.hsts = sel;
          fields.push(h('div', { class: 'field' }, h('label', { for: 'cs-hsts', text: it.title }), sel));
          const [f2, s2] = tri('hsts_subdomains', 'Secure address: also cover sub-domains');
          sels.hsts_subdomains = s2; fields.push(f2);
        } else {
          const [f, sel] = tri(it.id, it.title);
          sels[it.id] = sel; fields.push(f);
        }
      }
      const excl = h('input', { type: 'checkbox', id: 'cs-exclude', checked: !!o.exclude });
      const clash = ownNames(s);
      const takeBox = h('input', { type: 'checkbox', id: 'cs-take' });
      const content = h('div', {}, h('p', { class: 'muted', text: s.domain }), fields,
        clash.length ? tick('cs-take', takeBox, 'Take over what this website sets itself (' + clash.join(', ') + '). Its lines are switched off, not deleted.') : null,
        tick('cs-exclude', excl, 'Leave this website alone. CP-Security will never change its .htaccess, and removes its own lines now.'));
      if (!await dialog({ title: 'Choices for one website', content, ok: 'Save and apply' })) return;
      const changes = {};
      for (const [key, sel] of Object.entries(sels)) {
        changes[key] = sel.value === '' ? null : (key === 'hsts' ? parseInt(sel.value, 10) : sel.value === 'on');
      }
      changes.exclude = excl.checked ? true : null;
      await act('/api/headers/site', { domain: s.domain, changes, apply: true, take_over: takeBox.checked }, 'Applying…');
      redraw();
    };

    // ---- the websites
    const chip = (it, c) => {
      const sent = c.seen === null ? (c.source === 'ours' || c.source === 'site') : c.seen;
      const own = c.source === 'site' ? ' (own)' : (c.source === 'other' ? ' (other)' : '');
      return h('span', { class: 'badge ' + (sent ? 'ok' : ''), title: it.short + ': ' + SOURCE_TEXT[c.source] + (c.seen === null ? ' (not checked yet)' : ''),
        text: (sent ? '\u2713 ' : '\u2013 ') + it.short + own });
    };
    const rows = data.sites.map(s => {
      const buttons = [];
      if (s.needs_apply) buttons.push(h('button', { class: 'btn small primary', type: 'button', text: 'Apply', onclick: async () => {
        await act('/api/headers/apply', { domains: [s.domain] }, 'Applying…'); redraw(); } }));
      buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Choices…', onclick: () => customize(s) }));
      if (s.has_block) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Remove', onclick: async () => {
        if (!await confirmBox('Remove from ' + s.domain + '?', 'CP-Security\u2019s lines are taken out of this website\u2019s .htaccess. Headers the website set itself stay.', 'Remove', true)) return;
        await act('/api/headers/remove', { domains: [s.domain] }, 'Removing…'); redraw(); } }));
      const actions = h('div', { class: 'row', style: small ? 'margin-top:.6rem' : 'justify-content:flex-end' }, buttons);
      return h('tr', {},
        h('td', {}, h('strong', { text: s.domain }), h('div', {}, badge(s.status_text, SITE_BADGE[s.status])),
          s.error ? h('div', { class: 'small error', text: s.error }) : null,
          s.taken ? h('div', { class: 'muted small', text: s.taken + ' of the website\u2019s own line' + (s.taken === 1 ? ' is' : 's are') + ' switched off by CP-Security' }) : null,
          small ? actions : null),
        h('td', {}, h('div', { class: 'chips' }, data.items.map((it, i) => chip(it, s.chips[i])))),
        small ? null : h('td', { class: 'actions' }, actions));
    });

    const need = data.sites.filter(s => s.needs_apply).length;
    return h('div', { class: 'stack' }, head,
      h('section', { class: 'card' }, h('h2', { text: 'What your websites should send' }),
        h('p', { class: 'muted', text: 'The safe ones are on. The two that can cause trouble are off until you choose them.' }),
        data.items.map(choiceRow),
        h('div', { class: 'row', style: 'margin-top:1rem' },
          h('button', { class: 'btn primary', type: 'button', text: 'Save and apply to all websites…', onclick: applyAll }),
          h('button', { class: 'btn', type: 'button', text: 'Only save', onclick: async () => { if (await saveChoices()) redraw(); } }),
          h('button', { class: 'btn danger', type: 'button', text: 'Remove from all websites…', onclick: removeAll }))),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Your websites' }), need ? badge(need + ' to apply', 'warn') : badge('all up to date', 'ok'),
          h('span', { class: 'muted small right', text: data.checking ? 'Asking the websites…' : (data.checked_at ? 'Last asked at ' + data.checked_at : 'Not asked yet') }),
          h('button', { class: 'btn small', type: 'button', text: 'Ask the websites now', onclick: async () => { await act('/api/headers/check', {}, 'Asking the websites…'); redraw(); } })),
        table(small ? ['Website', 'What it sends'] : ['Website', 'What it sends', ''], rows, 'No websites were found.'),
        h('div', { class: 'card-foot muted small', text: '\u2713 is sent, \u2013 is not. \u201c(own)\u201d means the website sets it itself; \u201c(other)\u201d means something else sends it, such as a plugin or Cloudflare. The result is what the web server really answers.' })));
  }

  // ------------------------------------------------------------------ web firewall
  const MODE_INFO = {
    off: ['Off', 'Does nothing.'],
    watch: ['Watch only', 'Records hacking attempts. Never refuses anybody. The safe way to start.'],
    block: ['Blocking', 'Refuses requests that look like attacks. A harmless request can occasionally be refused by mistake.'],
  };

  async function chooseMode(mode, current, threshold) {
    if (mode === current) return;
    if (mode === 'block') {
      const typed = h('input', { id: 'blk-confirm', type: 'text', autocomplete: 'off', placeholder: 'BLOCK' });
      const strict = h('select', { id: 'blk-th' }, h('option', { value: '5', text: 'Normal (recommended)' }), h('option', { value: '10', text: 'More relaxed (fewer false alarms)' }));
      if (threshold >= 10) strict.value = '10';
      const content = h('div', {}, h('p', { text: 'Blocking refuses requests that look like attacks. Visitors who are refused see "403 Forbidden". Use the watch-only mode for a week first and allow the false alarms.' }),
        h('div', { class: 'field' }, h('label', { for: 'blk-th', text: 'Strictness' }), strict),
        h('div', { class: 'field' }, h('label', { for: 'blk-confirm', text: 'Type BLOCK to switch it on' }), typed));
      if (!await dialog({ title: 'Switch on blocking?', content, ok: 'Switch on blocking', danger: true,
        validate: () => typed.value === 'BLOCK' ? null : 'Type BLOCK in capital letters to confirm.' })) return;
      await act('/api/firewall/mode', { mode, confirm: 'BLOCK', threshold: Number(strict.value) }, 'Applying… the web server restarts gracefully and the websites are checked afterwards.');
    } else {
      const text = mode === 'off' ? 'The web firewall will stop checking requests.' : 'The web firewall will record hacking attempts but never refuse anybody.';
      if (!await confirmBox('Change to "' + MODE_INFO[mode][0] + '"?', text, 'Change')) return;
      await act('/api/firewall/mode', { mode }, 'Applying… the web server restarts gracefully and the websites are checked afterwards.');
    }
    redraw();
  }

  async function allowDialog(g) {
    let scope = 'site';
    const opts = [
      ['site', 'Allow this rule on ' + g.host + ' only', 'Best choice for a false alarm on one website.'],
      ['all', 'Allow this rule on all websites', 'Use if the same false alarm happens everywhere.'],
      ['site_off', 'Turn the web firewall off for ' + g.host, 'That website is no longer checked at all.'],
    ];
    const radios = opts.map(([v, t, d]) => h('label', { class: 'row', style: 'align-items:flex-start;margin-bottom:.6rem' },
      h('input', { type: 'radio', name: 'scope', value: v, checked: v === 'site' ? true : null, onchange: () => { scope = v; } }),
      h('span', {}, h('strong', { text: t }), h('br'), h('span', { class: 'muted small', text: d }))));
    const content = h('div', {}, h('p', { class: 'muted', text: g.host + g.path + ' – ' + g.message + ' (rule ' + g.rule + ')' }), radios);
    if (!await dialog({ title: 'Allow this?', content, ok: 'Allow' })) return;
    await act('/api/firewall/exception', { scope, host: g.host, rule: g.rule }, 'Applying…');
    redraw();
  }

  async function viewFirewall() {
    const { data } = await api('/api/firewall');
    if (!data.installed) {
      return h('div', { class: 'stack' }, pageHead('Web firewall'),
        card(null, h('p', { text: 'The web firewall is not set up on this server yet.' }),
          h('p', { class: 'muted', text: 'The Setup page checks whether it can be added safely next to the security settings CyberPanel already has, and starts it in watch-only mode.' }),
          h('a', { class: 'btn primary', href: '#/setup', text: 'Open Setup' })));
    }
    const sum = data.summary, day = sum.periods.day, week = sum.periods.week;
    const periodCard = (title, p) => h('section', { class: 'card' }, h('h2', { text: title }),
      h('p', {}, h('strong', { text: String(p.requests) }), ' suspicious requests from ', h('strong', { text: String(p.addresses) }), ' addresses',
        data.mode === 'block' ? [', ', h('strong', { text: String(p.blocked) }), ' blocked'] : ' (nobody refused)'),
      p.rules.length ? h('div', { class: 'stack' }, p.rules.slice(0, 5).map(r => h('div', { class: 'row' }, h('span', { class: 'small', text: r.message }), h('span', { class: 'right' }, badge(String(r.count)))))) : h('p', { class: 'muted', text: 'Nothing recorded.' }));
    return h('div', { class: 'stack' },
      pageHead('Web firewall', 'Watches the requests to your websites for typical hacking attempts (SQL injection, scripts, file tricks).',
        h('button', { class: 'btn', type: 'button', text: 'Run a test', title: 'Sends one harmless request that looks like an attack and checks that the firewall noticed it',
          onclick: async () => { await act('/api/firewall/selftest', {}, 'Sending a harmless test request…'); } })),
      h('section', { class: 'card' }, h('h2', { text: 'Mode' }),
        h('div', { class: 'choices' }, ['off', 'watch', 'block'].map(m =>
          h('button', { class: 'choice', type: 'button', 'aria-pressed': String(data.mode === m), onclick: () => chooseMode(m, data.mode, data.threshold) },
            h('div', { class: 'title' }, MODE_INFO[m][0], data.mode === m ? badge('now', 'brand') : null), h('div', { class: 'desc', text: MODE_INFO[m][1] })))),
        data.mode === 'block' ? h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'Strictness: a request is refused at score ' + data.threshold + ' or more (5 = normal, 10 = more relaxed).' }) : null),
      data.mode === 'watch' && sum.trusted_hits ? h('div', { class: 'note warn', text: sum.trusted_hits + ' hit(s) came from your own trusted addresses. Those are probably false alarms: allow them in the list below before you ever switch to blocking.' }) : null,
      h('div', { class: 'grid' }, periodCard('Last 24 hours', day), periodCard('Last 7 days', week)),
      h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { text: 'Recent hits' }), h('span', { class: 'muted small', text: 'Hits from your own addresses come first – they are the likely false alarms.' })),
        table(['Website and page', 'What the rule saw', 'Times', ''], data.recent.map(g =>
          h('tr', {}, h('td', { class: 'mono' }, g.host + g.path, g.trusted ? [' ', badge('you', 'brand')] : null, g.blocked ? [' ', badge('blocked', 'bad')] : null),
            h('td', { class: 'small', text: g.rule + ': ' + g.message }), h('td', { text: String(g.count) }),
            h('td', { class: 'actions' }, g.rule === 'blocked' ? null : h('button', { class: 'btn small', type: 'button', text: 'Allow…', onclick: () => allowDialog(g) })))), 'Nothing recorded yet.')),
      h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { text: 'Exceptions I made' })),
        table(['Exception', ''], data.exceptions.map((e, i) =>
          h('tr', {}, h('td', { text: (e.rule === 'ALL' ? 'Firewall off' : 'Rule ' + e.rule + ' allowed') + (e.site === '*' ? ' on every website' : ' on ' + e.site) }),
            h('td', { class: 'actions' }, h('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: async () => {
              if (await confirmBox('Remove this exception?', 'The firewall will check this again.', 'Remove', true)) { await act('/api/firewall/exception/remove', { index: i }, 'Applying…'); redraw(); } } })))), 'No exceptions. Every website is treated the same.')),
      h('div', { class: 'note', text: 'Pages that LiteSpeed serves from its cache are not checked. Every change restarts the web server gracefully and is undone automatically if a website stops answering.' }));
  }

  // ------------------------------------------------------------------ WP updates (WordPress, plugins, themes)
  const KIND = { plugin: ['Plugin', 'brand'], theme: ['Theme', 'warn'] };
  const kindBadge = k => k.startsWith('core') ? badge('WordPress', 'bad') : badge(KIND[k][0], KIND[k][1]);
  const JOB_STATUS = { waiting: ['waiting', ''], working: ['working…', 'brand'], done: ['updated', 'ok'], failed: ['failed', 'bad'], restored: ['old version put back', 'warn'], skipped: ['skipped', ''] };

  // a small turning circle inside a label: something is happening right now
  const workingBadge = text => h('span', { class: 'badge brand' }, h('span', { class: 'dot-spin', 'aria-hidden': 'true' }), text);
  const stepLine = i => i.step ? h('div', { class: 'small muted', style: 'white-space:normal', text: i.step + (i.seconds ? ' \u00b7 ' + i.seconds + ' s' : '') }) : null;
  // a thin bar under the heading: finished items, plus half of the one that is running
  const progressBar = (job, finished) => {
    const total = job.items.length || 1;
    const running = job.status === 'running';
    const pct = !running ? 100 : job.phase === 'checking' ? 100 : Math.min(99, Math.round((finished + 0.5) / total * 100));
    return h('div', { class: 'bar' + (running ? ' running' : ''), role: 'progressbar', 'aria-label': 'Update progress', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) },
      h('div', { class: 'fill', style: 'width:' + pct + '%' }));
  };

  // the progress of the updates you started (nothing here runs by itself)
  function renderJob(job, stop) {
    if (!job || job.status === 'idle' || !job.items.length) return null;
    const running = job.status === 'running';
    const c = job.counts;
    const finished = c.done + c.failed + c.restored + c.skipped;
    const rows = job.items.map(i => {
      const [label, kind] = JOB_STATUS[i.status] || [i.status, ''];
      const manual = i.status === 'failed' || i.status === 'restored';
      return h('tr', { class: i.status === 'working' ? 'updating' : null },
        h('td', { class: 'mono', text: i.site }),
        h('td', {}, kindBadge(i.kind), ' ', i.title),
        h('td', { class: 'mono', text: (i.from || '–') + (i.to && i.to !== i.from ? ' \u2192 ' + i.to : '') }),
        h('td', {}, i.status === 'working' ? workingBadge('Updating\u2026') : badge(label, kind), i.status === 'working' ? stepLine(i) : null,
          i.message ? h('div', { class: 'small ' + (manual ? '' : 'muted'), text: i.message }) : null,
          manual ? h('a', { class: 'small', href: 'https://' + i.site + '/wp-admin/update-core.php', target: '_blank', rel: 'noopener', text: 'Update it by hand in WordPress' }) : null));
    });
    return h('section', { class: 'card flush' },
      h('div', { class: 'card-head' },
        running ? h('div', { class: 'spinner small-spin', style: 'margin:0' }) : null,
        h('h2', { 'aria-live': 'polite', text: running ? (job.phase === 'checking' ? 'Checking again what is still waiting…' : 'Updating… ' + finished + ' of ' + job.items.length) : 'Updates finished' }),
        c.done ? badge(c.done + ' updated', 'ok') : null, c.restored ? badge(c.restored + ' put back', 'warn') : null,
        c.failed ? badge(c.failed + ' failed', 'bad') : null, c.skipped ? badge(c.skipped + ' skipped', '') : null,
        running && job.phase !== 'checking' ? h('button', { class: 'btn small right', type: 'button', text: job.stop ? 'Stopping…' : 'Stop after this one', disabled: !!job.stop, onclick: stop }) : null),
      progressBar(job, finished),
      table(['Website', 'What', 'Version', 'Result'], rows, ''),
      h('div', { class: 'card-foot muted small', text: running
        ? 'Each update saves a copy first, then checks the website. If the website stops working, the old version goes back by itself. You can leave this page: it keeps going.'
        : 'A website that failed stays on its old version and still works. A copy of every changed plugin and theme, and of the database, is kept in a folder next to the website (the last 3).' }));
  }


  // the shared look of "this item is part of the running job": used in the list of waiting updates and on the cards of uploaded files
  const jobStatusCell = ji => {
    if (ji.status === 'working') return h('span', {}, workingBadge('Updating\u2026'), stepLine(ji));
    if (ji.status === 'waiting') return badge('In line', '');
    if (ji.status === 'done') return badge('updated', 'ok');
    if (ji.status === 'skipped') return badge('skipped', '');
    return badge('not updated', 'warn');
  };

  // ------------------------------------------------------------------ plugins and themes updated by uploading a file
  const sizeText = n => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';

  // version numbers compared the way the server does it ('7.1.10' is newer than '7.1.9')
  const PRE_RANK = { dev: -4, alpha: -3, a: -3, beta: -2, b: -2, rc: -1 };
  const versionParts = v => String(v).trim().toLowerCase().replace(/^v/, '').replace(/[-_+]/g, '.').replace(/(\d)([a-z])/g, '$1.$2').replace(/([a-z])(\d)/g, '$1.$2')
    .split('.').filter(Boolean).map(p => /^\d+$/.test(p) ? [0, parseInt(p, 10)] : [p === 'p' || p === 'pl' ? 1 : (p in PRE_RANK ? PRE_RANK[p] : -5), 0]);
  const cmpVersion = (a, b) => {
    const x = versionParts(a), y = versionParts(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const p = x[i] || [0, 0], q = y[i] || [0, 0];
      if (p[0] !== q[0]) return p[0] < q[0] ? -1 : 1;
      if (p[1] !== q[1]) return p[1] < q[1] ? -1 : 1;
    }
    return 0;
  };

  // one file, sent as it is (not wrapped), with a real progress figure
  function sendFile(file, onProgress) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/uploads/upload');
      xhr.setRequestHeader('X-CSRF-Token', S.csrf);
      xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
      xhr.setRequestHeader('Content-Type', 'application/zip');
      xhr.upload.onprogress = e => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      xhr.onload = () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
        if (xhr.status === 401 && S.me) { S.me = null; draw(); }
        resolve({ ok: xhr.status === 200 && data.ok === true, message: data.message || 'The upload did not work (' + xhr.status + ').' });
      };
      xhr.onerror = () => resolve({ ok: false, message: 'The upload was interrupted. If you were signed out, sign in again and try once more.' });
      xhr.send(file);
    });
  }

  function renderUploads(up, ctl) {
    const zips = up.zips || [];
    const scanning = up.inventory && up.inventory.status === 'running';
    const ticked = [];
    const cards = zips.map(z => {
      const shown = z.rows.filter(r => r.state !== 'missing');
      const missing = z.rows.filter(r => r.state === 'missing').map(r => r.site);
      const updatable = z.rows.filter(r => r.can_update);
      const allOn = updatable.every(r => ctl.ticks[z.id + '|' + r.site] !== false);
      const rows = shown.map(r => {
        const key = z.id + '|' + r.site;
        const ji = ctl.jobBy(r.site, z.kind, z.slug);
        const on = r.can_update && ctl.ticks[key] !== false;
        if (on && !ji) ticked.push({ z, r });
        let result;
        if (ji) result = jobStatusCell(ji);
        else if (r.state === 'update') result = h('span', {}, badge('can be updated', 'ok'), ' \u2192 ', h('span', { class: 'mono', text: z.version }));
        else if (r.state === 'same') result = h('span', { class: 'muted', text: 'already has this version' });
        else if (r.state === 'newer') result = badge('has a newer version', 'warn');
        else result = h('span', { class: 'muted', text: 'could not be read' });
        return h('tr', { class: ji && ji.status === 'working' ? 'updating' : null },
          h('td', { style: 'width:2.6rem' }, r.can_update && !ji ? h('input', { type: 'checkbox', checked: on, disabled: ctl.busy, 'aria-label': 'Update ' + r.site, onchange: ev => ctl.tick(key, ev.target.checked) }) : null),
          h('td', { class: 'mono', text: r.site }),
          h('td', {}, h('span', { class: 'mono', text: r.installed || '\u2013' }), r.status === 'inactive' ? [' ', badge('switched off', '')] : null),
          h('td', {}, result));
      });
      return h('div', { class: 'zipcard' },
        h('div', { class: 'door-head' }, kindBadge(z.kind), h('strong', { text: z.name }), h('span', { class: 'mono', text: z.version }),
          z.careful ? badge('careful', 'warn') : null,
          h('span', { class: 'right row' },
            updatable.length > 1 ? h('button', { class: 'btn small', type: 'button', disabled: ctl.busy, text: allOn ? 'Untick all' : 'Tick all', onclick: () => ctl.tickAll(z, !allOn) }) : null,
            h('button', { class: 'btn small danger', type: 'button', disabled: ctl.busy, text: 'Delete file from the server', onclick: () => ctl.del(z) }))),
        h('div', { class: 'muted small', style: 'margin:.3rem 0 .6rem' },
          z.filename + ' \u00b7 ' + sizeText(z.size) + ' \u00b7 uploaded ' + z.uploaded + ' \u00b7 fingerprint ',
          h('span', { class: 'mono', title: z.sha256, text: z.sha256.slice(0, 12) + '\u2026' }),
          z.renamed_from ? ' \u00b7 the folder inside was called ' + z.renamed_from + ' and is renamed to ' + z.slug : null),
        table(['Choose', 'Website', 'Has now', 'Result'], rows, scanning ? 'Looking at the websites\u2026' : 'No website has this ' + z.kind + ' yet.', 'files-table'),
        missing.length ? h('div', { class: 'muted small', style: 'margin-top:.5rem', text: 'Not installed on ' + missing.length + ' website' + (missing.length > 1 ? 's' : '') + ' (nothing is installed where it is missing): ' + missing.join(', ') }) : null);
    });

    const input = h('input', { type: 'file', accept: '.zip,application/zip', multiple: true, hidden: true, id: 'up-file', 'aria-label': 'Choose zip files', onchange: ev => { ctl.pick(Array.from(ev.target.files)); ev.target.value = ''; } });
    const drop = h('div', { class: 'drop' },
      h('button', { class: 'btn primary', type: 'button', text: 'Choose zip files\u2026', onclick: () => input.click() }),
      h('span', { class: 'muted', text: 'or drop them here. Up to ' + (up.max_mb || 200) + ' MB each.' }), input);
    drop.addEventListener('dragover', ev => { ev.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', ev => { ev.preventDefault(); drop.classList.remove('over'); ctl.pick(Array.from(ev.dataTransfer.files)); });

    const sending = (ctl.sending || []).map(s => h('div', { class: 'sending' },
      h('div', { class: 'row' }, s.state === 'sending' || s.state === 'checking' ? h('span', { class: 'dot-spin', 'aria-hidden': 'true' }) : null,
        h('strong', { text: s.name }), h('span', { class: s.state === 'bad' ? 'error' : 'muted', style: 'min-height:0', text:
          s.state === 'sending' ? s.pct + '%' : s.state === 'checking' ? 'checking the file\u2026' : s.message })),
      s.state === 'sending' || s.state === 'checking' ? h('div', { class: 'bar running', role: 'progressbar', 'aria-label': 'Upload of ' + s.name, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(s.pct) },
        h('div', { class: 'fill', style: 'width:' + s.pct + '%' })) : null));

    return h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Update by uploading a file' }), zips.length ? badge(String(zips.length)) : null,
        scanning ? h('span', { class: 'row muted small' }, h('span', { class: 'dot-spin', 'aria-hidden': 'true' }), 'looking at what each website has\u2026') : null,
        zips.length ? h('button', { class: 'btn small right', type: 'button', disabled: scanning || ctl.busy, text: 'Check the websites again', onclick: ctl.rescan }) : null),
      h('p', { class: 'muted pad', style: 'margin:.9rem 0 .75rem', text: 'For plugins and themes that cannot update by themselves, such as paid ones. Upload the zip you got from the maker once, then choose the websites to update. Each website is saved first, checked afterwards and put back if it breaks. Nobody is asked about licences: an update counts as done when the website has the new version and still answers. The file stays on the server until you delete it here.' }),
      drop, sending,
      cards,
      ticked.length ? h('div', { class: 'card-foot row' },
        h('button', { class: 'btn primary', type: 'button', disabled: ctl.busy, text: 'Update ' + ticked.length + ' ticked website' + (ticked.length > 1 ? 's' : '') + '\u2026',
          onclick: () => ctl.apply(ticked) }),
        h('span', { class: 'muted small', text: 'One at a time. Your files run on those websites, so use only files from the maker.' })) : null);
  }

  function renderUpdates(state, ctl) {
    ctl = ctl || { busy: false, update: () => {}, recheck: () => {}, jobBy: () => null, loginFor: () => null, openAdmin: () => {} };
    const sites = state.sites || [];
    const checkingNow = state.checking || [];
    const withItems = sites.filter(s => s.items.length);
    const unchecked = sites.filter(s => !s.checked);
    const partial = sites.filter(s => s.checked && s.vendors === false);
    if (state.status === 'running') return card(null, h('div', { class: 'row' }, h('div', { class: 'spinner', style: 'margin:0' }), h('span', { text: 'Looking at every WordPress site… this takes about a minute.' })));
    if (state.status === 'idle') return card(null, h('p', { class: 'muted', text: 'Press "Look for updates" to see which websites have plugins, themes or WordPress itself waiting for an update.' }));
    if (state.status === 'failed') return card(null, h('p', { class: 'error', text: 'Looking failed: ' + (state.error || 'unknown reason') }));

    const all = withItems.flatMap(s => s.items.map(i => Object.assign({ site: s.site }, i)));
    const count = test => all.filter(test).length;
    const plugins = count(i => i.kind === 'plugin'), themes = count(i => i.kind === 'theme'), core = count(i => i.kind.startsWith('core'));
    // the same plugin or theme waiting on several websites
    const groups = {};
    all.forEach(i => {
      const key = i.kind + ':' + (i.slug || i.what);
      (groups[key] = groups[key] || { kind: i.kind, what: i.what, to: i.to, sites: [] }).sites.push(i.site);
    });
    const shared = Object.values(groups).filter(g => g.sites.length > 1).sort((a, b) => b.sites.length - a.sites.length);
    const updatable = i => (i.kind === 'plugin' || i.kind === 'theme') && i.slug;

    return h('div', { class: 'stack' },
      h('div', { class: 'banner ' + (withItems.length ? 'warn' : 'ok') }, icon(withItems.length ? 'alert' : 'check'),
        h('div', {}, h('div', { text: withItems.length ? all.length + ' update' + (all.length > 1 ? 's' : '') + ' waiting on ' + withItems.length + ' website' + (withItems.length > 1 ? 's' : '') : 'No updates are waiting' }),
          h('div', { class: 'sub', text: 'Looked ' + state.finished }))),
      withItems.length ? h('div', { class: 'grid tiles' }, tile('Websites affected', withItems.length), tile('Plugins', plugins), tile('Themes', themes), tile('WordPress itself', core)) : null,
      shared.length ? h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'The same update on several websites' }), h('span', { class: 'muted small right', text: 'Update these one website at a time below.' })),
        table(['What', 'Type', 'New version', 'Websites'], shared.map(g => h('tr', {}, h('td', { text: g.what }), h('td', {}, kindBadge(g.kind)),
          h('td', { class: 'mono', text: g.to }), h('td', { class: 'small', text: g.sites.length + ': ' + g.sites.sort().join(', ') }))), '')) : null,
      withItems.map(s => {
        const mine = s.items.filter(updatable).map(i => Object.assign({ site: s.site }, i));
        const looking = checkingNow.includes(s.site);
        const busyHere = mine.some(i => ctl.jobBy && ctl.jobBy(s.site, i.kind, i.slug));
        // a file you uploaded for this plugin is the way that works (the maker's server may refuse); use it when it is at least as new
        const viaUpload = i => {
          const z = ctl.uploadFor ? ctl.uploadFor(i.kind, i.slug, i.to) : null;
          const row = z ? (z.rows || []).find(r => r.site === s.site) : null;
          return z && row && row.can_update
            ? { site: s.site, kind: i.kind, slug: i.slug, zip: z.id, what: z.name + ' (your upload)', from: i.from, to: z.version, careful: i.careful, file: z }
            : null;
        };
        const action = i => {
          if (!updatable(i)) return null;
          const ji = ctl.jobBy ? ctl.jobBy(s.site, i.kind, i.slug) : null;
          if (ji) return jobStatusCell(ji);
          const up = viaUpload(i);
          if (up) return h('button', { class: 'btn small primary', type: 'button', disabled: ctl.busy, text: 'Update from your upload',
            title: 'Uses the file you uploaded (' + up.file.name + ' ' + up.file.version + ') instead of asking the plugin maker\u2019s server', onclick: () => ctl.update([up]) });
          return h('button', { class: 'btn small', type: 'button', disabled: ctl.busy, text: 'Update', onclick: () => ctl.update([Object.assign({ site: s.site }, i)]) });
        };
        return h('section', { class: 'card flush' },
          h('div', { class: 'card-head' }, h('h2', { class: 'site-name', text: s.site }), badge(s.items.length + ' waiting', 'warn'),
            looking ? h('div', { class: 'spinner small-spin', style: 'margin:0' }) : null,
            s.looked ? h('span', { class: 'muted small', text: 'looked ' + s.looked }) : null,
            h('button', { class: 'btn small', type: 'button', disabled: looking || ctl.busy, text: looking ? 'Looking…' : 'Check again', onclick: () => ctl.recheck(s.site),
              title: 'Read the updates of this website again, for example after you updated something in WordPress yourself' }),
            ctl.loginFor && ctl.loginFor(s.site) ? h('button', { class: 'btn small', type: 'button', text: 'Open admin', 'aria-label': 'Open the dashboard of ' + s.site,
              title: 'Opens the dashboard of ' + s.site + ' in a new tab, signed in as ' + ctl.loginFor(s.site).login, onclick: () => ctl.openAdmin(s.site) }) : null,
            mine.length > 1 ? h('button', { class: 'btn small primary right', type: 'button', disabled: ctl.busy, onclick: () => ctl.update(mine.map(i => viaUpload(i) || i)) },
              busyHere ? [h('span', { class: 'dot-spin', 'aria-hidden': 'true' }), 'Updating\u2026'] : 'Update all ' + mine.length + ' on this website\u2026') : null),
          table(['Type', 'Name', 'Now', 'Update to', ''], s.items.map(i => h('tr', { class: updatable(i) && ctl.jobBy && (ctl.jobBy(s.site, i.kind, i.slug) || {}).status === 'working' ? 'updating' : null },
            h('td', {}, kindBadge(i.kind)),
            h('td', {}, i.what, i.careful ? [' ', badge('careful', 'warn')] : null),
            h('td', { class: 'mono', text: i.from || '\u2013' }),
            h('td', {}, h('span', { class: 'mono', text: i.to }), i.kind.startsWith('core-') ? [' ', badge(i.kind.replace('core-', '') + ' update', 'warn')] : null),
            h('td', { class: 'actions' }, i.status === 'inactive' ? badge('switched off', '') : null, ' ', action(i)))), '', 'items-table'));
      }),
      unchecked.length ? h('div', { class: 'note', text: 'Could not check: ' + unchecked.map(s => s.site).join(', ') }) : null,
      partial.length ? h('div', { class: 'note', text: 'Only partly checked: ' + partial.map(s => s.site).join(', ') + '. A plugin on these websites would not load for the check, so updates that plugin makers send from their own servers (not WordPress.org) may be missing here. Look at them in WordPress.' }) : null);
  }

  async function viewUpdates() {
    let state = (await api('/api/updates')).data;
    let job = (await api('/api/wpupdate')).data;
    let uploads = (await api('/api/uploads')).data;
    let logins = { scan: { status: 'done' }, sites: [] };            // which websites can be opened with one click
    const loadLogins = async () => { try { const r = await api('/api/logins'); if (r && r.data && r.data.sites) logins = r.data; } catch (e) { /* the page works without it */ } };
    await loadLogins();
    const uploadHolder = h('div', {}, null);
    const ticks = {};                       // 'file id|website' -> chosen or not (what can be updated starts chosen)
    const seenFiles = new Set();
    const sending = [];                     // the files being sent right now, with their progress
    const holder = h('div', {}, null);
    const jobHolder = h('div', {}, null);
    const button = h('button', { class: 'btn primary', type: 'button', text: 'Look for updates' });

    const stopJob = async () => { await act('/api/wpupdate/stop', {}); await showJob(); };
    // the moment you confirm, the rows show it, before the server has answered
    let starting = null;
    const keyOf = (site, kind, slug) => site + '|' + kind + '|' + slug;
    const jobBy = (site, kind, slug) => {
      if (job.status === 'running') {
        const found = job.items.find(x => x.site === site && x.kind === kind && x.slug === slug);
        if (found) return found;
      }
      return starting && starting.has(keyOf(site, kind, slug)) ? { status: 'working', step: 'Starting\u2026', seconds: 0 } : null;
    };
    const paint = () => {
      jobHolder.replaceChildren(renderJob(job, stopJob) || '');
      holder.replaceChildren(renderUpdates(state, { busy: job.status === 'running' || !!starting, update: askUpdate, recheck, jobBy,
        loginFor: site => (logins.sites || []).find(x => x.site === site && x.status === 'installed') || null,
        openAdmin: async site => { if (!await openAdminTab(site)) { await loadLogins(); paint(); } },
        uploadFor: (kind, slug, to) => (uploads.zips || []).find(z => z.kind === kind && z.slug === slug && cmpVersion(z.version, to || '0') >= 0) || null }));
      paintUploads();
      // the tab itself shows it too, for when you are looking at something else
      if (job.status === 'running') document.title = '\u27f3 Updating ' + (job.counts.done + job.counts.failed + job.counts.restored + job.counts.skipped) + ' of ' + job.items.length + ' \u2013 CP-Security';
      else if (document.title.startsWith('\u27f3')) document.title = 'WP Updates \u2013 CP-Security';
    };
    function paintUploads() {
      (uploads.zips || []).forEach(z => {
        if (seenFiles.has(z.id)) return;
        seenFiles.add(z.id);
        z.rows.forEach(r => { if (r.can_update) ticks[z.id + '|' + r.site] = true; });
      });
      uploadHolder.replaceChildren(renderUploads(uploads, {
        busy: job.status === 'running' || !!starting, jobBy, ticks, sending,
        tick: (key, on) => { ticks[key] = on; paintUploads(); },
        tickAll: (z, on) => { z.rows.forEach(r => { if (r.can_update) ticks[z.id + '|' + r.site] = on; }); paintUploads(); },
        pick: sendFiles, del: deleteFile, rescan: rescanWebsites, apply: applyFiles,
      }));
    }
    // while the websites are being read, ask again every moment until it is done
    const watchUploads = () => {
      clearInterval(S.uploadTimer);
      if (!(uploads.inventory && uploads.inventory.status === 'running')) return;
      S.uploadTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.uploadTimer); return; }
        uploads = (await api('/api/uploads')).data;
        paint();                                  // the list of waiting updates uses the uploaded files too
        if (uploads.inventory.status !== 'running') clearInterval(S.uploadTimer);
      }, 1500);
    };
    async function refreshUploads() { uploads = (await api('/api/uploads')).data; paint(); watchUploads(); }
    async function sendFiles(files) {
      for (const file of files) {
        const item = { name: file.name, pct: 0, state: 'sending', message: '' };
        sending.push(item);
        paintUploads();
        if (!/\.zip$/i.test(file.name)) { item.state = 'bad'; item.message = 'Choose a .zip file, exactly as you downloaded it.'; paintUploads(); continue; }
        if (file.size > (uploads.max_mb || 200) * 1048576) { item.state = 'bad'; item.message = 'That file is bigger than the ' + (uploads.max_mb || 200) + ' MB limit.'; paintUploads(); continue; }
        let last = 0;
        const res = await sendFile(file, p => {
          item.pct = Math.round(p * 100);
          if (item.pct >= 100) item.state = 'checking';
          if (Date.now() - last > 250 || item.pct >= 100) { last = Date.now(); paintUploads(); }
        });
        item.state = res.ok ? 'ok' : 'bad';
        item.message = res.message;
        toast(res.message, res.ok ? 'ok' : 'bad');
        await refreshUploads();
        if (res.ok) setTimeout(() => { const at = sending.indexOf(item); if (at >= 0) { sending.splice(at, 1); paintUploads(); } }, 8000);
      }
    }
    async function deleteFile(z) {
      if (!await confirmBox('Delete ' + z.name + ' ' + z.version + ' from the server?', 'Only the uploaded file is removed. The websites keep what was installed. You can upload it again later.', 'Delete the file', true)) return;
      await act('/api/uploads/delete', { id: z.id });
      await refreshUploads();
    }
    async function rescanWebsites() { await act('/api/uploads/scan', {}); await refreshUploads(); }
    function applyFiles(chosen) {
      askUpdate(chosen.map(({ z, r }) => ({ site: r.site, kind: z.kind, slug: z.slug, zip: z.id, what: z.name + ' (your upload)', from: r.installed, to: z.version, careful: z.careful })));
    }
    // the progress is looked at every second while updates run, and the list is read again when they finish
    const watch = () => {
      clearInterval(S.pollTimer);
      S.pollTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.pollTimer); return; }
        const was = job.status;
        job = (await api('/api/wpupdate')).data;
        if (was === 'running' && job.status !== 'running') {
          state = (await api('/api/updates')).data;
          uploads = (await api('/api/uploads')).data;
          clearInterval(S.pollTimer);
          toast(job.counts.failed + job.counts.restored ? 'Updates finished. Some need a look.' : 'Updates finished.', job.counts.failed + job.counts.restored ? 'bad' : 'ok');
        }
        paint();
      }, 1000);
    };
    async function showJob() { job = (await api('/api/wpupdate')).data; paint(); }
    async function askUpdate(items) {
      const careful = items.filter(i => i.careful);
      const content = h('div', {},
        h('p', { text: 'These will be updated now, one after the other:' }),
        h('ul', { class: 'plain' }, items.map(i => h('li', {}, h('span', { class: 'mono', text: i.site }), ' \u2013 ' + i.what + ' ', h('span', { class: 'mono muted', text: i.from + ' \u2192 ' + i.to })))),
        careful.length ? h('p', { class: 'error', style: 'min-height:0', text: 'Careful: ' + careful.map(i => i.what).join(', ') + ' can change how a shop or a page looks and works. If you have a test copy of this website, update that one first.' }) : null,
        items.some(i => i.zip) ? h('p', { class: 'small', text: 'The files come from your upload, not from WordPress.org. They run on those websites, so use only files you got from the plugin or theme\u2019s maker. Nobody is asked about licences: an update counts as done when the website has the new version and still answers.' }) : null,
        h('p', { class: 'muted small', text: 'Before each update a copy of the files is saved, and once per website a copy of the database. Afterwards the website is checked. If it does not work, the old version is put back and you are told. Putting files back cannot undo changes an update made to the database; that is what the database copy is for.' }));
      if (!await dialog({ title: 'Update ' + items.length + ' item' + (items.length > 1 ? 's' : '') + '?', content, ok: 'Start updating' })) return;
      starting = new Set(items.map(i => keyOf(i.site, i.kind, i.slug)));
      paint();
      const r = await act('/api/wpupdate/start', { items: items.map(i => i.zip ? { site: i.site, kind: i.kind, slug: i.slug, zip: i.zip } : { site: i.site, kind: i.kind, slug: i.slug }), confirmed: true });
      if (r.ok) { await showJob(); starting = null; paint(); watch(); } else { starting = null; paint(); }
    }

    // one website read again (fast): follow it until it is done
    const pollChecking = () => {
      clearInterval(S.pollTimer);
      S.pollTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.pollTimer); return; }
        state = (await api('/api/updates')).data;
        paint();
        if (!(state.checking || []).length) { clearInterval(S.pollTimer); if (job.status === 'running') watch(); }
      }, 1500);
    };
    async function recheck(site) {
      const r = await act('/api/updates/refresh', { site });
      if (!r.ok) return;
      state = (await api('/api/updates')).data;
      paint();
      pollChecking();
    }

    const poll = async () => {
      clearInterval(S.pollTimer);
      S.pollTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.pollTimer); return; }
        state = (await api('/api/updates')).data;
        paint();
        if (state.status !== 'running') { clearInterval(S.pollTimer); button.disabled = false; if (job.status === 'running') watch(); }
      }, 3000);
    };
    button.addEventListener('click', async () => {
      button.disabled = true;
      const r = await act('/api/updates/refresh', {});
      state = (await api('/api/updates')).data;
      paint();
      if (state.status === 'running') poll(); else button.disabled = false;
      if (!r.ok) button.disabled = false;
    });
    // right after a restart of the panel the websites are still being looked at: the buttons appear as they are found
    const watchLogins = () => {
      clearInterval(S.loginTimer);
      if (!logins.scan || logins.scan.status !== 'running') return;
      S.loginTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.loginTimer); return; }
        await loadLogins();
        paint();
        if (logins.scan.status !== 'running') clearInterval(S.loginTimer);
      }, 2500);
    };
    paint();
    watchUploads();
    watchLogins();
    if (state.status === 'running') { button.disabled = true; poll(); } else if ((state.checking || []).length) pollChecking(); else if (job.status === 'running') watch();
    return h('div', { class: 'stack' },
      pageHead('WP Updates', 'Updates waiting for WordPress itself, plugins and themes, website by website. Nothing is updated unless you press an Update button: there are no automatic updates.', button),
      jobHolder, uploadHolder, holder,
      h('div', { class: 'note', text: 'Updates of plugins and themes can be started here, one website at a time, with a copy saved first and a check afterwards. WordPress itself is updated in each website\u2019s own dashboard (Dashboard \u2192 Updates). A plugin marked "switched off" is not running, but its old files can still be attacked: delete it if you do not need it. Plugins that get their updates from their maker\u2019s own server (not WordPress.org) are included. If you updated something in WordPress yourself, press Check again on that website. Websites that have the one-click login set up show an Open admin button (set it up on the One-click login page).' }));
  }
  // ------------------------------------------------------------------ one-click login to the websites
  // Opens a website's dashboard in a new tab, signed in (the One-click login and the WP Updates pages both use this).
  // The tab is opened first, while the click is fresh, so the browser does not block it; the link is put in once the panel has made it.
  async function openAdminTab(site) {
    const tab = window.open('', '_blank');
    const { data: r } = await api('/api/logins/open', { method: 'POST', body: { site } });
    if (r && r.ok && r.url) {
      if (tab) { try { tab.opener = null; } catch (e) { /* ignore */ } tab.location.href = r.url; toast(r.message, 'ok'); }
      else await dialog({ title: 'Open ' + site, ok: 'Close', cancel: '', content: h('div', {},
        h('p', { text: 'Your browser blocked the new tab. Use this link within a minute (it works once):' }),
        h('p', {}, h('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer', text: 'Open the dashboard of ' + site }))) });
      return true;
    }
    if (tab) tab.close();
    toast((r && r.message) || 'That did not work.', 'bad');
    return false;
  }

  const HELPER_STATUS = {
    installed: ['Ready', 'ok'], missing: ['Not installed', ''], changed: ['Needs reinstalling', 'warn'],
    unknown: ['Not read yet', ''], unsupported: ['Cannot be used here', 'warn'],
  };

  function renderLogins(data, ctl) {
    const sites = data.sites || [];
    const job = data.job || { status: 'idle', items: [] };
    const working = job.status === 'running';
    const scanning = data.scan && data.scan.status === 'running';
    const ready = sites.filter(s => s.status === 'installed');
    const canInstall = sites.filter(s => s.checked && ['missing', 'changed'].includes(s.status));
    const inJob = Object.fromEntries((job.items || []).map(i => [i.site, i]));

    const rows = sites.map(s => {
      const [label, kind] = HELPER_STATUS[s.status] || [s.status, ''];
      const ji = working ? inJob[s.site] : null;
      const accounts = s.admins.map(a => h('option', { value: a.login, dir: 'auto', selected: a.login === s.login, text: a.name === a.login ? a.login : a.login + ' \u2013 ' + a.name }));
      const buttons = [];
      if (s.status === 'installed') buttons.push(h('button', { class: 'btn primary', type: 'button', disabled: working, 'aria-label': 'Open the dashboard of ' + s.site, text: 'Open admin', onclick: () => ctl.openAdmin(s.site) }));
      if (s.checked && s.status !== 'installed' && s.status !== 'unsupported') {
        const again = s.status === 'changed';
        buttons.push(h('button', { class: 'btn' + (again ? '' : ' primary'), type: 'button', disabled: working, 'aria-label': (again ? 'Reinstall the login helper on ' : 'Install the login helper on ') + s.site, text: again ? 'Reinstall' : 'Install', onclick: () => ctl.install([s.site]) }));
      }
      if (s.status === 'installed' || s.status === 'changed') buttons.push(h('button', { class: 'btn', type: 'button', disabled: working, 'aria-label': 'Remove the login helper from ' + s.site, text: 'Remove', onclick: () => ctl.remove([s.site]) }));
      const tone = s.status === 'installed' ? ' is-ready' : (s.status === 'changed' || s.status === 'unsupported' ? ' is-warn' : '');
      return h('div', { class: 'login-row' + tone },
        h('div', { class: 'lr-site' },
          h('strong', { class: 'lr-name', text: s.site }),
          ji ? (ji.status === 'working' ? workingBadge('Working\u2026') : ji.status === 'waiting' ? badge('In line', '') : badge(ji.status === 'done' ? 'done' : 'failed', ji.status === 'done' ? 'ok' : 'bad')) : badge(label, kind),
          ji && ji.status === 'working' && ji.step ? h('div', { class: 'lr-note', text: ji.step }) : null,
          s.problem ? h('div', { class: 'lr-note', text: s.problem }) : null),
        s.admins.length ? h('div', { class: 'lr-who' },
          h('label', { for: 'who-' + s.site, text: 'Log in as' }),
          h('span', { class: 'pick' }, h('select', { id: 'who-' + s.site, disabled: working, 'aria-label': 'Log in to ' + s.site + ' as', onchange: ev => ctl.pickUser(s.site, ev.target.value) }, accounts))) : null,
        buttons.length ? h('div', { class: 'lr-actions' }, buttons) : null);
    });

    const last = job.status !== 'idle' && (job.items || []).length ? h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, working ? h('div', { class: 'spinner small-spin', style: 'margin:0' }) : null,
        h('h2', { 'aria-live': 'polite', text: working ? (job.action === 'install' ? 'Installing\u2026' : 'Removing\u2026') : 'Finished' }),
        job.counts.done ? badge(job.counts.done + ' done', 'ok') : null, job.counts.failed ? badge(job.counts.failed + ' failed', 'bad') : null),
      table(['Website', 'Result'], job.items.map(i => h('tr', {}, h('td', {}, h('strong', { class: 'lr-name', text: i.site })),
        h('td', {}, i.status === 'working' ? workingBadge('Working\u2026') : i.status === 'waiting' ? badge('In line', '') : badge(i.status === 'done' ? 'done' : 'failed', i.status === 'done' ? 'ok' : 'bad'),
          h('div', { class: 'small ' + (i.status === 'failed' ? '' : 'muted'), text: i.status === 'working' ? i.step : i.message })))), '')) : null;

    return h('div', { class: 'stack' },
      h('section', { class: 'card login-intro' },
        h('p', { text: 'Open any website\u2019s dashboard with one click, without typing a password. Each website needs one small helper file, which the panel puts there and tests first. The link it makes works once, for one minute, and it does not matter if a website has a custom login address.' }),
        h('div', { class: 'note warn', text: 'This skips a website\u2019s own 2-step login, so this panel\u2019s login is the only gate. Every use is written to the Activity log.' }),
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', type: 'button', disabled: working || !canInstall.length, text: canInstall.length ? 'Install on ' + canInstall.length + ' website' + (canInstall.length > 1 ? 's' : '') + '\u2026' : 'Installed everywhere', onclick: () => ctl.install(null, canInstall.length) }),
          ready.length ? h('button', { class: 'btn', type: 'button', disabled: working, text: ready.length === 1 ? 'Remove from 1 website\u2026' : 'Remove from all ' + ready.length + '\u2026', onclick: () => ctl.remove(null, ready.length) }) : null,
          scanning ? h('span', { class: 'row muted small' }, h('span', { class: 'dot-spin', 'aria-hidden': 'true' }), 'looking at the websites\u2026') : null)),
      last,
      h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { text: 'Websites' }), badge(ready.length + ' of ' + sites.length + ' ready', ready.length ? 'ok' : ''),
        h('button', { class: 'btn small right', type: 'button', disabled: scanning || working, text: 'Check again', onclick: ctl.rescan })),
        rows.length ? rows : empty('No WordPress websites were found on this server.')));
  }

  async function viewLogins() {
    let data = (await api('/api/logins')).data;
    const holder = h('div', {}, null);
    const paint = () => holder.replaceChildren(renderLogins(data, ctl));
    const poll = () => {
      clearInterval(S.pollTimer);
      S.pollTimer = setInterval(async () => {
        if (S.view !== 'logins') { clearInterval(S.pollTimer); return; }
        data = (await api('/api/logins')).data;
        paint();
        if (data.scan.status !== 'running' && data.job.status !== 'running') clearInterval(S.pollTimer);
      }, 1200);
    };
    const refresh = async () => { data = (await api('/api/logins')).data; paint(); if (data.scan.status === 'running' || data.job.status === 'running') poll(); };

    async function openAdmin(site) { if (!await openAdminTab(site)) await refresh(); }
    async function run(action, names, count) {
      const many = names ? names.length : count;
      const adding = action === 'install';
      const content = h('div', {},
        h('p', { text: adding
          ? 'One small file is put in the must-use plugins folder of ' + (names ? names[0] : many + ' website' + (many > 1 ? 's' : '')) + (names && names.length > 1 ? ' and ' + (names.length - 1) + ' more' : '') + ', one website at a time.'
          : 'The helper file is taken off ' + (names ? names[0] : many + ' website' + (many > 1 ? 's' : '')) + (names && names.length > 1 ? ' and ' + (names.length - 1) + ' more' : '') + '. Nothing else on the website is touched.' }),
        adding ? h('p', { class: 'muted small', text: 'Before it is switched on the file is checked for mistakes, tested with a link that has already expired, and the website must still answer. If anything is wrong the website is put back as it was. You can remove it again at any time.' }) : null);
      if (!await dialog({ title: adding ? 'Install the login helper?' : 'Remove the login helper?', content, ok: adding ? 'Install' : 'Remove', danger: !adding })) return;
      const r = await act('/api/logins/' + action, names ? { domains: names, confirmed: true } : { all: true, confirmed: true });
      if (r.ok) await refresh();
    }
    const ctl = {
      openAdmin, install: (names, count) => run('install', names, count), remove: (names, count) => run('remove', names, count),
      pickUser: async (site, login) => { const r = await act('/api/logins/user', { site, login }); await refresh(); return r; },
      rescan: async () => { await act('/api/logins/scan', {}); await refresh(); },
    };
    paint();
    if (data.scan.status === 'running' || data.job.status === 'running') poll();
    return h('div', { class: 'stack' },
      pageHead('One-click login', 'Open the dashboard of any website from here, signed in, without typing a password.'), holder);
  }

  // ------------------------------------------------------------------ settings
  const minutes = seconds => Math.round(seconds / 60);

  function blockerCard(b) {
    const inputs = {};
    const num = (name, key, value, min, max) => {
      const el = h('input', { type: 'number', inputmode: 'numeric', min: String(min), max: String(max), value: String(value), required: true,
        'aria-label': (b.names[name] || name) + ': ' + key });
      inputs[name + '.' + key] = [el, value];
      return el;
    };
    const rows = Object.keys(b.tuning).map(name => {
      const t = b.tuning[name], L = b.limits;
      const off = b.missing_logs.includes(name);
      return h('tr', { class: off ? 'dim' : null },
        h('td', {}, h('strong', { text: b.names[name] || name }), off ? h('div', { class: 'muted small', text: 'Not available: this server has no log file for it.' }) : null),
        h('td', {}, num(name, 'maxretry', t.maxretry, L.maxretry[0], L.maxretry[1])),
        h('td', {}, num(name, 'findtime', minutes(t.findtime), minutes(L.findtime[0]), minutes(L.findtime[1]))),
        h('td', {}, num(name, 'bantime', minutes(t.bantime), minutes(L.bantime[0]), minutes(L.bantime[1]))));
    });
    const save = h('button', { class: 'btn primary', type: 'submit', text: 'Save these numbers' });
    const head = ['Protection', 'Block after this many wrong tries', '…within this many minutes', '…for this many minutes'];
    labelCells(head, rows);
    const form = h('form', {}, h('div', { class: 'table-wrap' }, h('table', { class: 'numbers' },
      h('thead', {}, h('tr', {}, head.map(x => h('th', { scope: 'col', text: x })))),
      h('tbody', {}, rows))), h('div', { class: 'card-foot' }, save));
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      const changes = {};
      for (const [id, [el, original]] of Object.entries(inputs)) {
        const [name, key] = id.split('.');
        const value = Number(el.value);
        if (!Number.isInteger(value)) { toast('Please use whole numbers.', 'bad'); return; }
        if (value !== original) (changes[name] = changes[name] || {})[key] = key === 'maxretry' ? value : value * 60;
      }
      if (!Object.keys(changes).length) { toast('Nothing was changed.'); return; }
      const r = await act('/api/settings/blocker', { changes }, 'Applying to the blocker…');
      if (r.ok) redraw();
    });
    return h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: 'How strict the attack blocker is' }),
        h('span', { class: 'muted small right', text: 'Stricter means fewer tries and longer blocks. The defaults suit most servers.' })),
      form);
  }

  function twoStepCard(s) {
    const box = h('div', { class: 'stack' });
    if (s.twofa) {
      const off = h('form', { class: 'inline-form' }, field('tf-off-pw', 'Your password', { type: 'password', autocomplete: 'current-password', required: true }),
        h('button', { class: 'btn danger', type: 'submit', text: 'Turn off' }));
      off.addEventListener('submit', async ev => {
        ev.preventDefault();
        const r = await act('/api/settings/2fa/disable', { password: $('#tf-off-pw').value });
        if (r.ok) { S.twofa = false; redraw(); }
      });
      box.append(h('p', {}, badge('on', 'ok'), ' Signing in asks for a 6-digit code from your authenticator app.'), off);
    } else {
      const start = h('form', { class: 'inline-form' }, field('tf-pw', 'Your password', { type: 'password', autocomplete: 'current-password', required: true }),
        h('button', { class: 'btn', type: 'submit', text: 'Turn on' }));
      start.addEventListener('submit', async ev => {
        ev.preventDefault();
        const { data } = await api('/api/settings/2fa/start', { method: 'POST', body: { password: $('#tf-pw').value } });
        if (!data.ok) { toast(data.message, 'bad'); return; }
        const confirm = h('form', { class: 'inline-form' }, field('tf-code', 'Code from the app', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, maxlength: 8 }),
          h('button', { class: 'btn primary', type: 'submit', text: 'Confirm' }));
        confirm.addEventListener('submit', async e2 => {
          e2.preventDefault();
          const r = await act('/api/settings/2fa/confirm', { code: $('#tf-code').value });
          if (r.ok) { S.twofa = true; redraw(); }
        });
        box.replaceChildren(h('p', { text: 'Type this key into your authenticator app (choose "time based"):' }),
          h('p', { class: 'mono secret', text: data.secret.match(/.{1,4}/g).join(' ') }), confirm);
      });
      box.append(h('p', {}, badge('off', ''), ' Signing in needs only the username and password. Add a second step if the panel is open to everyone.'), start);
    }
    return card('Two-step login (optional)', box);
  }

  async function viewSettings() {
    const [{ data: s }, { data: act_ }, { data: b }] = await Promise.all([api('/api/settings'), api('/api/activity'), api('/api/settings/blocker')]);
    S.twofa = !!s.twofa;
    let access = s.access;
    const accessCard = card('Who can reach this panel',
      h('div', { class: 'choices' }, [['login', 'Anyone with the login', 'The login page is open to everyone' + (s.twofa ? ', protected by your password and the 6-digit code.' : ', protected only by your password. Add the optional two-step login below.') + ' Best if your home address changes a lot.'],
        ['trusted', 'Trusted addresses only', 'Other addresses cannot even see the login page. Most secure. If your address changes, run "security myip" on the server.']].map(([v, t, d]) =>
        h('button', { class: 'choice', type: 'button', 'aria-pressed': String(access === v), onclick: async () => {
          if (v === access) return;
          let confirmed = false;
          let r = await api('/api/settings/access', { method: 'POST', body: { access: v } });
          if (r.status === 409) {
            if (!await confirmBox('You could lock yourself out', r.data.message + ' Continue anyway?', 'Continue', true)) return;
            confirmed = true; r = await api('/api/settings/access', { method: 'POST', body: { access: v, confirmed } });
          }
          toast(r.data.message, r.data.ok ? 'ok' : 'bad'); redraw();
        } }, h('div', { class: 'title' }, t, access === v ? badge('now', 'brand') : null), h('div', { class: 'desc', text: d })))));

    const pwForm = h('form', { class: 'stack' },
      field('pw-current', 'Current password', { type: 'password', autocomplete: 'current-password', required: true }),
      field('pw-new', 'New password (at least 12 characters)', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12 }),
      h('button', { class: 'btn primary', type: 'submit', text: 'Change password' }));
    pwForm.addEventListener('submit', async ev => {
      ev.preventDefault();
      const r = await act('/api/settings/password', { current: $('#pw-current').value, new: $('#pw-new').value });
      if (r.ok) pwForm.reset();
    });

    const sv = s.server || {};
    const cert = sv.certificate;
    const about = card('About this panel', h('div', { class: 'kv-row stacked' },
      [['Version', s.version], ['Address', s.domain ? 'https://' + s.domain + ':' + s.port : 'not set'],
        ['Certificate', !cert ? 'not set' : cert.found ? (cert.days_left === null ? 'found' : cert.days_left + ' days left') : 'not found'],
        ['Web server', (sv.web_server || 'none found') + (sv.web_server_version ? ' ' + sv.web_server_version : '')],
        ['Your address', s.client_ip + (s.client_ip_trusted ? ' (trusted)' : '')]].map(([k, v]) =>
        h('div', { class: 'kv' }, h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v })))));

    const baseline = card('Normal state of your websites',
      h('p', { class: 'muted', text: 'The panel remembers how every website answers when all is well. Later it can tell a site that just broke from one that was always giving an error. Save again after you add or fix websites.' }),
      h('button', { class: 'btn', type: 'button', text: 'Save today as normal', onclick: async () => {
        await act('/api/settings/baseline', {}, 'Asking every website for its home page…'); } }));

    return h('div', { class: 'stack' },
      pageHead('Settings', 'Signed in as ' + s.user + '.'),
      accessCard,
      h('div', { class: 'grid' }, card('Change password', pwForm), twoStepCard(s)),
      blockerCard(b),
      h('div', { class: 'grid' }, baseline, about),
      h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { text: 'Recent activity' })),
        table(['When', 'What', 'Details'], act_.events.map(e => h('tr', {}, h('td', { class: 'mono small', text: e.when }), h('td', {}, badge(e.event.replace(/_/g, ' ').toLowerCase(), /FAIL|ERROR/.test(e.event) ? 'bad' : '')), h('td', { class: 'mono small muted', text: e.details }))), 'Nothing yet.')));
  }


  // ------------------------------------------------------------------ advisor
  function fixButton(fix) {
    if (fix.kind === 'page') return h('a', { class: 'btn small', href: '#/' + fix.id, text: fix.label });
    return h('button', { class: 'btn small primary', type: 'button', text: fix.label, onclick: async () => {
      const r = await act('/api/advisor/fix', { id: fix.id }, 'Working…');
      if (r.ok) redraw(true);
    } });
  }

  async function viewAdvisor(refresh) {
    const { data } = await api('/api/advisor' + (refresh ? '?refresh=1' : ''));
    const c = data.counts;
    S.advice = c.bad + c.warn;
    rememberAdvice(data.findings.filter(f => f.level === 'bad' || f.level === 'warn').map(f => ({ level: f.level, title: f.title, advice: f.advice || '' })));
    const of = lvl => data.findings.filter(f => f.level === lvl);
    const finding = f => h('article', { class: 'finding ' + f.level },
      icon(f.level === 'ok' ? 'check' : f.level === 'info' ? 'info' : 'alert'),
      h('div', { class: 'finding-body' }, h('h3', { text: f.title }),
        f.detail ? h('p', { class: 'muted', text: f.detail }) : null,
        f.advice ? h('p', { class: 'advice' }, h('strong', { text: 'What to do: ' }), f.advice) : null,
        f.fix ? fixButton(f.fix) : null));
    const banner = c.bad ? ['bad', 'alert', c.bad + ' thing' + (c.bad > 1 ? 's' : '') + ' need action now', 'These put your server at real risk. Start at the top.']
      : c.warn ? ['warn', 'alert', c.warn + ' suggestion' + (c.warn > 1 ? 's' : ''), 'Nothing is on fire, but these are worth fixing soon.']
        : ['ok', 'check', 'No problems found', 'The advisor looked at your server and found nothing to worry about.'];
    const sv = data.server;
    const section = (title, lvl) => of(lvl).length ? h('div', { class: 'stack' }, h('h2', { class: 'section-title', text: title }), of(lvl).map(finding)) : null;
    return h('div', { class: 'stack' },
      pageHead('Advisor', 'Looks at your whole server, notices other security tools, and tells you what to do. It only looks: nothing changes unless you press a button.',
        h('button', { class: 'btn', type: 'button', text: 'Look again', onclick: () => redraw(true) })),
      h('div', { class: 'banner ' + banner[0] }, icon(banner[1]), h('div', {}, h('div', { text: banner[2] }), h('div', { class: 'sub', text: banner[3] }))),
      h('div', { class: 'kv-row' },
        [['Server', sv.os || 'unknown'], ['Web server', (sv.web_server || 'none') + (sv.web_server_version ? ' ' + sv.web_server_version : '')],
          ['CyberPanel', sv.cyberpanel ? 'found' : 'not found'], ['Checked', data.checked_at]].map(([k, v]) =>
          h('div', { class: 'kv' }, h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v })))),
      section('Needs action now', 'bad'), section('Worth fixing soon', 'warn'), section('Good to know', 'info'),
      of('ok').length ? h('section', { class: 'card' }, h('h2', { text: 'These look fine' }),
        h('div', { class: 'stack' }, of('ok').map(f => h('div', { class: 'row ok-line' }, icon('check'), h('span', { text: f.title }))))) : null);
  }

  // ------------------------------------------------------------------ setup
  const STEP_STATE = { done: ['Done', 'ok'], todo: ['To do', 'warn'], blocked: ['Blocked', 'bad'], skip: ['Not needed', ''] };
  const JOB_STATE = { waiting: ['Waiting', ''], running: ['Working…', 'brand'], done: ['Done', 'ok'], failed: ['Failed', 'bad'], skipped: ['Skipped', ''] };

  function jobCard(job) {
    const done = job.status === 'done', failed = job.status === 'failed', running = job.status === 'running';
    return h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, h('h2', { text: running ? 'Setting up…' : done ? 'Setup finished' : 'Setup stopped' }),
        running ? h('div', { class: 'spinner small-spin', 'aria-hidden': 'true' }) : badge(done ? 'all done' : 'a step failed', done ? 'ok' : 'bad'),
        h('span', { class: 'muted small right', text: job.finished ? 'Finished ' + job.finished : 'Started ' + job.started })),
      h('ol', { class: 'steps' }, job.steps.map(s => {
        const [label, kind] = JOB_STATE[s.state] || [s.state, ''];
        return h('li', { class: 'step ' + s.state }, h('div', { class: 'step-main' }, h('strong', { text: s.title }), badge(label, kind)),
          s.message ? h('div', { class: 'step-msg ' + (s.state === 'failed' ? 'error' : 'muted'), text: s.message }) : null);
      })),
      failed ? h('div', { class: 'note warn', style: 'margin:0 1.25rem 1rem', text: 'Nothing is left half-done: the step that failed undid its own changes. Fix the cause named above, then run setup again.' }) : null,
      job.log.length ? h('details', { class: 'log-box', open: running ? true : null }, h('summary', { text: 'Technical log' }), h('pre', { class: 'log', text: job.log.join('\n') })) : null);
  }

  async function viewSetup() {
    const holder = h('div', { class: 'stack' });
    const runBtn = h('button', { class: 'btn primary', type: 'button', text: 'Run setup' });
    let lastStatus = null;

    async function start(keys, todo) {
      const names = todo.filter(t => !keys || keys.includes(t.key)).map(t => t.title);
      const content = h('div', {}, h('p', { text: 'These steps will run, one after the other:' }),
        h('ul', { class: 'plain-list' }, names.map(n => h('li', { text: n }))),
        h('p', { class: 'muted small', text: 'Each step undoes its own changes if something goes wrong. The web server restarts gracefully once, and your websites are checked afterwards.' }));
      if (!await dialog({ title: 'Run setup?', content, ok: 'Run setup' })) return;
      const r = await act('/api/setup/run', keys ? { keys } : {});
      if (r.ok) load();
    }

    function render(d) {
      const todo = d.plan.filter(p => p.state === 'todo');
      const running = d.job.status === 'running';
      runBtn.disabled = running || !todo.length;
      runBtn.onclick = () => start(null, todo);
      const sv = d.server;
      const cert = sv.certificate;
      const info = h('div', { class: 'kv-row' },
        [['Web server', (sv.web_server || 'none found') + (sv.web_server_version ? ' ' + sv.web_server_version : '')],
          ['Panel address', sv.panel_domain ? 'https://' + sv.panel_domain + ':' + sv.panel_port : 'not set'],
          ['Panel certificate', !cert ? 'not set' : cert.found ? (cert.days_left === null ? 'found' : cert.days_left + ' days left') : 'not found']].map(([k, v]) =>
          h('div', { class: 'kv' }, h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v }))));
      const plan = running ? null : h('div', { class: 'stack' }, d.plan.map(p => {
        const [label, kind] = STEP_STATE[p.state] || [p.state, ''];
        return h('section', { class: 'card plan-step ' + p.state },
          h('div', { class: 'row' }, h('h3', { text: p.title }), badge(label, kind),
            p.state === 'todo' && todo.length > 1 ? h('button', { class: 'btn small right', type: 'button', text: 'Run only this', onclick: () => start([p.key], todo) }) : null),
          h('p', { class: p.state === 'blocked' ? 'error' : 'muted', text: p.note }),
          p.will_do.length ? h('details', {}, h('summary', { text: 'What it will do' }), h('ul', { class: 'plain-list' }, p.will_do.map(w => h('li', { text: w })))) : null);
      }));
      const nothing = !running && !todo.length && d.plan.every(p => p.state !== 'blocked')
        ? h('div', { class: 'banner ok' }, icon('check'), h('div', {}, h('div', { text: 'Everything is set up' }), h('div', { class: 'sub', text: 'Nothing is left to do on this server.' }))) : null;
      // replaceChildren would print the word "null" for an empty slot, so only real elements are passed
      holder.replaceChildren(...[info, nothing, d.job.status !== 'idle' ? jobCard(d.job) : null, plan].filter(Boolean));
    }

    async function load() {
      const { data } = await api('/api/setup');
      if (!data.plan) return;
      render(data);
      clearInterval(S.pollTimer);
      if (data.job.status === 'running') {
        S.pollTimer = setInterval(() => { if (S.view !== 'setup') clearInterval(S.pollTimer); else load(); }, 1500);
      } else if (lastStatus === 'running') {
        toast(data.job.status === 'done' ? 'Setup finished.' : 'Setup stopped. See the details on this page.', data.job.status === 'done' ? 'ok' : 'bad');
      }
      lastStatus = data.job.status;
    }
    await load();
    return h('div', { class: 'stack' },
      pageHead('Setup', 'Installs and checks every protection. You can see the plan first; nothing changes until you press the button. Safe to run again at any time.', runBtn),
      holder);
  }

  // ------------------------------------------------------------------ drawing
  const VIEWS = { overview: viewOverview, advisor: viewAdvisor, blocked: viewBlocked, access: viewAccess, ports: viewPorts, serverfw: viewServerFw, headers: viewHeaders, firewall: viewFirewall, updates: viewUpdates, logins: viewLogins, setup: viewSetup, settings: viewSettings };

  function currentView() {
    const id = (location.hash.match(/^#\/(\w+)/) || [])[1];
    return VIEWS[id] ? id : 'overview';
  }

  async function draw(refresh) {
    const id = ++S.drawId;
    const app = $('#app');
    if (!S.me) { app.replaceChildren(viewLogin()); document.title = 'Sign in – CP-Security'; return; }
    S.view = currentView();
    document.title = (NAV.find(n => n[0] === S.view) || [])[1] + ' – CP-Security';
    app.replaceChildren(shell(h('p', { class: 'muted', text: 'Loading…' })));
    let content;
    try { content = await VIEWS[S.view](refresh); }
    catch (e) { content = card('Something went wrong', h('p', { text: 'The page could not be shown. Reload and try again.' })); }
    if (id !== S.drawId || !S.me) return;                 // the user already went somewhere else
    app.replaceChildren(shell(content));
    const first = $('#main h1'); if (first) first.tabIndex = -1;
  }
  const redraw = refresh => draw(refresh === true);

  // refresh the page content without the "Loading…" flash (used while something finishes in the background)
  async function softRedraw() {
    const id = S.drawId;
    let content;
    try { content = await VIEWS[S.view](false, true); } catch (e) { return; }
    const main = $('#main');
    if (id !== S.drawId || !S.me || !main) return;
    main.replaceChildren(versionBar(), content);
  }

  async function boot() {
    const { data } = await api('/api/me');
    S.twofa = !!data.twofa;
    if (data.authenticated) { S.me = data; S.csrf = data.csrf; } else { S.me = null; }
    if (S.me) await loadUpdate(false);
    draw();
  }

  window.addEventListener('hashchange', () => { S.more = false; draw(); });
  matchMedia('(max-width:900px)').addEventListener('change', () => { S.more = false; if (S.me) draw(); });
  boot();
})();
