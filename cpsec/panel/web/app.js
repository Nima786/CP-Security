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
    updates: 'M17.65 6.35A7.96 7.96 0 0012 4a8 8 0 108 8h-2a6 6 0 11-1.76-4.24L13 11h7V4l-2.35 2.35z',
    settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z',
    check: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z',
    alert: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z',
    info: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z',
    advisor: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z',
    ports: 'M7.77 6.76L6.23 5.48.82 12l5.41 6.52 1.54-1.28L3.42 12l4.35-5.24zM7 13h2v-2H7v2zm10-2h-2v2h2v-2zm-6 2h2v-2h-2v2zm6.77-7.52l-1.54 1.28L20.58 12l-4.35 5.24 1.54 1.28L23.18 12l-5.41-6.52z',
    headers: 'M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 14v2h8v-2h-8zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z',
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

  function table(headers, rows, emptyText) {
    if (!rows.length) return empty(emptyText);
    return h('div', { class: 'table-wrap' }, h('table', {},
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
    ['headers', 'Security headers', 'headers', 'Headers', 'Protection', false],
    ['firewall', 'Web firewall', 'firewall', 'Firewall', 'Protection', true],
    ['updates', 'WP Updates', 'updates', 'WP Updates', 'Protection', false],
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
    return h('div', { class: 'stack' },
      pageHead('Admin access', 'Who can open CyberPanel, the LiteSpeed admin page and the web terminal. Your websites are not affected.'),
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
        h('div', { class: 'card-head' }, h('h2', { text: 'Trusted addresses' }), data.lock_live ? badge('lock is on', 'ok') : badge('lock is NOT on', 'bad')),
        table(['Address', 'Name', ''], data.trusted.map(t => h('tr', {}, h('td', { class: 'mono', text: t.address }),
          h('td', {}, t.label, t.address === mine ? [' ', badge('you', 'brand')] : null),
          h('td', { class: 'actions' }, h('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: () => remove(t) })))), 'No trusted addresses.')),
      card('Add a trusted address', addForm,
        h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'Use the public address (search Google for "what is my IP"). Addresses like 192.168.x.x only exist inside a home network and do not work.' })),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Never blocked by the attack blocker' }), badge(String(data.never_block.length)),
          h('span', { class: 'muted small right', text: 'Cloudflare, your office, a monitoring service…' })),
        table(['Address', 'Name', ''], data.never_block.map(n => h('tr', {}, h('td', { class: 'mono', text: n.address }), h('td', { text: n.label }),
          h('td', { class: 'actions' }, h('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: async () => {
            if (await confirmBox('Remove ' + n.address + '?', 'The blocker will be allowed to block it again if it keeps guessing passwords.', 'Remove', true)) {
              await act('/api/access/never/remove', { address: n.address }, 'Updating the blocker…'); redraw(); } } })))),
          'Nothing is on this list.'),
        h('div', { class: 'card-foot' }, neverForm)));
  }

  // ------------------------------------------------------------------ open ports
  const PORT_STATUS = {
    open: ['Open to everyone', 'warn'], locked: ['Trusted addresses only', 'ok'], closed: ['This server only', 'ok'],
    private: ['Private network only', 'ok'], idle: ['Nothing running', ''],
  };

  async function viewPorts() {
    const { data } = await api('/api/ports');
    const head = pageHead('Open ports', 'The doors this server has open, who can reach each one, and which ones you keep for trusted addresses only.');
    if (!data.supported) return h('div', { class: 'stack' }, head, card(null, empty(data.message)));

    const lockPort = async r => {
      const lines = [h('p', { text: r.warn || ('Only your trusted addresses (' + data.trusted + ') will be able to reach ' + r.name + '. Everybody else is refused.') })];
      if (!data.client_ip_trusted) lines.push(h('p', { class: 'error', text: 'Your own address (' + data.client_ip + ') is not on the trusted list, so you would lose access to it too. Add it on the Admin access page first.' }));
      if (!await dialog({ title: 'Lock port ' + r.port + '?', content: h('div', {}, lines), ok: 'Lock it', danger: !!r.warn })) return;
      await act('/api/ports/lock', { port: r.port, confirmed: true }, 'Updating the lock…');
      redraw();
    };
    const openPort = async r => {
      if (!await confirmBox('Open port ' + r.port + ' to everybody?', r.open_warning || ('Port ' + r.port + ' will be open to everybody again.'), 'Open it', true)) return;
      await act('/api/ports/unlock', { port: r.port, confirmed: true }, 'Updating the lock…');
      redraw();
    };
    const accept = async (r, on) => { await act('/api/ports/accept', { port: r.port, accepted: on }); redraw(); };

    const small = isSmall();
    const rows = data.ports.map(r => {
      const [label, kind] = PORT_STATUS[r.status] || [r.status, ''];
      const badKind = r.level === 'bad' ? 'bad' : (r.level === 'warn' ? 'warn' : kind);
      const buttons = [];
      if (r.can_lock) buttons.push(h('button', { class: 'btn small' + (r.level === 'bad' || r.level === 'warn' ? ' primary' : ''), type: 'button', text: 'Lock it', onclick: () => lockPort(r) }));
      if (r.can_open) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Open it up', onclick: () => openPort(r) }));
      if (r.ignored) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'Warn me again', onclick: () => accept(r, false) }));
      else if (r.can_accept) buttons.push(h('button', { class: 'btn small', type: 'button', text: 'I know about this', onclick: () => accept(r, true) }));
      // on a phone there is no room for a third column: the buttons go under the status instead
      const actions = buttons.length ? h('div', { class: 'row', style: small ? 'margin-top:.6rem' : 'justify-content:flex-end' }, buttons) : null;
      return h('tr', {},
        h('td', {},
          h('div', {}, h('span', { class: 'mono', text: String(r.port) }), ' ', h('strong', { text: r.name })),
          h('div', { class: 'muted small', text: r.what }),
          h('div', { class: 'small' }, badge(r.kind_name), r.programs.length ? h('span', { class: 'muted', text: '  ' + r.programs.join(', ') }) : null)),
        h('td', {},
          badge(label, badKind),
          h('div', { class: 'muted small', text: r.status_text }),
          r.advice ? h('div', { class: 'small', style: 'margin-top:.25rem', text: r.advice }) : null,
          !r.can_lock && r.status === 'open' && r.cannot_lock_reason ? h('div', { class: 'muted small', text: r.cannot_lock_reason }) : null,
          small ? actions : null),
        small ? null : h('td', { class: 'actions' }, actions));
    });

    const attention = data.counts.bad + data.counts.warn;
    const summary = card(null,
      h('div', { class: 'row' },
        attention ? badge(attention + ' to look at', data.counts.bad ? 'bad' : 'warn') : badge('nothing to worry about', 'ok'),
        h('span', { class: 'muted', text: 'Lock a door and only your ' + data.trusted + ' trusted address' + (data.trusted === 1 ? '' : 'es') + ' can use it.' })),
      h('p', { class: 'muted small', style: 'margin-top:.75rem', text: 'This shows what the programs on the server allow. A firewall outside the server, such as your hosting company\u2019s, may close more.'
        + (data.firewall ? ' A firewall (' + data.firewall + ') is also switched on here.' : '') + ' Only TCP doors are listed. Nothing is locked unless you press the button, and you can undo every choice.' }));

    return h('div', { class: 'stack' }, head, summary,
      h('section', { class: 'card flush' }, table(small ? ['Door', 'Who can reach it'] : ['Door', 'Who can reach it', ''], rows, 'No open ports were found.')));
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

  function renderUpdates(state) {
    const sites = state.sites || [];
    const withItems = sites.filter(s => s.items.length);
    const unchecked = sites.filter(s => !s.checked);
    if (state.status === 'running') return card(null, h('div', { class: 'row' }, h('div', { class: 'spinner', style: 'margin:0' }), h('span', { text: 'Looking at every WordPress site… this takes about a minute.' })));
    if (state.status === 'idle') return card(null, h('p', { class: 'muted', text: 'Press "Look for updates" to see which websites have plugins, themes or WordPress itself waiting for an update.' }));
    if (state.status === 'failed') return card(null, h('p', { class: 'error', text: 'Looking failed: ' + (state.error || 'unknown reason') }));

    const all = withItems.flatMap(s => s.items.map(i => Object.assign({ site: s.site }, i)));
    const count = test => all.filter(test).length;
    const plugins = count(i => i.kind === 'plugin'), themes = count(i => i.kind === 'theme'), core = count(i => i.kind.startsWith('core'));
    // the same plugin or theme waiting on several websites: update them together
    const groups = {};
    all.forEach(i => {
      const key = i.kind + ':' + (i.slug || i.what);
      (groups[key] = groups[key] || { kind: i.kind, what: i.what, to: i.to, sites: [] }).sites.push(i.site);
    });
    const shared = Object.values(groups).filter(g => g.sites.length > 1).sort((a, b) => b.sites.length - a.sites.length);

    return h('div', { class: 'stack' },
      h('div', { class: 'banner ' + (withItems.length ? 'warn' : 'ok') }, icon(withItems.length ? 'alert' : 'check'),
        h('div', {}, h('div', { text: withItems.length ? all.length + ' update' + (all.length > 1 ? 's' : '') + ' waiting on ' + withItems.length + ' website' + (withItems.length > 1 ? 's' : '') : 'No updates are waiting' }),
          h('div', { class: 'sub', text: 'Looked ' + state.finished }))),
      withItems.length ? h('div', { class: 'grid tiles' }, tile('Websites affected', withItems.length), tile('Plugins', plugins), tile('Themes', themes), tile('WordPress itself', core)) : null,
      shared.length ? h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'The same update on several websites' }), h('span', { class: 'muted small right', text: 'Update these together.' })),
        table(['What', 'Type', 'New version', 'Websites'], shared.map(g => h('tr', {}, h('td', { text: g.what }), h('td', {}, kindBadge(g.kind)),
          h('td', { class: 'mono', text: g.to }), h('td', { class: 'small', text: g.sites.length + ': ' + g.sites.sort().join(', ') }))), '')) : null,
      withItems.map(s => h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { class: 'mono', text: s.site }), badge(s.items.length + ' waiting', 'warn')),
        table(['Type', 'Name', 'Now', 'Update to', ''], s.items.map(i => h('tr', {},
          h('td', {}, kindBadge(i.kind)), h('td', { text: i.what }), h('td', { class: 'mono', text: i.from || '–' }),
          h('td', {}, h('span', { class: 'mono', text: i.to }), i.kind.startsWith('core-') ? [' ', badge(i.kind.replace('core-', '') + ' update', 'warn')] : null),
          h('td', {}, i.status === 'inactive' ? badge('switched off', '') : null))), ''))),
      unchecked.length ? h('div', { class: 'note', text: 'Could not check: ' + unchecked.map(s => s.site).join(', ') }) : null);
  }

  async function viewUpdates() {
    let state = (await api('/api/updates')).data;
    const holder = h('div', {}, renderUpdates(state));
    const button = h('button', { class: 'btn primary', type: 'button', text: 'Look for updates' });
    const poll = async () => {
      clearInterval(S.pollTimer);
      S.pollTimer = setInterval(async () => {
        if (S.view !== 'updates') { clearInterval(S.pollTimer); return; }
        state = (await api('/api/updates')).data;
        holder.replaceChildren(renderUpdates(state));
        if (state.status !== 'running') { clearInterval(S.pollTimer); button.disabled = false; }
      }, 3000);
    };
    button.addEventListener('click', async () => {
      button.disabled = true;
      const r = await act('/api/updates/refresh', {});
      state = (await api('/api/updates')).data;
      holder.replaceChildren(renderUpdates(state));
      if (state.status === 'running') poll(); else button.disabled = false;
      if (!r.ok) button.disabled = false;
    });
    if (state.status === 'running') { button.disabled = true; poll(); }
    return h('div', { class: 'stack' },
      pageHead('WP Updates', 'Updates waiting for WordPress itself, plugins and themes, website by website. This page only looks – it never installs anything.', button),
      holder,
      h('div', { class: 'note', text: 'Update from each website\'s WordPress dashboard (Dashboard → Updates), one website at a time, and look at the website afterwards. Security updates matter most. A plugin marked "switched off" is not running, but its old files can still be attacked: delete it if you do not need it.' }));
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
    const form = h('form', {}, h('div', { class: 'table-wrap' }, h('table', { class: 'numbers' },
      h('thead', {}, h('tr', {}, ['Protection', 'Block after this many wrong tries', '…within this many minutes', '…for this many minutes'].map(x => h('th', { scope: 'col', text: x })))),
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
  const VIEWS = { overview: viewOverview, advisor: viewAdvisor, blocked: viewBlocked, access: viewAccess, ports: viewPorts, headers: viewHeaders, firewall: viewFirewall, updates: viewUpdates, setup: viewSetup, settings: viewSettings };

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
