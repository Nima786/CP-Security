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
  const S = { me: null, csrf: '', view: 'overview', problems: 0, drawId: 0, pollTimer: null };

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
      field('code', '6-digit code from your authenticator app', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]*', maxlength: 8, required: true }),
      error,
      h('button', { class: 'btn primary', type: 'submit', text: 'Sign in', style: 'width:100%' }));
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      error.textContent = '';
      const btn = $('button', form); btn.disabled = true;
      const { data } = await api('/api/login', { method: 'POST', body: {
        username: $('#username').value, password: $('#password').value, code: $('#code').value } });
      btn.disabled = false;
      if (data.ok) { await boot(); } else { error.textContent = data.message || 'Could not sign in.'; $('#code').value = ''; }
    });
    return h('div', { class: 'login' }, h('div', { class: 'card' },
      h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), 'CP-Security'),
      h('p', { class: 'muted', text: 'Sign in to look after your server.' }), form));
  }

  // ------------------------------------------------------------------ the frame around every page
  // id, long name, icon, short name for the phone's bottom bar
  const NAV = [
    ['overview', 'Overview', 'overview', 'Overview'], ['blocked', 'Blocked', 'blocked', 'Blocked'],
    ['access', 'Admin access', 'access', 'Access'], ['firewall', 'Web firewall', 'firewall', 'Firewall'],
    ['updates', 'Updates', 'updates', 'Updates'], ['settings', 'Settings', 'settings', 'Settings'],
  ];

  function shell(main) {
    const small = matchMedia('(max-width:900px)').matches;
    const nav = h('nav', { class: 'nav', 'aria-label': 'Main' }, NAV.map(([id, label, ic, short]) =>
      h('a', { href: '#/' + id, 'aria-current': S.view === id ? 'page' : null },
        icon(ic), h('span', { text: small ? short : label }),
        id === 'overview' && S.problems ? h('span', { class: 'dot', title: S.problems + ' need attention' }) : null)));
    const signOut = () => h('button', { class: 'btn small', type: 'button', text: 'Sign out', onclick: async () => {
      await api('/api/logout', { method: 'POST', body: {} }); S.me = null; draw(); } });
    return h('div', {},
      h('div', { class: 'topbar' }, h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', width: 28, height: 28, alt: '' }), 'CP-Security'),
        h('span', { class: 'right' }, signOut())),
      h('div', { class: 'shell' },
        h('aside', { class: 'side' }, h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), 'CP-Security'), nav,
          h('div', { class: 'foot small muted' }, h('div', { text: 'Signed in as ' + S.me.user }),
            S.me.demo ? h('div', { text: 'DEMO – made-up data' }) : null,
            h('div', { class: 'row', style: 'margin-top:.5rem' }, signOut()))),
        h('main', { class: 'main', id: 'main' }, main)));
  }

  function pageHead(title, sub, ...actions) {
    return h('div', { class: 'page-head' }, h('div', {}, h('h1', { text: title }), sub ? h('div', { class: 'sub', text: sub }) : null),
      h('div', { class: 'right row' }, actions));
  }

  // ------------------------------------------------------------------ overview
  async function viewOverview(refresh) {
    const { data } = await api('/api/overview' + (refresh ? '?refresh=1' : ''));
    S.problems = data.problems || 0;
    const ok = S.problems === 0;
    const sites = data.sites || { sites: [], new_problems: [], old_problems: [] };
    const sorted = sites.sites.slice().sort((a, b) => Number(a.ok) - Number(b.ok) || a.domain.localeCompare(b.domain));
    return h('div', { class: 'stack' },
      pageHead('Overview', 'Checked ' + data.checked_at, h('button', { class: 'btn', type: 'button', text: 'Check again', onclick: () => redraw(true) })),
      h('div', { class: 'banner ' + (ok ? 'ok' : 'bad') }, icon(ok ? 'check' : 'alert'),
        h('div', {}, h('div', { text: ok ? 'Everything looks fine' : S.problems + ' thing' + (S.problems > 1 ? 's' : '') + ' need attention' }),
          h('div', { class: 'sub', text: ok ? 'The protections are on and your websites are answering.' : 'Look at the items marked in red below.' }))),
      h('div', { class: 'grid tiles' },
        tile('Blocked in the last 24 hours', data.blocked_24h),
        tile('Web firewall', data.waf_mode ? MODES[data.waf_mode] : 'Not set up'),
        tile('Websites answering', sites.normal + ' of ' + sites.total)),
      h('div', { class: 'grid' }, data.rows.map(r =>
        h('div', { class: 'card status-row' }, h('span', { class: 'dot-s ' + r.status, 'aria-hidden': 'true' }),
          h('div', {}, h('div', { class: 'what', text: r.label }), h('div', { class: 'text', text: r.text }))))),
      h('section', { class: 'card flush' },
        h('div', { class: 'card-head' }, h('h2', { text: 'Websites' }),
          sites.new_problems.length ? badge(sites.new_problems.length + ' new problem' + (sites.new_problems.length > 1 ? 's' : ''), 'bad') : badge('no new problems', 'ok')),
        table(['Website', 'Answer'], sorted.map(s => {
          const old = sites.old_problems.some(o => o.domain === s.domain);
          return h('tr', {}, h('td', { class: 'mono', text: s.domain }),
            h('td', {}, badge(s.code === '000' ? 'no answer' : s.code, s.ok ? 'ok' : 'bad'), old ? h('span', { class: 'muted small', text: '  already like this before' }) : null));
        }), 'No websites found.')));
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
      h('details', { class: 'card' }, h('summary', { text: 'Never blocked by the attack blocker (' + data.never_block.length + ')' }),
        h('p', { class: 'muted small', text: 'Cloudflare and similar services. Blocking one of their addresses would cut off many real visitors.' }),
        h('div', { class: 'stack' }, data.never_block.map(n => h('div', { class: 'row' }, h('span', { class: 'mono', text: n.address }), h('span', { class: 'muted', text: n.label }))))));
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
      return h('div', { class: 'stack' }, pageHead('Web firewall'), card(null, h('p', { text: 'The web firewall is not set up on this server yet.' })));
    }
    const sum = data.summary, day = sum.periods.day, week = sum.periods.week;
    const periodCard = (title, p) => h('section', { class: 'card' }, h('h2', { text: title }),
      h('p', {}, h('strong', { text: String(p.requests) }), ' suspicious requests from ', h('strong', { text: String(p.addresses) }), ' addresses',
        data.mode === 'block' ? [', ', h('strong', { text: String(p.blocked) }), ' blocked'] : ' (nobody refused)'),
      p.rules.length ? h('div', { class: 'stack' }, p.rules.slice(0, 5).map(r => h('div', { class: 'row' }, h('span', { class: 'small', text: r.message }), h('span', { class: 'right' }, badge(String(r.count)))))) : h('p', { class: 'muted', text: 'Nothing recorded.' }));
    return h('div', { class: 'stack' },
      pageHead('Web firewall', 'Watches the requests to your websites for typical hacking attempts (SQL injection, scripts, file tricks).'),
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

  // ------------------------------------------------------------------ updates
  function renderUpdates(state) {
    const sites = state.sites || [];
    const withItems = sites.filter(s => s.items.length);
    const unchecked = sites.filter(s => !s.checked);
    if (state.status === 'running') return card(null, h('div', { class: 'row' }, h('div', { class: 'spinner', style: 'margin:0' }), h('span', { text: 'Looking at every WordPress site… this takes a minute.' })));
    if (state.status === 'idle') return card(null, h('p', { class: 'muted', text: 'Press "Look for updates" to see which sites are behind.' }));
    if (state.status === 'failed') return card(null, h('p', { class: 'error', text: 'Looking failed: ' + (state.error || 'unknown reason') }));
    return h('div', { class: 'stack' },
      h('div', { class: 'banner ' + (withItems.length ? 'warn' : 'ok') }, icon(withItems.length ? 'alert' : 'check'),
        h('div', {}, h('div', { text: withItems.length ? withItems.length + ' site(s) have updates waiting' : 'No updates are waiting' }), h('div', { class: 'sub', text: 'Looked ' + state.finished }))),
      withItems.map(s => h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { class: 'mono', text: s.site }), badge(s.items.length + ' waiting', 'warn')),
        table(['What', 'From', 'To'], s.items.map(i => h('tr', {}, h('td', { text: i.what }), h('td', { class: 'mono', text: i.from || '–' }),
          h('td', {}, h('span', { class: 'mono', text: i.to }), i.kind.startsWith('core-') ? [' ', badge(i.kind.replace('core-', '') + ' update', 'warn')] : null))), ''))),
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
      pageHead('Updates waiting', 'WordPress, plugins and themes that are behind. This page only looks – it never installs anything.', button),
      holder,
      h('div', { class: 'note', text: 'Update from each site\'s WordPress dashboard (Dashboard → Updates), one site at a time, and look at the site afterwards. Security updates matter most.' }));
  }

  // ------------------------------------------------------------------ settings
  async function viewSettings() {
    const [{ data: s }, { data: act_ }] = await Promise.all([api('/api/settings'), api('/api/activity')]);
    let access = s.access;
    const accessCard = card('Who can reach this panel',
      h('div', { class: 'choices' }, [['login', 'Anyone with the login', 'The login page is open to everyone, protected by your password and the 6-digit code. Best if your home address changes.'],
        ['trusted', 'Trusted addresses only', 'Other addresses cannot even see the login page. Most secure, but you need the trusted list to be right.']].map(([v, t, d]) =>
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

    const tfaBox = h('div', { class: 'stack' });
    const tfaStart = h('form', { class: 'inline-form' }, field('tf-pw', 'Your password', { type: 'password', autocomplete: 'current-password', required: true }),
      h('button', { class: 'btn', type: 'submit', text: 'Get a new key' }));
    tfaStart.addEventListener('submit', async ev => {
      ev.preventDefault();
      const { data } = await api('/api/settings/2fa/start', { method: 'POST', body: { password: $('#tf-pw').value } });
      if (!data.ok) { toast(data.message, 'bad'); return; }
      const confirmForm = h('form', { class: 'inline-form' }, field('tf-code', 'Code from the app', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, maxlength: 8 }),
        h('button', { class: 'btn primary', type: 'submit', text: 'Confirm' }));
      confirmForm.addEventListener('submit', async e2 => {
        e2.preventDefault();
        const r = await act('/api/settings/2fa/confirm', { code: $('#tf-code').value });
        if (r.ok) tfaBox.replaceChildren(h('p', { class: 'muted', text: 'Done.' }));
      });
      tfaBox.replaceChildren(h('p', { text: 'Type this key into your authenticator app (choose "time based"):' }),
        h('p', { class: 'mono', style: 'font-size:1.1rem;word-break:break-all', text: data.secret.match(/.{1,4}/g).join(' ') }), confirmForm);
    });
    tfaBox.append(tfaStart);

    return h('div', { class: 'stack' },
      pageHead('Settings', 'Signed in as ' + s.user + '. Version ' + s.version + '.'),
      accessCard,
      h('div', { class: 'grid' }, card('Change password', pwForm), card('Authenticator app', h('p', { class: 'muted', text: 'Lost your phone or changed it? Get a new key for the 6-digit codes. The old key stops working.' }), tfaBox)),
      h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', { text: 'Recent activity' })),
        table(['When', 'What', 'Details'], act_.events.map(e => h('tr', {}, h('td', { class: 'mono small', text: e.when }), h('td', {}, badge(e.event.replace(/_/g, ' ').toLowerCase(), /FAIL|ERROR/.test(e.event) ? 'bad' : '')), h('td', { class: 'mono small muted', text: e.details }))), 'Nothing yet.')));
  }

  // ------------------------------------------------------------------ drawing
  const VIEWS = { overview: viewOverview, blocked: viewBlocked, access: viewAccess, firewall: viewFirewall, updates: viewUpdates, settings: viewSettings };

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

  async function boot() {
    const { data } = await api('/api/me');
    if (data.authenticated) { S.me = data; S.csrf = data.csrf; } else { S.me = null; }
    draw();
  }

  window.addEventListener('hashchange', () => draw());
  boot();
})();
