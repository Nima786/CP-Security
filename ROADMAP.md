# Roadmap

Legend: ✅ done · 🚧 in progress · ⬜ not started

## M0 – Project skeleton ✅
- ✅ Repository, README, architecture notes, CI

## M1 – Engine as a library ✅
The tested logic from the hand-built server hardening, rewritten as a package that returns data instead of
printing, so a terminal menu and a browser panel can share it.
- ✅ Admin access (lists, firewall table, trusted addresses reach the blocker)
- ✅ Attack blocker views (who is blocked, let someone back in, history)
- ✅ Web firewall (modes, exceptions, what it recorded, automatic undo)
- ✅ Sites check with a saved baseline (new problems vs. old ones)
- ✅ Updates waiting (the list is read-only; updating plugins and themes by hand came in M7)
- ✅ OWASP rule converter (the LiteSpeed engine only runs the first rule file unless the stricter levels are cut out)
- ✅ Terminal menu (`security`)

## M2 – Browser panel ✅
- ✅ Login with username + password (scrypt); optional authenticator code; sessions with idle/absolute timeout, CSRF protection, per-address login lock-out
- ✅ JSON API over the engine; strict security headers; only the panel's own address answers (host check)
- ✅ Demo mode with made-up data: `security panel demo`

## M3 – Works next to CyberPanel, on both web servers ✅
- ✅ Web server detection (LiteSpeed Enterprise / OpenLiteSpeed) and one-line hook into each one's own settings file
- ✅ Web firewall keeps its own settings in its own folder (engine switch, log settings, rule list)
- ✅ Never doubles up with CyberPanel's OWASP/Comodo rule packs or Imunify
- ✅ **Advisor**: CyberPanel ModSecurity, Imunify, CSF/LFD, other fail2ban jails, firewalld/ufw, Cloudflare, SSH, OS updates, open databases, certificate, WordPress updates, panel exposure
- ✅ Firewall self-test (a harmless attack-looking request must appear in the log, else the firewall is taken out again)
- ✅ Blocker numbers (tries, window, block time per protection) editable in the panel
- ✅ Never-block list editable; one-click Cloudflare preset

## M4 – Installer and setup ✅
- ✅ `install.sh` / `security install`: asks for sub-domain, port, email, username, password, trusted addresses; checks DNS and Cloudflare
- ✅ Let's Encrypt certificate through CyberPanel's own command line; opens the port in firewalld/ufw; renewed certificates are picked up without a restart
- ✅ Setup steps with a readable plan, progress page, log, rollback on failure: admin lock, attack blocker, login watcher, baseline, web firewall
- ✅ Takes over the earlier hand-made setup (lists and settings copied; old services, jails and firewall table moved to a dated backup folder only once the new ones are live)
- ✅ Panel: Advisor, Setup, Settings pages; phone menu with a "More" sheet
- ✅ `uninstall.sh` / `security uninstall` (panel only by default; protections and lock only on their own yes)

## M5 – Prove it on real servers 🚧
- 🚧 Install on the first production server (LiteSpeed Enterprise) and migrate the hand-built setup
- ⬜ Run on a live **OpenLiteSpeed** server and fix whatever the pretend file trees missed
- ⬜ AlmaLinux / Rocky check (log paths, dnf packages, firewalld)
- ⬜ WordPress exclusion rules for the web firewall (fewer false alarms in wp-admin)

## M6 – Hardening and release 🚧
- ✅ Release workflow: a tag like `v0.2.0` builds the files, runs the tests and publishes them with checksums; the installer uses only these
- ✅ Update from the panel (fetch the newest release, verify its checksum, restart, roll back if it does not start)
- ✅ Typing `http://` for the panel redirects to `https://`
- ⬜ Security review of the panel (headers, input validation, privilege separation)

## M7 – More protection, all of it visible and switchable 🚧
Rule for everything here: explained in plain words, shown on a page, and the owner can switch it on or off
(for all websites or for one), because other servers have other needs.
- ✅ Open ports: every listening port, what it is, who uses it today and what would stop if it were limited (from the server's real websites, mailboxes, FTP accounts and domains); limit to trusted addresses, open again, or "I know about this"
- ✅ Server firewall: tells the truth about CyberPanel's Firewall page, and a firewall that really works (list of ports, TCP/UDP, addresses; on, off, reload; a 2-minute "Keep it" safety net)
- ✅ Security headers (LiteSpeed Enterprise): a safe set on by default, the risky ones off; per website; takes over a site's own
  header lines only on request and gives them back on removal; checks the live answer and undoes the change if a website stops answering
- ✅ Manual plugin and theme updates: one item at a time, started by a person (never automatic). The website must answer first; a copy of the
  folder and, once per website, of the database are saved; WP-CLI updates it as the website's own user; the website is asked again and the
  old copy goes back if it does not answer or shows a PHP crash. Limits: a database change made by an update is not undone by putting files
  back, licensed plugins may need a manual update, and WordPress core is not updated from here
- ✅ Update by uploading a zip: for paid or custom plugins and themes. Upload once (kept on the server until you delete it), see which websites have the plugin and their versions, tick the ones to update; same safe routine, one at a time, several files in one run
- ✅ "Refused in the last hour" on the Server firewall page (which ports the firewall turned away, with an "Allow this port" button);
  the Open ports page now says when the server firewall is what refuses a port
- ✅ One-click admin login: "Open admin" per website, a signed link that works once for one minute, through a small tested helper file installed only on request (works with custom login addresses; skips a website's own 2-step login)
- ⬜ Security headers on OpenLiteSpeed (its `.htaccess` ignores header lines, so they go into the virtual host instead)
- ✅ Block PHP in uploads folders (per website, proved with a harmless test file, put back if the website gets worse)
- ⬜ Hide backups, logs and other sensitive files (per website, with a self-test)
- ⬜ Daily scan for backdoors and changed WordPress files
- ⬜ Known-vulnerable plugin and theme check
- ⬜ Alerts (Telegram / email) for new backdoors, a blocker or website going down, certificate expiry
- ⬜ Off-server backups and a freshness check
- ⬜ Switching the web firewall from watching to blocking, with WordPress exclusion rules
