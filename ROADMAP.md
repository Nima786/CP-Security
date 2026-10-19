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
- ✅ Updates waiting (read-only)
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
- ⬜ Update from the panel (fetch the newest release, verify its checksum, restart)
- ⬜ Security review of the panel (headers, input validation, privilege separation)
