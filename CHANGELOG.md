# Changelog

## 0.3.0
* **Update from the panel.** The version number is shown at the top of every page with "up to date" or "update
  available". "Check for updates" asks GitHub; "Update now" downloads the release, checks its fingerprint, tests the new
  program files, switches to them and restarts the panel. If the new version does not start, a helper started by
  systemd puts the old one back by itself. The same from the terminal: `security update`.
* **WP Updates** (was "Updates"): lists plugins, themes and WordPress itself, website by website, with the version now
  and the version it goes to, whether the plugin is switched off, and which updates are waiting on several websites at once.
* **Faster Overview.** The page appears at once; the websites are asked in the background (every 5 minutes, or
  with "Check again") instead of making you wait 4 to 10 seconds.
* After an update the system files that depend on the program (service files, blocker filters) are refreshed too.

## 0.2.2
Found by checking the first real installation:
* **Fix:** the WordPress login watcher read no logins at all, because CyberPanel's LiteSpeed writes the request without
  quotes. It now accepts both forms (tested with lines copied from the real server).
* **Fix:** after installing, the SSH protection logged attackers but had lost its ban action (a fail2ban 0.11 reload
  problem), so nobody was really blocked. The blocker now checks every protection after each reload and restarts
  once to repair it; the overview and the Advisor warn if it ever happens again and offer a repair button.
* **Fix:** the admin-lock service is now started, not only enabled (it showed as inactive).

## 0.2.1
* **Fix:** the panel crashed on start-up (a mix-up of two names in the start-up code). Found on the first real
  install. New tests now start the panel for real over HTTPS and call every page's data from the live engine.
* The panel falls back to IPv4 when the server has IPv6 switched off.
* Re-running the installer replaces the old program files and restarts the panel, so it always runs the newest version.
* A code checker (pyflakes) now runs with the automatic tests.

## 0.2.0
* **OpenLiteSpeed** support next to LiteSpeed Enterprise (one hook line in each server's own file; CyberPanel's
  files are otherwise untouched). Tested against pretend file trees only so far.
* **Advisor**: notices CyberPanel's own ModSecurity rules, Imunify, CSF/LFD, other fail2ban jails, Cloudflare,
  SSH settings, open databases, OS and WordPress updates, certificate expiry; safe one-click fixes.
* **Setup** with a readable plan, progress, rollback; takes over the earlier hand-made setup.
* **Installer** (`install.sh`): sub-domain, port, Let's Encrypt via CyberPanel, username + password, trusted addresses.
* Login is now username + password; the authenticator code is optional (Settings).
* The panel opens only from trusted addresses by default.
* New panel pages: Advisor, Setup. Settings gained attack-blocker numbers, never-block list, saved baseline.
* Web firewall: self-test, own settings folder, no clash with CyberPanel's rule packs.
* Login watcher service (copies failed WordPress logins for the blocker), included in the repository.
* Numbered releases: the installer downloads a release (not the main branch) and verifies its checksum.
* CyberPanel's own rule pack, when installed but switched off, is set aside (reversibly) instead of blocking the web firewall.
* The earlier hand-made setup's trusted addresses, lists and lock are taken over.

## 0.1.0
* First version of the engine as a library (admin access, attack blocker views, web firewall, sites, updates, health).
* Terminal menu with the same screens as the hand-built version.
* OWASP rule converter for the LiteSpeed engine.
* Browser panel: login, overview, blocked addresses, admin access, web firewall, updates, settings; demo mode.
