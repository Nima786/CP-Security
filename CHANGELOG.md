# Changelog

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
