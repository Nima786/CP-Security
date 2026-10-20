# Changelog

## 0.5.0
* **Server firewall** (new page). On servers where CyberPanel's firewall program (firewalld) is not installed, CyberPanel's
  Firewall page still shows "ON" and keeps a list of rules, but nothing is enforced: its ON light only turns OFF when the
  program reports "dead", and a missing program gives a different answer. The new page tells the truth side by side with
  CyberPanel's claim, and gives a firewall that really works, with the same kind of list (name, TCP or UDP, address, port
  or range): add and remove rules, copy CyberPanel's list once, turn on, turn off, reload.
* While it is on, only the listed ports are open. Always allowed: replies to connections the server started, the server
  itself, ping, automatic network settings (DHCP), the server login and the admin pages (the admin lock still decides
  who may use those).
* **A safety net:** turning it on starts a 2-minute timer (a systemd timer, so it survives a panel restart). Unless you
  press "Keep it" the firewall switches itself off again, so a wrong list cannot lock you out for long. It only becomes
  permanent (and comes back after a restart) when you press Keep it. Opening a port, closing one, turning off and
  reloading need no such net.
* "In use but not on your list" shows what would stop working (ports with a program behind them, UDP too, and
  ports that other tools already allow in the firewall); one button adds them, and turning on offers the same.
  Closing a port that is in use asks again.
* The Advisor now says "CyberPanel's Firewall page says ON, but no firewall is running" when that is the case, and no
  longer sends people to that page. From the command line: `security serverfw status|on|off|reload|keep|undo`.

## 0.4.1
* **The "Advice for you" card on the Overview no longer blinks.** It used to appear only after the advice had been
  gathered (a few seconds), pushing the rest of the page down, and it disappeared and came back each time the page
  refreshed itself while the websites were being asked. The last advice is now shown at once, kept for the visit, and
  replaced quietly only when it really changed.

## 0.4.0
* **http:// now goes to https://.** Typing the panel's address without the "s" used to show an error. The panel now
  answers a plain-http request on its port with a permanent redirect to the same page over https. The destination is
  always the panel's own configured name, never taken from the request.
* **Security headers** (new page, LiteSpeed Enterprise). Small instructions every website sends to every visitor's browser.
  Seven are offered, each explained: file types, framing, referrer, browser features, hiding the technology label (on by
  default), the secure-address rule (HSTS, off, with a chosen time) and the gentle content rule (off). Choices apply to all
  websites or are changed for one. A block of lines is written at the top of the website's `.htaccess`; nothing else is touched.
  A header the website already sets itself is left alone unless you choose "take over" (those lines are switched off, not
  deleted, and come back when CP-Security's block is removed). After a change the website is asked for its home page; if it
  stops answering, or the web server ignores the headers, the file is put back exactly. LiteSpeed notices a changed
  `.htaccess` only every few seconds, so the check asks again for up to 15 seconds. A copy of every file is kept.
  The file work is done as the website's own user, never as root, so a link planted in a hacked site's folder
  cannot make the panel overwrite or read a system file.
* **Open ports** (new page). Lists every port a program is listening on, with a plain-English name and purpose,
  who can reach it (everyone, only trusted addresses, only this server, private network) and what CP-Security
  thinks of it. Every choice belongs to the owner: "Lock it" limits a port to the trusted addresses, "Open it up"
  undoes it (even for CyberPanel's own pages, after a warning), "I know about this" silences the advisor for a
  port that is meant to be open. Ports 80 and 443 can never be locked; the server login, mail, DNS and FTP ask
  for a confirmation first; the panel's own port stays under Settings. Choices are saved and survive restarts.
* The Advisor's old "database open to the internet" check now uses the same list, also flags unknown programs
  that are open to everyone, and points to the Open ports page.

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
