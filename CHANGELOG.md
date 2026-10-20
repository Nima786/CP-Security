# Changelog

## 0.7.1
* **The Admin access page now says what the trusted list protects.** A new card at the top lists every door that only the
  trusted addresses can open (CyberPanel, the LiteSpeed admin page, the web terminal, this panel when it is set to trusted
  addresses only, and every door you limited on the Open ports page), why each one is limited, and whether anything is running
  there. A button goes to the Open ports page to change them. The page also says that the attack blocker never bans a trusted
  address, and the server's own address in the list is explained.
* **The "never blocked" list is explained and shorter.** It starts with a plain paragraph: the attack blocker bans an address for a while
  when it keeps guessing passwords, and the addresses here are never banned. Lines with the same name become one (Cloudflare's
  twenty-odd ranges are one line with a "Show the ranges" fold-out and one "Remove all" button, and a sentence says why Cloudflare is
  there). A range like 173.245.48.0/20 is now described as what it is: a block of 4,096 addresses. IPv4 and IPv6 ranges are counted
  apart. Removing a whole group reloads the blocker once instead of once per range.

## 0.7.0
* **The Open ports page now says who uses each door and what would stop if you limited it.** Before, a door was just a
  name and a button. Now every door shows "Used by" and "If you limit it", worked out from this server itself: the real
  list of websites, whether any mailboxes or email domains exist (so the mail doors say "nothing would stop working" on a
  server without mail), the FTP accounts, and the domains the server answers DNS for. Whatever cannot be read is never guessed:
  the general sentence is used instead. A program CP-Security does not know says where it comes from (its file, folder, service
  name and owner, never its arguments, which can hold passwords).
* **A short list at the top of the page shows your trusted addresses** (with their names), a button to change the list, and a
  warning when the address you are using now is not on it.
* **Less clutter.** Doors that belong together are one line (80 and 443; 465 and 587; the two POP3 ports; the two IMAP ports). The page
  is in sections: "Worth a look", "Open to everyone", "Limited to your trusted addresses", and a folded list of the doors only this
  server can reach (nothing to decide). The tags that said "Normal server service", the repeated "anybody on the internet can try to
  reach it" sentence and the long grey paragraph are gone. Buttons say what they do: "Limit to trusted addresses" and "Open to
  everyone". Limiting a grouped door limits all its ports together; the dialog shows who gets through and what would change.

## 0.6.2
* **Plugins that only start inside the WordPress admin area are found.** Some plugins begin with "if this is not the admin
  area, do nothing", and several of them are the ones that fetch their own updates (Admin Columns Pro, JetEngine). From the
  command line WordPress is never "inside wp-admin", so they stayed silent and their updates never showed up here, although the
  website's own Plugins page showed them. Looking (and updating, when the plain way finds nothing) now first lets WordPress
  believe it is inside wp-admin, as the Dashboard > Updates page does, and falls back to the plain way if a plugin cannot cope.
  On the real server this showed Admin Columns Pro on three websites and JetEngine on one that were missing before.
  Looking still installs nothing.

## 0.6.1
* **After an update, the page now shows the true list.** The page read the list of what is still waiting the moment the
  updates said "finished", but the list was only read again after that, so the item just updated was still shown. The
  updates now count as finished only after the list was read again (the card says "Checking again what is still waiting").
* **Plugins that are not on WordPress.org are found** (WPCodeBox, BricksExtras, Perfmatters and similar, which update from
  their maker's own server). Looking used to ask WordPress with every plugin switched off, and such plugins only speak when
  they are loaded and an administrator asks. Looking now does what the website's own Dashboard > Updates page does: it
  asks again first (WordPress.org and the plugin makers), then reads the lists with the plugins loaded, as an administrator.
  Nothing is installed by looking. If a website's plugin will not load, that website falls back to the WordPress.org list and the page
  says "Only partly checked". Updating such a plugin is tried the plain way first and then once the way the Dashboard does it.
  Found on the real server: three updates that were invisible before.
* **Check again** on every website: reads that one website again in a few seconds, for example after you updated something in
  WordPress yourself. Each website also shows when it was last looked at.
* A failed update now shows the real cause (the website's own "Warning" line, such as an unauthorised download) with a plain-words
  hint when it looks like a licence problem, and removes a leftover "upgrading" marker that a killed update could leave behind.
* A stray invisible character printed by one website no longer makes the panel throw that website's list away.
* WP-CLI's own cache files now go into the website's home folder, not into its public folder.

## 0.6.0
* **Update plugins and themes by hand, from the panel (WP Updates page).** Nothing ever updates by itself: a person picks
  an item and confirms. One item at a time, in the background, with a progress card. For each one: the website must
  answer normally first (otherwise nothing is touched); a copy of the plugin or theme folder is saved in the website's
  own `cps-backups` folder, and once per website a copy of its database; WP-CLI does the update as the website's own
  user (never root); the home page (with a fresh address, so the cache cannot answer) and the login page are asked
  again; if the site stops answering or shows a PHP crash, the saved copy is put back and the site is checked again.
  The cache is cleared after a good update. The last 3 copies are kept. If an update fails, the message says why and
  links to the website's own update page for a manual update. Plugins such as shops, payments and page builders are
  marked "careful". There is deliberately no "update everything everywhere" button and no WordPress core update.
  Limits, said plainly in the panel: putting the old files back cannot undo changes an update made to the database
  (that is what the database copy is for), and plugins that need a licence may have to be updated by hand.
* **"Refused in the last hour"** on the Server firewall page: which ports the firewall turned visitors away from, how
  often, and an "Allow this port" button. Counts restart when the firewall is reloaded.
* **Open ports is firewall-aware.** A port the server firewall refuses now says so ("Refused by the server firewall")
  instead of looking open, and one that is allowed says it is allowed by the firewall's list.
* The Advisor, the terminal menu and the command-line help no longer say the panel "never installs": they say that
  updating is done one item at a time in the panel.

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
