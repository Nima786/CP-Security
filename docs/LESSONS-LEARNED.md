# Lessons learned on the production server

Things that cost hours to discover. They explain several design choices, so they are written down.

## The incident
* A critical unauthenticated file-upload flaw in the **Bricksforge** WordPress plugin (CVE-2026-85097, versions up to
  3.1.8.9, fixed in 4.0.x) was used on 8 October to plant PHP web shells, then to take over the whole server.
* The attacker installed a memory-only backdoor disguised as a kernel thread, a fake systemd unit that started it at
  boot, a second remote-control agent, a SUID helper and a re-infecting "cache" must-use plugin. Restoring a snapshot
  restored the backdoors too, because they pre-dated it.
* Fixing it meant: kill and quarantine the backdoors, remove the web shells, update the plugin everywhere, lock the
  admin ports, then add the layers in this project.

## fail2ban 0.11.2 (Ubuntu 22.04)
* The date detector **crashes with `IndexError`** on some web-server log lines (attack payloads containing line breaks
  produce short continuation lines). A crashed filter thread silently stops protecting.
  → WordPress logins are not read from the site logs directly. A small service copies only well-formed
  `POST /wp-login.php` lines into one tidy file (`/var/log/cps-wp-login.log`) that fail2ban reads.
* The jail needs an explicit `datepattern`, and the failregex must not depend on the brackets around the date.
* Package install does not enable the service: `systemctl enable --now fail2ban`.
* Ban actions: `nftables-multiport` / `nftables-allports`.

## nftables
* iptables on this system is the nf_tables variant; rules from `iptables` and from `nft` coexist.
* The admin lock is its own table at hook priority -1 so it is evaluated before everything else and cannot be
  undone by other firewall tools. Test it from an address that is **not** on the list – the person running the
  tests is usually on the list.

## LiteSpeed Enterprise web firewall (ModSecurity engine)
* The server reads the Apache-style config (`httpd.conf` → `modsec.conf`). Rules added to the XML config are ignored.
* **Tests were masked by LiteSpeed's page cache.** A cached response is never scanned. Every test request needs a
  brand-new URL (random path) or it proves nothing.
* `SecAuditEngine On` records only requests that matched a rule (not all traffic); `RelevantOnly` recorded nothing.
* Rule engine quirk: **after the first `skipAfter` the remaining rule files never run.** The OWASP files use
  `skipAfter` to hide their stricter paranoia levels, so only the first file worked. `cpsec.crs_convert` cuts the
  stricter levels out and removes the skip instructions. The start-up file (901) is kept as it is.
* Do not include `REQUEST-905-COMMON-EXCEPTIONS.conf`: it switches the engine off for local requests.
* `DetectionOnly` records nothing on this engine. Watch-only = engine **On** without a blocking rule.
* `SecRuleEngine`, `ctl:ruleRemoveById` and `ctl:ruleEngine=Off` work, so per-site exceptions are possible.
* Blocking uses one small rule (`TX:ANOMALY_SCORE_PL1 >= threshold`), not CRS file 949: the scores accumulate in
  `anomaly_score_pl1`, not in `anomaly_score`, and the stock rule depends on macro expansion that this engine does
  not do reliably. The threshold is a plain number, so an unset value can never block everything.
* The audit log holds request headers (cookies!). Keep it `0600`, owned by the web server user.
* Do not add a logrotate rule for the audit log. LiteSpeed Enterprise rolls it itself (10 MB pieces, `keepDays` 30), and Ubuntu's
  `logrotate.service` runs with `ProtectSystem=full`, so `/usr/local/lsws/logs` is read-only to it: the rule fails every night and
  marks the whole clean-up as failed. The copies stay private because `/usr/local/lsws/logs` is `0750 root:nobody`.

## Found by checking the first real installation
* fail2ban 0.11: when a reload changes the ban action of a protection that already exists (the Ubuntu default
  `iptables-multiport` becomes `nftables-multiport`), that protection can end up with **no action at all**. The log
  then says "already banned" again and again while nothing is blocked, and the blocker's own firewall table is
  missing. `fail2ban-client get <jail> actions` answering "No actions for jail" is the tell-tale; a restart repairs it
  and the earlier bans are restored from the blocker's database.
* CyberPanel's LiteSpeed writes access-log lines WITHOUT quotes around the request:
  `1.2.3.4 - - [19/Oct/2026:08:46:15 +0100] POST /wp-login.php HTTP/2 401 1469 …`. A pattern that insists on the quotes
  silently reads nothing. Always test a log reader against lines copied from the real server.
* A failed WordPress login is answered 200 (form shown again) or 401; a good one 302.
* A tool that "has been installed" is not the same as one that works: check the result the way an attacker would
  see it (send harmless attack-looking requests, look at what was recorded).

## Reading what commands print
* Python's `subprocess` in text mode is strict by default: one byte that is not valid text (a picture fetched with curl to check it
  loads) raises an error instead of returning. `util.run` therefore replaces odd bytes. A check that only needs the answer code should
  ask curl for the code alone (`-o /dev/null -w %{http_code}`), never read the body.

## Operational
* Run LiteSpeed changes with a graceful restart (`lswsctrl restart`) and a check of several sites afterwards.
* CyberPanel regenerates `httpd.conf` and `modsec.conf` from its own pages. Never save the ModSecurity page there.
* Do not run commands in parallel from the same terminal session when scripting the server – output got mixed up and
  uploads raced. Long jobs: start in the background on the server and poll.

## CyberPanel and OpenLiteSpeed (from CyberPanel's own source, `plogical/modSec.py`)
* Where each web server keeps ModSecurity settings differs: LiteSpeed Enterprise uses `conf/modsec.conf` and
  `conf/rules.conf`; OpenLiteSpeed uses a `module mod_security { … }` block in `conf/httpd_config.conf`, rule files
  listed with `modsecurity_rules_file`, and the module file `modules/mod_security.so` (package `ols-modsecurity`).
* CyberPanel's ModSecurity page edits those files **by searching for text** (`modsecurity `, `SecRuleEngine `,
  `SecAuditEngine `, …) and rewriting the matching lines. Our hook line contains none of those words on purpose, and
  our own settings are in a separate file so a save on that page cannot change them.
* CyberPanel's OWASP and Comodo rule packs add many `modsecurity_rules_file` lines (OLS) or a rules folder
  (Enterprise). They use the same rule numbers as the OWASP rules we load, so both must never be active together.
* The program decides "OpenLiteSpeed or Enterprise" by the existence of `bin/openlitespeed`. We use the same test.
* Creating a site and its certificate from the command line: `cyberpanel createWebsite --package Default --owner admin
  --domainName … --email … --php 8.1`, then `cyberpanel issueSSL --domainName …`. Certificates land in
  `/etc/letsencrypt/live/<domain>/`.
* CyberPanel's firewall page uses firewalld. An open port there is not enough for a locked port: our nftables table
  decides who may use it, firewalld decides whether it is reachable at all. Both must allow.

## Cloudflare
* With the orange cloud on, only ports 443, 2053, 2083, 2087, 2096 and 8443 are passed through. A panel on any other
  port is unreachable through it. "DNS only" (grey cloud) has no such limit.
* The web server sees Cloudflare's addresses instead of the visitor's unless it is told to read the real address
  from Cloudflare's header. The blocker would then block Cloudflare itself, which is why Cloudflare's ranges are on
  the never-block list and the Advisor offers to add them.
## .htaccess and headers (LiteSpeed Enterprise)
* LiteSpeed re-reads a changed `.htaccess` only about every 5 seconds (measured: 4.2 to 5.8 s on a live server). A
  check made right after writing still sees the old file and would wrongly undo a good change. Ask again for up to
  15 seconds, and compare the header VALUE, not just its presence (a website that already sent another value
  would otherwise look fine).
* `Header always set` also works on error pages and cached pages; `Header always merge` keeps a content policy the
  website already sends; `Header always unset X-Powered-By` removes the PHP label. `env=HTTPS` restricts a header to
  secure connections (used for HSTS).
* OpenLiteSpeed only understands rewrite rules in `.htaccess`; header lines there are ignored.
* The folder of a website is often owned by a shared group (`nogroup`) so the web server can read it. Run file work
  with the user's own primary group, or new files end up in the wrong group.
## Ports
* `ss -ltnp` shows the program name with the port. CyberPanel's web terminal listens on 8888 (`uvicorn`), 
  the panel itself on 8090 (`lscpd`); the LiteSpeed admin on 7080. A connection from `127.0.0.2` is a handy stand-in
  for an outsider when proving the lock, because only `127.0.0.1` is trusted on the loopback.
## CyberPanel's Firewall page
* The ON light is `systemctl status firewalld` not containing the word "dead". A missing firewalld gives "Unit
  firewalld.service could not be found", so the page says ON with nothing behind it. Rules on that page are rows in the
  `cyberpanel.firewall_firewallrules` table (root can read them with `mysql -N -e`, no password needed).
* Ubuntu's `ufw.service` can be "enabled" and active while `ufw status` says "inactive": ask `ufw status`, not systemctl.
* Test a firewall without touching live traffic: (1) `nft -c -f file` only checks the syntax; (2) a table that only
  judges one stand-in address such as 127.0.0.2; (3) best: two network namespaces joined by a veth pair, load the real file
  in one and try the ports from the other (`ip netns exec`). Replies, loopback, ping, address-limited rules and the empty
  list can all be proven that way.
* Several base chains on the same hook all judge a packet: an accept in one does not skip the others. That is why the
  admin ports must also be allowed in the firewall table, and why the admin lock stays stricter.

## Updating plugins by hand (WP-CLI)
* `wp plugin install <local zip> --force` replaces an existing plugin, keeps it switched on and keeps its settings (they are in the
  database); it creates a second folder if the zip's folder has another name (a zip packed as `name-1.2.3/`), so rename the folder first.
* Clean up only what you made: the website's `cps-backups` folder also holds the safety copies of the owner's own earlier updates.
* `cp -a` keeps the folder's old modified time, so every saved copy of one plugin looks equally old. Clean up old copies by
  the time stamp in their name, never by `ls -t`. Also match the whole name: `plugin-foo-*` also matches `plugin-foo-bar-*`.
* Run WP-CLI as the website's own user with `--skip-plugins --skip-themes`, and pick the PHP program that can start the site
  (`lsphp81` here for old sites, `lsphp83` for new ones): the system `php` is often the wrong version.
* Proved on a real server with a test site: update, check, simulated "site broke" (the old files went back and the version
  matched), a name that does not exist, a theme and an active plugin in one run (one database copy per website).
* WP-CLI with `--skip-plugins` only knows what WordPress.org knows. A plugin that updates from its maker's own server
  (plugin-update-checker, Easy Digital Downloads licensing and the like) adds its update only when it is loaded AND the
  current user may update plugins, so ask with plugins loaded and `--user=<an administrator>`. Before reading, do what
  Dashboard > Updates does: `do_action('load-update-core.php')` makes WordPress and those plugins check again (they allow
  a check every minute on that page, instead of every 12 hours), without zeroing any of their stored state.
* After `wp plugin update`, WordPress deletes its stored update list, so the next plain `plugin list --update=available`
  shows nothing for the other plugins until somebody asks again. Always ask again (the line above) before reading.
* One website printed U+FEFF (a byte-order mark from a stray file) in front of WP-CLI's CSV: strip it before looking for the header.
* The website's language is not always English (`Warning:` is, the rest may be Persian): show the website's own line,
  and match only on words like "Unauthorized" for a hint.
* A page that fetches data the moment a background job says "finished" must find the data ready: finish the follow-up
  work first, or the page shows the old state.
* Some update-capable plugins start with `if (!is_admin()) return;` (Admin Columns Pro does), so WP-CLI never loads them. Define
  `WP_ADMIN` before WordPress loads with `wp --exec="define('WP_ADMIN', true);" ...` (it runs early enough) and they speak.
  Try that first and fall back to a plain load, then to `--skip-plugins`.
