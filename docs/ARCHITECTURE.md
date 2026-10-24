# Architecture

## Goals
* A non-programmer owner can see the state of the server's protection and change it safely.
* Nothing the tools do can leave the server worse than it was: every change is validated, applied, verified and
  undone automatically when verification fails.
* Never fight CyberPanel or another security tool: look first, advise, and keep our own files separate.
* No dependencies to install on the server: Python 3.10+ standard library only.

## Layers

```
 browser ──HTTPS──► panel (cpsec.panel)  ─┐
 terminal ─────────► menu  (cpsec.menu)  ─┼──►  engine  ──► fail2ban · nftables · LiteSpeed/OLS · WP-CLI · CyberPanel CLI
 install.sh ───────► installer            ─┘
```

* **Engine** – plain functions. They read and write the real files and run the real commands, and return data or a
  `Result(ok, message, code)`. They never print and never read the keyboard. Every path goes through `cpsec.config.P`
  and every command through `cpsec.util.run`, which is how the tests replace the whole server.
* **Terminal menu / installer** – format engine data as numbered screens and questions.
* **Panel** – an HTTPS server (standard library) with its own login. Same engine, JSON instead of text.

### Engine modules

| Module | Job |
|---|---|
| `webserver` | Detects LiteSpeed Enterprise vs OpenLiteSpeed; adds/removes the one hook line; notices CyberPanel's rule packs |
| `waf` | Web firewall modes, exceptions, what it recorded, self-test; writes our `cps-waf/main.conf` |
| `access` | Trusted-address list, the admin lock (nftables), the never-block list |
| `blocker` | fail2ban: who is blocked, our filters and jails, the numbers per protection |
| `feed` | The login watcher service: failed WordPress logins into one tidy file |
| `advisor` | Reads the whole server and says what to do; the few safe fixes |
| `provision` | Setup steps (plan → run → rollback), the job runner, takeover of the earlier hand-made setup |
| `tls`, `netinfo` | Certificate lookup/issue through CyberPanel, expiry, firewalld/ufw port; DNS and Cloudflare checks |
| `installer` | The question-and-answer installer and uninstaller |
| `sites`, `updates`, `health`, `settings` | Website checks with a baseline, WordPress updates (read-only), overview, panel settings |

## Two web servers, one firewall file

CyberPanel keeps ModSecurity settings in different places:

| | LiteSpeed Enterprise | OpenLiteSpeed |
|---|---|---|
| Detected by | `conf/httpd_config.xml` / `bin/litespeed` | `bin/openlitespeed` (same rule CyberPanel uses) |
| ModSecurity settings | `conf/modsec.conf` | `module mod_security { … }` block in `conf/httpd_config.conf` |
| Our hook (one line) | `Include …/cps-waf/main.conf` inside `<IfModule security2_module>` | `modsecurity_rules_file …/cps-waf/main.conf` inside the module block |
| Needs | `modsec.conf` present | `modules/mod_security.so` and the block (CyberPanel installs both) |

Everything else lives in `…/conf/cps-waf/`: `main.conf` (engine on/off, audit-log settings, include of
`rules.conf`), `rules.conf` (setup, per-site exceptions, the OWASP files in order, our blocking rule, global
exceptions), `crs/` (the pinned, converted rule files). The on/off switch is in **our** file, read last, so
CyberPanel's ModSecurity page cannot silently undo it (the Advisor explains this).

OLS caveat: written from CyberPanel's source and documentation; covered by tests with pretend file trees, not yet by
a live OpenLiteSpeed server. That is why the install step proves itself with a self-test and rolls back.

## Setup steps

`provision.plan()` reports each step as `done`, `todo`, `blocked` or `skip` without changing anything. Steps, in
order: `migrate`, `lock`, `blocker`, `feed`, `baseline`, `waf`, `retire`. Each is safe to run again. The `waf`
step snapshots every file it touches, restarts the web server, checks sample websites, sends a test attack, and
restores everything if any of that fails. `retire` moves the old hand-made setup into a dated folder, never deletes,
and only runs once the new lock, blocker, login watcher and firewall are live.

## Safety rules (apply to every new feature)
1. **Validate before writing.** Addresses, host names and rule numbers are checked against strict patterns before they
   reach a command line or a rule file.
2. **Check before loading.** nftables and fail2ban configurations are tested (`nft -c`, `fail2ban-client -t`) before use.
   A protection whose log file does not exist is left out, because fail2ban refuses to start otherwise.
3. **Verify after changing the web server.** Restart gracefully, check a sample of websites, restore the old files if
   any site stops answering.
4. **Never lock the owner out silently.** Removing the address you are connecting from asks for confirmation; the
   last trusted address cannot be removed; the installer insists on at least one trusted address.
5. **No secrets in the repository.** Passwords are stored as scrypt hashes, the TOTP secret and TLS key stay in
   `/etc/cp-security` (root only). Downloads are pinned to a version and checked against a fingerprint.
6. **Changes wait for setup.** While the Setup job runs, other changing actions answer "busy".

## Where things live on the server

| What | Path |
|---|---|
| Settings and lists | `/etc/cp-security/` (`admin-access.list`, `never-block.list`, `blocker.json`, `site-baseline.json`, `panel.json`, `waf-*.json`) |
| Admin lock rules | `/etc/cp-security/admin-lock.nft` (table `inet cps_lock`, service `cps-admin-lock`) |
| Blocker config | `/etc/fail2ban/jail.d/cps-jails.local`, `cps-never-block.local`, `/etc/fail2ban/filter.d/cps-*.conf` |
| Login watcher | service `cps-wplogin-feed`, log `/var/log/cps-wp-login.log` |
| Web firewall | `/usr/local/lsws/conf/cps-waf/`, one line in `modsec.conf` or `httpd_config.conf` |
| Panel | code `/opt/cp-security/`, service `cp-security-panel`, log `/var/log/cp-security/panel.log` |
| Command | `/usr/local/sbin/security` |

## Decisions
* **Python, not Go.** The server already has Python 3.10, the hardening logic already existed and was tested in
  Python, and there is no build step or binary to ship.
* **Panel access defaults to trusted addresses only.** The panel port joins the admin lock, so strangers cannot even
  see the login page. The alternative (login open to everyone) is a Settings choice. With only a password in front
  of it that mode is flagged by the Advisor; the optional authenticator code strengthens it. A changed home address is
  fixed with `security myip …` on the server or the "use my current address" button from another trusted address.
* **Certificates through CyberPanel's own command line.** Port 80 belongs to the web server, so the simplest reliable
  way to prove ownership is the one CyberPanel already does: create a small site for the sub-domain and issue its
  certificate. Renewal is CyberPanel's job; the panel notices the renewed files and reloads them without a restart.
* **No second set of rules next to CyberPanel's.** Both would use the same rule numbers. The setup step is blocked
  (and the Advisor says why) while CyberPanel's OWASP/Comodo pack or Imunify is active.
* **A website's files are changed as that website's user, never as root.** The folders belong to the website, and a
  hacked site can plant a link there (for example a `.htaccess` that points at a system file). A root program that
  follows it would overwrite or leak that file. `headers.py` therefore starts `htfile.py` as the website's own user
  (no extra groups) for every write; the file is opened without following links, written through a randomly named
  temporary file and renamed, and the original text comes back to the panel so a failed change can be undone.
* **Every protection is explained, visible and switchable.** Other servers have other needs, so nothing is forced:
  the Open ports page and the Security headers page show what each thing is, what it does, what could go wrong, and
  let the owner switch it on or off for all websites or for one, and undo it. Risky choices start off.
* **Security headers go into the website's `.htaccess` on LiteSpeed Enterprise** (Apache-style, as CyberPanel's
  own vhost files are). OpenLiteSpeed ignores header lines there, so the page says so and writes nothing.
* **The server firewall is our own nftables table, not firewalld.** CyberPanel's Firewall page drives firewalld, which is
  often not installed, while the page still shows ON (it turns OFF only when the status text contains "dead"). Installing
  and enabling firewalld on a live server would close every port not in its list. `serverfw.py` keeps its own list and
  loads one table (`cps_fw`, hook priority 10, after the admin lock at -1 and the blocker at -1, so the stricter always
  wins). Turning it on is always followed by a 2-minute systemd timer that undoes it unless the owner presses "Keep it";
  it becomes permanent (service enabled) only then.
* **Updates are manual, one item at a time, and all file work is done as the website's own user.** `wpupdate.py` never
  runs by itself (no timer, no hook): a person confirms in the panel. Per item: check the website answers, copy the
  plugin or theme folder and (once per website) the database into `<site home>/cps-backups` (outside the web root,
  mode 700), update with WP-CLI, ask the website again (fresh address to dodge the page cache, plus the login page, and
  look for PHP crash text), put the copy back if it got worse. Putting files back cannot undo database changes made by
  an update; that is why the database copy exists and why the panel says so. Roll-back and clean-up go through `su` as
  the site user, never as root, because a hacked site could plant a link that makes root overwrite a system file.
* **Bot protection (`botguard.py`).** Three independent marked blocks (`# BEGIN CP-Security bot-<key>`) at the top of the website's
  root `.htaccess`, written as the site user through the same read/write/put-back helpers as `phpguard.py`. `xmlrpc`:
  `<Files "xmlrpc.php"> Require all denied`. `files`: a `FilesMatch` for logs, dumps, backup and editor copies, `wp-config.php.*`,
  `error_log`, plus `RewriteRule (^|/)\.(?!well-known(/|$)) - [F]` for dotfiles (certificate renewals stay open). `users`: refuse
  `/wp-json/wp/v2/users` and `rest_route=/wp/v2/users` (also URL-encoded) and `?author=N` outside `/wp-admin/`, only without a
  `wordpress_logged_in_` cookie. Proof per switch: refused = 403 (files: two random test files, one a dotfile, that answered 200
  with their marker before); kept = home/login no worse, plus REST root and the signed-in users list (users) and a test file in
  `.well-known` (files) not newly refused. The scan reports what a stranger can see now: WordPress answering at xmlrpc.php,
  private paths that answer 200, and slugs from the users list or the `?author=1` redirect. The login watcher (`feed.py`) also
  copies `POST /xmlrpc.php` lines answered 403 (`<site>/xmlrpc` in the tidy line), never ones the door answered.
* **No PHP in uploads (`phpguard.py`).** The uploads folder comes from WordPress (`wp_get_upload_dir()['basedir']`) and must be inside the
  website's web folder (otherwise there is nothing to protect). The rule is a marked block at the top of `<uploads>/.htaccess`:
  `<FilesMatch "(?i)\.(php[0-9]?|phtml|phar|pht|phps|shtml?)$"> Require all denied </FilesMatch>` (both this and the older
  `Deny from all` form were seen to work on LiteSpeed Enterprise; it notices the change after about 6 to 8 seconds, so the proof asks
  again for up to 24). Switching on: refuse a website that is not answering; write a random-named test PHP file; it must answer 200
  with its marker; write the block (as the site user, through a temporary file and a rename, keeping the file's mode); the same file
  must now answer 403 without the marker; home, login and one picture from the uploads folder must still be as good as before; any
  failure puts the old file back (or removes it when there was none). The test file is removed in every case. A link in place of the
  `.htaccess`, or damaged marker lines, are refused, never guessed at. Switching off removes only the block (and the file when it held
  nothing else).
* **Saved copies are listed, limited and deleted from the panel (`wpupdate.copies*`).** The folder is the website's own `cps-backups`
  (mode 700). Only names the panel makes are recognised (`plugin|theme-<slug>-<date>-<time>`, `db-<date>-<time>.sql`, strict patterns), listed
  with `du` as the website's user, and only those are removed, as that user, never a name taken from the browser. Deleting is refused
  while a job runs (the copies are the roll-back). `copies_keep` (1 to 5, default 1) in the panel settings replaces the old constant in
  the clean-up after each update. New database dumps are `chmod 600`; a failed dump is deleted and never triggers the clean-up, so it cannot push out the last good one.
* **Uploaded plugin and theme zips (`library.py`).** The panel never unpacks or runs a zip. It checks the zip's table of contents
  (one folder, a plugin or theme header with a version, no unsafe paths, links, passwords; limits on size, count and unpacked size),
  keeps it in `/var/lib/cp-security/uploads` (root only, 700/600) and, for an update, pipes it into the website's own
  `cps-backups` folder through `su` as the website's user (`util.run_with_file`), checks its SHA-256 there, lets WP-CLI
  (`plugin|theme install <zip> --force`, the same as "replace current with uploaded") unpack it as that user, and removes the
  copy whatever happened. After a job made only of uploaded files nobody is asked anything (`LiveEngine._wpupdate_done`:
  the new versions are written into the lists directly; a normal "look again" would contact the plugin makers' servers).
  The update itself is `wpupdate.update_one(..., upload=entry)`: the same copy, check, roll back and
  cache clearing as every other update. The upload request is the only one allowed to be larger than 64 KB: `server.py`
  gates it from the headers (host, session, secret token, size, free disk) BEFORE reading the body, then streams it to a private
  temporary file and removes that whatever happens.
* **One-click admin login (`adminlogin.py`).** A per-website must-use plugin (`wp-content/mu-plugins/cp-security-login.php`, the folder
  comes from WordPress's own `WPMU_PLUGIN_DIR` and must be under the website's home) is installed by an explicit action only. The
  panel makes a link `/?cps-login=<payload>.<hmac>`: payload = base64url JSON `{u: login, e: expiry, n: nonce, t: optional dashboard page}`,
  HMAC-SHA256 with a per-website secret. The secret lives in the helper file (written as the website's user, mode 600, fed through
  standard input so it never shows on a command line) and in root-only `/etc/cp-security/adminlogin.json`. The helper acts on `init`
  at priority 1: bad signature = ignored silently (410 only for a validly signed link that is expired, over 5 minutes ahead, or already
  used; 403 for a non-administrator); success = `wp_set_auth_cookie` + redirect to `admin_url(t)`, with `DONOTCACHEPAGE`, no-cache and
  `Referrer-Policy: no-referrer`. The only state on the website is a 15-minute transient noting that a nonce was used. Install =
  write `.new` → `php -l` → move into place (keeping `.old`) → self-test with an expired token that must answer 410 containing "one-time
  login link" → health check before and after → roll back on any failure (`drop_new` before the switch, `put_back` after). The page
  never offers "Open admin" without re-reading the file's checksum, so a changed helper gets no link. Rejected on purpose: storing
  passwords, setting cookies across domains from the panel, per-link tokens stored from WP-CLI (object-cache mismatch), binding the
  link to an IP address. Trade-off: it bypasses a website's own 2-step login; the panel's login is the gate.
* **Refused-port counts** come from per-port dynamic sets in the firewall table (`refused_tcp`, `refused_udp`, one hour
  timeout). They restart on a reload. If this nftables rejects the counters, the file is written without them and the
  firewall still works.
