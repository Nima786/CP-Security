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
