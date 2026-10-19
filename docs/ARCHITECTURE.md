# Architecture

## Goals
* A non-programmer owner can see the state of the server's protection and change it safely.
* Nothing the tools do can leave the server worse than it was: every change is validated, applied, verified and
  undone automatically when verification fails.
* No dependencies to install on the server: Python 3.10+ standard library only.

## Layers

```
 browser ──HTTPS──► panel (cpsec.panel)  ─┐
 terminal ─────────► menu  (cpsec.menu)  ─┼──►  engine  ──► fail2ban · nftables · LiteSpeed · WP-CLI
                                           │   (cpsec.access / blocker / waf / sites / updates / health)
```

* **Engine** – plain functions. They read and write the real files and run the real commands, and return data or a
  `Result(ok, message, code)`. They never print and never read the keyboard. Every path goes through `cpsec.config.P`
  and every command through `cpsec.util.run`, which is how the tests replace the whole server.
* **Terminal menu** – formats engine data as numbered screens.
* **Panel** – an HTTPS server (standard library) with its own login. Same engine, JSON instead of text.

## Safety rules (apply to every new feature)
1. **Validate before writing.** Addresses, host names and rule numbers are checked against strict patterns before they
   reach a command line or a rule file.
2. **Check before loading.** nftables and fail2ban configurations are tested (`nft -c`, `fail2ban-client -t`) before use.
3. **Verify after changing the web server.** Restart gracefully, check a sample of websites, restore the old files if
   any site stops answering.
4. **Never lock the owner out silently.** Removing the address you are connecting from asks for confirmation; the
   last trusted address cannot be removed.
5. **No secrets in the repository.** Passwords are stored as scrypt hashes, the TOTP secret and TLS key stay in
   `/etc/cp-security` (root only).

## Where things live on the server

| What | Path |
|---|---|
| Settings and lists | `/etc/cp-security/` (`admin-access.list`, `never-block.list`, `site-baseline.json`, `panel.json`, `tls/`) |
| Admin lock rules | `/etc/cp-security/admin-lock.nft` (table `inet cps_lock`) |
| Blocker config | `/etc/fail2ban/jail.d/cps-*.local`, `/etc/fail2ban/filter.d/cps-*.conf` |
| Web firewall | `/usr/local/lsws/conf/cps-waf/` and `/usr/local/lsws/conf/modsec.conf` |
| Panel code | `/opt/cp-security/` |

## Decisions
* **Python, not Go.** The server already has Python 3.10, the hardening logic already existed and was tested in
  Python, and there is no build step or binary to ship.
* **Panel reachable by login (default) or by trusted addresses only.** The owner's home address changes; with
  login-only access they can open the panel from a new address and press *Use my current address*. The login needs
  a password and a 6-digit code, five wrong attempts block the address, and the panel can be switched to
  trusted-only at any time.
* **Let's Encrypt through LiteSpeed's default site.** Port 80 belongs to LiteSpeed. The certificate is requested
  with the web-root method into LiteSpeed's default document root, so no extra website has to be created.
