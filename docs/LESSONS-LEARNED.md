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

## Operational
* Run LiteSpeed changes with a graceful restart (`lswsctrl restart`) and a check of several sites afterwards.
* CyberPanel regenerates `httpd.conf` and `modsec.conf` from its own pages. Never save the ModSecurity page there.
* Do not run commands in parallel from the same terminal session when scripting the server – output got mixed up and
  uploads raced. Long jobs: start in the background on the server and poll.
