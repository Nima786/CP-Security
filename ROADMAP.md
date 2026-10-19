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
- ✅ Terminal menu (`security`) with parity to the hand-built version
- ✅ 55 unit tests

## M2 – Browser panel 🚧
- ⬜ Login: password (scrypt) + mandatory 6-digit code (TOTP), sessions, CSRF protection, login rate limit
- ⬜ JSON API over the engine
- ⬜ Interface: Overview · Blocked · Admin access · Web firewall · Updates · Settings
- ⬜ "Use my current address" button (fixes the changing-home-IP problem in one click)
- ⬜ Demo mode with sample data for design work and screenshots
- ⬜ Panel login attempts blocked by the attack blocker

## M3 – Installer ⬜
- ⬜ `install.sh`: asks for the sub-domain and port, checks DNS
- ⬜ Let's Encrypt certificate (acme.sh, web-root method through LiteSpeed's default site – no extra site needed) with automatic renewal
- ⬜ systemd service with hardening, first admin user + authenticator setup
- ⬜ Option: panel reachable by trusted addresses only
- ⬜ Provisioning of the protections themselves on a fresh server (blocker jails and filters, login-watcher service, firewall rules, OWASP rules) so the repository can rebuild everything
- ⬜ Migration of the existing hand-built setup (`/etc/pb-security`, `pb-*` services) to the new names

## M4 – Hardening and release ⬜
- ⬜ Update from the panel (pull a release, verify, restart)
- ⬜ Release workflow and checksums
- ⬜ Security review of the panel (headers, input validation, privilege separation)
