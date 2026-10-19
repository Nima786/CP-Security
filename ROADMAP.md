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
- ✅ Unit tests (116 including the panel)

## M2 – Browser panel ✅
- ✅ Login: password (scrypt) + mandatory 6-digit code (TOTP, replay-proof), sessions with idle/absolute timeout, CSRF protection, per-address login lock-out
- ✅ JSON API over the engine; strict security headers; only the panel's own address answers (host check)
- ✅ Interface: Overview · Blocked · Admin access · Web firewall · Updates · Settings (phone bottom bar, dark mode, no inline scripts/styles)
- ✅ "Use this as my home address" button (fixes the changing-home-IP problem in one click)
- ✅ Demo mode with made-up data: `security panel demo` (for design work and screenshots; touches nothing on the server)
- ✅ Checked in a real browser at desktop and phone sizes, light and dark
- ✅ Login attempts are written in a log format the attack blocker can read (the blocker rule itself comes with M3)

## M3 – Installer 🚧 (next)
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
