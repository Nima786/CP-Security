"""`security panel ...`: set the panel up, run it, and recover from a lost password."""
import argparse
import getpass
import signal
import sys
import tempfile
import threading
import time

from .. import config, settings, tls
from . import activity, auth

HELP = """security panel  -  the browser panel

  security panel setup --domain panel.example.com --port 9443
                       create the admin login (asks for a username and password)
  security panel run                      run the panel (the system service does this)
  security panel reset-password           choose a new password (use this if you forgot it)
  security panel disable-2fa              turn the optional two-step login off (lost phone)
  security panel status                   show the panel's settings
  security panel demo                     try the interface with made-up data (nothing on the server is touched)
"""


def _ask_password(username):
    while True:
        pw = getpass.getpass("Choose a password (at least %d characters): " % auth.MIN_PASSWORD_LENGTH)
        problem = auth.password_problem(pw, username)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Type it again: ") != pw:
            print("They did not match. Try again.")
            continue
        return pw


def _confirm_totp(secret, username):
    print("\nOpen your authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, ...),")
    print("add an account by typing this key, and choose 'time based':\n")
    print("    " + " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
    print("\n(or open this link on the phone: %s)\n" % auth.otpauth_uri(secret, username))
    for _ in range(5):
        code = input("Type the 6-digit code the app shows now: ").strip()
        counter = auth.verify_totp(secret, code)
        if counter is not None:
            return counter
        print("That code is not right. Wait for the next one and try again.")
    return None


def cmd_setup(args):
    changes = {}
    if args.domain:
        changes["domain"] = args.domain.strip().lower()
    if args.port:
        changes["port"] = int(args.port)
    changes["access"] = "login" if args.open_login else "trusted"
    existing = settings.get_user()
    if existing and not args.force:
        print("A login already exists (%s). Use 'reset-password', or add --force to start over." % existing["name"])
        return 1
    settings.save(changes)
    username = (args.username or input("Choose a username [admin]: ").strip() or "admin")[:40]
    password = _ask_password(username)
    user = {"name": username, "password_hash": auth.hash_password(password), "totp_enabled": False, "last_counter": 0}
    if args.with_2fa:
        secret = auth.new_totp_secret()
        counter = _confirm_totp(secret, username)
        if counter is None:
            print("Setup was not finished. Nothing was saved.")
            return 1
        user.update(totp_secret=secret, totp_enabled=True, last_counter=counter)
    settings.save_user(user)
    print("\nDone. The login '%s' is ready." % username)
    if not args.open_login:
        print("The panel opens only from trusted addresses (add yours with:  security myip YOUR.ADDRESS).")
    return 0


def cmd_reset_password(args):
    user = settings.get_user()
    if not user:
        print("No login exists yet. Run: security panel setup")
        return 1
    user["password_hash"] = auth.hash_password(_ask_password(user["name"]))
    settings.save_user(user)
    print("Password changed. Restart the panel to sign everybody out:  systemctl restart cp-security-panel")
    return 0


def cmd_disable_2fa(args):
    user = settings.get_user()
    if not user:
        print("No login exists yet. Run: security panel setup")
        return 1
    user["totp_enabled"] = False
    user.pop("totp_secret", None)
    settings.save_user(user)
    print("Two-step login is off. Restart the panel to sign everybody out:  systemctl restart cp-security-panel")
    return 0


def cmd_status(args):
    s = settings.load()
    user = settings.get_user()
    print("Address:  https://%s:%s" % (s["domain"] or "(not set)", s["port"] or "(not set)"))
    print("Reachable by: " + ("everyone with the login" if s["access"] == "login" else "trusted addresses only"))
    print("Login:    " + (user["name"] if user else "(none yet: run 'security panel setup')"))
    print("Two-step: " + ("on" if user and user.get("totp_enabled") else "off"))
    return 0


def _build_server(args, engine, secure):
    from .app import App
    from .server import PanelServer, make_tls_context
    s = settings.load()
    hosts = [h for h in [s["domain"]] + (args.allow_host or []) if h]
    app = App(engine, secure_cookies=secure, allowed_hosts=hosts)
    found = tls.find(s["domain"]) if s["domain"] else None
    cert = args.cert or (found[0] if found else config.P.tls_dir + "/fullchain.pem")
    key = args.key or (found[1] if found else config.P.tls_dir + "/privkey.pem")
    port = args.port or s["port"]
    if not port:
        raise SystemExit("No port is set. Run: security panel setup --domain ... --port ...")
    context = make_tls_context(cert, key) if secure else None
    try:
        server = PanelServer((args.host, int(port)), app, context)
    except OSError:
        # a server with IPv6 switched off cannot listen on "::": listen on every IPv4 address instead
        if ":" not in args.host:
            raise
        server = PanelServer(("0.0.0.0", int(port)), app, context)
    return server, (cert, key)


def cmd_run(args):
    from .engine import LiveEngine
    if not settings.get_user():
        print("No login exists yet. Run: security panel setup")
        return 1
    engine = LiveEngine()
    server, (cert, key) = _build_server(args, engine, secure=not args.insecure)
    engine.warm_up()

    def reload_cert(*_):
        try:
            server.reload_certificate(cert, key)
        except OSError:
            pass

    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_cert)            # sent after the certificate is renewed
    if not args.insecure:
        threading.Thread(target=watch_certificate, args=(server, settings.load()["domain"], cert, key),
                         daemon=True).start()               # CyberPanel renews it quietly; we notice
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def watch_certificate(server, domain, cert, key, every=600, stop=None):
    """Reload the certificate when it was renewed, without restarting the panel."""
    last = tls.mtime_of(domain)
    while not (stop and stop.is_set()):
        time.sleep(every)
        now = tls.mtime_of(domain)
        if now and now != last:
            try:
                found = tls.find(domain)
                server.reload_certificate(found[0] if found else cert, found[1] if found else key)
                last = now
                activity.write("CERTIFICATE_RELOADED", domain=domain)
            except OSError:
                pass


DEMO_USER, DEMO_PASSWORD = "demo", "demo-password-123"


def cmd_demo(args):
    """The real panel with made-up data, kept in a throw-away folder."""
    from .engine import DemoEngine
    tmp = tempfile.mkdtemp(prefix="cps-demo-")
    config.P = config.Paths(tmp)
    settings.save({"domain": "", "port": int(args.port or 8765), "access": "login"})
    settings.save_user({"name": DEMO_USER, "password_hash": auth.hash_password(DEMO_PASSWORD, n=2 ** 12),
                        "totp_enabled": False, "last_counter": 0})
    args.host = args.host if args.host != "::" else "127.0.0.1"
    args.allow_host = ["127.0.0.1", "localhost"]
    server, _ = _build_server(args, DemoEngine(), secure=False)
    print("Demo panel (made-up data): http://127.0.0.1:%s" % server.server_address[1])
    print("Username: %s   Password: %s" % (DEMO_USER, DEMO_PASSWORD))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv):
    if not argv or argv[0] in ("help", "-h", "--help"):
        print(HELP)
        return 0
    parser = argparse.ArgumentParser(prog="security panel", add_help=False)
    parser.add_argument("command")
    parser.add_argument("--domain")
    parser.add_argument("--port")
    parser.add_argument("--host", default="::")
    parser.add_argument("--username")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--open-login", action="store_true", help="let every address reach the login page")
    parser.add_argument("--with-2fa", action="store_true", help="also set up the optional authenticator code")
    parser.add_argument("--insecure", action="store_true", help="plain HTTP, for testing only")
    parser.add_argument("--allow-host", action="append")
    args = parser.parse_args(argv)
    handlers = {"setup": cmd_setup, "run": cmd_run, "reset-password": cmd_reset_password,
                "disable-2fa": cmd_disable_2fa, "status": cmd_status, "demo": cmd_demo}
    if args.command not in handlers:
        print(HELP)
        return 1
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
