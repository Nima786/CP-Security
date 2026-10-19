"""`security panel ...`: set the panel up, run it, and recover from a lost password or phone."""
import argparse
import getpass
import os
import signal
import sys
import tempfile

from .. import config, settings
from . import auth

HELP = """security panel  -  the browser panel

  security panel setup --domain panel.example.com --port 9443
                       create the admin login (asks for a password, shows the key for your authenticator app)
  security panel run                      run the panel (the system service does this)
  security panel reset-password           choose a new password (use this if you forgot it)
  security panel reset-2fa                get a new key for your authenticator app (lost phone)
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
    if args.domain or args.port:
        changes = {}
        if args.domain:
            changes["domain"] = args.domain.strip().lower()
        if args.port:
            changes["port"] = int(args.port)
        settings.save(changes)
    existing = settings.get_user()
    if existing and not args.force:
        print("A login already exists (%s). Use 'reset-password' or 'reset-2fa', or add --force to start over." % existing["name"])
        return 1
    username = (args.username or input("Choose a username [admin]: ").strip() or "admin")[:40]
    password = _ask_password(username)
    secret = auth.new_totp_secret()
    counter = _confirm_totp(secret, username)
    if counter is None:
        print("Setup was not finished. Nothing was saved.")
        return 1
    settings.save_user({"name": username, "password_hash": auth.hash_password(password),
                        "totp_secret": secret, "last_counter": counter})
    print("\nDone. The login '%s' is ready." % username)
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


def cmd_reset_2fa(args):
    user = settings.get_user()
    if not user:
        print("No login exists yet. Run: security panel setup")
        return 1
    secret = auth.new_totp_secret()
    counter = _confirm_totp(secret, user["name"])
    if counter is None:
        print("Nothing was changed.")
        return 1
    user["totp_secret"], user["last_counter"] = secret, counter
    settings.save_user(user)
    print("The new key is active. Restart the panel to sign everybody out:  systemctl restart cp-security-panel")
    return 0


def cmd_status(args):
    s = settings.load()
    user = settings.get_user()
    print("Address:  https://%s:%s" % (s["domain"] or "(not set)", s["port"] or "(not set)"))
    print("Reachable by: " + ("everyone with the login" if s["access"] == "login" else "trusted addresses only"))
    print("Login:    " + (user["name"] if user else "(none yet: run 'security panel setup')"))
    return 0


def _build_server(args, engine, secure):
    from .app import App
    from .server import PanelServer, make_tls_context
    s = settings.load()
    hosts = [h for h in [s["domain"]] + (args.allow_host or []) if h]
    app = App(engine, secure_cookies=secure, allowed_hosts=hosts)
    tls = None
    if secure:
        cert, key = args.cert or config.P.tls_dir + "/fullchain.pem", args.key or config.P.tls_dir + "/privkey.pem"
        tls = make_tls_context(cert, key)
    port = args.port or s["port"]
    if not port:
        raise SystemExit("No port is set. Run: security panel setup --domain ... --port ...")
    return PanelServer((args.host, int(port)), app, tls), (args.cert or config.P.tls_dir + "/fullchain.pem",
                                                           args.key or config.P.tls_dir + "/privkey.pem")


def cmd_run(args):
    from .engine import LiveEngine
    if not settings.get_user():
        print("No login exists yet. Run: security panel setup")
        return 1
    server, (cert, key) = _build_server(args, LiveEngine(), secure=not args.insecure)

    def reload_cert(*_):
        try:
            server.reload_certificate(cert, key)
        except OSError:
            pass

    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_cert)            # sent after the certificate is renewed
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


DEMO_USER, DEMO_PASSWORD, DEMO_SECRET = "demo", "demo-password-123", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def cmd_demo(args):
    """The real panel with made-up data, kept in a throw-away folder."""
    from .engine import DemoEngine
    tmp = tempfile.mkdtemp(prefix="cps-demo-")
    config.P = config.Paths(tmp)
    settings.save({"domain": "", "port": int(args.port or 8765), "access": "login"})
    settings.save_user({"name": DEMO_USER, "password_hash": auth.hash_password(DEMO_PASSWORD, n=2 ** 12),
                        "totp_secret": DEMO_SECRET, "last_counter": 0})
    args.host = args.host if args.host != "::" else "127.0.0.1"
    args.allow_host = ["127.0.0.1", "localhost"]
    server, _ = _build_server(args, DemoEngine(), secure=False)
    print("Demo panel (made-up data): http://127.0.0.1:%s" % server.server_address[1])
    print("Username: %s   Password: %s" % (DEMO_USER, DEMO_PASSWORD))
    print("Authenticator key: %s   (or run: python -c \"from cpsec.panel import auth; print(auth.totp_now('%s'))\")"
          % (DEMO_SECRET, DEMO_SECRET))
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
    parser.add_argument("--insecure", action="store_true", help="plain HTTP, for testing only")
    parser.add_argument("--allow-host", action="append")
    args = parser.parse_args(argv)
    handlers = {"setup": cmd_setup, "run": cmd_run, "reset-password": cmd_reset_password,
                "reset-2fa": cmd_reset_2fa, "status": cmd_status, "demo": cmd_demo}
    if args.command not in handlers:
        print(HELP)
        return 1
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
