"""The installer: asks a few questions, gets a certificate, sets everything up, starts the panel.

    python3 -m cpsec install        (install.sh runs exactly this after fetching the files)
    python3 -m cpsec uninstall

Everything it asks has a sensible default. It can also run without questions: give all the answers as
options (see HELP) and add --yes. Nothing is changed until the last question has been answered.
"""
import argparse
import getpass
import os
import re
import shutil
import socket
import ssl
import sys
import time

from . import __version__, access, blocker, config, netinfo, provision, settings, tls, util, webserver
from .panel import auth

DEFAULT_PORT = 9443
CLOUDFLARE_PORTS = (443, 2053, 2083, 2087, 2096, 8443)        # the HTTPS ports Cloudflare can pass through
RESERVED_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 7080, 8088, 8090, 8888}
USERNAME_OK = re.compile(r"^[A-Za-z0-9._-]{3,40}$")
EMAIL_OK = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LAUNCHER = "/usr/local/sbin/security"

HELP = """CP-Security installer

  python3 -m cpsec install                       asks everything it needs
  python3 -m cpsec install --yes --domain security.example.com --port 9443 --email me@example.com \\
        --username admin --trusted-ip 203.0.113.9          (no questions; the password comes from the
                                                             CPSEC_PASSWORD environment variable)
Options:  --open-login   let every address reach the login page (default: trusted addresses only)
          --skip-protections   only install the panel, do not set up the blocker/lock/firewall now
          --skip-certificate   use a certificate that is already on the server
"""


class Console:
    """Talks to the person. Tests replace it with a scripted one."""

    def __init__(self, assume_yes=False):
        self.assume_yes = assume_yes

    def say(self, text=""):
        print(text)

    def ask(self, prompt, default=""):
        if self.assume_yes:
            return default
        try:
            answer = input("%s%s: " % (prompt, " [%s]" % default if default else "")).strip()
        except EOFError:
            raise SystemExit("Cancelled.")
        return answer or default

    def secret(self, prompt):
        if self.assume_yes:
            return os.environ.get("CPSEC_PASSWORD", "")
        try:
            return getpass.getpass(prompt + ": ")
        except EOFError:
            raise SystemExit("Cancelled.")

    def yes(self, prompt, default=True):
        if self.assume_yes:
            return default
        answer = self.ask("%s (%s)" % (prompt, "Y/n" if default else "y/N")).lower()
        return default if not answer else answer.startswith("y")


# ----------------------------------------------------------------------------- checks
def preflight():
    """[(level, text)] where level is 'stop', 'warn' or 'ok'."""
    out = []
    if hasattr(os, "geteuid") and os.geteuid() != 0 and not os.environ.get("CPSEC_ROOT"):
        out.append(("stop", "Run this as root (log in as root, or put sudo in front)."))
    if sys.version_info < (3, 10):
        out.append(("stop", "Python 3.10 or newer is needed (this is %d.%d). On AlmaLinux/Rocky: "
                            "dnf install python3.11, then run the installer with python3.11." % sys.version_info[:2]))
    info = webserver.info()
    if info["kind"] is None:
        out.append(("stop", "No LiteSpeed web server was found. CP-Security is made for CyberPanel servers "
                            "(LiteSpeed Enterprise or OpenLiteSpeed)."))
    else:
        out.append(("ok", "Web server: %s %s" % (info["name"], info["version"])))
    if os.path.isdir(config.P.at("/usr/local/CyberCP")):
        out.append(("ok", "CyberPanel found."))
    else:
        out.append(("warn", "CyberPanel was not found. A certificate cannot be requested automatically; "
                            "you will need a certificate that is already on this server."))
    return out


def port_problem(port, cloudflare=False):
    """Plain-English reason the port cannot be used, or None."""
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        return "Please choose a number between 1024 and 65535."
    if port in RESERVED_PORTS:
        return "Port %d is already used by something else on a CyberPanel server." % port
    if port_in_use(port):
        return "Something is already listening on port %d." % port
    if cloudflare and port not in CLOUDFLARE_PORTS:
        return ("This name goes through Cloudflare's orange cloud, which only passes ports %s. "
                "Choose one of those, or switch the name to 'DNS only' (grey cloud) in Cloudflare."
                % ", ".join(str(p) for p in CLOUDFLARE_PORTS if p != 443))
    return None


def port_in_use(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


# ----------------------------------------------------------------------------- asking
def _domain_questions(c, preset):
    for _ in range(6):
        raw = preset or c.ask("Sub-domain for the panel (for example security.example.com)")
        domain = netinfo.clean_domain(raw)
        if not domain:
            c.say("That is not a plain host name. Use something like security.example.com (no https://, no port).")
            if preset or c.assume_yes:
                return None, None
            continue
        c.say("Looking up %s ..." % domain)
        dns = netinfo.check_domain(domain)
        have_cert = bool(tls.find(domain))
        if not dns["exists"] and not have_cert:
            c.say("%s does not exist in DNS yet. Create an A record that points it to this server's address, "
                  "wait a few minutes, and try again." % domain)
            if preset or c.assume_yes:
                return None, None
            preset = None
            continue
        if dns["exists"] and dns["points_here"] is False and not have_cert:
            c.say("%s points to %s, which is not an address of this server. The certificate request will fail "
                  "unless the name points here." % (domain, ", ".join(dns["ips"])))
            if not c.yes("Continue anyway?", default=False):
                preset = None
                if c.assume_yes:
                    return None, None
                continue
        return domain, dns
    return None, None


def gather(c, args):
    """Ask for everything. Returns a settings dict, or None when the person gave up."""
    c.say("CP-Security %s installer" % __version__)
    c.say("-" * 40)
    stops = False
    for level, text in preflight():
        c.say(("  [ok]   " if level == "ok" else "  [warn] " if level == "warn" else "  [STOP] ") + text)
        stops = stops or level == "stop"
    if stops:
        return None
    c.say()
    domain, dns = _domain_questions(c, args.domain)
    if not domain:
        return None
    cloudflare = bool(dns and dns["cloudflare"])
    if cloudflare:
        c.say("Note: %s is behind Cloudflare's orange cloud. Certificates still work, but only a few ports "
              "pass through." % domain)

    fallback = 8443 if cloudflare else DEFAULT_PORT
    port = args.port or fallback
    for attempt in range(5):
        try:
            port = int(c.ask("Port for the panel", str(port)))
        except ValueError:
            port = 0
        problem = port_problem(port, cloudflare)
        if not problem:
            break
        c.say(problem)
        if c.assume_yes:
            return None
        port = fallback
    else:
        return None

    email = args.email or c.ask("Email address for Let's Encrypt (certificate warnings go here)", "admin@" + domain)
    if not EMAIL_OK.match(email):
        c.say("That email address does not look right.")
        return None

    username = args.username or c.ask("Username for the panel", "admin")
    if not USERNAME_OK.match(username):
        c.say("The username should be 3-40 letters, digits, dots, dashes or underscores.")
        return None
    password = None
    for _ in range(5):
        candidate = c.secret("Choose a password (at least %d characters)" % auth.MIN_PASSWORD_LENGTH)
        problem = auth.password_problem(candidate, username)
        if problem:
            c.say(problem)
            if c.assume_yes:
                return None
            continue
        if not c.assume_yes and c.secret("Type it again") != candidate:
            c.say("They did not match.")
            continue
        password = candidate
        break
    if not password:
        return None

    trusted = []
    existing = [a["address"] for a in access.list_admin()]
    for a in access.list_legacy_admin():                    # the earlier setup's trusted addresses count too
        if a["address"] not in existing:
            existing.append(a["address"])
    if existing:
        c.say("Already trusted on this server: %s" % ", ".join(existing))
    candidates = list(args.trusted_ip or [])
    ssh_ip = _ssh_ip()
    explicit_only = c.assume_yes and bool(candidates)         # automation that names its addresses gets exactly those
    if ssh_ip and not explicit_only and ssh_ip not in existing and ssh_ip not in candidates and c.yes(
            "You are connected from %s. Trust this address (it may open CyberPanel and this panel)?" % ssh_ip):
        candidates.append(ssh_ip)
    for raw in candidates:
        clean, err = access.check_address(raw)
        if err:
            c.say("%s: %s" % (raw, err))
            return None
        trusted.append(clean)
    while not c.assume_yes:
        extra = c.ask("Another trusted address (press Enter when done)")
        if not extra:
            if trusted or existing:
                break
            c.say("At least one trusted address is needed, or the admin pages would be locked for everybody.")
            continue
        clean, err = access.check_address(extra)
        if err:
            c.say(err)
            continue
        trusted.append(clean)
    if not trusted and not existing:
        c.say("At least one trusted address is needed (--trusted-ip).")
        return None

    if args.open_login:
        mode = "login"
    elif c.assume_yes:
        mode = "trusted"
    else:
        c.say("\nWho may open the panel?\n  1) Only trusted addresses (recommended: strangers cannot even see the login page)"
              "\n  2) Anyone who has the username and password")
        mode = "login" if c.ask("Choose 1 or 2", "1") == "2" else "trusted"
    protections = not args.skip_protections and c.yes(
        "Also set up the attack blocker, the admin lock and the web firewall now?")

    c.say("\nReady to install:")
    c.say("  Panel address : https://%s:%d" % (domain, port))
    c.say("  Username      : %s" % username)
    c.say("  Reachable by  : %s" % ("trusted addresses only" if mode == "trusted" else "anyone with the login"))
    c.say("  Trusted       : %s" % ", ".join(trusted + existing))
    c.say("  Protections   : %s" % ("set up now (blocker, admin lock, web firewall)" if protections else "later, from the Setup page"))
    if not c.yes("Go ahead?"):
        return None
    return {"domain": domain, "port": port, "email": email, "username": username, "password": password,
            "trusted": trusted, "access": mode, "protections": protections,
            "certificate": not args.skip_certificate}


def _ssh_ip():
    parts = os.environ.get("SSH_CONNECTION", os.environ.get("SSH_CLIENT", "")).split()
    return parts[0] if parts and parts[0] not in ("127.0.0.1", "::1") else None


# ----------------------------------------------------------------------------- doing
def deploy_code(source_dir):
    """Copy the program into /opt/cp-security (when it is not running from there already)."""
    target = config.P.install_dir
    if os.path.realpath(source_dir) == os.path.realpath(target):
        return util.Result(True, "The program is already in " + target)
    os.makedirs(target, exist_ok=True)
    shutil.rmtree(os.path.join(target, "cpsec"), ignore_errors=True)     # no leftovers of an older version
    shutil.copytree(os.path.join(source_dir, "cpsec"), os.path.join(target, "cpsec"), dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    version = os.path.join(source_dir, "VERSION")
    if os.path.exists(version):
        shutil.copy2(version, os.path.join(target, "VERSION"))
    return util.Result(True, "Program files copied to " + target)


def write_launcher():
    """The `security` command."""
    path = config.P.at(LAUNCHER)
    if os.path.exists(path) and "cpsec" not in util.read_text(path):
        shutil.copy2(path, path + ".before-cp-security")
    text = '#!/bin/sh\n# Written by the CP-Security installer.\nPYTHONPATH=%s exec %s -m cpsec "$@"\n' % (
        config.P.install_dir, provision.python_path())
    util.atomic_write(path, text, 0o755)


def wait_for_panel(domain, port, tries=20, pause=1.0):
    """True once the panel answers over HTTPS on this machine."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(tries):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    s.sendall(("GET /api/me HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % domain).encode())
                    if s.recv(64).startswith(b"HTTP/1.1 200"):
                        return True
        except (OSError, ssl.SSLError):
            pass
        time.sleep(pause)
    return False


def execute(c, cfg, source_dir):
    """Do it. Returns 0 when the panel is up."""
    p = config.P
    c.say("\nInstalling ...")
    c.say("  " + deploy_code(source_dir).message)

    if cfg["certificate"]:
        c.say("  Requesting a certificate for %s (this can take a minute) ..." % cfg["domain"])
        res = tls.get_certificate(cfg["domain"], cfg["email"])
        c.say("  " + res.message)
        if not res.ok:
            c.say("\nNothing else was changed. Fix the problem above and run the installer again.")
            return 1
    elif not tls.find(cfg["domain"]):
        c.say("  No certificate for %s was found, and --skip-certificate was given." % cfg["domain"])
        return 1

    # bring the earlier setup's lists over first, so its trusted addresses are not lost
    if provision.BY_KEY["migrate"].state()[0] == "todo":
        c.say("  " + provision.BY_KEY["migrate"].run(lambda line: None).message)
    # settings, login and trusted addresses
    settings.save({"domain": cfg["domain"], "port": cfg["port"], "access": cfg["access"]})
    settings.save_user({"name": cfg["username"], "password_hash": auth.hash_password(cfg["password"]),
                        "totp_enabled": False, "last_counter": 0})
    existing = access.read_list(p.admin_list)
    have = set(a for a, _ in existing)
    for addr in cfg["trusted"]:
        if addr not in have:
            existing.append((addr, "Added by the installer"))
    if existing:
        os.makedirs(p.conf_dir, exist_ok=True)
        access.write_list(p.admin_list, existing, access.ADMIN_HEADER)
    c.say("  Login '%s' created. Trusted addresses: %d." % (cfg["username"], len(existing)))

    res = tls.open_port(cfg["port"])
    c.say("  " + res.message)
    write_launcher()
    c.say("  The 'security' command is ready.")

    failed = []
    if cfg["protections"]:
        c.say("\nSetting up the protections (the web server restarts once; your websites are checked afterwards) ...")
        runner = provision.Runner(on_log=lambda line: c.say("    " + line))
        runner.start(background=False)
        job = runner.snapshot()
        for step in job["steps"]:
            if step["state"] == "failed":
                failed.append(step)
                c.say("  PROBLEM: %s - %s" % (step["title"], step["message"]))
    else:
        # the admin lock is the one protection the panel's own port depends on, so it is never skipped
        provision.Runner(on_log=lambda line: c.say("    " + line)).start(["migrate", "lock"], background=False)

    res = provision.install_panel_service()
    c.say("\n  " + res.message)
    up = res.ok and wait_for_panel(cfg["domain"], cfg["port"])
    c.say("")
    if up:
        c.say("The panel is ready:  https://%s:%d" % (cfg["domain"], cfg["port"]))
        c.say("Sign in as '%s' with the password you chose." % cfg["username"])
        if cfg["access"] == "trusted":
            c.say("It opens only from trusted addresses. If your internet address changes, run on the server:  security myip YOUR.NEW.ADDRESS")
    else:
        c.say("The panel service did not answer. Look with:  journalctl -u cp-security-panel -n 50")
    if failed:
        c.say("Some protections could not be set up. Open the Setup page in the panel to see why and to try again.")
    c.say("Open the Advisor page first: it notices other security tools on this server and tells you what to do.")
    return 0 if up else 1


# ----------------------------------------------------------------------------- taking it away again
def uninstall(c, purge=False):
    """Removes the panel always; the protections only when asked. Returns 0."""
    p = config.P
    c.say("This removes the CP-Security panel from this server.")
    if not c.yes("Continue?", default=False):
        return 1
    util.run(["systemctl", "disable", "--now", provision.SERVICE_PANEL], timeout=120)
    for path in (p.systemd_dir + "/" + provision.SERVICE_PANEL,):
        if os.path.exists(path):
            os.remove(path)
    c.say("  The panel service was removed.")

    if c.yes("Also remove the attack blocker settings, the login watcher and the web firewall rules?", default=False):
        util.run(["systemctl", "disable", "--now", provision.SERVICE_FEED], timeout=120)
        for path in (p.systemd_dir + "/" + provision.SERVICE_FEED, p.f2b_jails, p.f2b_ignore,
                     p.logrotate_dir + "/cps-wp-login", p.logrotate_dir + "/cp-security-panel"):
            if os.path.exists(path):
                os.remove(path)
        for name in ("cps-wp-login", "cps-mail-auth", "cps-panel"):
            path = p.f2b_filter_dir + "/%s.conf" % name
            if os.path.exists(path):
                os.remove(path)
        rc, out = util.run(["fail2ban-client", "-t"], timeout=90)
        if rc == 0:
            util.run(["fail2ban-client", "reload"], timeout=90)
            blocker.ensure_actions()
        if webserver.hook_present():
            webserver.disconnect()
            shutil.rmtree(p.waf_dir, ignore_errors=True)
            webserver.restart()
        c.say("  The blocker settings, login watcher and web firewall were removed.")

    if c.yes("Also remove the admin lock? CyberPanel and the other admin pages would be open to everybody.", default=False):
        util.run(["systemctl", "disable", "--now", provision.SERVICE_LOCK], timeout=120)
        util.run(["nft", "delete", "table", "inet", access.TABLE])
        path = p.systemd_dir + "/" + provision.SERVICE_LOCK
        if os.path.exists(path):
            os.remove(path)
        c.say("  The admin lock was removed.")
    util.run(["systemctl", "daemon-reload"])

    if purge:
        shutil.rmtree(p.conf_dir, ignore_errors=True)
        shutil.rmtree(p.install_dir, ignore_errors=True)
        if os.path.exists(p.at(LAUNCHER)) and "cpsec" in util.read_text(p.at(LAUNCHER)):
            os.remove(p.at(LAUNCHER))
        c.say("  All settings and program files were deleted.")
    else:
        c.say("  Your settings stay in %s (add --purge to delete them too)." % p.conf_dir)
    return 0


# ----------------------------------------------------------------------------- entry points
def main(argv, console=None):
    parser = argparse.ArgumentParser(prog="cpsec install", add_help=False)
    parser.add_argument("--domain")
    parser.add_argument("--port", type=int)
    parser.add_argument("--email")
    parser.add_argument("--username")
    parser.add_argument("--trusted-ip", action="append")
    parser.add_argument("--open-login", action="store_true")
    parser.add_argument("--skip-protections", action="store_true")
    parser.add_argument("--skip-certificate", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--help", "-h", action="store_true")
    args = parser.parse_args(argv)
    if args.help:
        print(HELP)
        return 0
    c = console or Console(assume_yes=args.yes)
    cfg = gather(c, args)
    if cfg is None:
        c.say("\nNothing was installed.")
        return 1
    source = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return execute(c, cfg, source)


def main_uninstall(argv, console=None):
    purge = "--purge" in argv
    return uninstall(console or Console(assume_yes="--yes" in argv), purge=purge)
