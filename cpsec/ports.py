"""Open ports: the doors this server has open, who can walk through each one, and what the owner decided.

Every program that waits for connections uses a "port" (a door number). Websites use 80 and 443, the
server login uses 22, and so on. A door that has no business being open to the whole internet is how
many servers get attacked: a database, a test app, a control interface.

This module only READS the list of listening programs. The one thing it can change is the admin lock
(the small firewall table in access.py): a locked port can only be reached from the trusted addresses.
The owner's choices are saved in ports.json and also drive settings.lock_ports(), so the lock keeps
them after a restart.

What a person can do with each port:
    lock      only trusted addresses may reach it (never for 80 and 443: that would take every website down)
    open      stop locking a port again (admin pages need an extra confirmation)
    accept    "I know this port is open, stop warning me" (nothing is changed)
"""
import ipaddress
import os
import re

from . import access, config, provision, settings, util
from .util import Result

PROTECTED = (80, 443)               # the websites themselves: never lockable
LEVEL_ORDER = {"bad": 0, "warn": 1, "info": 2, "ok": 3}

KIND_NAMES = {
    "web": "Websites",
    "service": "Normal server service",
    "admin": "Admin page",
    "private": "Database or internal tool",
    "other": "Other program",
    "unknown": "Not recognised",
}

KNOWN = {}


def _known(ports, name, kind, what, warn=""):
    for p in ports:
        KNOWN[p] = {"name": name, "kind": kind, "what": what, "warn": warn}


_known([80], "Websites (HTTP)", "web", "Visitors reach your websites through this door. It has to stay open.")
_known([443], "Websites (HTTPS)", "web", "Visitors reach your websites securely through this door. It has to stay open.")
_known([22], "Server login (SSH)", "service",
       "How you and your tools log in to the server's command line.",
       "Only your trusted addresses will be able to log in to the server. If your internet address changes, "
       "you will need your hosting provider's emergency console to get back in.")
_known([21], "File transfer (FTP)", "service", "Lets people upload and download website files with an FTP program.",
       "FTP programs will be refused unless they connect from a trusted address.")
_known([25], "Incoming email (SMTP)", "service", "Receives email sent to your domains from other mail servers.",
       "Email from other servers will stop arriving. Only lock this if this server does not receive email.")
_known([465, 587], "Sending email (SMTP)", "service", "Mail programs and phones send email through this door.",
       "Mail programs and websites that send through this server will be refused unless they are trusted.")
_known([110, 995], "Reading email (POP3)", "service", "Mail programs download email from the server through this door.",
       "Mailboxes can then only be read from trusted addresses.")
_known([143, 993], "Reading email (IMAP)", "service", "Mail programs and phones read email on the server through this door.",
       "Mailboxes can then only be read from trusted addresses.")
_known([4190], "Email filters (Sieve)", "service", "Lets mail programs manage server-side email filters.",
       "Mail programs will not be able to edit filters unless they are trusted.")
_known([53], "Domain names (DNS)", "service", "Answers the question 'where is this website?' for the domains hosted here.",
       "Visitors' computers will no longer be able to look up your websites through this server. "
       "Only lock this if another company hosts your domain names.")
_known([8090], "CyberPanel", "admin", "The control panel where you manage websites, email and databases.")
_known([7080], "LiteSpeed admin page", "admin", "The web server's own settings page.")
_known([8888], "CyberPanel web terminal", "admin",
       "A command line that opens inside CyberPanel, in your browser. Powerful, so it should stay private.")
_known([5678], "CyberPanel web terminal (older versions)", "admin",
       "A command line that opens inside CyberPanel, in your browser. Powerful, so it should stay private.")
_known([2812], "Monit status page", "admin", "A page that shows which programs on the server are running.")
_known([3306], "MySQL / MariaDB database", "private",
       "Stores the content of your websites. Websites on this server reach it from inside, never from outside.")
_known([5432], "PostgreSQL database", "private", "A database. Programs on this server reach it from inside.")
_known([6379], "Redis cache", "private", "A fast memory store used by websites. Meant for this server only.")
_known([11211], "Memcached cache", "private", "A fast memory store used by websites. Meant for this server only.")
_known([27017], "MongoDB database", "private", "A database. Programs on this server reach it from inside.")
_known([9200], "Elasticsearch", "private", "A search database. Meant for programs on this server only.")
_known([2375, 2376], "Docker control", "private",
       "Lets programs start and stop Docker containers. Whoever reaches it can take over the server.")

# programs that give a port away when the port number is not one we know
PROGRAMS = {
    "sshd": ("Server login (SSH)", "service", "How you and your tools log in to the server's command line."),
    "litespeed": ("Web server", "web", "Serves websites."),
    "lshttpd": ("Web server", "web", "Serves websites."),
    "openlitespeed": ("Web server", "web", "Serves websites."),
    "nginx": ("Web server", "web", "Serves websites."),
    "apache2": ("Web server", "web", "Serves websites."),
    "httpd": ("Web server", "web", "Serves websites."),
    "lscpd": ("CyberPanel", "admin", "The control panel where you manage websites, email and databases."),
    "mysqld": ("Database", "private", "A database. Programs on this server reach it from inside."),
    "mariadbd": ("Database", "private", "A database. Programs on this server reach it from inside."),
    "postgres": ("Database", "private", "A database. Programs on this server reach it from inside."),
    "mongod": ("Database", "private", "A database. Programs on this server reach it from inside."),
    "redis-server": ("Redis cache", "private", "A fast memory store used by websites. Meant for this server only."),
    "memcached": ("Memcached cache", "private", "A fast memory store used by websites. Meant for this server only."),
    "pdns_server": ("DNS server control interface", "private",
                    "Lets programs change the DNS records of your domains. Meant for this server only."),
    "dovecot": ("Reading email", "service", "Mail programs read email on the server through this door."),
    "pure-ftpd": ("File transfer (FTP)", "service", "Lets people upload and download website files."),
    "docker-proxy": ("A Docker container", "other", "A program running inside Docker that is published to the internet."),
}

# ports that cannot be locked here, and why
NOT_LOCKABLE_PROGRAMS = {
    "docker-proxy": "Docker opens this port in a way the lock cannot cover. Close it in Docker's own settings, "
                    "or publish it on 127.0.0.1 only.",
}


# ----------------------------------------------------------------------------- reading what is listening
def _scope(host):
    """How far a listening address reaches: everyone, private (inside the provider's network), or server."""
    host = host.strip("[]").split("%")[0]
    if host in ("*", "", "0.0.0.0", "::"):
        return "everyone"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "everyone"                  # do not guess: treat the unknown as exposed
    if ip.is_loopback:
        return "server"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "everyone"


_REACH_RANK = {"server": 0, "private": 1, "everyone": 2}


def listening():
    """Every TCP port something is waiting on: [{'port', 'reach', 'programs'}], or None if it cannot be read."""
    rc, out = util.run(["ss", "-H", "-ltnp"])
    if rc != 0:
        return None
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[3]:
            continue
        host, _, number = parts[3].rpartition(":")
        if not number.isdigit():
            continue
        port = int(number)
        entry = found.setdefault(port, {"port": port, "reach": "server", "programs": []})
        scope = _scope(host)
        if _REACH_RANK[scope] > _REACH_RANK[entry["reach"]]:
            entry["reach"] = scope
        for name in re.findall(r'\("([^"]+)",pid=', line):
            if name not in entry["programs"]:
                entry["programs"].append(name)
    return [found[p] for p in sorted(found)]


def general_firewall():
    """Name of a general firewall that is switched on (it may close more than CP-Security's lock), or ''."""
    rc, out = util.run(["nft", "list", "table", "inet", provision.FW_TABLE])
    if rc == 0 and ("table inet %s" % provision.FW_TABLE) in out and "drop" in out:
        return "CP-Security firewall"
    rc, out = util.run(["systemctl", "is-active", "firewalld"])
    if rc == 0 and out.strip() == "active":
        return "firewalld"
    rc, out = util.run(["ufw", "status"])
    if rc == 0 and "Status: active" in out:
        return "ufw"
    if os.path.exists(config.P.at("/etc/csf/csf.conf")):
        return "CSF"
    return ""


# ----------------------------------------------------------------------------- describing each port
def _identify(port, programs):
    """(name, kind, what, warning) for a port, from its number first and the program second."""
    if port in KNOWN:
        k = KNOWN[port]
        return k["name"], k["kind"], k["what"], k["warn"]
    for prog in programs:
        key = prog if prog in PROGRAMS else next((p for p in PROGRAMS if prog.startswith(p + "-")), None)     # pure-ftpd-mysql
        if key:
            name, kind, what = PROGRAMS[key]
            warn = ""
            if kind == "service":
                warn = "Whatever uses this door will be refused unless it connects from a trusted address."
            elif kind == "web":
                warn = "Websites served on this door will only open for trusted addresses. Visitors will be refused."
            return name, kind, what, warn
    if programs:
        return ("Program: %s" % ", ".join(programs), "unknown",
                "CP-Security does not know this program.", "")
    return "Port %d" % port, "unknown", "CP-Security cannot tell which program uses this door.", ""


def _panel_port():
    p = settings.load()["port"]
    return p if settings.valid_port(p) else None


def _row(port, reach, programs, choices, locked_set):
    name, kind, what, warn = _identify(port, programs)
    panel = _panel_port()
    if panel == port:
        name, kind, what = ("CP-Security panel", "admin", "This control panel. Who may reach it is set on the Settings page.")
    in_lock = port in locked_set
    if port == panel:
        locked_by = "panel" if in_lock else ""
    elif in_lock and port in choices["locked"]:
        locked_by = "you"
    elif in_lock:
        locked_by = "default"
    else:
        locked_by = ""
    accepted = port in choices["accepted"] or port in choices["opened"]
    blocker_text = ""
    for prog in programs:
        if prog in NOT_LOCKABLE_PROGRAMS:
            blocker_text = NOT_LOCKABLE_PROGRAMS[prog]

    if reach is None:
        status, status_text = "idle", "Nothing is listening here right now."
    elif reach == "server":
        status, status_text = "closed", "Only this server itself can reach it."
    elif in_lock:
        status, status_text = "locked", "Only your trusted addresses can reach it."
    elif reach == "private":
        status, status_text = "private", "Only reachable inside your provider's private network."
    else:
        status, status_text = "open", "Anybody on the internet can try to reach it."

    level, advice = "ok", ""
    if status == "open":
        if kind in ("web", "service"):
            level = "ok"
        elif kind == "admin":
            level = "info" if accepted else "warn"
            advice = ("You chose to leave this page open." if port in choices["opened"] else
                      "This is an admin page, so only you should be able to open it. Lock it to your trusted addresses.")
        elif kind == "private":
            level = "info" if accepted else "bad"
            advice = ("Databases and internal tools should not be open to the internet, and nothing on this server "
                      "needs them open from outside. Lock this door here, or make the program listen on 127.0.0.1 only.")
        else:
            level = "info" if accepted else "warn"
            advice = ("If you do not use this from outside the server, lock it. If you do use it, press "
                      "'I know about this' and the warning goes away.")
        if accepted and port not in choices["opened"]:
            advice = "You told CP-Security you know about this door."

    managed = port == panel
    if managed:
        level, advice = "ok", ""            # reachable by a login page is the owner's choice on the Settings page
    fixed_open = port in PROTECTED
    can_lock = (status in ("open", "private") and not fixed_open and not managed and not blocker_text)
    return {
        "port": port, "name": name, "kind": kind, "kind_name": KIND_NAMES[kind], "what": what,
        "programs": list(programs), "reach": reach, "status": status, "status_text": status_text,
        "level": level, "advice": advice, "warn": warn,
        "locked_by": locked_by, "accepted": accepted, "ignored": port in choices["accepted"],
        "can_lock": can_lock,
        "cannot_lock_reason": ("This is where your websites are served. Locking it would take every website offline."
                               if fixed_open else
                               "Who may reach the panel is set on the Settings page." if managed and status != "locked" else
                               blocker_text),
        "can_open": locked_by in ("you", "default"),
        "open_warning": ("This admin page will be reachable by anybody on the internet. Its password still protects it, "
                         "but it will be attacked constantly." if locked_by == "default" else ""),
        "can_accept": (status == "open" and not managed and kind in ("admin", "private", "unknown", "other")
                       and port not in choices["opened"]),
    }


def rows():
    """Every port worth showing, worst first. None when the list of listening programs cannot be read."""
    live = listening()
    if live is None:
        return None
    choices = settings.port_choices()
    locked_set = set(settings.lock_ports())
    seen = set()
    out = []
    for item in live:
        seen.add(item["port"])
        out.append(_row(item["port"], item["reach"], item["programs"], choices, locked_set))
    # a port the owner chose to lock or open must stay on the page even while its program is stopped
    for port in sorted(set(choices["locked"]) | set(choices["opened"])):
        if port not in seen:
            out.append(_row(port, None, [], choices, locked_set))
    out.sort(key=lambda r: (LEVEL_ORDER[r["level"]], r["port"]))
    return out


def state():
    found = rows()
    if found is None:
        return {"supported": False, "ports": [], "counts": {}, "firewall": "", "trusted": len(access.list_admin()),
                "message": "The list of open ports could not be read on this server."}
    counts = {lvl: sum(1 for r in found if r["level"] == lvl) for lvl in LEVEL_ORDER}
    return {"supported": True, "ports": found, "counts": counts, "firewall": general_firewall(),
            "trusted": len(access.list_admin()), "message": ""}


# ----------------------------------------------------------------------------- the owner's choices
def _as_port(value):
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if settings.valid_port(port) else None


def _apply_choices(new_choices, old_choices):
    """Save the choices and load the lock. If the firewall refuses, the old choices come back."""
    settings.save_port_choices(new_choices)
    res = access.apply()
    if not res.ok:
        settings.save_port_choices(old_choices)
        access.apply()
        return Result(False, "Nothing was changed. " + res.message, res.code)
    return Result(True, "ok")


def _in_live_lock(port):
    """Does the firewall table that is loaded right now cover this port? (nft may print 7080-7081 as a range.)"""
    rc, out = util.run(["nft", "list", "table", "inet", access.TABLE])
    if rc != 0:
        return False
    for block in re.findall(r"dport\s*\{([^}]*)\}", out):
        for piece in block.split(","):
            piece = piece.strip()
            lo, _, hi = piece.partition("-")
            if lo.isdigit() and int(lo) <= port <= int(hi if hi.isdigit() else lo):
                return True
    return False


def lock(port, caller_ip=None, confirmed=False):
    """Only trusted addresses may reach this port from now on."""
    port = _as_port(port)
    if port is None:
        return Result(False, "That is not a port number (it must be between 1 and 65535).", "invalid")
    found = rows()
    if found is None:
        return Result(False, "The list of open ports could not be read, so nothing was changed.", "unsupported")
    row = next((r for r in found if r["port"] == port), None)
    if row is None:
        return Result(False, "Nothing is listening on port %d." % port, "not_listening")
    if port in PROTECTED:
        return Result(False, row["cannot_lock_reason"], "protected")
    if row["locked_by"] == "panel" or port == _panel_port():
        return Result(False, "Who may reach the panel is set on the Settings page.", "managed")
    for prog in row["programs"]:
        if prog in NOT_LOCKABLE_PROGRAMS:
            return Result(False, NOT_LOCKABLE_PROGRAMS[prog], "not_supported")
    old = settings.port_choices()
    if row["locked_by"] in ("you", "default"):
        return Result(False, "Port %d is already locked." % port, "already")
    if row["status"] == "closed":
        return Result(False, "Only this server itself can reach port %d already, so there is nothing to lock." % port,
                      "already")

    trusted = [t["address"] for t in access.list_admin()]
    if not trusted:
        return Result(False, "Add at least one trusted address first (yours), or you would lock everybody out.", "no_trusted")
    is_ssh = "sshd" in row["programs"] or port == 22
    if is_ssh and caller_ip and caller_ip not in trusted:
        return Result(False, "Your own address (%s) is not on the trusted list, so locking the server login would "
                             "cut you off. Add your address on the Admin access page first." % caller_ip, "would_lock_you_out")
    if row["warn"] and not confirmed:
        return Result(False, row["warn"], "needs_confirm")

    new = dict(old)
    new["opened"] = [p for p in old["opened"] if p != port]         # re-locking an admin page the owner had opened
    if port not in config.ADMIN_PORTS:
        new["locked"] = sorted(set(old["locked"]) | {port})
    res = _apply_choices(new, old)
    if not res.ok:
        return res
    if not _in_live_lock(port):
        return Result(True, "Port %d is saved as locked, but the firewall does not show it yet. Run a health check." % port)
    return Result(True, "Port %d is now locked: only your trusted addresses can reach it." % port)


def unlock(port, confirmed=False):
    """Stop locking this port."""
    port = _as_port(port)
    if port is None:
        return Result(False, "That is not a port number (it must be between 1 and 65535).", "invalid")
    old = settings.port_choices()
    if port == _panel_port():
        return Result(False, "Who may reach the panel is set on the Settings page.", "managed")
    new = dict(old)
    if port in old["locked"]:
        new["locked"] = [p for p in old["locked"] if p != port]
        done = "Port %d is open to everybody again." % port
    elif port in config.ADMIN_PORTS and port not in old["opened"]:
        if not confirmed:
            return Result(False, "This admin page will be reachable by anybody on the internet. Its password still "
                                 "protects it, but it will be attacked constantly.", "needs_confirm")
        new["opened"] = sorted(set(old["opened"]) | {port})
        done = "Port %d is open to everybody. The lock will not close it again until you lock it." % port
    else:
        return Result(False, "Port %d is not locked." % port, "not_locked")
    res = _apply_choices(new, old)
    return Result(True, done) if res.ok else res


def accept(port, accepted=True):
    """'I know this port is open.' Changes nothing on the server; the advisor just stops mentioning it."""
    port = _as_port(port)
    if port is None:
        return Result(False, "That is not a port number (it must be between 1 and 65535).", "invalid")
    old = settings.port_choices()
    new = dict(old)
    if accepted:
        new["accepted"] = sorted(set(old["accepted"]) | {port})
        settings.save_port_choices(new)
        return Result(True, "Noted. CP-Security will stop warning you about port %d." % port)
    new["accepted"] = [p for p in old["accepted"] if p != port]
    settings.save_port_choices(new)
    return Result(True, "CP-Security will mention port %d again if it stays open." % port)
