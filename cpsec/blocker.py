"""The attack blocker (fail2ban): who is blocked, letting people back in, and how well it is running."""
import datetime
import glob
import gzip
import ipaddress
import os
import re
import shutil

from . import config, util
from .util import Result


def installed():
    return shutil.which("fail2ban-client") is not None


def jails():
    """Names of the running protections, or None when the blocker is not running."""
    rc, out = util.run(["fail2ban-client", "status"])
    m = re.search(r"Jail list:\s*(.*)", out)
    if rc != 0 or not m:
        return None
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def banned_count(jail):
    rc, out = util.run(["fail2ban-client", "status", jail])
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return int(m.group(1)) if m else 0


def service_enabled():
    rc, out = util.run(["systemctl", "is-enabled", "fail2ban"])
    return out.strip() == "enabled"


def feed_active():
    """The helper that copies WordPress login attempts for the blocker."""
    rc, out = util.run(["systemctl", "is-active", "cps-wplogin-feed.service"])
    return out.strip() == "active"


def status():
    names = jails()
    return {
        "installed": installed(),
        "running": names is not None,
        "jails": names or [],
        "banned_now": sum(banned_count(j) for j in names) if names else 0,
        "enabled_at_boot": service_enabled() if installed() else False,
        "feed_active": feed_active(),
        "recent_errors": recent_errors(),
    }


def recent_errors():
    """True if the blocker wrote an internal 'unhandled exception' line today or yesterday."""
    try:
        with open(config.P.f2b_log, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 400000))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return False
    today = datetime.date.today()
    days = (today.isoformat(), (today - datetime.timedelta(days=1)).isoformat())
    return any(ln[:10] in days and re.search(r"unhandled exception|terminating", ln, re.I)
               for ln in tail.splitlines())


def _until_info(until):
    """('never' | 'YYYY-MM-DD HH:MM:SS' | '') -> seconds left (None = permanent or unknown)."""
    if not until or until == "never":
        return None
    try:
        dt = datetime.datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return max(0, int((dt - datetime.datetime.now()).total_seconds()))


def nice_until(until):
    """A short phrase for people: 'in 12 min', 'in 5 hours', 'never (permanent)'."""
    if until == "never":
        return "never (permanent)"
    if not until:
        return ""
    secs = _until_info(until)
    if secs is None:
        return until
    if secs <= 0:
        return "any moment now"
    if secs < 3600:
        return "in %d min" % max(1, round(secs / 60))
    if secs < 48 * 3600:
        return "in %.0f hours" % (secs / 3600)
    return datetime.datetime.strptime(until, "%Y-%m-%d %H:%M:%S").strftime("%d %b")


def banned_with_time(jail):
    rc, out = util.run(["fail2ban-client", "get", jail, "banip", "--with-time"])
    rows = []
    if rc != 0:
        # older versions cannot show the end time: list the addresses only
        rc2, out2 = util.run(["fail2ban-client", "status", jail])
        m = re.search(r"Banned IP list:\s*(.*)", out2)
        if m:
            rows.extend((ip, jail, "") for ip in m.group(1).split())
        return rows
    for line in out.splitlines():
        m = re.match(r"^\s*(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s*\+\s*(-?\d+)\s*=\s*"
                     r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
        if m:
            rows.append((m.group(1), jail, m.group(4) if int(m.group(3)) >= 0 else "never"))
        else:
            m2 = re.match(r"^\s*([0-9a-fA-F:.]+)\s*$", line)
            if m2:
                rows.append((m2.group(1), jail, ""))
    return rows


def all_blocked():
    """Everyone blocked right now, soonest-to-be-released first. None when the blocker is not running."""
    names = jails()
    if names is None:
        return None
    rows = []
    for j in names:
        rows.extend(banned_with_time(j))
    rows.sort(key=lambda r: (r[2] == "never", r[2]))
    return [{"ip": ip, "jail": jail, "why": config.JAIL_NAMES.get(jail, jail), "until": until,
             "until_text": nice_until(until), "seconds_left": _until_info(until)}
            for ip, jail, until in rows]


def unban(ip):
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return Result(False, "That does not look like an address: %s" % ip, "invalid")
    ip = ip.strip()
    rc, out = util.run(["fail2ban-client", "unban", ip])
    last = out.strip().splitlines()[-1] if out.strip() else ""
    if rc == 0 and last and last != "0":
        return Result(True, "%s can get in again." % ip)
    return Result(False, "%s was not blocked right now." % ip, "not_blocked")


def unban_all():
    rc, out = util.run(["fail2ban-client", "unban", "--all"])
    if rc == 0:
        return Result(True, "Everybody can get in again.")
    return Result(False, "Could not let everybody back in: " + out.strip()[:200], "failed")


def set_running(running):
    """Emergency switch: stop (or start) all automatic blocking."""
    if running:
        rc, out = util.run(["systemctl", "start", "fail2ban"], timeout=90)
        return Result(rc == 0, "Automatic blocking is on again." if rc == 0 else "Could not start it: " + out.strip()[:200])
    rc, out = util.run(["systemctl", "stop", "fail2ban"], timeout=90)
    return Result(rc == 0, "Automatic blocking is stopped. Nobody is blocked any more." if rc == 0
                  else "Could not stop it: " + out.strip()[:200])


BAN_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ \S+\s+\[\d+\]:\s+\w+\s+\[([^\]]+)\] "
                    r"(?:Increase )?Ban (\S+)")


def ban_events(days):
    """[(when, jail, ip)] for the last N days, read from the blocker's log (and its rotated copies)."""
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    events = []
    for path in sorted(glob.glob(config.P.f2b_log + "*")):
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", errors="replace") as f:
                for line in f:
                    if "Ban " not in line:
                        continue
                    m = BAN_RE.match(line)
                    if not m:
                        continue
                    when = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                    if when >= cutoff:
                        events.append((when, m.group(2), m.group(3)))
        except OSError:
            continue
    return events


def recent_summary():
    """Counts for the last 24 hours and 7 days, ready to show."""
    ev7 = ban_events(7)
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
    ev1 = [e for e in ev7 if e[0] >= cutoff]

    def pack(ev):
        by_jail = {}
        for _, jail, _ in ev:
            by_jail[jail] = by_jail.get(jail, 0) + 1
        return {"blocks": len(ev), "addresses": len(set(e[2] for e in ev)),
                "by_reason": [{"jail": j, "why": config.JAIL_NAMES.get(j, j), "count": n}
                              for j, n in sorted(by_jail.items(), key=lambda kv: -kv[1])]}

    tops = {}
    for _, _, ip in ev7:
        tops[ip] = tops.get(ip, 0) + 1
    return {"day": pack(ev1), "week": pack(ev7),
            "top_addresses": [{"ip": ip, "times": n} for ip, n in sorted(tops.items(), key=lambda kv: -kv[1])[:5]]}


# ----------------------------------------------------------------------------- the protections we install
# What each protection watches, in the blocker's own language. Written to /etc/fail2ban when set up.
FILTER_WP_LOGIN = """# Written by CP-Security.
# Reads the tidy file made by the cps-wplogin-feed helper: one line per failed WordPress login.
[Definition]
failregex = WPLOGIN <HOST> \\S+ \\d{3}\\s*$
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S
ignoreregex =
"""
FILTER_MAIL_AUTH = """# Written by CP-Security.
# Wrong passwords on the mail server (Postfix).
[INCLUDES]
before = common.conf

[Definition]
_daemon = postfix(-\\w+)?/(?:submission/|smtps/)?smtp[ds]
failregex = ^%(__prefix_line)swarning: [-._\\w]+\\[<HOST>\\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed(?::.*)?\\s*$
ignoreregex =
"""
FILTER_PANEL = """# Written by CP-Security.
# Wrong passwords on the CP-Security panel itself.
[Definition]
failregex = LOGIN_FAILED ip=<HOST> user=\\S*\\s*$
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S
ignoreregex =
"""
OWN_FILTERS = {"cps-wp-login": FILTER_WP_LOGIN, "cps-mail-auth": FILTER_MAIL_AUTH, "cps-panel": FILTER_PANEL}

TUNABLE = ("sshd", "cps-wp-login", "cps-mail-auth", "dovecot", "pure-ftpd", "cps-panel")
DEFAULT_TUNING = {name: {"maxretry": 5, "findtime": 600, "bantime": 3600} for name in TUNABLE}
LIMITS = {"maxretry": (2, 50), "findtime": (60, 86400), "bantime": (60, 2592000)}
PORTS = {
    "cps-wp-login": "http,https",
    "cps-mail-auth": "25,465,587,143,993,110,995",
}
BAN_ACTIONS = "banaction = nftables-multiport\nbanaction_allports = nftables-allports\n"

LOGROTATE = """# Written by CP-Security.
%s {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
"""


def tuning():
    """The numbers for every protection: defaults, then whatever the owner changed."""
    stored = util.read_json(config.P.blocker_settings, {})
    out = {}
    for name in TUNABLE:
        merged = dict(DEFAULT_TUNING[name])
        for key, value in (stored.get(name) or {}).items():
            if key in merged and isinstance(value, int) and not isinstance(value, bool):
                merged[key] = value
        out[name] = merged
    return out


def _first_existing(paths):
    for p in paths:
        if os.path.exists(config.P.at(p)):
            return config.P.at(p)
    return None


def log_for(jail):
    """The log file a protection reads, or None when this server has no such log (the protection is skipped)."""
    if jail == "cps-wp-login":
        return config.P.wplogin_log
    if jail == "cps-panel":
        return config.P.panel_log
    if jail in ("cps-mail-auth", "dovecot"):
        return _first_existing(("/var/log/mail.log", "/var/log/maillog"))
    if jail == "pure-ftpd":
        return _first_existing(("/var/log/pure-ftpd/pure-ftpd.log", "/var/log/syslog", "/var/log/messages"))
    return None                                             # sshd: the blocker already knows where to look


def render_jails():
    """The text of our jail file and the list of protections left out because their log does not exist."""
    numbers = tuning()
    out = ["# Written by CP-Security. Change the numbers in the panel (Settings), not here.\n"]
    skipped = []
    for name in TUNABLE:
        logpath = log_for(name)
        if name != "sshd" and not logpath:
            skipped.append(name)
            out.append("\n# %s: left out, this server has no log file for it\n" % name)
            continue
        n = numbers[name]
        lines = ["", "[%s]" % name, "enabled = true"]
        if name in OWN_FILTERS:
            lines.append("filter = %s" % name)
        if logpath:
            lines.append("logpath = %s" % logpath)
        if name in PORTS:
            lines.append("port = %s" % PORTS[name])
        lines += ["maxretry = %d" % n["maxretry"], "findtime = %d" % n["findtime"], "bantime = %d" % n["bantime"]]
        out.append("\n".join(lines) + "\n" + BAN_ACTIONS)
    return "".join(out), skipped


def write_config():
    """Write our filters, our jail file and the log-rotation rules; check them; reload the blocker.

    Everything is put back if the blocker does not accept it. Returns a Result.
    """
    p = config.P
    own = [p.f2b_filter_dir + "/%s.conf" % n for n in OWN_FILTERS] + [p.f2b_jails]
    snap = util.snapshot(own)
    for name, text in OWN_FILTERS.items():
        util.atomic_write(p.f2b_filter_dir + "/%s.conf" % name, text)
    jails_text, skipped = render_jails()
    util.atomic_write(p.f2b_jails, jails_text)
    for path in (p.wplogin_log, p.panel_log):                # a missing log would stop the whole blocker from starting
        if not os.path.exists(path):
            util.atomic_write(path, "", 0o640)
    rc, out = util.run(["fail2ban-client", "-t"], timeout=90)
    if rc != 0:
        util.restore(snap)
        return Result(False, "The blocker rejected the new settings, so nothing was changed: " + out.strip()[-200:],
                      "f2b_rejected")
    if jails() is not None:
        rc, out = util.run(["fail2ban-client", "reload"], timeout=90)
        if rc != 0:
            util.restore(snap)
            util.run(["fail2ban-client", "reload"], timeout=90)
            return Result(False, "The blocker would not reload, so the old settings were put back.", "reload_failed")
    note = (" Left out because this server has no log for them: %s." % ", ".join(skipped)) if skipped else ""
    return Result(True, "The blocker settings are in place." + note)


def set_tuning(changes):
    """changes: {jail: {maxretry, findtime, bantime}} - any of the three. Checked, saved, applied."""
    stored = util.read_json(config.P.blocker_settings, {})
    for jail, values in (changes or {}).items():
        if jail not in TUNABLE or not isinstance(values, dict):
            return Result(False, "Unknown protection: %s" % jail, "invalid")
        entry = dict(stored.get(jail) or {})
        for key, value in values.items():
            if key not in LIMITS:
                return Result(False, "Unknown setting: %s" % key, "invalid")
            if isinstance(value, bool) or not isinstance(value, int):
                return Result(False, "%s must be a whole number." % key, "invalid")
            low, high = LIMITS[key]
            if not low <= value <= high:
                return Result(False, "%s must be between %d and %d." % (key, low, high), "invalid")
            entry[key] = value
        stored[jail] = entry
    old = util.read_json(config.P.blocker_settings, None)
    util.write_json(config.P.blocker_settings, stored)
    res = write_config()
    if not res.ok:
        if old is None:
            try:
                os.remove(config.P.blocker_settings)
            except OSError:
                pass
        else:
            util.write_json(config.P.blocker_settings, old)
    return res if not res.ok else Result(True, "Saved. The blocker uses the new numbers now.")
