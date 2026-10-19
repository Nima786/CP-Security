"""The attack blocker (fail2ban): who is blocked, letting people back in, and how well it is running."""
import datetime
import glob
import gzip
import ipaddress
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
