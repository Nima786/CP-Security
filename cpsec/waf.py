"""The web firewall: the OWASP rules running inside the LiteSpeed (or OpenLiteSpeed) web server.

Three modes:
  off    nothing is checked
  watch  suspicious requests are recorded, nobody is refused
  block  requests that score too high are refused with "403 Forbidden"

Every change restarts the web server gracefully, then checks that the websites still answer.
If one does not, the change is undone automatically.

The web server's own file only gets one line that points to our main.conf (see webserver.py).
The on/off state, the log settings and the list of rule files all live in our own folder.
"""
import datetime
import os
import re
import socket
import ssl
import time
import uuid

from . import access, config, sites, util, webserver
from .util import Result

MODE_TEXT = {
    "off": "OFF - the web firewall does nothing",
    "watch": "WATCH ONLY - records suspicious requests, blocks nothing",
    "block": "BLOCKING - refuses requests that look like attacks",
}
MODE_SHORT = {"off": "Off", "watch": "Watch only", "block": "Blocking"}

WATCH_BLOCK = "# Watch-only mode: nothing is blocked. Written by CP-Security.\n"
BLOCK_TEMPLATE = (
    "# Blocking mode. Written by CP-Security.\n"
    "# A request is refused when the rules found enough suspicious things in it (score %d or more).\n"
    "SecRule TX:ANOMALY_SCORE_PL1 \"@ge %d\" \"id:1000900,phase:2,deny,status:403,log,auditlog,"
    "msg:'Request blocked by the web firewall'\"\n"
)
HOST_OK = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")

MAIN_TEMPLATE = (
    "# CP-Security web firewall. Written by CP-Security: change it from the panel or the menu, not by hand.\n"
    "SecRuleEngine %(engine)s\n"
    "SecAuditEngine On\n"
    "SecAuditLogParts ABH\n"
    "SecAuditLogType Serial\n"
    "SecAuditLog %(audit)s\n"
    "Include %(rules)s\n"
)


def render_main(engine):
    """The text of our main file. engine: 'On' or 'Off'."""
    return MAIN_TEMPLATE % {"engine": engine, "audit": config.P.audit_log, "rules": config.P.waf_rules}


# ----------------------------------------------------------------------------- state
def installed():
    p = config.P
    return all(os.path.exists(x) for x in (p.waf_main, p.waf_rules, p.waf_block)) and webserver.hook_present()


def mode():
    """'off', 'watch', 'block', or None when the web firewall was never set up."""
    if not installed():
        return None
    conf = util.read_text(config.P.waf_main)
    m = re.search(r"^\s*SecRuleEngine\s+(\w+)", conf, re.M | re.I)
    if not m or m.group(1).lower() != "on":
        return "off"
    blk = util.read_text(config.P.waf_block)
    return "block" if re.search(r"^\s*SecRule\b", blk, re.M) else "watch"


def threshold():
    return int(util.read_json(config.P.waf_settings, {}).get("threshold", 5))


def state():
    """(ok flag, short text) for the health check. ok is None when it is simply not in use."""
    m = mode()
    if m is None:
        return None, "not set up"
    if m == "off":
        return None, MODE_TEXT["off"]
    return True, MODE_TEXT[m]


# ----------------------------------------------------------------------------- applying changes
def restart_and_check():
    """Gracefully restart the web server and make sure the websites still answer."""
    webserver.restart()
    time.sleep(10)
    bad = []
    for d in sites.sample_for_check():
        code = sites.check_site(d)[1]
        if not sites.is_ok(code):
            bad.append((d, code))
    return (not bad), bad


def _commit(snap, label):
    """The files are written. Restart; undo everything if a site stops answering."""
    ok, bad = restart_and_check()
    if ok:
        return Result(True, label)
    util.restore(snap)
    restart_and_check()
    return Result(False, "A website stopped answering normally (%s), so everything was put back as it was."
                  % ", ".join("%s %s" % x for x in bad[:3]), "rolled_back")


def set_mode(new_mode, new_threshold=None):
    if new_mode not in MODE_TEXT:
        return Result(False, "Unknown mode.", "invalid")
    if not installed():
        return Result(False, "The web firewall is not set up on this server.", "not_installed")
    p = config.P
    snap = util.snapshot([p.waf_main, p.waf_block, p.waf_settings])
    try:
        t = threshold() if new_threshold is None else int(new_threshold)
    except (TypeError, ValueError):
        return Result(False, "The strictness must be a number between 1 and 100.", "invalid")
    if t < 1 or t > 100:
        return Result(False, "The strictness must be between 1 and 100.", "invalid")
    util.atomic_write(p.waf_main, render_main("Off" if new_mode == "off" else "On"), 0o644, "lsadm:lsadm")
    util.atomic_write(p.waf_block, BLOCK_TEMPLATE % (t, t) if new_mode == "block" else WATCH_BLOCK, 0o640, "lsadm:lsadm")
    old = util.read_json(p.waf_settings, {})
    since = old.get("since") if old.get("mode") == new_mode and old.get("since") else datetime.date.today().isoformat()
    util.write_json(p.waf_settings, {"threshold": t, "mode": new_mode, "since": since})
    return _commit(snap, "The web firewall is now: " + MODE_TEXT[new_mode] + ".")


def mode_since():
    """The day the current mode was chosen (a date) or None."""
    try:
        return datetime.date.fromisoformat(util.read_json(config.P.waf_settings, {}).get("since", ""))
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- exceptions
def list_exceptions():
    return util.read_json(config.P.waf_exceptions, [])


def _write_exception_files(items):
    before = ["# Per-website exceptions. Written by CP-Security.\n"]
    after = ["# Rules switched off for every website. Written by CP-Security.\n"]
    n = 0
    for e in items:
        site, rule = e.get("site", ""), str(e.get("rule", ""))
        if site == "*":
            if rule.isdigit():
                after.append("SecRuleRemoveById %s\n" % rule)
            continue
        if not HOST_OK.match(site) or not (rule == "ALL" or rule.isdigit()):
            continue
        n += 1
        pattern = r"^(?:www\.)?" + site.replace(".", r"\.") + r"(?::\d+)?$"
        action = "ctl:ruleEngine=Off" if rule == "ALL" else "ctl:ruleRemoveById=%s" % rule
        before.append('SecRule REQUEST_HEADERS:Host "@rx %s" "id:%d,phase:1,pass,nolog,%s"\n' % (pattern, 1100000 + n, action))
    util.atomic_write(config.P.waf_before, "".join(before), 0o640, "lsadm:lsadm")
    util.atomic_write(config.P.waf_after, "".join(after), 0o640, "lsadm:lsadm")


def set_exceptions(items, label):
    p = config.P
    snap = util.snapshot([p.waf_before, p.waf_after, p.waf_exceptions])
    util.write_json(p.waf_exceptions, items)
    _write_exception_files(items)
    return _commit(snap, label)


def add_exception(scope, host, rule):
    """scope: 'site' (one rule, one website), 'all' (one rule, every website), 'site_off' (firewall off for a website)."""
    items = list_exceptions()
    if scope == "all":
        if not str(rule).isdigit():
            return Result(False, "That is not a rule number.", "invalid")
        entry, label = {"site": "*", "rule": str(rule)}, "Rule %s is now allowed on every website." % rule
    elif scope == "site":
        if not HOST_OK.match(host or "") or not str(rule).isdigit():
            return Result(False, "That is not a valid website or rule.", "invalid")
        entry, label = {"site": host, "rule": str(rule)}, "Rule %s is now allowed on %s." % (rule, host)
    elif scope == "site_off":
        if not HOST_OK.match(host or ""):
            return Result(False, "That is not a valid website.", "invalid")
        entry, label = {"site": host, "rule": "ALL"}, "The web firewall is now off for %s." % host
    else:
        return Result(False, "Unknown choice.", "invalid")
    if entry in items:
        return Result(False, "That exception already exists.", "exists")
    return set_exceptions(items + [entry], label)


def remove_exception(index):
    items = list_exceptions()
    if not (0 <= index < len(items)):
        return Result(False, "That exception does not exist.", "missing")
    gone = items.pop(index)
    return set_exceptions(items, "Exception removed (%s)." % gone["site"])


# ----------------------------------------------------------------------------- what it recorded
A_RE = re.compile(r"^\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+\d+")
ID_RE = re.compile(r'\[id "(\d+)"\]')
MSG_RE = re.compile(r'\[msg "([^"]*)"\]')


def parse_audit_text(text):
    """Turn the firewall's log into one event per request (the log has one record per matched rule)."""
    txs, tx, part = [], None, None
    for line in text.split("\n"):
        m = re.match(r"^--([0-9a-f]+)-([A-Z])--$", line)
        if m:
            part = m.group(2)
            if part == "A":
                tx = {"A": [], "B": [], "H": []}
                txs.append(tx)
            continue
        if tx is not None and part in ("A", "B", "H"):
            tx[part].append(line)
    events = []
    for t in txs:
        a = A_RE.match(t["A"][0]) if t["A"] else None
        if not a or not t["B"]:
            continue
        try:
            when = datetime.datetime.strptime(a.group(1).split()[0], "%d/%b/%Y:%H:%M:%S")
        except (ValueError, IndexError):
            continue
        reqline = t["B"][0].strip()
        parts = reqline.split(" ")
        host = ""
        for ln in t["B"][1:]:
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip().lower()
                break
        path = parts[1].split("?")[0] if len(parts) > 1 else reqline
        hits, blocked = [], False
        for ln in t["H"]:
            # any line that names a rule counts; the two web servers word the start of the line differently
            i = ID_RE.search(ln)
            if i:
                mm = MSG_RE.search(ln)
                rid = i.group(1)
                if rid == "1000900":
                    blocked = True
                elif int(rid) < 1000000:
                    hits.append((rid, mm.group(1) if mm else ""))
            elif ln.startswith("Action: Intercepted"):
                blocked = True
        if hits or blocked:
            events.append({"id": a.group(2), "when": when, "ip": a.group(3), "host": host,
                           "method": parts[0], "path": path, "hits": hits, "blocked": blocked})
    merged, by_id = [], {}
    for e in events:
        prev = by_id.get(e["id"])
        if prev is None:
            by_id[e["id"]] = e
            merged.append(e)
        else:
            prev["hits"].extend(e["hits"])
            prev["blocked"] = prev["blocked"] or e["blocked"]
    return merged


def audit_tail(max_mb=30):
    """The last part of the firewall's log as text ('' when there is none)."""
    try:
        with open(config.P.audit_log, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - int(max_mb * 1024 * 1024)))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def parse_audit(max_mb=30):
    return parse_audit_text(audit_tail(max_mb))


# ----------------------------------------------------------------------------- does it really work?
def _send_probe(domain, token):
    """Send one attack-looking request to the local web server. Returns the HTTP status or None."""
    path = "/cps-selftest-%s?id=1%%27%%20UNION%%20SELECT%%20NULL" % token
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: cp-security-selftest\r\n"
               "Connection: close\r\n\r\n" % (path, domain)).encode("ascii")
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                s.sendall(request)
                data = b""
                while len(data) < 4096:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
    except (OSError, ssl.SSLError):
        return None
    m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", data)
    return int(m.group(1)) if m else None


def selftest(domain=None, sender=None, token=None, wait=2.0):
    """Prove the firewall sees attacks.

    Sends one harmless request that merely LOOKS like an attack, to a web address nobody has asked for
    before (the page cache never holds those), then looks for it in the firewall's log.
    """
    m = mode()
    if m in (None, "off"):
        return Result(False, "The web firewall is not switched on, so there is nothing to test.", "not_active")
    if domain is None:
        sample = sites.sample_for_check(1)
        if not sample:
            return Result(False, "No website was found to test with.", "no_site")
        domain = sample[0]
    token = token or uuid.uuid4().hex[:12]
    status = (sender or _send_probe)(domain, token)
    if status is None:
        return Result(False, "The web server did not answer the test request.", "no_answer")
    time.sleep(wait)
    if token not in audit_tail(2):
        return Result(False, "The test request went through, but the firewall did not record it. "
                             "It may not be loaded by the web server. Check the Advisor page.", "not_seen")
    blocked = status in (403, 406)
    if m == "block" and not blocked:
        return Result(True, "The firewall saw the test request, but let it through (it scored below your "
                            "strictness level).", "seen_not_blocked")
    return Result(True, "The firewall saw the test request%s." % (" and refused it" if blocked else ""), "seen")


def trusted_ips():
    return set(a["address"] for a in access.list_admin()) | \
        set(a["address"] for a in access.list_never_block() if "/" not in a["address"])


def summary(events=None, now=None):
    ev = parse_audit() if events is None else events
    now = now or datetime.datetime.now()
    trusted = trusted_ips()
    out = {"mode": mode(), "periods": {}, "trusted_hits": sum(1 for e in ev if e["ip"] in trusted)}
    for label, hours in (("day", 24), ("week", 168)):
        sub = [e for e in ev if (now - e["when"]).total_seconds() <= hours * 3600]
        rules, sites_hit = {}, {}
        for e in sub:
            for rid, msg in set(e["hits"]):
                r = rules.setdefault(rid, {"rule": rid, "message": msg, "count": 0})
                r["count"] += 1
            sites_hit[e["host"]] = sites_hit.get(e["host"], 0) + 1
        out["periods"][label] = {
            "requests": len(sub),
            "addresses": len(set(e["ip"] for e in sub)),
            "blocked": sum(1 for e in sub if e["blocked"]),
            "rules": sorted(rules.values(), key=lambda r: -r["count"])[:8],
            "sites": [{"site": s, "count": n} for s, n in sorted(sites_hit.items(), key=lambda kv: -kv[1])[:5]],
        }
    return out


def recent(limit=15, events=None):
    """Recent hits grouped by website, page and rule. Hits from trusted addresses come first (likely false alarms)."""
    ev = parse_audit() if events is None else events
    trusted = trusted_ips()
    groups = {}
    for e in sorted(ev, key=lambda x: x["when"], reverse=True):
        for rid, msg in (set(e["hits"]) or [("blocked", "Blocked request")]):
            key = (e["host"], e["path"], rid)
            g = groups.setdefault(key, {"host": e["host"], "path": e["path"], "rule": rid, "message": msg,
                                        "count": 0, "last": e["when"], "trusted": False, "blocked": False})
            g["count"] += 1
            g["trusted"] = g["trusted"] or e["ip"] in trusted
            g["blocked"] = g["blocked"] or e["blocked"]
    ordered = sorted(groups.values(), key=lambda g: (not g["trusted"], -g["last"].timestamp()))[:limit]
    for g in ordered:
        g["last"] = g["last"].strftime("%Y-%m-%d %H:%M:%S")
    return ordered
