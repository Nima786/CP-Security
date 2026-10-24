"""Known security holes: checks every website's plugins, themes and WordPress itself against a public list of
known holes, and says which ones are dangerous and whether an update fixes them.

Why: most WordPress break-ins use a hole in an out-of-date plugin that was already public and already fixed. This is
exactly how this server was broken into in October (the Bricksforge plugin). Knowing which websites have a known hole,
before a bot finds it, is the single most useful warning there is.

Where the list comes from: the free WPVulnerability database (wpvulnerability.net). It needs no account and no key, it
asks nothing about the websites (only "is there anything known about plugin X?"), and it is the community database that
the WordPress security world shares. Only the name and version of each plugin, theme and WordPress itself is looked up;
nothing about the website's content leaves the server.

How it is safe and quiet:
* Reading each website's plugin list is done as that website's own user (WP-CLI), never as root.
* What the database says is kept for a day, so a second look is instant and the database is not hammered.
* A version is only flagged when it really falls inside a known hole's affected range; the newest, fixed version is not.
"""
import copy
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import config, library, updates, util
from .util import Result

API = "https://www.wpvulnerability.net"
CACHE_SECONDS = 24 * 3600
TIMEOUT = 20
_lock = threading.Lock()
_scan = {"status": "idle", "finished": "", "sites": {}}


# ----------------------------------------------------------------------------- the database
def _fetch(url):
    """The database's answer as a dict, or None. Never raises. (Tests replace this.)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CP-Security vulnerability check"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read(4_000_000).decode("utf-8", "replace"))
    except Exception:                                   # network down, bad JSON, anything: treat as "could not ask"
        return None


def _endpoint(kind, slug):
    if kind == "core":
        return "%s/core/%s/" % (API, slug)
    return "%s/%s/%s/" % (API, kind, slug)


def _cache():
    data = util.read_json(config.P.vuln_cache, {})
    return data if isinstance(data, dict) else {}


def _known(kind, slug, refresh=False):
    """The list of known holes for one plugin/theme/core version, from the day's cache or freshly asked. None = could not ask."""
    key = "%s:%s" % (kind, slug)
    now = time.time()
    with _lock:
        entry = _cache().get(key)
    if entry and not refresh and now - entry.get("fetched", 0) < CACHE_SECONDS:
        return entry.get("vulns") or []
    answer = _fetch(_endpoint(kind, slug))
    if answer is None:
        return (entry.get("vulns") or []) if entry else None       # keep yesterday's answer rather than nothing
    data = answer.get("data") or {}
    vulns = data.get("vulnerability") or []
    with _lock:
        full = _cache()
        full[key] = {"fetched": now, "vulns": vulns}
        util.write_json(config.P.vuln_cache, full)
    return vulns


# ----------------------------------------------------------------------------- matching a version
def _side(installed, version, operator, low):
    """Is `installed` on the vulnerable side of one bound? low=True for the minimum bound, False for the maximum."""
    if not version:
        return True                                     # no bound on this side: everything is on the vulnerable side
    cmp = library.version_cmp(installed, version)
    if low:
        return cmp > 0 if operator == "gt" else cmp >= 0     # ge (default) or gt
    return cmp < 0 if operator == "lt" else cmp <= 0         # lt (fixed in `version`) or le


def _affected(installed, op):
    """Does this installed version fall inside one known hole's affected range?"""
    if not installed:
        return False
    return (_side(installed, op.get("min_version"), op.get("min_operator") or "ge", True)
            and _side(installed, op.get("max_version"), op.get("max_operator") or "le", False))


def _truthy(value):
    """The database sends yes/no fields as the strings '0' and '1'; a bare `if value` would read '0' as true."""
    return str(value).strip().lower() not in ("", "0", "false", "no", "none", "null")


def _fix(op):
    """('update' and the version it is fixed in) or ('none', '') when there is no fix yet."""
    if _truthy(op.get("unfixed")):
        return "none", ""
    if (op.get("max_operator") or "le") == "lt" and op.get("max_version"):
        return "update", op["max_version"]               # versions below max_version are vulnerable: fixed in max_version
    return "update", ""                                  # a fix exists but the exact version is not stated


def _severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown", 0.0
    if s >= 9:
        return "critical", s
    if s >= 7:
        return "high", s
    if s >= 4:
        return "medium", s
    if s > 0:
        return "low", s
    return "unknown", 0.0


RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def check_item(kind, slug, installed, refresh=False):
    """Known holes that this exact installed version is open to: a list of plain findings (may be empty). None = could not ask."""
    known = _known(kind, slug, refresh)
    if known is None:
        return None
    out = []
    for hole in known:
        op = hole.get("operator") or {}
        if not _affected(installed, op):
            continue
        fix, fixed_version = _fix(op)
        level, score = _severity(((hole.get("impact") or {}).get("cvss") or {}).get("score"))
        ids = [s.get("id") for s in (hole.get("source") or []) if (s.get("id") or "").upper().startswith("CVE")]
        out.append({"title": hole.get("name") or slug, "severity": level, "score": score,
                    "fix": fix, "fixed_version": fixed_version, "cve": ids[0] if ids else ""})
    out.sort(key=lambda f: (-RANK[f["severity"]], -f["score"]))
    return out


# ----------------------------------------------------------------------------- one website
def _core_version(site, php):
    from . import wpupdate
    rc, out = wpupdate._wp(site, php, "core version", 60)
    for line in reversed((out or "").strip().splitlines()):
        line = line.strip()
        if line and line[0].isdigit():
            return line
    return ""


def _inspect(name, refresh=False):
    """{'site', 'checked', 'problem', 'items':[{kind, slug, name, version, status, holes:[...]}], 'asked_ok'}."""
    from . import wpupdate
    out = {"site": name, "checked": False, "problem": "", "items": [], "asked_ok": True}
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        out["problem"] = "WordPress could not be started on this website."
        return out
    inv = library._read_site(name)
    if not inv.get("checked"):
        out["problem"] = "The list of plugins and themes could not be read."
        return out
    out["checked"] = True
    targets = []
    core = _core_version(site, php)
    if core:
        targets.append(("core", core, "WordPress itself", core, "active"))
    for kind in ("plugin", "theme"):
        for slug, info in sorted(inv.get(kind, {}).items()):
            targets.append((kind, slug, slug, info.get("version") or "", info.get("status") or ""))
    for kind, slug, title, version, status in targets:
        holes = check_item(kind, slug, version, refresh)
        if holes is None:
            out["asked_ok"] = False
            continue
        if holes:
            out["items"].append({"kind": kind, "slug": slug, "name": title, "version": version, "status": status, "holes": holes})
    out["items"].sort(key=lambda i: (-RANK[i["holes"][0]["severity"]], -i["holes"][0]["score"], i["kind"], i["slug"]))
    return out


def _worst(items):
    return max([RANK[h["severity"]] for i in items for h in i["holes"]] + [0])


# ----------------------------------------------------------------------------- the list for the page
def _names():
    return sorted(n for _d, _u, n in updates._wordpress_sites())


def scan_state():
    with _lock:
        return copy.deepcopy(_scan)


def scan_start(refresh=False):
    with _lock:
        if _scan["status"] == "running":
            return Result(False, "Already checking the websites.", "busy")
        _scan["status"] = "running"
    threading.Thread(target=_scan_run, args=(refresh,), daemon=True).start()
    return Result(True, "Checking the websites for known holes.")


def _inspect_safe(name, refresh):
    try:
        return _inspect(name, refresh)
    except Exception as exc:                            # one website must never hide the others
        return {"site": name, "checked": False, "problem": "Checking this website failed (%s)." % str(exc)[:80],
                "items": [], "asked_ok": True}


def _scan_run(refresh):
    try:
        try:
            names = _names()
        except (ImportError, OSError):
            names = []
        with ThreadPoolExecutor(max_workers=3) as ex:
            results = list(ex.map(lambda n: _inspect_safe(n, refresh), names))
        with _lock:
            _scan["sites"] = {r["site"]: r for r in results}
    finally:
        with _lock:
            _scan["status"] = "done"
            _scan["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


LEVELS = ("critical", "high", "medium", "low", "unknown")


def state(names=None):
    """For the page: one line per website, worst first, with how many holes and how many are fixable by updating."""
    names = names if names is not None else _names()
    scan = scan_state()
    sites = []
    totals = {k: 0 for k in LEVELS}
    any_unasked = False
    for name in names:
        s = scan["sites"].get(name) or {"checked": False, "problem": "", "items": [], "asked_ok": True}
        counts = {k: 0 for k in LEVELS}
        fixable = 0
        for item in s.get("items", []):
            for hole in item["holes"]:
                counts[hole["severity"]] += 1
                totals[hole["severity"]] += 1
            if any(h["fix"] == "update" for h in item["holes"]):
                fixable += 1
        any_unasked = any_unasked or not s.get("asked_ok", True)
        sites.append({"site": name, "checked": s.get("checked", False), "problem": s.get("problem", ""),
                      "asked_ok": s.get("asked_ok", True), "items": s.get("items", []), "counts": counts,
                      "fixable": fixable, "worst": _worst(s.get("items", []))})
    sites.sort(key=lambda r: (-r["worst"], r["site"]))
    return {"scan": {"status": scan["status"], "finished": scan["finished"]}, "sites": sites,
            "totals": totals, "any_unasked": any_unasked}
