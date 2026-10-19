"""Security headers: small instructions every website sends to every visitor's browser.

They protect visitors and the site's reputation (against being shown inside another page, against browsers
guessing file types, against leaking addresses, and so on). They do not stop a break-in.

How it works (LiteSpeed Enterprise, Apache-style .htaccess):
* the owner chooses defaults and, if needed, different choices for single websites;
* "apply" writes ONE marked block at the top of the website's .htaccess (see htfile.py) and nothing else;
* a header the website already sets itself is left alone unless the owner asks to take it over;
* after every change the panel asks the website for its home page: if it stopped answering, or the web server
  ignored the headers, the file is put back exactly as it was;
* the file work is done as the website's own user, never as root (see htfile.py for why).

OpenLiteSpeed ignores header lines in .htaccess, so it needs a different method (not built yet).
"""
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, htfile, sites, util, webserver
from .util import Result

HSTS_CHOICES = [(0, "Off"), (86400, "1 day"), (604800, "1 week"), (15552000, "6 months"), (31536000, "1 year")]
HSTS_SECONDS = [s for s, _ in HSTS_CHOICES]
PACKAGE_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PERMISSIONS_VALUE = "camera=(), microphone=(), geolocation=()"
BACKUPS_KEPT = 5

# id, header name, short label, title, what it does, risk, switched on by default
ITEMS = [
    {"id": "nosniff", "name": "X-Content-Type-Options", "short": "File types",
     "title": "Browsers must not guess file types",
     "what": "Stops a browser from treating an uploaded file as something it is not, for example running a picture as a script.",
     "risk": "", "default": True},
    {"id": "frame", "name": "X-Frame-Options", "short": "Framing",
     "title": "Other websites cannot show your pages inside theirs",
     "what": "Stops 'clickjacking': a trick where your page is hidden inside another one so visitors click on it without knowing.",
     "risk": "Turn it off for a website that other sites must be able to show in a frame (some payment or booking pages).",
     "default": True},
    {"id": "referrer", "name": "Referrer-Policy", "short": "Referrer",
     "title": "Share less about where visitors came from",
     "what": "When a visitor follows a link to another site, only your site's name is passed on, not the full page address.",
     "risk": "", "default": True},
    {"id": "permissions", "name": "Permissions-Policy", "short": "Browser features",
     "title": "Switch off camera, microphone and location for your pages",
     "what": "Pages cannot ask for these, even if a hacked script tries to.",
     "risk": "Turn it off for a website that really uses the visitor's location, camera or microphone (a store finder, for example).",
     "default": True},
    {"id": "hide_powered", "name": "X-Powered-By", "short": "Hidden tech",
     "title": "Hide the name of the technology behind the website",
     "what": "Removes the 'powered by PHP' label that helps attackers choose tools for your exact version.",
     "risk": "", "default": True},
    {"id": "hsts", "name": "Strict-Transport-Security", "short": "Secure only",
     "title": "Always use the secure address (HTTPS)",
     "what": "Tells a browser that has visited once to use https:// for this website from then on, even if a link says http://.",
     "risk": "Browsers remember this for the time you choose, and nobody can make them forget it sooner. "
             "Only use it on websites that work fully with https://. Start with 1 week.",
     "default": False},
    {"id": "csp_upgrade", "name": "Content-Security-Policy", "short": "Content rules",
     "title": "Load everything on a page securely",
     "what": "Asks the browser to load a page's pictures and files over https:// even if the page's code says http://. "
             "This is the gentle version of content rules; strict ones break page builders and shops and are not offered.",
     "risk": "Can hide a file that only exists on plain http://. Rarely a problem.", "default": False},
]
BY_ID = {i["id"]: i for i in ITEMS}
FLAGS = ("nosniff", "frame", "referrer", "permissions", "hide_powered", "csp_upgrade", "hsts_subdomains")
DEFAULTS = {"nosniff": True, "frame": True, "referrer": True, "permissions": True, "hide_powered": True,
            "csp_upgrade": False, "hsts": 0, "hsts_subdomains": False}
SITE_KEYS = FLAGS + ("hsts", "exclude")

STATUS_TEXT = {
    "applied": "Managed by CP-Security",
    "outdated": "Out of date: press Apply",
    "none": "Not applied yet",
    "own": "The website sets these itself",
    "off": "Nothing switched on",
    "excluded": "Left alone (your choice)",
    "error": "Cannot be changed",
}


# ----------------------------------------------------------------------------- the owner's choices
def _clean(changes, allow_exclude):
    """Validate a dict of choices. Returns (clean dict, error text or '')."""
    clean = {}
    for key, value in (changes or {}).items():
        if key == "hsts":
            if isinstance(value, bool) or value not in HSTS_SECONDS:
                return None, "Choose one of the listed times for the secure-address setting."
            clean[key] = value
        elif key in FLAGS or (allow_exclude and key == "exclude"):
            if not isinstance(value, bool):
                return None, "Each switch must be on or off."
            clean[key] = value
        else:
            return None, "Unknown setting."
    return clean, ""


def load():
    stored = util.read_json(config.P.headers_settings, {})
    stored = stored if isinstance(stored, dict) else {}
    defaults = dict(DEFAULTS)
    clean, _ = _clean(stored.get("defaults") if isinstance(stored.get("defaults"), dict) else {}, False)
    defaults.update(clean or {})
    per_site = {}
    raw = stored.get("sites") if isinstance(stored.get("sites"), dict) else {}
    for domain, changes in raw.items():
        c, _ = _clean(changes if isinstance(changes, dict) else {}, True)
        if c:
            per_site[domain] = c
    return {"defaults": defaults, "sites": per_site}


def _save(cfg):
    util.write_json(config.P.headers_settings, {"defaults": cfg["defaults"], "sites": cfg["sites"]}, mode=0o600)


def effective(cfg, domain):
    out = dict(cfg["defaults"])
    out.update(cfg["sites"].get(domain, {}))
    return out


def set_defaults(changes):
    clean, err = _clean(changes, False)
    if err:
        return Result(False, err, "invalid")
    cfg = load()
    cfg["defaults"].update(clean)
    _save(cfg)
    return Result(True, "Saved. Press Apply to put the new choices on your websites.")


def set_site(domain, changes):
    """changes: a value per key, or None to go back to the default for that key."""
    if domain not in sites.list_sites():
        return Result(False, "That website is not on this server.", "unknown_site")
    wanted = {k: v for k, v in (changes or {}).items() if v is not None}
    clean, err = _clean(wanted, True)
    if err:
        return Result(False, err, "invalid")
    unknown = [k for k, v in (changes or {}).items() if v is None and k not in SITE_KEYS]
    if unknown:
        return Result(False, "Unknown setting.", "invalid")
    cfg = load()
    mine = cfg["sites"].get(domain, {})
    for key, value in (changes or {}).items():
        if value is None:
            mine.pop(key, None)
    mine.update(clean)
    if mine:
        cfg["sites"][domain] = mine
    else:
        cfg["sites"].pop(domain, None)
    _save(cfg)
    return Result(True, "Saved for %s." % domain)


# ----------------------------------------------------------------------------- what to send
def enabled(item_id, eff):
    if item_id == "hsts":
        return eff["hsts"] > 0
    return bool(eff.get(item_id))


def header_value(item_id, eff):
    """The value a header is given (None for the one that is removed)."""
    if item_id == "nosniff":
        return "nosniff"
    if item_id == "frame":
        return "SAMEORIGIN"
    if item_id == "referrer":
        return "strict-origin-when-cross-origin"
    if item_id == "permissions":
        return PERMISSIONS_VALUE
    if item_id == "hsts":
        return "max-age=%d%s" % (eff["hsts"], "; includeSubDomains" if eff["hsts_subdomains"] else "")
    if item_id == "csp_upgrade":
        return "upgrade-insecure-requests"
    return None


def header_line(item_id, eff):
    name, value = BY_ID[item_id]["name"], header_value(item_id, eff)
    if item_id == "hide_powered":
        return "Header always unset X-Powered-By"
    if item_id == "hsts":
        return 'Header always set %s "%s" env=HTTPS' % (name, value)       # only on secure connections
    if item_id == "csp_upgrade":
        # merge, not set: a policy the website already sends is kept, ours is added next to it
        return 'Header always merge %s "%s"' % (name, value)
    return 'Header always set %s "%s"' % (name, value)


def build_block(eff, skip_names):
    """(text of our block or None, ids included). Headers the site sets itself (skip_names) are left out."""
    lines, used = [], []
    for item in ITEMS:
        if enabled(item["id"], eff) and item["name"].lower() not in skip_names:
            lines.append(header_line(item["id"], eff))
            used.append(item["id"])
    if not lines:
        return None, []
    body = ([htfile.BEGIN,
             "# Managed by CP-Security (Security headers page). Anything between these two lines is rewritten.",
             "<IfModule mod_headers.c>"] + ["    " + ln for ln in lines] + ["</IfModule>", htfile.END])
    return "\n".join(body) + "\n", used


# ----------------------------------------------------------------------------- looking at the websites
def docroot_of(domain):
    return "%s/%s/public_html" % (config.P.home_dir, domain)


def _safe_domain(domain):
    return bool(domain) and all(c.isalnum() or c in ".-" for c in domain) and not domain.startswith(".")


def fetch(domain):
    """{'status': '200', 'headers': {lower name: value}} as the web server answers for this site, or None."""
    rc, out = util.run(["curl", "-sk", "-D", "-", "-o", "/dev/null", "--resolve", "%s:443:127.0.0.1" % domain,
                        "https://%s/" % domain, "--max-time", "15"], timeout=25)
    if rc != 0 or not out.strip():
        return None
    blocks = [b for b in out.replace("\r", "").strip().split("\n\n") if b.strip()]
    lines = blocks[-1].split("\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        return None
    headers = {}
    for ln in lines[1:]:
        name, sep, value = ln.partition(":")
        if sep:
            key = name.strip().lower()
            headers[key] = (headers[key] + ", " if key in headers else "") + value.strip()
    return {"status": parts[1], "headers": headers}


_live = {}
_live_lock = threading.Lock()
_checking = [False]


def _record(domain, res):
    """Remember what a website answered, for the page. res is fetch()'s answer, or None if it did not answer."""
    with _live_lock:
        _live[domain] = dict(res or {"status": "000", "headers": {}}, at=time.time(), failed=res is None)


def check_all(domains=None):
    """Ask the websites what they send right now (takes a few seconds). Updates what the page shows."""
    domains = sites.list_sites() if domains is None else list(domains)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(fetch, domains))
    for domain, res in zip(domains, results):
        _record(domain, res)
    return len(domains)


def refresh_async(max_age=900):
    """Start a background look at the websites unless one is running or the last one is recent."""
    with _live_lock:
        newest = max([v["at"] for v in _live.values()] or [0])
        if _checking[0] or time.time() - newest < max_age:
            return False
        _checking[0] = True

    def work():
        try:
            check_all()
        finally:
            with _live_lock:
                _checking[0] = False
    threading.Thread(target=work, daemon=True).start()
    return True


def _live_of(domain):
    with _live_lock:
        return dict(_live[domain]) if domain in _live else None


def _site_row(domain, cfg):
    docroot = docroot_of(domain)
    info = htfile.inspect(docroot) if _safe_domain(domain) else {"error": "Unusual website name.", "damaged": False}
    return build_row(domain, cfg, info, _live_of(domain))


def build_row(domain, cfg, info, live):
    """One website's line on the page, from what is in its .htaccess (info) and what it answered (live)."""
    eff = effective(cfg, domain)
    own = set(info.get("site_names", []))
    desired, used = build_block(eff, own)
    wanted = [i["id"] for i in ITEMS if enabled(i["id"], eff)]
    if eff.get("exclude"):
        status = "excluded"
    elif info.get("error"):
        status = "error"
    elif desired is None:
        status = "outdated" if info.get("has_block") else ("own" if wanted else "off")
    elif not info.get("has_block"):
        status = "none"
    else:
        status = "applied" if info["block"] == desired else "outdated"

    ours = htfile.header_names(info.get("block", "")) if info.get("has_block") else set()
    chips = []
    for item in ITEMS:
        name = item["name"].lower()
        if name in ours:
            source = "ours"
        elif name in own:
            source = "site"
        else:
            source = "none"
        seen = None
        if live is not None and not live.get("failed"):
            present = name in live["headers"]
            seen = (not present) if item["id"] == "hide_powered" else present
            if source == "none" and seen and item["id"] != "hide_powered":
                source = "other"
        chips.append({"id": item["id"], "source": source, "seen": seen})
    return {
        "domain": domain, "status": status, "status_text": STATUS_TEXT[status], "error": info.get("error", ""),
        "has_block": bool(info.get("has_block")), "excluded": bool(eff.get("exclude")),
        "own_headers": sorted(own), "taken": info.get("taken", 0), "chips": chips,
        "overrides": cfg["sites"].get(domain, {}),
        "live_status": live["status"] if live else "", "checked_at": time.strftime("%H:%M", time.localtime(live["at"])) if live else "",
        "needs_apply": status in ("none", "outdated"),
    }


def state(start_check=True):
    cfg = load()
    if start_check:
        refresh_async()
    rows = [_site_row(d, cfg) for d in sites.list_sites()]
    with _live_lock:
        newest = max([v["at"] for v in _live.values()] or [0])
        checking = _checking[0]
    return assemble(cfg, rows, checking, newest, supported(), webserver.info()["name"])


def supported():
    """Header lines in .htaccess work on LiteSpeed Enterprise. OpenLiteSpeed ignores them."""
    return webserver.kind() == webserver.ENTERPRISE


UNSUPPORTED = Result(False, "This server runs OpenLiteSpeed, which ignores header lines in .htaccess. Support for it "
                            "comes later. Nothing was changed.", "unsupported")


def assemble(cfg, rows, checking, newest, ok=True, server=""):
    """Everything the page needs, from the choices, the website lines and when they were last asked."""
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "supported": ok, "web_server": server,
        "items": [{k: i[k] for k in ("id", "name", "short", "title", "what", "risk", "default")} for i in ITEMS],
        "hsts_choices": [{"seconds": s, "text": t} for s, t in HSTS_CHOICES],
        "defaults": cfg["defaults"], "sites": rows, "counts": counts, "checking": checking,
        "checked_at": time.strftime("%H:%M", time.localtime(newest)) if newest else "",
    }


def summary():
    """For the Advisor: how many websites still need the headers. No web requests."""
    cfg = load()
    rows = [_site_row(d, cfg) for d in sites.list_sites()]
    return {"total": len(rows), "needs": sum(1 for r in rows if r["needs_apply"]),
            "applied": sum(1 for r in rows if r["status"] == "applied")}


# ----------------------------------------------------------------------------- changing a website
def _primary_group(uid):
    """The user's own group (the website's folder often belongs to a shared group such as nogroup)."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_gid
    except (ImportError, KeyError):
        return None


def _owner(docroot):
    """(user id, group id) to do the file work as: the website's own user, never root or a system account."""
    try:
        st = os.stat(docroot)
    except OSError:
        raise htfile.Refused("The website's folder cannot be found.")
    if st.st_uid < 100:
        raise htfile.Refused("The website's folder belongs to a system account, so CP-Security will not write there. "
                             "Give it to the website's own user first.")
    gid = _primary_group(st.st_uid)
    return st.st_uid, st.st_gid if gid is None else gid


def _run_as_owner(uid, gid, request):
    """Run htfile as the website's own user. (Tests replace this with a direct call.)"""
    code = "import sys; sys.path.insert(0, %r); from cpsec import htfile; htfile.main()" % PACKAGE_PARENT
    try:
        done = subprocess.run([sys.executable, "-c", code], input=json.dumps(request), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True, timeout=30, user=uid, group=gid,
                              extra_groups=[], cwd="/",
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": "The file work could not be started (%s)." % exc}
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {"ok": False, "error": "The file work failed: %s" % (done.stderr.strip()[-200:] or "no answer")}


def _backup(domain, original):
    if original is None:
        return
    folder = "%s/htaccess/%s" % (config.P.backup_dir, domain)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    path = "%s/%s.htaccess" % (folder, time.strftime("%Y%m%d-%H%M%S"))
    with open(path, "wb") as f:                      # bytes, so a file that is not clean UTF-8 is kept exactly
        f.write(original.encode("utf-8", errors="surrogateescape"))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    old = sorted(os.listdir(folder))[:-BACKUPS_KEPT]
    for name in old:
        try:
            os.remove(os.path.join(folder, name))
        except OSError:
            pass


def _answers(res):
    return res is not None and res["status"][:1] in ("2", "3")


# LiteSpeed looks at a changed .htaccess only about every 5 seconds (measured on a real server), so the answer
# right after a change still shows the OLD file. We ask again until the new one shows, up to about 15 seconds.
_sleep = time.sleep
SETTLE_TRIES = 15
SETTLE_PAUSE = 1.0


def _settle(domain, done):
    """Ask the website until done(answer) is true (or the tries run out). Returns the last answer, or None."""
    res = None
    for attempt in range(SETTLE_TRIES):
        res = fetch(domain)
        if res is None or done(res):
            return res
        if attempt < SETTLE_TRIES - 1:
            _sleep(SETTLE_PAUSE)
    return res


def _expected(used, eff):
    """{lower-case header name: the value we asked for}, for the headers that must appear."""
    return {BY_ID[i]["name"].lower(): header_value(i, eff) for i in used if i != "hide_powered"}


def _missing(res, expected):
    """Names of the expected headers the website is not (yet) sending with our value."""
    return [n for n, v in expected.items() if v.lower() not in res["headers"].get(n, "").lower()]


def _shows_change(before, used, eff):
    """A test for _settle: does the website already send what we added?"""
    expected = _expected(used, eff)
    hide = "hide_powered" in used and before is not None and "x-powered-by" in before["headers"]

    def done(res):
        if before is not None and _answers(before) and not _answers(res):
            return True                                  # it broke: no need to wait for more
        if expected:
            return not _missing(res, expected)
        return not hide or "x-powered-by" not in res["headers"]
    return done


def _verify(before, after, used, eff):
    """(keep it?, note). A website that stopped answering, or ignored every header, gets its file back."""
    if before is not None and _answers(before) and not _answers(after):
        return False, "The website stopped answering after the change, so the change was undone."
    if after is None:
        return True, "The website could not be asked afterwards, so the result is not confirmed."
    expected = _expected(used, eff)
    missing = _missing(after, expected)
    if expected and len(missing) == len(expected):
        return False, ("The web server did not send the headers (it may ignore .htaccess settings for this "
                       "website), so the change was undone.")
    notes = []
    if missing:
        by_name = {i["name"].lower(): i["short"] for i in ITEMS}
        notes.append("Not seen yet: " + ", ".join(by_name[n] for n in missing))
    if "hide_powered" in used and before and "x-powered-by" in before["headers"] and "x-powered-by" in after["headers"]:
        notes.append("The technology label is still sent")
    return True, "; ".join(notes)


def _change_one(domain, cfg, take_over, remove):
    """Returns {'domain', 'ok', 'changed', 'message'}."""
    def out(ok, message, changed=False):
        return {"domain": domain, "ok": ok, "changed": changed, "message": message}

    if not _safe_domain(domain):
        return out(False, "Unusual website name.")
    docroot = docroot_of(domain)
    eff = effective(cfg, domain)
    if eff.get("exclude") and not remove:
        return out(True, "Left alone, as you chose.")
    try:
        uid, gid = _owner(docroot)
        info = htfile.inspect(docroot)
        if info["error"]:
            return out(False, info["error"])
        if remove:
            block, used, names = None, [], []
        else:
            own = set(info["site_names"])
            block, used = build_block(eff, set() if take_over else own)
            names = [BY_ID[i]["name"] for i in used if BY_ID[i]["name"].lower() in own] if take_over else []
        request = {"op": "apply", "docroot": docroot, "block": block, "take_over": names, "give_back": remove}
        before = fetch(domain)
        res = _run_as_owner(uid, gid, request)
        if not res.get("ok"):
            return out(False, res.get("error") or "The file could not be changed.")
        if not res.get("changed"):
            _record(domain, before)
            return out(True, "Already up to date.")
        _backup(domain, res.get("original"))
        if remove:
            # wait until the headers we had added stop being sent (lines given back to the site keep being sent)
            gone = set(htfile.header_names(info["block"])) - set(info["taken_names"]) - {"x-powered-by"}
            after = _settle(domain, lambda r: not _answers(r) or not any(n in r["headers"] for n in gone))
        else:
            after = _settle(domain, _shows_change(before, used, eff))
        keep, note = (True, "") if remove else _verify(before, after, used, eff)
        if remove and before is not None and _answers(before) and not _answers(after):
            keep, note = False, "The website stopped answering after the change, so the change was undone."
        _record(domain, after if keep else before)
        if not keep:
            back = _run_as_owner(uid, gid, {"op": "restore", "docroot": docroot, "original": res.get("original")})
            extra = "" if back.get("ok") else " The old file could not be put back: " + str(back.get("error")) + " (a copy is in the backup folder)."
            return out(False, note + extra)
        if remove:
            done = "Removed."
        else:
            done = "Applied"
            if res.get("taken"):
                done += " (took over %d line%s the website had set)" % (res["taken"], "" if res["taken"] == 1 else "s")
            done += "."
        return out(True, done + ((" " + note.rstrip(".") + ".") if note else ""), True)
    except htfile.Refused as exc:
        return out(False, str(exc))


def _targets(domains):
    known = sites.list_sites()
    if domains is None:
        return known, None
    bad = [d for d in domains if d not in known]
    return [d for d in known if d in domains], bad


def _run_many(domains, take_over, remove):
    if not supported() and not remove:
        return UNSUPPORTED
    targets, bad = _targets(domains)
    if bad:
        return Result(False, "Not a website on this server: %s." % ", ".join(bad[:3]), "unknown_site")
    if not targets:
        return Result(False, "There are no websites to change.", "none")
    cfg = load()
    with ThreadPoolExecutor(max_workers=6) as ex:               # websites are independent: do several at once
        results = list(ex.map(lambda d: _change_one(d, cfg, take_over, remove), targets))
    changed = sum(1 for r in results if r["ok"] and r["changed"])
    failed = [r for r in results if not r["ok"]]
    verb = "Removed from" if remove else "Applied to"
    if len(targets) == 1:
        r = results[0]
        return Result(r["ok"], "%s: %s" % (r["domain"], r["message"]), "" if r["ok"] else "failed")
    msg = "%s %d website%s." % (verb, changed, "" if changed == 1 else "s")
    unchanged = len(results) - changed - len(failed)
    if unchanged:
        msg += " %d needed no change." % unchanged
    if failed:
        msg += " %d could not be changed: %s" % (len(failed), "; ".join("%s (%s)" % (r["domain"], r["message"]) for r in failed[:3]))
        return Result(False, msg, "failed")
    return Result(True, msg)


def apply(domains=None, take_over=False):
    """Put the chosen headers on these websites (all of them when domains is None)."""
    return _run_many(domains, bool(take_over), False)


def remove(domains=None):
    """Take our block off these websites and give back any lines we had switched off."""
    return _run_many(domains, False, True)
