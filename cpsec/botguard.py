"""Bot protection: three switches per website against what bots do to WordPress every day.

* xmlrpc  Close the old app-login door. WordPress has a second login door (xmlrpc.php), made for publishing from apps.
          It takes a user name and password like the login page, a hidden login address does not protect it, and one
          request can try hundreds of passwords. Bots use it all the time. Only the WordPress phone app and Jetpack need it.
* files   Hide private files: error logs, database dumps, backup copies of the settings file, and hidden files such as
          .env or .git. Bots ask for these names on every website; one of them can hand over passwords or file paths.
          The folder that certificate renewals use (.well-known) stays open.
* users   Hide account names. WordPress lists its authors' account names to anybody who asks (through its REST door and
          through ?author=1); bots read them and then guess only the password. People who are signed in are not affected.

How it is done: each switch is one small block of lines between marker lines at the top of the website's own settings file
(.htaccess in the web folder). Lines that were there before are never changed; "Turn off" removes only that block.

Made safe the same way as everything else in the panel
* All file work is done as the website's own user, never as root.
* A website that is not answering normally is not touched.
* Before a block is kept, it is proved: the thing it refuses must really be refused (a harmless test file for private files),
  and the website, its login page and what must keep working (signed-in users, the REST door, certificate renewals) must still
  answer as well as before. Otherwise the settings file is put back as it was. Test files are always removed.
"""
import copy
import re
import secrets
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import phpguard, updates, util, wpupdate
from .util import Result

SETTLE_TRIES = 12                   # LiteSpeed looks at a changed settings file only every few seconds (measured: about 6 to 8)
SETTLE_PAUSE = 2.0
_sleep = time.sleep

XMLRPC_BODY = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
PRIVATE_PROBES = ("/wp-content/debug.log", "/debug.log", "/error_log", "/.env", "/.git/config", "/wp-config.php.bak",
                  "/wp-config.bak", "/wp-config.php~", "/wp-config.old", "/wp-config.php.save", "/wp-config.php.orig")

RULES = {
    "xmlrpc": {
        "title": "Close the old app-login door",
        "lines": ('<Files "xmlrpc.php">\n'
                  "    Require all denied\n"
                  "</Files>\n"),
    },
    "files": {
        "title": "Hide private files",
        "lines": ('<FilesMatch "(?i)(\\.(log|sql|sql\\.gz|sqlite3?|bak|backup|old|orig|save|swp|swo|ini)|~|^wp-config\\.php.+|^error_log|^php_errorlog)$">\n'
                  "    Require all denied\n"
                  "</FilesMatch>\n"
                  "<IfModule mod_rewrite.c>\n"
                  "RewriteEngine On\n"
                  "RewriteRule (^|/)\\.(?!well-known(/|$)) - [F]\n"
                  "</IfModule>\n"),
    },
    "users": {
        "title": "Hide account names",
        "lines": ("<IfModule mod_rewrite.c>\n"
                  "RewriteEngine On\n"
                  "RewriteCond %{HTTP_COOKIE} !wordpress_logged_in_ [NC]\n"
                  "RewriteCond %{REQUEST_URI} ^/wp-json/wp/v2/users [NC,OR]\n"
                  "RewriteCond %{QUERY_STRING} (^|&)rest_route=(/|%2F)wp(/|%2F)v2(/|%2F)users [NC]\n"
                  "RewriteRule .* - [F]\n"
                  "RewriteCond %{HTTP_COOKIE} !wordpress_logged_in_ [NC]\n"
                  "RewriteCond %{REQUEST_URI} !^/wp-admin/ [NC]\n"
                  "RewriteCond %{QUERY_STRING} (^|&)author=[0-9] [NC]\n"
                  "RewriteRule .* - [F]\n"
                  "</IfModule>\n"),
    },
}
KEYS = tuple(RULES)                  # the order the page shows them in


# ----------------------------------------------------------------------------- the text of the settings file
def markers(key):
    return "# BEGIN CP-Security bot-%s" % key, "# END CP-Security bot-%s" % key


def block(key):
    begin, end = markers(key)
    return begin + "\n" + RULES[key]["lines"] + end + "\n"


def split_block(text, key):
    """(text before the block, the block or None, text after it). Raises ValueError when the block is damaged."""
    begin, end = markers(key)
    lines = text.splitlines(keepends=True)
    b = [i for i, ln in enumerate(lines) if ln.strip() == begin]
    e = [i for i, ln in enumerate(lines) if ln.strip() == end]
    if not b and not e:
        return text, None, ""
    if len(b) != 1 or len(e) != 1 or e[0] < b[0]:
        raise ValueError("damaged")
    return "".join(lines[:b[0]]), "".join(lines[b[0]:e[0] + 1]), "".join(lines[e[0] + 1:])


def without_block(text, key):
    before, found, after = split_block(text, key)
    if found is None:
        return text
    return before + after


def with_block(text, key):
    """Our block first (rules near the top are read first), then everything that was there, unchanged."""
    return block(key) + without_block(text, key)


def status_in(text, key):
    """on | off | changed (our marker lines are there, but not as we wrote them)."""
    try:
        _b, found, _a = split_block(text, key)
    except ValueError:
        return "changed"
    if found is None:
        return "off"
    return "on" if found == block(key) else "changed"


# ----------------------------------------------------------------------------- asking the website
def _code(domain, path, post=None, cookie=None):
    """Only the answer code (nothing of the page is read into the panel)."""
    cmd = ["curl", "-sk", "--resolve", "%s:443:127.0.0.1" % domain, "--max-time", "20", "-o", "/dev/null", "-w", "%{http_code}"]
    if post is not None:
        cmd += ["-X", "POST", "-H", "Content-Type: text/xml", "--data-binary", post]
    if cookie:
        cmd += ["-b", cookie]
    rc, out = util.run(cmd + ["https://%s%s" % (domain, path)], timeout=40)
    return out.strip()[-3:] if rc == 0 and out.strip() else "000"


def _fresh():
    return "cps=" + secrets.token_hex(4)                 # a new address every time: the page cache can never answer


def _names_shown(domain):
    """Account names a stranger can read: from the REST door's users list, and from where ?author=1 leads."""
    names = []
    code, body = wpupdate._get(domain, "/wp-json/wp/v2/users?" + _fresh())
    if code == "200":
        names += re.findall(r'"slug"\s*:\s*"([^"]{1,60})"', body)
    rc, out = util.run(["curl", "-sk", "--resolve", "%s:443:127.0.0.1" % domain, "--max-time", "20", "-o", "/dev/null", "-D", "-",
                        "https://%s/?author=1&%s" % (domain, _fresh())], timeout=40)
    m = re.search(r"(?im)^location:\s*\S*/author/([^/\s?#]{1,60})", out or "")
    if m:
        names.append(m.group(1))
    return sorted(set(names))


def _door_open(domain):
    """True when WordPress itself answers at the old app-login door (it says it 'accepts POST requests only')."""
    code, body = wpupdate._get(domain, "/xmlrpc.php?" + _fresh())
    return "accepts POST requests only" in body


def _exposed(domain):
    return [p for p in PRIVATE_PROBES if _code(domain, p + ("&" if "?" in p else "?") + _fresh()) == "200"]


# ----------------------------------------------------------------------------- what the page shows
def _htaccess(site):
    return site["docroot"] + "/.htaccess"


def _inspect(name):
    out = {"site": name, "checked": False, "problem": "", "rules": {k: {"status": "unknown"} for k in KEYS}}
    site = wpupdate._site(name)
    if site is None:
        out["problem"] = "That website was not found."
        return out
    kind, text = phpguard._read(site, _htaccess(site))
    if kind in ("link", "error"):
        out["problem"] = "The website's settings file is a link or cannot be read, so it is left alone."
        out["rules"] = {k: {"status": "unsupported"} for k in KEYS}
        return out
    out["checked"] = True
    for key in KEYS:
        out["rules"][key] = {"status": status_in(text, key)}
    out["rules"]["xmlrpc"]["open"] = _door_open(name)
    out["rules"]["files"]["exposed"] = _exposed(name)
    out["rules"]["users"]["shown"] = _names_shown(name)
    return out


_lock = threading.Lock()
_scan = {"status": "idle", "finished": "", "sites": {}}
_job = {"status": "idle", "action": "", "rule": "", "items": [], "started": "", "finished": ""}


def _names():
    return sorted(n for _d, _u, n in updates._wordpress_sites())


def scan_state():
    with _lock:
        return copy.deepcopy(_scan)


def scan_start():
    with _lock:
        if _scan["status"] == "running":
            return Result(False, "Already looking at the websites.", "busy")
        _scan["status"] = "running"
    threading.Thread(target=_scan_run, daemon=True).start()
    return Result(True, "Looking at the websites.")


def _inspect_safe(name):
    try:
        return _inspect(name)
    except Exception as exc:                            # one website must never hide the others
        return {"site": name, "checked": False, "problem": "Looking at this website failed (%s)." % str(exc)[:80],
                "rules": {k: {"status": "unknown"} for k in KEYS}}


def _scan_run():
    try:
        try:
            names = _names()
        except (ImportError, OSError):                  # not a server with websites on it
            names = []
        with ThreadPoolExecutor(max_workers=3) as ex:
            results = list(ex.map(_inspect_safe, names))
        with _lock:
            _scan["sites"] = dict(_scan["sites"], **{r["site"]: r for r in results})
    finally:
        with _lock:
            _scan["status"] = "done"
            _scan["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _update_scan(name, key, **fields):
    with _lock:
        if name in _scan["sites"]:
            _scan["sites"][name]["rules"].setdefault(key, {}).update(fields)


def state(names=None):
    """For the page: one line per WordPress website, with the state of each switch and what a stranger can see now."""
    names = names if names is not None else _names()
    scan = scan_state()
    sites = []
    for name in names:
        s = scan["sites"].get(name) or {"checked": False, "problem": "", "rules": {k: {"status": "unknown"} for k in KEYS}}
        sites.append({"site": name, "checked": s.get("checked", False), "problem": s.get("problem", ""),
                      "rules": {k: dict(s.get("rules", {}).get(k) or {"status": "unknown"}) for k in KEYS}})
    return {"scan": {"status": scan["status"], "finished": scan["finished"]}, "rules": [{"key": k, "title": RULES[k]["title"]} for k in KEYS],
            "sites": sites}


# ----------------------------------------------------------------------------- proving a switch
class _Proof:
    """What to ask before and after a switch, to know it works and broke nothing. Test files are made and removed here."""

    def __init__(self, key, name, site):
        self.key, self.name, self.site = key, name, site
        self.token = secrets.token_hex(6)
        self.made = []                                   # paths of the test files (and a folder) we created
        self.made_dir = None
        self.before = {}

    # -- test files (private files only)
    def _put(self, path, text):
        rc, out = util.run_with_input(["su", "-s", "/bin/bash", self.site["user"], "-c", "umask 022; cat > %s" % shlex.quote(path)],
                                      text.encode("utf-8"), timeout=60)
        if rc == 0:
            self.made.append(path)
        return rc == 0

    def prepare(self):
        """None, or a sentence saying why the test cannot be done (then nothing is changed)."""
        if self.key != "files":
            return None
        d = self.site["docroot"]
        self.marker = "CPS-PRIVATE-" + self.token
        self.files = {"/cps-selftest-%s.log" % self.token: d + "/cps-selftest-%s.log" % self.token,
                      "/.cps-selftest-%s" % self.token: d + "/.cps-selftest-%s" % self.token}
        wk = d + "/.well-known"
        rc, out = wpupdate._shell(self.site["user"], "if [ -L %s ]; then echo LINK; elif [ -d %s ]; then echo DIR; else mkdir -m 755 %s && echo MADE; fi"
                                  % (shlex.quote(wk), shlex.quote(wk), shlex.quote(wk)), 30)
        state_ = out.strip().splitlines()[-1] if out.strip() else ""
        if state_ == "MADE":
            self.made_dir = wk
        self.keep_open = None
        if state_ in ("DIR", "MADE"):
            self.keep_open = ("/.well-known/cps-selftest-%s.txt" % self.token, wk + "/cps-selftest-%s.txt" % self.token)
        for path in list(self.files.values()) + ([self.keep_open[1]] if self.keep_open else []):
            if not self._put(path, self.marker):
                return "a test file could not be saved in the website's folder"
        return None

    def cleanup(self):
        if self.made:
            wpupdate._shell(self.site["user"], "rm -f -- " + " ".join(shlex.quote(p) for p in self.made), 30)
        if self.made_dir:
            wpupdate._shell(self.site["user"], "rmdir -- %s 2>/dev/null; true" % shlex.quote(self.made_dir), 30)

    # -- the questions
    def _refused(self):
        """Is what the switch must refuse really refused now?"""
        n = self.name
        if self.key == "xmlrpc":
            return _code(n, "/xmlrpc.php?" + _fresh(), post=XMLRPC_BODY) == "403"
        if self.key == "files":
            return all(_code(n, url + "?" + _fresh()) == "403" for url in self.files)
        return (_code(n, "/wp-json/wp/v2/users?" + _fresh()) == "403" and _code(n, "/?rest_route=/wp/v2/users&" + _fresh()) == "403"
                and _code(n, "/?author=1&" + _fresh()) == "403")

    def _kept(self):
        """What must keep working, as answer codes."""
        n = self.name
        out = {}
        if self.key == "files" and self.keep_open:
            out["the folder that certificate renewals use"] = _code(n, self.keep_open[0] + "?" + _fresh())
        if self.key == "users":
            out["the REST door that the editor and plugins use"] = _code(n, "/wp-json/?" + _fresh())
            out["the users list for people who are signed in"] = _code(n, "/wp-json/wp/v2/users?" + _fresh(), cookie="wordpress_logged_in_cps=1")
        return out

    def take_before(self):
        self.before = self._kept()
        if self.key == "files":
            for url in self.files:
                code, body = wpupdate._get(self.name, url + "?" + _fresh())
                if not (code == "200" and self.marker in body) and code != "403":
                    return "the test could not be done (a test file answered %s)" % code
        return None

    def worse(self):
        """Sentences about what stopped working (empty list = fine)."""
        bad = []
        for what, code in self._kept().items():
            was = self.before.get(what, "")
            if code != was and (code == "403" or (was[:1] in ("2", "3") and code[:1] not in ("2", "3"))):
                bad.append("%s now answers %s" % (what, code))
        return bad


def enable_one(name, key, progress=None):
    """Turn one switch on for one website, prove it, and put the settings file back if anything is wrong."""
    say = progress or (lambda text: None)
    if key not in RULES:
        return Result(False, "Unknown protection.", "invalid")
    site = wpupdate._site(name)
    if site is None:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    say("Checking that the website answers normally")
    before = wpupdate.health(name)
    if not wpupdate._good(before["home"]):
        return Result(False, "The website is not answering normally now, so nothing was changed.", "unhealthy")
    path = _htaccess(site)
    kind, original = phpguard._read(site, path)
    if kind in ("link", "error"):
        return Result(False, "The website's settings file is a link or cannot be read, so nothing was changed.", "unsafe")
    text = original if kind == "file" else ""
    try:
        new = with_block(text, key)
    except ValueError:
        return Result(False, "The CP-Security lines for this protection are damaged in the website's settings file, so nothing was changed. "
                             "Remove them by hand first.", "damaged")
    if kind == "file" and status_in(original, key) == "on":
        _update_scan(name, key, status="on")
        return Result(True, "%s was already on for %s." % (RULES[key]["title"], name))

    proof = _Proof(key, name, site)
    try:
        say("Preparing the test")
        why = proof.prepare() or proof.take_before()
        if why:
            return Result(False, "Nothing was changed: %s." % why, "no_test")
        say("Switching it on")
        ok, problem = phpguard._write(site, path, new)
        if not ok:
            return Result(False, "The settings file could not be written (%s), so nothing was changed." % (problem or "no reason given"), "write")
        say("Checking that it really works (this takes a few seconds)")
        proven = False
        for attempt in range(SETTLE_TRIES):
            if proof._refused():
                proven = True
                break
            if attempt < SETTLE_TRIES - 1:
                _sleep(SETTLE_PAUSE)
        if not proven:
            phpguard._put_back(site, path, kind, original)
            return Result(False, "The web server did not apply it, so the settings file was put back. Nothing was changed on this website.", "not_applied")
        say("Checking the website again")
        bad = wpupdate.problems(before, wpupdate.health(name)) + proof.worse()
        if bad:
            phpguard._put_back(site, path, kind, original)
            return Result(False, "It was taken out again: %s." % " and ".join(bad), "regression")
    finally:
        proof.cleanup()
    fields = {"status": "on"}
    if key == "xmlrpc":
        fields["open"] = False
    elif key == "files":
        fields["exposed"] = []
    else:
        fields["shown"] = []
    _update_scan(name, key, **fields)
    return Result(True, "%s: on for %s, and tested." % (RULES[key]["title"], name))


def disable_one(name, key, progress=None):
    """Turn one switch off for one website. Only its own block is taken out of the settings file."""
    say = progress or (lambda text: None)
    if key not in RULES:
        return Result(False, "Unknown protection.", "invalid")
    site = wpupdate._site(name)
    if site is None:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    path = _htaccess(site)
    kind, original = phpguard._read(site, path)
    if kind in ("link", "error"):
        return Result(False, "The website's settings file is a link or cannot be read, so nothing was changed.", "unsafe")
    try:
        if kind == "none" or split_block(original, key)[1] is None:
            _update_scan(name, key, status="off")
            return Result(True, "%s was already off for %s." % (RULES[key]["title"], name))
        rest = without_block(original, key)
    except ValueError:
        return Result(False, "The CP-Security lines for this protection are damaged in the website's settings file, so nothing was changed. "
                             "Remove them by hand first.", "damaged")
    say("Taking it off")
    if rest.strip():
        ok, problem = phpguard._write(site, path, rest)
    else:                                                   # the file held only our lines: it goes away with them
        rc, out = wpupdate._shell(site["user"], "rm -f -- %s" % shlex.quote(path), 60)
        ok, problem = rc == 0, out.strip()[:100]
    if not ok:
        return Result(False, "The settings file could not be changed (%s)." % (problem or "no reason given"), "write")
    _update_scan(name, key, status="off")
    return Result(True, "%s: off for %s (as before)." % (RULES[key]["title"], name))


# ----------------------------------------------------------------------------- the job (many websites, one at a time)
def job_state():
    with _lock:
        s = copy.deepcopy(_job)
    s["counts"] = {k: sum(1 for i in s["items"] if i["status"] == k) for k in ("waiting", "working", "done", "failed")}
    return s


def start(action, key, names):
    if action not in ("enable", "disable") or key not in RULES:
        return Result(False, "Unknown action.", "invalid")
    known = set(_names())
    names = [n for n in dict.fromkeys(names or [])]
    if not names or any(n not in known for n in names):
        return Result(False, "Choose WordPress websites that are on this server.", "invalid")
    with _lock:
        if _job["status"] == "running":
            return Result(False, "Already working. Wait for it to finish.", "busy")
        _job.update(status="running", action=action, rule=key, started=time.strftime("%Y-%m-%d %H:%M:%S"), finished="",
                    items=[{"site": n, "status": "waiting", "message": "", "step": ""} for n in names])
    threading.Thread(target=_run, args=(action, key), daemon=True).start()
    return Result(True, "Started on %d website%s." % (len(names), "" if len(names) == 1 else "s"))


def _set(index, **fields):
    with _lock:
        _job["items"][index].update(fields)


def _run(action, key):
    try:
        with _lock:
            names = [i["site"] for i in _job["items"]]
        for index, name in enumerate(names):
            _set(index, status="working", step="Starting")
            try:
                fn = enable_one if action == "enable" else disable_one
                res = fn(name, key, progress=lambda text, at=index: _set(at, step=text))
            except Exception as exc:                    # one website must never stop the others
                res = Result(False, "Unexpected problem: %s" % str(exc)[:120], "error")
            _set(index, status="done" if res.ok else "failed", message=res.message, step="")
    finally:
        with _lock:
            _job["status"] = "done"
            _job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
