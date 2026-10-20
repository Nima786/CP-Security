"""One-click login: open a website's dashboard from the panel without typing a password.

How it works
* Each website that is switched on gets ONE small file in its must-use plugins folder (wp-content/mu-plugins). WordPress loads
  that folder by itself, so nothing has to be activated. The file belongs to the website's own user and nobody else can read
  it, because it holds a secret that only this website and this panel know.
* "Open admin" in the panel makes a link that works for 60 seconds and once: the link carries the account to log in as, an
  expiry time and a random number, signed with that secret (HMAC). The browser opens the link on the website; the helper checks the
  signature, the time and that the link was not used before, logs that administrator in, and sends the browser to the dashboard.
  Because the login happens directly, a custom login address (a "hide login" plugin) does not matter.
* Nothing is stored on the website for a link except a note that it was used.

Safety, in the order it matters
* The helper is checked before it is switched on: its PHP is linted, it is tested end to end with a link that is already expired
  (the website must answer with the "link expired" page, which proves the file is loaded and the secret matches), and the website
  must still answer afterwards. If anything fails, the old state is put back.
* Every file operation runs as the website's own user (never as root), for the same reason as everywhere else in the panel.
* Only the panel can make a link (it holds the secret); a link cannot be guessed or changed (the signature) and a stolen one is
  useless after a minute or a single use. A link for an account that is not an administrator is refused by the website.
* Every use is written to the panel's activity log.
* The trade-off, said on the page: this skips a website's own 2-step login, because it is the server owner. The panel's own login is the gate.
"""
import base64
import copy
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, updates, util, wpupdate
from .util import Result

HELPER_NAME = "cp-security-login.php"
HELPER_VERSION = 1
TOKEN_SECONDS = 60
DEEP_LINK_RE = re.compile(r"^[A-Za-z0-9_\-]+\.php(\?[A-Za-z0-9_=&%.\-]*)?$")      # the dashboard pages a link may open (never another site)

HELPER_TEMPLATE = r'''<?php
/**
 * Plugin Name: CP-Security one-click login
 * Description: Lets the server owner open this website's dashboard from the CP-Security panel with a link that works once, for one minute. Installed and removed by the panel.
 * Version: @@VERSION@@
 * Author: CP-Security
 */
// CPS-LOGIN-HELPER @@VERSION@@
if (!defined('ABSPATH')) {
    exit;
}

add_action('init', function () {
    if (!isset($_GET['cps-login']) || !is_string($_GET['cps-login'])) {
        return;
    }
    if (!preg_match('/^([A-Za-z0-9_\-]{20,2000})\.([a-f0-9]{64})$/', $_GET['cps-login'], $m)) {
        return;
    }
    $secret = '@@SECRET@@';
    if (!hash_equals(hash_hmac('sha256', $m[1], $secret), $m[2])) {
        return;                                   // not made by the panel: behave as if nothing was asked
    }
    $data = json_decode(base64_decode(strtr($m[1], '-_', '+/')), true);
    if (!is_array($data) || empty($data['u']) || !is_string($data['u']) || empty($data['e']) || empty($data['n'])) {
        return;
    }
    if (!defined('DONOTCACHEPAGE')) {
        define('DONOTCACHEPAGE', true);
    }
    nocache_headers();
    header('Referrer-Policy: no-referrer');
    header('X-Robots-Tag: noindex, nofollow');
    header('X-LiteSpeed-Cache-Control: no-cache');
    $key = 'cps_login_' . substr(hash('sha256', (string) $data['n']), 0, 24);
    $left = (int) $data['e'] - time();
    if ($left < 0 || $left > 300 || get_transient($key)) {
        wp_die('<p>This one-time login link has expired or was already used.</p><p>Go back to the CP-Security panel and press <strong>Open admin</strong> again.</p>', 'Link expired', array('response' => 410));
    }
    set_transient($key, 1, 900);                  // used: the same link never works twice
    $user = get_user_by('login', $data['u']);
    if (!$user || !user_can($user, 'manage_options')) {
        wp_die('<p>The account chosen in the panel is not an administrator of this website.</p>', 'Cannot sign in', array('response' => 403));
    }
    wp_set_current_user($user->ID, $user->user_login);
    wp_set_auth_cookie($user->ID, false, is_ssl());
    do_action('wp_login', $user->user_login, $user);
    $to = '';
    if (!empty($data['t']) && is_string($data['t']) && preg_match('/^[A-Za-z0-9_\-]+\.php(\?[A-Za-z0-9_=&%.\-]*)?$/', $data['t'])) {
        $to = $data['t'];
    }
    wp_safe_redirect(admin_url($to));
    exit;
}, 1);
'''


# ----------------------------------------------------------------------------- the helper file and the links
def render(secret):
    """The helper file for one website, with that website's secret inside."""
    return HELPER_TEMPLATE.replace("@@VERSION@@", str(HELPER_VERSION)).replace("@@SECRET@@", secret)


def fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_token(secret, login, to="", ttl=TOKEN_SECONDS, now=None):
    """'<payload>.<signature>': who to log in as, until when, a random number, and the page to open."""
    payload = {"u": login, "e": int((time.time() if now is None else now) + ttl), "n": secrets.token_hex(12)}
    if to and DEEP_LINK_RE.match(to):
        payload["t"] = to
    body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return body + "." + hmac.new(secret.encode("ascii"), body.encode("ascii"), hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------------- what is remembered
_lock = threading.Lock()


def _load():
    data = util.read_json(config.P.adminlogin_file, {"sites": {}})
    return data if isinstance(data, dict) and isinstance(data.get("sites"), dict) else {"sites": {}}


def _save(data):
    util.write_json(config.P.adminlogin_file, data, mode=0o600)


def _remember(name, **fields):
    with _lock:
        data = _load()
        entry = data["sites"].setdefault(name, {})
        entry.update({k: v for k, v in fields.items() if v is not None})
        _save(data)


def _forget_secret(name):
    with _lock:
        data = _load()
        if name in data["sites"]:
            data["sites"][name].pop("secret", None)
            data["sites"][name].pop("installed", None)
            if not data["sites"][name]:
                del data["sites"][name]
            _save(data)


def _entry(name):
    with _lock:
        return copy.deepcopy(_load()["sites"].get(name, {}))


# ----------------------------------------------------------------------------- reading a website
def _facts(site, php):
    """{'home', 'mu'} straight from WordPress (the address people use, and where its must-use folder is), or None."""
    code = "echo json_encode(array('home' => home_url(), 'mu' => WPMU_PLUGIN_DIR));"
    rc, out = wpupdate._wp(site, php, "eval " + shlex.quote(code), 90)
    if rc != 0:
        return None
    for line in reversed(out.replace("\ufeff", "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if isinstance(data, dict) and isinstance(data.get("home"), str) and isinstance(data.get("mu"), str):
                return {"home": data["home"], "mu": data["mu"].rstrip("/")}
    return None


def _admins(site, php):
    """The administrators of the website: [{'login', 'name'}], lowest account number first."""
    rc, out = wpupdate._wp(site, php, "user list --role=administrator --fields=ID,user_login,display_name --format=csv", 90)
    if rc != 0:
        return []
    lines = out.replace("\ufeff", "").strip().splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip().lower().startswith("id,")), None)
    if start is None:
        return []
    rows = []
    for row in csv.DictReader(io.StringIO("\n".join(lines[start:]))):
        if (row.get("user_login") or "") and str(row.get("ID", "")).isdigit():
            rows.append((int(row["ID"]), {"login": row["user_login"], "name": row.get("display_name") or row["user_login"]}))
    return [r for _id, r in sorted(rows, key=lambda x: x[0])]


def _file_state(site, final, secret):
    """installed | missing | changed (ours, but not as it should be) | unknown, by looking at the file as the website's user."""
    f = shlex.quote(final)
    rc, out = wpupdate._shell(site["user"], "if [ -f %s ]; then sha256sum -- %s; else echo MISSING; fi" % (f, f), 60)
    if rc != 0:
        return "unknown"
    lines = [ln.strip() for ln in out.strip().splitlines() if ln.strip()]
    if not lines or lines[0] == "MISSING":
        return "missing"
    sha = lines[0].split()[0]
    if secret and sha == fingerprint(render(secret)):
        return "installed"
    return "changed"


def _inspect(name):
    """Everything the page shows about one website."""
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    out = {"site": name, "checked": False, "home": "", "status": "unknown", "admins": [], "problem": ""}
    if not php:
        out["problem"] = "WordPress could not be started on this website."
        return out
    facts = _facts(site, php)
    if not facts:
        out["problem"] = "WordPress did not say where its folders are."
        return out
    out.update(checked=True, home=facts["home"], mu=facts["mu"])
    if not facts["mu"].startswith(site["home"] + "/"):
        out["status"] = "unsupported"
        out["problem"] = "This website keeps its must-use folder outside its own folder, so the helper cannot be put there."
        return out
    out["status"] = _file_state(site, facts["mu"] + "/" + HELPER_NAME, _entry(name).get("secret", ""))
    out["admins"] = _admins(site, php)
    return out


# ----------------------------------------------------------------------------- the list for the page
_scan = {"status": "idle", "finished": "", "sites": {}}


def _names():
    return sorted(n for _d, _u, n in updates._wordpress_sites())


def scan_state():
    with _lock:
        return copy.deepcopy(_scan)


def scan_start(only=None):
    with _lock:
        if _scan["status"] == "running":
            return Result(False, "Already looking at the websites.", "busy")
        _scan["status"] = "running"
    threading.Thread(target=_scan_run, args=(only,), daemon=True).start()
    return Result(True, "Looking at the websites.")


def _inspect_safe(name):
    try:
        return _inspect(name)
    except Exception as exc:                            # one website must never hide the others
        return {"site": name, "checked": False, "home": "", "status": "unknown", "admins": [],
                "problem": "Looking at this website failed (%s)." % str(exc)[:80]}


def _scan_run(only):
    try:
        try:
            names = list(only) if only else _names()
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


def _update_scan(name, **fields):
    with _lock:
        if name in _scan["sites"]:
            _scan["sites"][name].update(fields)


def state(names=None):
    """For the page: one line per WordPress website."""
    names = names if names is not None else _names()
    scan = scan_state()
    stored = _load()["sites"]
    sites = []
    for name in names:
        s = scan["sites"].get(name) or {"checked": False, "status": "unknown", "home": "", "admins": [], "problem": ""}
        chosen = (stored.get(name) or {}).get("login", "")
        logins = [a["login"] for a in s.get("admins", [])]
        sites.append({"site": name, "checked": s.get("checked", False), "home": s.get("home", ""), "status": s.get("status", "unknown"),
                      "problem": s.get("problem", ""), "admins": s.get("admins", []),
                      "login": chosen if chosen in logins else (logins[0] if logins else "")})
    return {"scan": {"status": scan["status"], "finished": scan["finished"]}, "sites": sites}


# ----------------------------------------------------------------------------- switching it on and off
def _selftest(name, secret):
    """Ask the website to open an already expired link: only a loaded helper with the right secret answers 'expired' (410)."""
    token = make_token(secret, "cps-selftest", ttl=-5)
    code, body = wpupdate._get(name, "/?cps-login=" + token)
    if code == "410" and "one-time login link" in body:
        return True, ""
    return False, "the website did not answer the test link the way the helper should (it answered %s)" % code


def install_one(name, progress=None):
    """Put the helper on one website, test it, and put everything back if anything is wrong."""
    say = progress or (lambda text: None)
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    say("Asking WordPress where its folders are")
    facts = _facts(site, php)
    if not facts:
        return Result(False, "WordPress did not say where its folders are, so nothing was changed.", "facts")
    if not facts["mu"].startswith(site["home"] + "/"):
        return Result(False, "This website keeps its must-use folder outside its own folder, so nothing was changed.", "unsupported")
    say("Checking that the website answers normally")
    before = wpupdate.health(name)
    if not wpupdate._good(before["home"]):
        return Result(False, "The website is not answering normally now, so nothing was changed.", "unhealthy")

    mu = facts["mu"]
    final, new, old = (mu + "/" + HELPER_NAME, mu + "/" + HELPER_NAME + ".new", mu + "/" + HELPER_NAME + ".old")
    q = shlex.quote
    secret = secrets.token_hex(32)
    say("Writing the helper")
    rc, out = util.run_with_input(
        ["su", "-s", "/bin/bash", site["user"], "-c", "umask 077; [ -d %s ] || mkdir -p -m 755 %s; cat > %s" % (q(mu), q(mu), q(new))],
        render(secret).encode("utf-8"), timeout=60)
    if rc != 0:
        return Result(False, "The helper could not be written (%s)." % (out.strip()[:100] or "no reason given"), "write")

    def drop_new():                                   # before anything was switched on: only the new file goes
        wpupdate._shell(site["user"], "rm -f %s" % q(new), 60)

    def put_back():                                   # after: the earlier helper comes back, or none if there was none
        wpupdate._shell(site["user"], "if [ -f %s ]; then mv -f %s %s; else rm -f %s; fi; rm -f %s" % (q(old), q(old), q(final), q(final), q(new)), 60)

    say("Checking the helper for mistakes")
    rc, out = wpupdate._shell(site["user"], "%s -l %s" % (php, q(new)), 60)
    if rc != 0 or "No syntax errors" not in out:
        drop_new()
        return Result(False, "The helper did not pass the PHP check on this website, so nothing was changed.", "lint")
    say("Switching it on")
    rc, out = wpupdate._shell(site["user"], "set -e; if [ -f %s ]; then cp -a %s %s; fi; mv -f %s %s" % (q(final), q(final), q(old), q(new), q(final)), 60)
    if rc != 0:
        put_back()
        return Result(False, "The helper could not be put in place (%s)." % (out.strip()[:100] or "no reason given"), "write")
    say("Testing it with a link that has already expired")
    ok, why = _selftest(name, secret)
    after = wpupdate.health(name)
    bad = wpupdate.problems(before, after)
    if not ok or bad:
        put_back()
        return Result(False, "It was taken out again: %s." % (why if not ok else " and ".join(bad)), "selftest")
    wpupdate._shell(site["user"], "rm -f %s" % q(old), 30)
    _remember(name, secret=secret, installed=time.strftime("%Y-%m-%d %H:%M"))
    _update_scan(name, status="installed", home=facts["home"], mu=mu)
    return Result(True, "The helper is on %s and tested." % name)


def remove_one(name, progress=None):
    """Take the helper off one website. Nothing else of the website is touched."""
    say = progress or (lambda text: None)
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    facts = _facts(site, php)
    if not facts or not facts["mu"].startswith(site["home"] + "/"):
        return Result(False, "WordPress did not say where its folders are, so nothing was changed.", "facts")
    say("Removing the helper")
    q = shlex.quote
    base = facts["mu"] + "/" + HELPER_NAME
    rc, out = wpupdate._shell(site["user"], "rm -f %s %s.new %s.old; test ! -e %s && echo gone" % (q(base), q(base), q(base), q(base)), 60)
    if "gone" not in out:
        return Result(False, "The helper could not be removed (%s)." % (out.strip()[:100] or "no reason given"), "write")
    _forget_secret(name)
    _update_scan(name, status="missing")
    return Result(True, "The helper was removed from %s." % name)


# ----------------------------------------------------------------------------- the job (many websites, one at a time)
_job = {"status": "idle", "action": "", "items": [], "started": "", "finished": ""}


def job_state():
    with _lock:
        s = copy.deepcopy(_job)
    s["counts"] = {k: sum(1 for i in s["items"] if i["status"] == k) for k in ("waiting", "working", "done", "failed")}
    return s


def start(action, names):
    """Install on, or remove from, these websites in the background."""
    if action not in ("install", "remove"):
        return Result(False, "Unknown action.", "invalid")
    known = set(_names())
    names = [n for n in dict.fromkeys(names or [])]
    if not names or any(n not in known for n in names):
        return Result(False, "Choose WordPress websites that are on this server.", "invalid")
    with _lock:
        if _job["status"] == "running":
            return Result(False, "Already working. Wait for it to finish.", "busy")
        _job.update(status="running", action=action, started=time.strftime("%Y-%m-%d %H:%M:%S"), finished="",
                    items=[{"site": n, "status": "waiting", "message": "", "step": ""} for n in names])
    threading.Thread(target=_run, args=(action,), daemon=True).start()
    return Result(True, "Started on %d website%s." % (len(names), "" if len(names) == 1 else "s"))


def _set(index, **fields):
    with _lock:
        _job["items"][index].update(fields)


def _run(action):
    try:
        with _lock:
            names = [i["site"] for i in _job["items"]]
        for index, name in enumerate(names):
            _set(index, status="working", step="Starting")
            try:
                fn = install_one if action == "install" else remove_one
                res = fn(name, progress=lambda text, at=index: _set(at, step=text))
            except Exception as exc:                    # one website must never stop the others
                res = Result(False, "Unexpected problem: %s" % str(exc)[:120], "error")
            _set(index, status="done" if res.ok else "failed", message=res.message, step="")
    finally:
        with _lock:
            _job["status"] = "done"
            _job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------------------------------------------------------- the choices and the link
def set_user(name, login):
    """Which administrator account 'Open admin' logs in as for this website."""
    entry = state([name])["sites"][0] if name in _names() else None
    if entry is None:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    if login not in [a["login"] for a in entry["admins"]]:
        return Result(False, "%s is not an administrator of that website." % login[:40], "invalid")
    _remember(name, login=login)
    return Result(True, "Open admin on %s now logs in as %s." % (name, login))


def make_link(name, to="", now=None):
    """The one-time link for a website: (Result, url). The helper is checked again first, so a changed file never gets a link."""
    site = wpupdate._site(name)
    if site is None:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found"), ""
    if to and not DEEP_LINK_RE.match(to):
        return Result(False, "That page cannot be opened this way.", "invalid"), ""
    info = scan_state()["sites"].get(name) or {}
    mu, home, admins = info.get("mu", ""), info.get("home", ""), info.get("admins", [])
    if not mu or not admins:
        fresh = _inspect(name)                                # a click before the page had finished looking
        mu, home, admins = fresh.get("mu", ""), fresh.get("home", ""), fresh.get("admins", [])
    stored = _entry(name)
    secret = stored.get("secret", "")
    if not mu or _file_state(site, mu + "/" + HELPER_NAME, secret) != "installed":
        return Result(False, "The helper is not installed (or was changed) on this website. Install it first.", "not_installed"), ""
    logins = [a["login"] for a in admins]
    if not logins:
        return Result(False, "This website has no administrator account to log in as.", "no_admin"), ""
    login = stored.get("login") if stored.get("login") in logins else logins[0]
    if not re.match(r"^https?://[^\s/?#]+(/[^\s?#]*)?$", home or ""):
        home = "https://%s" % name
    url = "%s/?cps-login=%s" % (home.rstrip("/"), make_token(secret, login, to, now=now))
    return Result(True, "Opening %s as %s." % (name, login)), url
