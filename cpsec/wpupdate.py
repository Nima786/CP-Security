"""Update WordPress plugins and themes by hand from the panel: one item at a time, with a copy kept and a check afterwards.

Nothing here runs by itself. A person chooses what to update and presses the button. Never "everything everywhere".

For every item, in this order:
  1. the website must be answering normally now (otherwise nothing is touched: a check afterwards would mean nothing);
  2. a copy of the plugin or theme folder is saved, and once per website a copy of its database;
  3. WordPress's own command-line tool (WP-CLI) does the update, as the website's own user;
  4. the website is asked again (home page with a fresh address so the cache cannot answer, and the login page);
  5. if it does not answer properly, or shows a PHP crash, the saved copy goes back and the website is checked again.
If something fails the website stays on its old version and the message says why; the owner updates that one by
hand in WordPress (a link to the website's own update page is shown).

Honest limit: putting the old files back cannot undo changes an update made to the database. That is why the
database copy is saved first (restoring it is a manual step).

All file work is done as the website's own user (`su`), never as root, for the same reason as in htfile.py.
"""
import copy
import os
import re
import secrets
import shlex
import threading
import time

from . import config, updates, util
from .util import Result

SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
KINDS = ("plugin", "theme")
KEEP_COPIES = 3
MAX_ITEMS = 100
FATAL = ("There has been a critical error", "Fatal error", "Parse error", "Uncaught ", "Call to undefined",
         "Allowed memory size", "Maximum execution time")
_sleep = time.sleep


is_careful = updates.is_careful


# ----------------------------------------------------------------------------- talking to the website
def _site(domain):
    """{'docroot', 'user', 'home'} for a WordPress website on this server, or None."""
    for docroot, user, name in updates._wordpress_sites():
        if name == domain:
            return {"docroot": docroot, "user": user, "home": os.path.dirname(docroot)}
    return None


def _shell(user, script, timeout):
    return util.run(["su", "-s", "/bin/bash", user, "-c", script], timeout=timeout)


_php_cache = {}


def _php(site):
    """The PHP program that can load this website (the first lsphp that answers 'core version')."""
    key = site["docroot"]
    if key in _php_cache:
        return _php_cache[key]
    for ver in config.PHP_TRY:
        php = "%s/%s/bin/php" % (config.P.lsws_root, ver)
        if not os.path.exists(php):
            continue
        rc, out = _shell(site["user"], "export HOME=%s; cd %s && %s /usr/bin/wp --skip-plugins --skip-themes core version 2>/dev/null"
                         % (shlex.quote(site["home"]), shlex.quote(site["docroot"]), php), 60)
        if rc == 0 and re.match(r"^\d", out.strip()):
            _php_cache[key] = php
            return php
    return None


def _wp(site, php, args, timeout=300):
    return _shell(site["user"], "export HOME=%s; cd %s && %s /usr/bin/wp --skip-plugins --skip-themes %s 2>&1"
                  % (shlex.quote(site["home"]), shlex.quote(site["docroot"]), php, args), timeout)


def _wp_full(site, php, args, timeout=120, admin=None, area=False):
    """Like _wp but with the plugins loaded (needed for commands a plugin adds, such as clearing the cache).
    admin: the number of an administrator to act as. A plugin that gets its updates from its maker's own server only
    offers them to somebody who is allowed to update."""
    who = "--user=%d " % int(admin) if admin else ""
    if area:
        who = updates.ADMIN_AREA + " " + who              # some plugins only start inside wp-admin
    return _shell(site["user"], "export HOME=%s; cd %s && %s /usr/bin/wp %s%s 2>&1"
                  % (shlex.quote(site["home"]), shlex.quote(site["docroot"]), php, who, args), timeout)


def _admin_id(site, php):
    rc, out = _wp(site, php, "user list --role=administrator --field=ID --number=1", 60)
    for line in reversed((out or "").strip().splitlines()):
        if rc == 0 and line.strip().isdigit():
            return int(line.strip())
    return None


LICENCE_RE = re.compile(r"unauthori[sz]ed|licen[cs]e|forbidden|\b40[13]\b|expired", re.I)


def reason(out):
    """Why WP-CLI's update failed, in its own words. The cause is usually on a 'Warning:' line (the download was refused);
    the 'Error:' line only says 'No plugins updated'. The website's language may not be English: show the line as it is."""
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    warnings = [ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("Warning:")]
    errors = [ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("Error")]
    text = (warnings or errors or ["the update tool reported a failure"])[0]
    if LICENCE_RE.search(text):
        text += " \u2013 this usually means the plugin's licence is not active for this website"
    return text


def _clear_maintenance(site):
    """A killed or crashed update can leave WordPress's 'upgrading' marker behind, which keeps the website in maintenance mode."""
    path = shlex.quote(site["docroot"] + "/.maintenance")
    _shell(site["user"], "test -f %s && grep -q upgrading %s && rm -f %s; true" % (path, path, path), 30)


def _current(site, php, kind, slug):
    rc, out = _wp(site, php, "%s get %s --field=version" % (kind, shlex.quote(slug)), 90)
    return _version(out) if rc == 0 else ""


def _version(text):
    """The version number in WP-CLI's answer (the last line that looks like one), or ''."""
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if re.match(r"^\d[\w.+-]*$", line):
            return line
    return ""


def _get(domain, path):
    """(status text, page text) as the local web server answers for this website."""
    rc, out = util.run(["curl", "-sk", "--resolve", "%s:443:127.0.0.1" % domain, "--max-time", "25", "-w", "\n%{http_code}",
                        "https://%s%s" % (domain, path)], timeout=40)
    if rc != 0:
        return "000", ""
    body, _, code = out.rpartition("\n")
    return code.strip() or "000", body[:400000]


def health(domain):
    """What the website answers now: {'home': code, 'login': code, 'markers': [PHP crash texts seen]}."""
    home_code, home_body = _get(domain, "/?cpsu=%s" % secrets.token_hex(4))        # a fresh address: the page cache cannot answer
    login_code, login_body = _get(domain, "/wp-login.php")
    markers = sorted(m for m in FATAL if m in home_body or m in login_body)
    return {"home": home_code, "login": login_code, "markers": markers}


def _good(code):
    return code[:1] in ("2", "3")


def problems(before, after):
    """Plain sentences about what got worse between two health() answers (empty list = fine)."""
    out = []
    if not _good(after["home"]):
        out.append("the home page now answers %s" % ("nothing" if after["home"] == "000" else after["home"]))
    if _good(before["login"]) and not _good(after["login"]):
        out.append("the login page now answers %s" % ("nothing" if after["login"] == "000" else after["login"]))
    new = [m for m in after["markers"] if m not in before["markers"]]
    if new:
        out.append("the page shows a PHP error (%s)" % new[0].strip())
    return out


# ----------------------------------------------------------------------------- one item
def _prune(site, pattern):
    """Keep the newest KEEP_COPIES entries of the backup folder whose name matches `pattern`; remove the rest.

    Newest = highest name, because every name ends in a time stamp. The folder's own modified time cannot be used:
    `cp -a` keeps the plugin's old time, so every copy of one plugin would look equally old.
    """
    d = site["home"] + "/cps-backups"
    rc, out = _shell(site["user"], "ls -1 %s 2>/dev/null" % shlex.quote(d), 30)
    names = sorted((n for n in out.splitlines() if re.match(pattern, n)), reverse=True)
    old = names[KEEP_COPIES:]
    if old:
        _shell(site["user"], "cd %s && rm -rf -- %s" % (shlex.quote(d), " ".join(shlex.quote(n) for n in old)), 120)


def _clean_old_copies(site, kind, slug):
    _prune(site, r"^%s-%s-\d{8}-\d{6}$" % (kind, re.escape(slug)))


def save_database(site, php, stamp):
    """One copy of the website's database in the website's own backup folder. Returns (ok, note)."""
    d = site["home"] + "/cps-backups"
    rc, out = _wp(site, php, "db export %s/db-%s.sql" % (shlex.quote(d), stamp), 900)
    _prune(site, r"^db-\d{8}-\d{6}\.sql$")
    return rc == 0, "" if rc == 0 else "the database copy could not be made"


def update_one(domain, kind, slug, db_saved=False, stamp=None, progress=None):
    """Update one plugin or theme. Returns {'ok', 'restored', 'from', 'to', 'message', 'notes'}.
    progress: called with a short plain sentence at each step, so the page can show that something is happening."""
    say = progress or (lambda text: None)
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    result = {"ok": False, "restored": False, "from": "", "to": "", "message": "", "notes": [], "db_attempted": bool(db_saved)}
    if kind not in KINDS or not SLUG_RE.match(slug or ""):
        result["message"] = "That is not a plugin or theme name."
        return result
    site = _site(domain)
    if site is None:
        result["message"] = "That website was not found as a WordPress website on this server."
        return result
    php = _php(site)
    if php is None:
        result["message"] = "WordPress could not be started on this website, so it cannot be updated from here."
        return result

    rc, out = _wp(site, php, "%s get %s --field=version" % (kind, shlex.quote(slug)), 90)
    old = _version(out) if rc == 0 else ""
    if not old:
        result["message"] = "This %s was not found on the website (it may have been removed)." % kind
        return result
    result["from"] = old

    say("Checking that the website answers normally")
    before = health(domain)
    if not _good(before["home"]):
        result["message"] = ("The website is not answering normally now (the home page gives %s), so nothing was changed. "
                             "A check afterwards would mean nothing." % ("no answer" if before["home"] == "000" else before["home"]))
        return result

    rc, out = _wp(site, php, "%s path" % kind, 60)
    base = out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else ""
    if not base or not os.path.isabs(base) or not base.startswith(site["docroot"]):
        result["message"] = "The folder of this %s could not be found, so nothing was changed." % kind
        return result
    path = base.rstrip("/") + "/" + slug
    rc, out = _shell(site["user"], "test -d %s && echo dir || (test -f %s.php && echo file)" % (shlex.quote(path), shlex.quote(path)), 30)
    shape = out.strip()
    if shape == "file":
        path += ".php"
    elif shape != "dir":
        result["message"] = "The files of this %s were not found where WordPress keeps them." % kind
        return result

    say("Saving a copy of the %s files" % kind)
    copy = "%s/cps-backups/%s-%s-%s" % (site["home"], kind, slug, stamp)
    rc, out = _shell(site["user"], "mkdir -p -m 700 %s && cp -a %s %s" % (shlex.quote(site["home"] + "/cps-backups"), shlex.quote(path), shlex.quote(copy)), 300)
    if rc != 0:
        result["message"] = "A copy of the current files could not be saved, so nothing was changed."
        return result
    if not db_saved:
        say("Saving a copy of the database (this can take a minute)")
        ok, note = save_database(site, php, stamp)
        result["db_attempted"] = True
        if not ok:
            result["notes"].append(note)

    command = "%s update %s" % (kind, shlex.quote(slug))
    say("Installing the new version")
    rc, out = _wp(site, php, command, 600)
    errors = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("Error")]
    new = _current(site, php, kind, slug)
    own_server = False
    if rc == 0 and not errors and new == old:
        # WordPress.org knows nothing about it. A plugin that updates from its maker's own server only says so once it is
        # loaded and an administrator is asking, which is what the website's own Updates page does. Try that way once.
        admin = _admin_id(site, php)
        for area in ((True, False) if admin else ()):      # as inside wp-admin first; plain if a plugin cannot cope with that
            say("Trying again the way the website\u2019s own Updates page does it")
            rc, out = _wp_full(site, php, command, 600, admin, area)
            errors = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("Error")]
            new = _current(site, php, kind, slug)
            own_server = new != old
            if new != old or rc == 0 or "Warning:" in out:   # worked, "already updated", or refused with a reason: do not ask twice
                break
    result["to"] = new
    if rc != 0 or errors or not new:
        result["message"] = "The update failed (%s). The website stays on version %s." % (reason(out)[:220], old)
        _clear_maintenance(site)
        _restore_if_changed(site, path, copy, result, domain, before)
        return result
    if new == old:
        result["message"] = ("Nothing changed: it is still version %s. This often means the update needs a licence or "
                             "a manual download. Update it in WordPress." % old)
        return result

    say("Checking the website again")
    after = health(domain)
    bad = problems(before, after)
    if bad:
        say("The website does not look right: putting the old version back")
        _restore(site, path, copy)
        again = health(domain)
        result["restored"] = True
        result["message"] = ("After the update %s, so the old version %s was put back%s." % (
            " and ".join(bad), old, "" if not problems(before, again) else ", but the website still does not look right: check it now"))
        result["to"] = old
        return result
    result["ok"] = True
    result["message"] = "Updated from %s to %s. The website still answers normally." % (old, new)
    if own_server:
        result["message"] += " (This one updates from its maker's own server, not from WordPress.org.)"
    say("Clearing the cache")
    _wp_full(site, php, "litespeed-purge all", 60)                    # ignored if the cache plugin is not there
    _clean_old_copies(site, kind, slug)
    return result


def _restore(site, path, copy):
    return _shell(site["user"], "rm -rf %s && cp -a %s %s" % (shlex.quote(path), shlex.quote(copy), shlex.quote(path)), 300)


def _restore_if_changed(site, path, copy, result, domain, before):
    """After a failed update tool run: if the files changed or vanished, put the saved copy back."""
    rc, out = _shell(site["user"], "diff -rq %s %s >/dev/null 2>&1 && echo same || echo different" % (shlex.quote(path), shlex.quote(copy)), 120)
    if "same" not in out.split():
        _restore(site, path, copy)
        result["restored"] = True
        result["message"] += " The saved copy was put back."


# ----------------------------------------------------------------------------- the background job
_lock = threading.Lock()
_job = {"status": "idle", "phase": "", "items": [], "started": "", "finished": "", "stop": False}


def state():
    with _lock:
        s = copy.deepcopy(_job)
    now = time.time()
    for i in s["items"]:                                   # how long the one that is running has been going
        i["seconds"] = int(now - i["since"]) if i["status"] == "working" and i.get("since") else 0
        i.pop("since", None)
    s["counts"] = {k: sum(1 for i in s["items"] if i["status"] == k) for k in ("waiting", "working", "done", "failed", "restored", "skipped")}
    return s


def check_items(items):
    """Validate the list from the page. Returns (clean list, error text)."""
    if not isinstance(items, list) or not items:
        return None, "Choose what to update."
    if len(items) > MAX_ITEMS:
        return None, "That is too many at once (the most is %d)." % MAX_ITEMS
    clean, seen = [], set()
    known = {name for _d, _u, name in updates._wordpress_sites()}
    for it in items:
        if not isinstance(it, dict):
            return None, "Those choices could not be read."
        site, kind, slug = it.get("site"), it.get("kind"), it.get("slug")
        if site not in known:
            return None, "%s is not a WordPress website on this server." % (str(site)[:60])
        if kind not in KINDS or not isinstance(slug, str) or not SLUG_RE.match(slug):
            return None, "That is not a plugin or theme name."
        if (site, kind, slug) not in seen:
            seen.add((site, kind, slug))
            clean.append({"site": site, "kind": kind, "slug": slug})
    return clean, ""


def start(items, titles=None, on_item=None, on_done=None):
    """Begin the updates in the background. titles: {(site,kind,slug): readable name}."""
    clean, err = check_items(items)
    if err:
        return Result(False, err, "invalid")
    with _lock:
        if _job["status"] == "running":
            return Result(False, "Updates are already running. Wait for them to finish.", "busy")
        titles = titles or {}
        _job.update(status="running", phase="updating", started=time.strftime("%Y-%m-%d %H:%M:%S"), finished="", stop=False,
                    items=[dict(i, title=titles.get((i["site"], i["kind"], i["slug"]), i["slug"]), status="waiting",
                                message="", step="", since=0, **{"from": "", "to": ""}) for i in clean])
    threading.Thread(target=_run, args=(on_item, on_done), daemon=True).start()
    return Result(True, "Started: %d update%s." % (len(clean), "" if len(clean) == 1 else "s"))


def stop():
    with _lock:
        if _job["status"] != "running":
            return Result(False, "Nothing is running.", "none")
        _job["stop"] = True
    return Result(True, "It stops after the update that is running now. The rest are skipped.")


def _set(index, **fields):
    with _lock:
        _job["items"][index].update(fields)


def _run(on_item=None, on_done=None):
    stamp_by_site, db_by_site, touched = {}, {}, set()
    try:
        with _lock:
            items = [dict(i) for i in _job["items"]]
        for index, it in enumerate(items):
            with _lock:
                halted = _job["stop"]
            if halted:
                _set(index, status="skipped", message="Skipped, because you stopped the updates.")
                continue
            _set(index, status="working", message="", step="Starting", since=time.time())
            site = it["site"]
            stamp = stamp_by_site.setdefault(site, time.strftime("%Y%m%d-%H%M%S"))
            try:
                res = update_one(site, it["kind"], it["slug"], db_saved=db_by_site.get(site, False), stamp=stamp,
                                 progress=lambda text, at=index: _set(at, step=text))
            except Exception as exc:                  # one item must never stop the others, or the panel
                res = {"ok": False, "restored": False, "from": "", "to": "", "message": "Unexpected problem: %s" % str(exc)[:120], "notes": [], "db_attempted": False}
            db_by_site[site] = db_by_site.get(site, False) or bool(res.get("db_attempted"))
            touched.add(site)
            status = "done" if res["ok"] else ("restored" if res["restored"] else "failed")
            note = (" (" + "; ".join(res["notes"]) + ")") if res["notes"] else ""
            _set(index, status=status, message=res["message"] + note, step="", **{"from": res["from"], "to": res["to"]})
            if on_item:
                try:
                    on_item(dict(it, status=status, message=res["message"]))
                except Exception:
                    pass
    finally:
        # The list of what is still waiting is read again BEFORE the job counts as finished. Otherwise the page, which
        # fetches that list the moment it sees "finished", would get the old list and still show what was just updated.
        if on_done:
            with _lock:
                _job["phase"] = "checking"
            try:
                on_done(sorted(touched))
            except Exception:
                pass
        with _lock:
            _job["status"] = "done"
            _job["phase"] = ""
            _job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
