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
from concurrent.futures import ThreadPoolExecutor

from . import config, library, settings, updates, util
from .util import Result

SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
KINDS = ("plugin", "theme")
KEEP_COPIES = 1                      # the default; the owner can choose 1 to MAX_KEEP on the WP Updates page
MAX_KEEP = 5
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


def upload_hint(kind, slug, installed):
    """When the owner has already uploaded a newer file of this plugin or theme, say so: it is the way that works."""
    for z in library.list_zips():
        if z["kind"] == kind and z["slug"] == slug and library.version_cmp(z["version"], installed) > 0:
            return (" You have already uploaded version %s of this: use \u201cUpdate by uploading a file\u201d (or the button "
                    "\u201cUpdate from your upload\u201d) instead." % z["version"])
    return ""


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
    old = names[keep_copies():]
    if old:
        _shell(site["user"], "cd %s && rm -rf -- %s" % (shlex.quote(d), " ".join(shlex.quote(n) for n in old)), 120)


def _clean_old_copies(site, kind, slug):
    _prune(site, r"^%s-%s-\d{8}-\d{6}$" % (kind, re.escape(slug)))


def save_database(site, php, stamp):
    """One copy of the website's database in the website's own backup folder. Returns (ok, note)."""
    d = site["home"] + "/cps-backups"
    rc, out = _wp(site, php, "db export %s/db-%s.sql" % (shlex.quote(d), stamp), 900)
    mine = shlex.quote("%s/db-%s.sql" % (d, stamp))
    if rc != 0:                                       # a half-written copy is worth nothing and must not push out the last good one
        _shell(site["user"], "rm -f -- %s" % mine, 30)
        return False, "the database copy could not be made"
    _shell(site["user"], "chmod 600 -- %s" % mine, 30)    # it holds everything the website knows: only its own user may read it
    _prune(site, r"^db-\d{8}-\d{6}\.sql$")
    return True, ""


# ----------------------------------------------------------------------------- the copies saved before each update
COPY_ITEM_RE = re.compile(r"^(plugin|theme)-([A-Za-z0-9][A-Za-z0-9._-]*)-(\d{8})-(\d{6})$")
COPY_DB_RE = re.compile(r"^db-(\d{8})-(\d{6})\.sql$")


def keep_copies():
    """How many saved copies of each plugin, theme and database are kept (the owner's choice, 1 to MAX_KEEP)."""
    try:
        n = int(settings.load().get("copies_keep", KEEP_COPIES))
    except (TypeError, ValueError):
        n = KEEP_COPIES
    return max(1, min(MAX_KEEP, n))


def set_keep(n):
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= MAX_KEEP:
        return Result(False, "Choose a number from 1 to %d." % MAX_KEEP, "invalid")
    settings.save({"copies_keep": n})
    return Result(True, "From the next update on, the newest %s of each plugin, theme and database %s kept. Copies that are already saved stay "
                        "until you delete them here." % ("copy" if n == 1 else "%d copies" % n, "is" if n == 1 else "are"))


def _all_sites():
    return [({"docroot": d, "user": u, "home": os.path.dirname(d)}, name) for d, u, name in updates._wordpress_sites()]


def _when(day, clock):
    return "%s-%s-%s %s:%s" % (day[:4], day[4:6], day[6:], clock[:2], clock[2:4])


def copies(site):
    """The copies the panel saved for one website, newest first: [{'name', 'kind', 'what', 'when', 'kb'}].

    Only names the panel itself makes are listed (and so only those can ever be removed): anything else the owner keeps in the
    same folder is left alone."""
    d = site["home"] + "/cps-backups"
    script = ('cd %s 2>/dev/null || exit 0; for n in *; do [ -e "$n" ] || continue; '
              'printf "%%s\\t%%s\\n" "$(du -sk -- "$n" | cut -f1)" "$n"; done' % shlex.quote(d))
    rc, out = _shell(site["user"], script, 120)
    found = []
    for line in out.splitlines():
        kb, _, name = line.partition("\t")
        if not kb.strip().isdigit() or not name:
            continue
        m = COPY_ITEM_RE.match(name)
        if m:
            found.append((m.group(3) + m.group(4), {"name": name, "kind": m.group(1), "what": m.group(2), "when": _when(m.group(3), m.group(4)), "kb": int(kb)}))
            continue
        m = COPY_DB_RE.match(name)
        if m:
            found.append((m.group(1) + m.group(2), {"name": name, "kind": "database", "what": "Database", "when": _when(m.group(1), m.group(2)), "kb": int(kb)}))
    return [item for _order, item in sorted(found, key=lambda x: x[0], reverse=True)]


def copies_state():
    """For the WP Updates page: the saved copies, website by website (only websites that have some)."""
    try:
        found = _all_sites()
    except (ImportError, OSError):                  # not a server with websites on it
        found = []
    with ThreadPoolExecutor(max_workers=3) as ex:
        listed = list(ex.map(lambda pair: (pair[1], copies(pair[0])), found))
    rows = [{"site": name, "count": len(items), "kb": sum(i["kb"] for i in items), "newest": items[0]["when"], "items": items}
            for name, items in sorted(listed, key=lambda x: x[0]) if items]
    return {"keep": keep_copies(), "max_keep": MAX_KEEP, "sites": rows, "count": sum(r["count"] for r in rows), "kb": sum(r["kb"] for r in rows)}


def size_text(kb):
    return "%.1f MB" % (kb / 1024.0) if kb >= 1024 else "%d KB" % max(1, kb)


def copies_remove(names=None):
    """Delete the saved copies of some websites (None = all). Websites themselves are not touched, only the copies in their backup folder."""
    if state()["status"] == "running":
        return Result(False, "Updates are running now. Wait for them to finish: the copies are what puts a website back if an update fails.", "busy")
    try:
        found = _all_sites()
    except (ImportError, OSError):
        found = []
    known = {name for _site_, name in found}
    if names is not None and (not names or any(n not in known for n in names)):
        return Result(False, "Choose websites that are on this server.", "invalid")
    removed, freed, websites, failed = 0, 0, 0, []
    for site, name in found:
        if names is not None and name not in names:
            continue
        items = copies(site)
        if not items:
            continue
        q = shlex.quote
        _shell(site["user"], "cd %s && rm -rf -- %s" % (q(site["home"] + "/cps-backups"), " ".join(q(i["name"]) for i in items)), 600)
        left = {i["name"] for i in copies(site)}
        gone = [i for i in items if i["name"] not in left]
        if len(gone) < len(items):
            failed.append(name)
        if gone:
            removed += len(gone)
            freed += sum(i["kb"] for i in gone)
            websites += 1
    if not removed and not failed:
        return Result(False, "There are no saved copies to delete.", "none")
    message = "Deleted %d saved cop%s (%s) from %d website%s." % (removed, "y" if removed == 1 else "ies", size_text(freed), websites, "" if websites == 1 else "s")
    if failed:
        return Result(False, message + " Some could not be deleted on: %s." % ", ".join(failed), "partial")
    return Result(True, message)


def update_one(domain, kind, slug, db_saved=False, stamp=None, progress=None, upload=None):
    """Update one plugin or theme. Returns {'ok', 'restored', 'skipped', 'from', 'to', 'message', 'notes'}.
    progress: called with a short plain sentence at each step, so the page can show that something is happening.
    upload: a file from the library (see library.py). The plugin or theme is then replaced with the files in it, the way
    "upload a zip and replace the current one" does in WordPress, instead of being fetched from WordPress.org."""
    say = progress or (lambda text: None)
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    result = {"ok": False, "restored": False, "skipped": False, "from": "", "to": "", "message": "", "notes": [], "db_attempted": bool(db_saved)}
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
    if upload is not None and library.version_cmp(upload["version"], old) <= 0:
        result["skipped"] = True
        result["message"] = ("This website already has version %s of this %s and the uploaded file is version %s, so nothing was changed."
                             % (old, kind, upload["version"]))
        return result

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
    own_server = False
    if upload is not None:
        say("Sending the uploaded file to the website")
        sent, problem = library.deliver(upload["id"], site)
        if not sent:
            result["message"] = problem
            return result
        try:
            say("Installing the uploaded version")
            rc, out = _wp(site, php, "%s install %s --force" % (kind, shlex.quote(sent)), 900)
        finally:
            library.discard(site, sent)                  # the website's copy of the file never stays behind
    else:
        say("Installing the new version")
        rc, out = _wp(site, php, command, 600)
    errors = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("Error")]
    new = _current(site, php, kind, slug)
    if upload is None and rc == 0 and not errors and new == old:
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
        if upload is None:
            result["message"] += upload_hint(kind, slug, old)
        _clear_maintenance(site)
        _restore_if_changed(site, path, copy, result, domain, before)
        return result
    if new == old:
        result["message"] = (("Nothing changed: it is still version %s. WordPress did not replace the files with the uploaded ones. "
                              "Update it in WordPress." % old) if upload is not None else
                             ("Nothing changed: it is still version %s. This often means the update needs a licence or "
                              "a manual download. Update it in WordPress." % old + upload_hint(kind, slug, old)))
        return result
    if upload is not None and new != upload["version"]:
        result["notes"].append("the website reports version %s, the file says %s" % (new, upload["version"]))

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
    result["message"] = "Updated from %s to %s%s. The website still answers normally." % (old, new, " with the file you uploaded" if upload is not None else "")
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
        site, kind, slug, zid = it.get("site"), it.get("kind"), it.get("slug"), it.get("zip")
        if site not in known:
            return None, "%s is not a WordPress website on this server." % (str(site)[:60])
        if kind not in KINDS or not isinstance(slug, str) or not SLUG_RE.match(slug):
            return None, "That is not a plugin or theme name."
        if zid is not None:
            entry = library.get(zid)
            if entry is None:
                return None, "One of the uploaded files is no longer on the server."
            if entry["kind"] != kind or entry["slug"] != slug:
                return None, "That uploaded file is not the %s you chose." % kind
        if (site, kind, slug) not in seen:
            seen.add((site, kind, slug))
            clean.append(dict({"site": site, "kind": kind, "slug": slug}, **({"zip": zid} if zid is not None else {})))
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
                upload = library.get(it["zip"]) if it.get("zip") else None
                if it.get("zip") and upload is None:
                    res = {"ok": False, "restored": False, "skipped": False, "from": "", "to": "", "notes": [], "db_attempted": False,
                           "message": "The uploaded file was deleted from the server before its turn came, so nothing was changed."}
                else:
                    res = update_one(site, it["kind"], it["slug"], db_saved=db_by_site.get(site, False), stamp=stamp,
                                     progress=lambda text, at=index: _set(at, step=text), upload=upload)
            except Exception as exc:                  # one item must never stop the others, or the panel
                res = {"ok": False, "restored": False, "from": "", "to": "", "message": "Unexpected problem: %s" % str(exc)[:120], "notes": [], "db_attempted": False}
            db_by_site[site] = db_by_site.get(site, False) or bool(res.get("db_attempted"))
            touched.add(site)
            status = "done" if res["ok"] else ("restored" if res["restored"] else ("skipped" if res.get("skipped") else "failed"))
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
