"""No PHP in the uploads folder: a PHP file placed there can no longer be run from the web.

Why: the usual way a WordPress website gets a back door is a plugin hole that lets a stranger save a file into the
uploads folder; the stranger then opens that file by its web address and it runs as a program (a "web shell").
Photos and documents belong in the uploads folder, programs do not. With this switch on, the web server refuses to
run any PHP file that is opened by its web address from there. Plugins that read their own PHP files from the folder
on the server's side (some do) are not affected, because the web server is not involved when they do.

How it is done: a small block of lines between two marker lines in the uploads folder's own settings file
(.htaccess). Lines that were already there are never changed. LiteSpeed (and OpenLiteSpeed) read that file.

How it is made safe, in the order it matters
* Everything is done as the website's own user (never as root), for the same reason as everywhere else in the panel.
* Before anything is kept, a harmless PHP test file is put into the folder: it must RUN before the rule and be REFUSED
  after it (which proves the web server really applies the rule), the website must still answer as well as before, and a
  picture from the uploads folder must still load. If any of that is wrong, the settings file is put back exactly as it
  was. The test file is always removed.
* A website whose uploads folder is not reachable by web address needs nothing and is left alone.
* Honest limit, said on the page: it stops the common attack (a file saved by a plugin hole and then opened by address).
  Somebody who can already change the website's files could take the rule out again.
"""
import copy
import json
import secrets
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import updates, util, wpupdate
from .util import Result

BEGIN = "# BEGIN CP-Security no-php-in-uploads"
END = "# END CP-Security no-php-in-uploads"
RULE = (BEGIN + "\n"
        '<FilesMatch "(?i)\\.(php[0-9]?|phtml|phar|pht|phps|shtml?)$">\n'
        "    Require all denied\n"
        "</FilesMatch>\n" + END + "\n")
SETTLE_TRIES = 12                   # LiteSpeed looks at a changed settings file only every few seconds (measured: up to about 8)
SETTLE_PAUSE = 2.0
_sleep = time.sleep
MAX_SIZE = 1024 * 1024


# ----------------------------------------------------------------------------- the text of the settings file
def split_block(text):
    """(text before our block, our block or None, text after it). Raises ValueError when the block is damaged."""
    lines = text.splitlines(keepends=True)
    begin = [i for i, ln in enumerate(lines) if ln.strip() == BEGIN]
    end = [i for i, ln in enumerate(lines) if ln.strip() == END]
    if not begin and not end:
        return text, None, ""
    if len(begin) != 1 or len(end) != 1 or end[0] < begin[0]:
        raise ValueError("damaged")
    return "".join(lines[:begin[0]]), "".join(lines[begin[0]:end[0] + 1]), "".join(lines[end[0] + 1:])


def without_block(text):
    before, block, after = split_block(text)
    if block is None:
        return text
    if after.startswith("\n"):                       # we put one blank line between our block and the rest: take it away with the block
        after = after[1:]
    return before + after


def with_block(text):
    base = without_block(text)
    return RULE + ("\n" + base if base.strip() else "")


# ----------------------------------------------------------------------------- reading and writing, as the website's user
def _read(site, path):
    """('none' | 'file' | 'link' | 'error', text)."""
    q = shlex.quote(path)
    rc, out = wpupdate._shell(site["user"], "if [ -L %s ]; then echo __LINK__; elif [ -f %s ]; then echo __FILE__; cat -- %s | head -c %d; else echo __NONE__; fi"
                              % (q, q, q, MAX_SIZE + 1), 60)
    if rc != 0:
        return "error", ""
    head, _, body = out.partition("\n")
    kind = {"__LINK__": "link", "__FILE__": "file", "__NONE__": "none"}.get(head.strip(), "error")
    if kind == "file" and len(body) > MAX_SIZE:
        return "error", ""
    return kind, (body if kind == "file" else "")


def _write(site, path, text):
    q = shlex.quote
    tmp = "%s.cps-%s" % (path, secrets.token_hex(4))
    script = ("umask 022; cat > %s && { [ -f %s ] && chmod --reference=%s %s; mv -f %s %s; } || { rm -f %s; exit 1; }"
              % (q(tmp), q(path), q(path), q(tmp), q(tmp), q(path), q(tmp)))
    rc, out = util.run_with_input(["su", "-s", "/bin/bash", site["user"], "-c", script], text.encode("utf-8"), timeout=60)
    return rc == 0, out.strip()[:100]


def _put_back(site, path, kind, original):
    """The settings file exactly as it was: the old text, or no file when there was none."""
    if kind == "file":
        return _write(site, path, original)[0]
    rc, _out = wpupdate._shell(site["user"], "rm -f -- %s" % shlex.quote(path), 60)
    return rc == 0


def _facts(site, php):
    """{'dir', 'rel'}: the uploads folder, and its address under the website (None when it is not reachable by address), or None."""
    code = "$u = wp_get_upload_dir(); echo json_encode(array('dir' => $u['basedir']));"
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
            if isinstance(data, dict) and isinstance(data.get("dir"), str) and data["dir"].startswith("/"):
                folder = data["dir"].rstrip("/")
                root = site["docroot"].rstrip("/")
                return {"dir": folder, "rel": folder[len(root):] if folder.startswith(root + "/") else None}
    return None


def _status(domain, path):
    """Only the answer code for an address (a picture's bytes are never read into the panel)."""
    rc, out = util.run(["curl", "-sk", "--resolve", "%s:443:127.0.0.1" % domain, "--max-time", "25", "-o", "/dev/null", "-w", "%{http_code}",
                        "https://%s%s" % (domain, path)], timeout=40)
    return out.strip()[-3:] if rc == 0 and out.strip() else "000"


def _sample_static(site, facts):
    """A picture, style sheet or script from the uploads folder with a plain name: its address, or None."""
    rc, out = wpupdate._shell(site["user"], "find %s -maxdepth 4 -type f \\( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.webp' -o -iname '*.gif' "
                              "-o -iname '*.css' -o -iname '*.js' \\) 2>/dev/null | grep -E '^[A-Za-z0-9_./-]+$' | head -1" % shlex.quote(facts["dir"]), 60)
    path = out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else ""
    return facts["rel"] + path[len(facts["dir"]):] if path.startswith(facts["dir"] + "/") else None


# ----------------------------------------------------------------------------- what the page shows
def _inspect(name):
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    out = {"site": name, "checked": False, "status": "unknown", "problem": ""}
    if not php:
        out["problem"] = "WordPress could not be started on this website."
        return out
    facts = _facts(site, php)
    if not facts:
        out["problem"] = "WordPress did not say where its uploads folder is."
        return out
    out["checked"] = True
    if facts["rel"] is None:
        out.update(status="unsupported", problem="The uploads folder of this website cannot be opened by web address, so there is nothing to protect.")
        return out
    kind, text = _read(site, facts["dir"] + "/.htaccess")
    if kind in ("link", "error"):
        out.update(status="unsupported", problem="The settings file in the uploads folder is a link or cannot be read, so it was left alone.")
        return out
    try:
        _before, block, _after = split_block(text)
    except ValueError:
        out.update(status="changed", problem="The CP-Security lines in the uploads folder are damaged.")
        return out
    out["status"] = "off" if block is None else ("on" if block == RULE else "changed")
    return out


_lock = threading.Lock()
_scan = {"status": "idle", "finished": "", "sites": {}}
_job = {"status": "idle", "action": "", "items": [], "started": "", "finished": ""}


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
        return {"site": name, "checked": False, "status": "unknown", "problem": "Looking at this website failed (%s)." % str(exc)[:80]}


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


def _update_scan(name, **fields):
    with _lock:
        if name in _scan["sites"]:
            _scan["sites"][name].update(fields)


def state(names=None):
    """For the page: one line per WordPress website."""
    names = names if names is not None else _names()
    scan = scan_state()
    sites = []
    for name in names:
        s = scan["sites"].get(name) or {"checked": False, "status": "unknown", "problem": ""}
        sites.append({"site": name, "checked": s.get("checked", False), "status": s.get("status", "unknown"), "problem": s.get("problem", "")})
    return {"scan": {"status": scan["status"], "finished": scan["finished"]}, "sites": sites}


# ----------------------------------------------------------------------------- switching it on
def enable_one(name, progress=None):
    """Turn the protection on for one website, prove it works, and put everything back if anything is wrong."""
    say = progress or (lambda text: None)
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    say("Asking WordPress where the uploads folder is")
    facts = _facts(site, php)
    if not facts:
        return Result(False, "WordPress did not say where its uploads folder is, so nothing was changed.", "facts")
    if facts["rel"] is None:
        return Result(False, "The uploads folder of this website cannot be opened by web address, so there is nothing to protect and nothing was changed.", "unsupported")
    say("Checking that the website answers normally")
    before = wpupdate.health(name)
    if not wpupdate._good(before["home"]):
        return Result(False, "The website is not answering normally now, so nothing was changed.", "unhealthy")
    path = facts["dir"] + "/.htaccess"
    kind, original = _read(site, path)
    if kind in ("link", "error"):
        return Result(False, "The settings file in the uploads folder is a link or cannot be read, so nothing was changed.", "unsafe")
    try:
        new = with_block(original if kind == "file" else "")
    except ValueError:
        return Result(False, "The CP-Security lines in the uploads folder are damaged, so nothing was changed. Remove them by hand first.", "damaged")
    if kind == "file" and new == original:
        _update_scan(name, status="on")
        return Result(True, "The protection was already on for %s." % name)

    q = shlex.quote
    token = secrets.token_hex(6)
    marker = "CPS-RAN-" + token
    test_file = "%s/cps-selftest-%s.php" % (facts["dir"], token)
    test_url = "%s/cps-selftest-%s.php" % (facts["rel"], token)
    static = _sample_static(site, facts)
    static_before = _status(name, static) if static else ""
    try:
        say("Putting a harmless test file in the uploads folder")
        rc, out = util.run_with_input(["su", "-s", "/bin/bash", site["user"], "-c", "umask 022; cat > %s" % q(test_file)],
                                      ('<?php echo "%s";' % marker).encode("utf-8"), timeout=60)
        if rc != 0:
            return Result(False, "A test file could not be saved in the uploads folder (%s), so nothing was changed." % (out.strip()[:80] or "no reason given"), "write")
        say("Checking that a PHP file there would run right now")
        code, body = wpupdate._get(name, test_url)
        runs_now = code[:1] == "2" and marker in body
        if not runs_now and code not in ("401", "403"):
            return Result(False, "The test could not be done (the website answered %s for the test file), so nothing was changed." % code, "no_test")
        say("Switching the protection on")
        ok, why = _write(site, path, new)
        if not ok:
            return Result(False, "The settings file could not be written (%s), so nothing was changed." % (why or "no reason given"), "write")
        refused = not runs_now                              # already refused by something else: nothing to prove, only to keep
        if runs_now:
            say("Checking that the same file is now refused (this takes a few seconds)")
            for attempt in range(SETTLE_TRIES):
                code, body = wpupdate._get(name, test_url)
                if code == "403" and marker not in body:
                    refused = True
                    break
                if attempt < SETTLE_TRIES - 1:
                    _sleep(SETTLE_PAUSE)
        if not refused:
            _put_back(site, path, kind, original)
            return Result(False, "The web server did not apply the rule (the test file still ran or the answer was %s), so everything was put back. "
                                 "Nothing was changed on this website." % code, "not_applied")
        say("Checking the website again")
        after = wpupdate.health(name)
        bad = wpupdate.problems(before, after)
        if static and wpupdate._good(static_before) and not wpupdate._good(_status(name, static)):
            bad.append("pictures from the uploads folder no longer load")
        if bad:
            _put_back(site, path, kind, original)
            return Result(False, "It was taken out again: %s." % " and ".join(bad), "regression")
    finally:
        wpupdate._shell(site["user"], "rm -f -- %s" % q(test_file), 30)
    _update_scan(name, status="on", problem="")
    return Result(True, "PHP files in the uploads folder of %s can no longer be run from the web. Tested." % name)


def disable_one(name, progress=None):
    """Take the protection off one website. Lines that were there before it was switched on are untouched."""
    say = progress or (lambda text: None)
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return Result(False, "That website was not found as a WordPress website on this server.", "not_found")
    facts = _facts(site, php)
    if not facts or facts["rel"] is None:
        return Result(False, "WordPress did not say where its uploads folder is, so nothing was changed.", "facts")
    path = facts["dir"] + "/.htaccess"
    kind, original = _read(site, path)
    if kind in ("link", "error"):
        return Result(False, "The settings file in the uploads folder is a link or cannot be read, so nothing was changed.", "unsafe")
    if kind == "none":
        _update_scan(name, status="off")
        return Result(True, "The protection was already off for %s." % name)
    try:
        _before, block, _after = split_block(original)
        rest = without_block(original)
    except ValueError:
        return Result(False, "The CP-Security lines in the uploads folder are damaged, so nothing was changed. Remove them by hand first.", "damaged")
    if block is None:
        _update_scan(name, status="off")
        return Result(True, "The protection was already off for %s." % name)
    say("Taking the protection off")
    if rest.strip():
        ok, why = _write(site, path, rest)
    else:                                                   # the file held only our lines: it goes away with them
        rc, out = wpupdate._shell(site["user"], "rm -f -- %s" % shlex.quote(path), 60)
        ok, why = rc == 0, out.strip()[:100]
    if not ok:
        return Result(False, "The settings file could not be changed (%s)." % (why or "no reason given"), "write")
    _update_scan(name, status="off", problem="")
    return Result(True, "PHP files in the uploads folder of %s can run from the web again (as before)." % name)


# ----------------------------------------------------------------------------- the job (many websites, one at a time)
def job_state():
    with _lock:
        s = copy.deepcopy(_job)
    s["counts"] = {k: sum(1 for i in s["items"] if i["status"] == k) for k in ("waiting", "working", "done", "failed")}
    return s


def start(action, names):
    if action not in ("enable", "disable"):
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
                fn = enable_one if action == "enable" else disable_one
                res = fn(name, progress=lambda text, at=index: _set(at, step=text))
            except Exception as exc:                    # one website must never stop the others
                res = Result(False, "Unexpected problem: %s" % str(exc)[:120], "error")
            _set(index, status="done" if res.ok else "failed", message=res.message, step="")
    finally:
        with _lock:
            _job["status"] = "done"
            _job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
