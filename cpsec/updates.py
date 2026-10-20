"""Which WordPress sites have updates waiting: WordPress itself, plugins and themes.
This module only looks. Installing is done by wpupdate.py, one item at a time, when a person presses the button."""
import csv
import glob
import io
import os
import re
import shlex
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, util

# things that are most likely to hurt a shop if an update goes wrong: the screen says "try the test copy first"
CAREFUL_RE = re.compile(r"woocommerce|payment|gateway|checkout|stripe|paypal|zarinpal|idpay|mellat|saman|snapp|bricks|"
                        r"elementor|divi|wpbakery|memberpress|learndash|revslider|slider-revolution", re.I)


def is_careful(slug, title=""):
    return bool(CAREFUL_RE.search("%s %s" % (slug or "", title or "")))


def _wordpress_sites():
    import pwd  # Linux only: imported here so the rest of the package also loads elsewhere (tests)
    found = []
    for d in sorted(glob.glob(config.P.home_dir + "/*/public_html")):
        if os.path.exists(d + "/wp-config.php"):
            try:
                user = pwd.getpwuid(os.stat(d).st_uid).pw_name
            except (OSError, KeyError):
                continue
            found.append((d, user, os.path.basename(os.path.dirname(d))))
    return found


# What WordPress's own "Dashboard > Updates" page does first: it asks again (WordPress.org, and every plugin or theme that
# has its own update server), but only if the last check is a minute old. Nothing is installed by this.
NUDGE = "do_action('load-update-core.php');"


def _shell(user, script, timeout):
    return util.run(["su", "-s", "/bin/bash", user, "-c", script], timeout=timeout)


def _wp(docroot, user, php, args, plugins=False, admin=None, timeout=90):
    """Run WP-CLI as the site's own user. Returns its answer, or None if it failed or said nothing.

    plugins=False leaves the website's plugins and themes switched off (safe, fast: only what WordPress.org knows).
    plugins=True loads them, as the administrator `admin`: the only way to see updates that a plugin gets from its
    maker's own server (not WordPress.org). Those plugins only talk to WordPress when somebody who may update is logged in."""
    flags = "" if plugins else "--skip-plugins --skip-themes "
    if admin:
        flags += "--user=%d " % int(admin)
    rc, out = _shell(user, "export HOME=%s; cd %s && %s /usr/bin/wp %s%s 2>/dev/null"
                     % (shlex.quote(os.path.dirname(docroot)), shlex.quote(docroot), php, flags, args), timeout)
    return out if rc == 0 and out.strip() else None


def _find_php(docroot, user):
    """The first PHP program that can load this website (the web server may run it with another version)."""
    for ver in config.PHP_TRY:
        php = "%s/%s/bin/php" % (config.P.lsws_root, ver)
        if not os.path.exists(php):
            continue
        out = _wp(docroot, user, php, "core version")
        if out and re.match(r"^\d", out.strip()):
            return php
    return None


def _admin_id(docroot, user, php):
    """The number of one administrator of the website, or None."""
    out = _wp(docroot, user, php, "user list --role=administrator --field=ID --number=1")
    for line in reversed((out or "").strip().splitlines()):
        if line.strip().isdigit():
            return int(line.strip())
    return None


def _csv(text):
    """The CSV part of WP-CLI's answer. A plugin that is switched on may print notices before it: drop them.
    None when there is no header line at all (the command did not work).
    Found on the real server: one website printed an invisible byte-order mark (U+FEFF) in front of the header,
    which made the whole look fall back to WordPress.org's list."""
    lines = (text or "").replace("\ufeff", "").strip().splitlines()      # a file with a stray byte-order mark prints one before the list
    for i, line in enumerate(lines):
        low = line.strip().lower()
        if re.match(r"^(name|title|version),", low) and "version" in low:
            return "\n".join(lines[i:])
    return None


LIST_FIELDS = "--fields=name,title,status,version,update_version --format=csv"


def _look(site, nudge=True):
    """-> (site name, plugins csv, core csv, themes csv, vendors). vendors is True when the plugins were loaded, so updates
    that come from a plugin maker's own server are included; False when only WordPress.org's list could be read."""
    docroot, user, name = site
    php = _find_php(docroot, user)
    if php is None:
        return name, None, None, None, False
    plugins = themes = None
    vendors = False
    admin = _admin_id(docroot, user, php)
    if admin:
        if nudge:
            _wp(docroot, user, php, "eval " + shlex.quote(NUDGE), plugins=True, admin=admin, timeout=180)
        p = _csv(_wp(docroot, user, php, "plugin list --update=available " + LIST_FIELDS, plugins=True, admin=admin, timeout=120))
        t = _csv(_wp(docroot, user, php, "theme list --update=available " + LIST_FIELDS, plugins=True, admin=admin, timeout=120))
        if p is not None and t is not None:
            plugins, themes, vendors = p, t, True
    if not vendors:                                       # a plugin would not load: fall back to WordPress.org's list
        plugins = _csv(_wp(docroot, user, php, "plugin list --update=available " + LIST_FIELDS))
        themes = _csv(_wp(docroot, user, php, "theme list --update=available " + LIST_FIELDS))
    core = _wp(docroot, user, php, "core check-update --fields=version,update_type --format=csv")    # after the refresh above
    return name, plugins, core, themes, vendors


def _rows(kind, text):
    items = []
    if text and text.strip():
        for row in csv.DictReader(io.StringIO(text.strip())):
            what = row.get("title") or row.get("name") or "?"
            items.append({"what": what, "slug": row.get("name", ""),
                          "from": row.get("version", ""), "to": row.get("update_version", ""), "kind": kind,
                          "status": row.get("status", ""), "careful": is_careful(row.get("name", ""), what)})
    return items


def parse_site(name, plugins_csv, core_csv, themes_csv=None, vendors=None):
    """-> {'site', 'items': [{'what', 'slug', 'from', 'to', 'kind', 'status'}], 'checked': bool}
    kind is 'plugin', 'theme' or 'core-<type>'; status is active / inactive for plugins and themes.
    vendors (when given): True = plugins were loaded, so updates from the makers' own servers are included."""
    if plugins_csv is None and core_csv is None and themes_csv is None:
        return {"site": name, "items": [], "checked": False}
    items = _rows("plugin", plugins_csv) + _rows("theme", themes_csv)
    for line in (core_csv or "").strip().splitlines():
        if re.match(r"^\d", line):
            version, _, update_type = line.partition(",")
            items.append({"what": "WordPress itself", "from": "", "to": version.strip(),
                          "kind": "core-" + (update_type.strip() or "update")})
    entry = {"site": name, "items": items, "checked": True}
    if vendors is not None:
        entry["vendors"] = bool(vendors)
    return entry


def _stamp(entry):
    entry["looked"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return entry


def look_one(name, nudge=True):
    """Look at one website again. Returns the same kind of entry as waiting(), or None if it is not a WordPress website here."""
    for site in _wordpress_sites():
        if site[2] == name:
            return _stamp(parse_site(*_look(site, nudge)))
    return None


def waiting():
    """Slow (several seconds per site). Returns a list with one entry per WordPress site."""
    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(_look, _wordpress_sites()))
    return [_stamp(parse_site(*r)) for r in results]
