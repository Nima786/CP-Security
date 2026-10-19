"""Which WordPress sites have updates waiting. This only looks; it never installs anything."""
import csv
import glob
import io
import os
import re
import shlex
from concurrent.futures import ThreadPoolExecutor

from . import config, util


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


def _wp(docroot, user, args):
    """Run WP-CLI as the site's own user, trying each PHP version until one can load WordPress."""
    for ver in config.PHP_TRY:
        php = "%s/%s/bin/php" % (config.P.lsws_root, ver)
        if not os.path.exists(php):
            continue
        cmd = ["su", "-s", "/bin/bash", user, "-c",
               "export HOME=%s; cd %s && %s /usr/bin/wp --skip-plugins --skip-themes %s 2>/dev/null"
               % (shlex.quote(docroot), shlex.quote(docroot), php, args)]
        rc, out = util.run(cmd, timeout=90)
        if rc == 0 and out.strip():
            return out
    return None


def _look(site):
    docroot, user, name = site
    plugins = _wp(docroot, user, "plugin list --update=available --fields=title,version,update_version --format=csv")
    core = _wp(docroot, user, "core check-update --fields=version,update_type --format=csv")
    return name, plugins, core


def parse_site(name, plugins_csv, core_csv):
    """-> {'site', 'items': [{'what', 'from', 'to', 'kind'}], 'checked': bool}"""
    if plugins_csv is None and core_csv is None:
        return {"site": name, "items": [], "checked": False}
    items = []
    if plugins_csv:
        for row in csv.DictReader(io.StringIO(plugins_csv.strip())):
            items.append({"what": row.get("title", "?"), "from": row.get("version", ""),
                          "to": row.get("update_version", ""), "kind": "plugin"})
    for line in (core_csv or "").strip().splitlines():
        if re.match(r"^\d", line):
            version, _, update_type = line.partition(",")
            items.append({"what": "WordPress itself", "from": "", "to": version.strip(),
                          "kind": "core-" + (update_type.strip() or "update")})
    return {"site": name, "items": items, "checked": True}


def waiting():
    """Slow (a few seconds per site). Returns a list with one entry per WordPress site."""
    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(_look, _wordpress_sites()))
    return [parse_site(*r) for r in results]
