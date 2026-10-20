"""Plugin and theme zip files the owner uploads from their own computer.

Some plugins cannot update by themselves (paid ones, ones whose licence server refuses, custom ones). The owner downloads the
new zip from the maker, uploads it to the panel ONCE, and the panel updates every website that has that plugin: one website
at a time, with the same safety as the other updates (see wpupdate.py). The uploaded files stay on the server until the owner
deletes them from the panel.

What keeps this safe
* A zip is checked before it is kept: it must be a real zip, hold exactly one folder, contain a plugin or a theme with a
  version number, and nothing that could write outside that folder (absolute paths, "..", links, passwords).
  Size, file count and unpacked size have limits (a "zip bomb" is refused).
* The panel never unpacks a zip itself and never runs anything from it. WordPress's own command-line tool unpacks it,
  as the website's own user, and only into that website's plugin or theme folder.
* The files are kept in a folder only root can open (mode 700, files 600). A website receives its copy through a pipe that is
  written BY the website's user, so a hacked website cannot make root write somewhere else, and other websites cannot read it.
* Only plugins and themes a website ALREADY has are offered. Nothing is installed on a website that did not have it.
"""
import copy
import csv
import hashlib
import io
import os
import re
import secrets
import shlex
import shutil
import stat
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from . import config, updates, util
from .util import Result

MAX_ZIP = 200 * 1024 * 1024               # the biggest zip accepted
MAX_UNPACKED = 1024 * 1024 * 1024         # what it may hold once unpacked (a zip bomb is refused)
MAX_FILES = 40000
HEADER_BYTES = 16384                      # the part of a file where WordPress looks for "Plugin Name:" and "Version:"
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
ID_RE = re.compile(r"^[0-9a-f]{16}$")
IGNORED = ("__MACOSX/",)
IGNORED_NAMES = (".DS_Store", "Thumbs.db")


# ----------------------------------------------------------------------------- where things are kept
def base_dir():
    return config.P.upload_dir


def incoming_dir():
    """Where an upload lands while it is being received (a half-finished upload is never in the library)."""
    return base_dir() + "/incoming"


def prepare():
    for d in (base_dir(), incoming_dir()):
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


def zip_path(zid):
    return "%s/%s.zip" % (base_dir(), zid)


def _index_path():
    return base_dir() + "/index.json"


# ----------------------------------------------------------------------------- version numbers
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1}


def _parts(version):
    text = re.sub(r"[-_+]", ".", version.strip().lower().lstrip("v"))
    text = re.sub(r"(\d)([a-z])", r"\1.\2", text)
    text = re.sub(r"([a-z])(\d)", r"\1.\2", text)
    out = []
    for piece in text.split("."):
        if not piece:
            continue
        out.append((0, int(piece)) if piece.isdigit() else (_PRE.get(piece, -5) if piece not in ("p", "pl") else 1, 0))
    return out


def version_cmp(a, b):
    """-1, 0 or 1. '1.0' equals '1.0.0'; '1.0.0-beta' is older than '1.0.0'; '7.1.10' is newer than '7.1.9'."""
    pa, pb = _parts(a), _parts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else (0, 0)
        y = pb[i] if i < len(pb) else (0, 0)
        if x != y:
            return -1 if x < y else 1
    return 0


# ----------------------------------------------------------------------------- looking inside a zip
def _unsafe(name):
    return ("\\" in name or "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name) is not None
            or ".." in name.split("/"))


def _ignored(name):
    return name.startswith(IGNORED) or name.rstrip("/").split("/")[-1] in IGNORED_NAMES


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug_of(folder):
    """The plugin's real folder name when the maker packed it with a version in the name ('name-1.2.3', 'name (1)')."""
    s = re.sub(r"[ _-]*\(\d+\)$", "", folder)
    s = re.sub(r"[-_ ]v?\d+(?:\.\d+)+[0-9A-Za-z._-]*$", "", s)
    return s or folder


def _header(z, name, label):
    """The value after 'Label:' near the top of a file in the zip, or ''."""
    try:
        with z.open(name) as f:
            head = f.read(HEADER_BYTES).decode("utf-8", "replace")
    except (KeyError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
        return ""
    m = re.search(r"^[ \t/*#@]*%s:\s*(.+)$" % re.escape(label), head, re.I | re.M)
    return m.group(1).strip().rstrip("*/ ").strip() if m else ""


def inspect_zip(path):
    """Look inside a zip without unpacking it. Returns (info, None) or (None, a sentence saying what is wrong)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, "The file could not be read."
    if size == 0:
        return None, "That file is empty."
    if size > MAX_ZIP:
        return None, "That file is bigger than the %d MB limit." % (MAX_ZIP // (1024 * 1024))
    if not zipfile.is_zipfile(path):
        return None, "That is not a zip file. Download the plugin or theme again from its maker and upload the .zip exactly as it is."
    try:
        with zipfile.ZipFile(path) as z:
            infos = [i for i in z.infolist() if not _ignored(i.filename)]
            if not infos:
                return None, "The zip file is empty."
            if len(infos) > MAX_FILES:
                return None, "The zip holds too many files (%d)." % len(infos)
            if sum(i.file_size for i in infos) > MAX_UNPACKED:
                return None, "The zip would unpack to more than %d MB." % (MAX_UNPACKED // (1024 * 1024))
            for i in infos:
                if _unsafe(i.filename):
                    return None, "The zip contains a file with an unsafe path (%s). I will not keep it." % i.filename[:60]
                if i.flag_bits & 0x1:
                    return None, "The zip is protected by a password. Upload the plain zip from the maker."
                if (i.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                    return None, "The zip contains a link (%s). I will not keep it." % i.filename[:60]
            names = {i.filename for i in infos}
            if any("/" not in n for n in names):
                return None, "The files are not inside one folder. A plugin or theme zip from its maker has exactly one folder inside."
            tops = {n.split("/")[0] for n in names}
            if len(tops) != 1:
                return None, "The zip holds %d folders. A plugin or theme zip has exactly one." % len(tops)
            folder = tops.pop()
            kind, name, main = "", "", ""
            if folder + "/style.css" in names:
                name = _header(z, folder + "/style.css", "Theme Name")
                if name:
                    kind, main = "theme", folder + "/style.css"
            if not kind:
                for n in sorted(names):
                    parts = n.split("/")
                    if len(parts) == 2 and parts[1].lower().endswith(".php"):
                        name = _header(z, n, "Plugin Name")
                        if name:
                            kind, main = "plugin", n
                            break
            if not kind:
                return None, "I could not find a plugin or a theme in this zip (no \"Plugin Name\" or \"Theme Name\" line)."
            found = re.match(r"[0-9A-Za-z][0-9A-Za-z._+-]*", _header(z, main, "Version"))
            version = found.group(0) if found else ""
            if not version:
                return None, "I could not find a version number inside this zip, so I could not tell whether it is newer."
            slug = _slug_of(folder)
            if not SLUG_RE.match(slug):
                return None, "The folder name (%s) is unusual. I will not keep it." % folder[:60]
            return {"kind": kind, "slug": slug, "name": name[:100], "version": version, "folder": folder, "renamed": slug != folder,
                    "files": len(infos), "unpacked": sum(i.file_size for i in infos), "size": size}, None
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
        return None, "The zip file is damaged, or packed in a way I cannot read."


def _repack(src, dst, old, new):
    """The same zip with its one folder renamed (the maker packed it as 'name-1.2.3'; WordPress needs 'name')."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for i in zin.infolist():
            if _ignored(i.filename):
                continue
            tail = i.filename[len(old):] if i.filename.startswith(old) else i.filename
            clone = zipfile.ZipInfo(new + tail, date_time=i.date_time)
            clone.external_attr = i.external_attr
            clone.compress_type = zipfile.ZIP_DEFLATED
            if i.is_dir():
                zout.writestr(clone, b"")
                continue
            with zin.open(i) as fin, zout.open(clone, "w") as fout:
                shutil.copyfileobj(fin, fout, 1024 * 1024)


# ----------------------------------------------------------------------------- the library
def _load():
    data = util.read_json(_index_path(), {"zips": []})
    zips = data.get("zips") if isinstance(data, dict) else []
    return [z for z in (zips or []) if isinstance(z, dict) and ID_RE.match(str(z.get("id", ""))) and os.path.exists(zip_path(z["id"]))]


def _save(entries):
    prepare()
    util.write_json(_index_path(), {"zips": entries}, mode=0o600)


def list_zips():
    return sorted(copy.deepcopy(_load()), key=lambda z: (z["name"].lower(), z["kind"]))


def get(zid):
    if not isinstance(zid, str) or not ID_RE.match(zid):
        return None
    return next((copy.deepcopy(z) for z in _load() if z["id"] == zid), None)


def add(tmp_path, filename):
    """Check a received file and keep it. Returns (Result, entry or None). A newer upload of the same plugin or theme replaces the older one."""
    info, err = inspect_zip(tmp_path)
    if err:
        return Result(False, err, "invalid"), None
    prepare()
    zid = secrets.token_hex(8)
    dest = zip_path(zid)
    try:
        if info["renamed"]:
            _repack(tmp_path, dest, info["folder"], info["slug"])
        else:
            shutil.copyfile(tmp_path, dest)
        os.chmod(dest, 0o600)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        try:
            os.remove(dest)
        except OSError:
            pass
        return Result(False, "The file could not be kept (%s)." % str(exc)[:80], "write"), None
    entry = {"id": zid, "filename": re.sub(r"[^A-Za-z0-9 ._()+-]", "_", os.path.basename(filename or "upload.zip"))[:120],
             "kind": info["kind"], "slug": info["slug"], "name": info["name"], "version": info["version"],
             "size": os.path.getsize(dest), "sha256": _sha256(dest), "uploaded": time.strftime("%Y-%m-%d %H:%M"),
             "renamed_from": info["folder"] if info["renamed"] else ""}
    entries, replaced = _load(), None
    for old in list(entries):
        if old["kind"] == entry["kind"] and old["slug"] == entry["slug"]:
            replaced = old
            entries.remove(old)
            try:
                os.remove(zip_path(old["id"]))
            except OSError:
                pass
    _save(entries + [entry])
    msg = "%s %s is ready." % (entry["name"], entry["version"])
    if replaced:
        msg += " It replaces the earlier upload of version %s." % replaced["version"]
    if entry["renamed_from"]:
        msg += " (The folder inside was called %s; it is renamed to %s, which is what WordPress needs.)" % (entry["renamed_from"], entry["slug"])
    return Result(True, msg), entry


def delete(zid):
    entry = get(zid)
    if entry is None:
        return Result(False, "That file is not on the server any more.", "missing")
    try:
        os.remove(zip_path(zid))
    except OSError:
        pass
    _save([z for z in _load() if z["id"] != zid])
    return Result(True, "%s %s was deleted from the server. The websites keep what was installed." % (entry["name"], entry["version"]))


# ----------------------------------------------------------------------------- sending a file to one website
def deliver(zid, site):
    """Put a copy of the file in the website's own folder, written by the website's user. Returns (path, error text)."""
    entry = get(zid)
    if entry is None:
        return "", "The uploaded file is no longer on the server."
    folder = site["home"] + "/cps-backups"
    dest = "%s/upload-%s.zip" % (folder, zid)
    script = "umask 077; mkdir -p -m 700 %s && cat > %s" % (shlex.quote(folder), shlex.quote(dest))
    rc, out = util.run_with_file(["su", "-s", "/bin/bash", site["user"], "-c", script], zip_path(zid), timeout=900)
    if rc != 0:
        return "", "The file could not be sent to the website (%s)." % (out.strip()[:100] or "no reason given")
    rc, out = util.run(["su", "-s", "/bin/bash", site["user"], "-c", "sha256sum -- %s" % shlex.quote(dest)], timeout=300)
    if rc != 0 or out.split()[:1] != [entry["sha256"]]:
        discard(site, dest)
        return "", "The copy on the website did not match the uploaded file, so nothing was changed."
    return dest, ""


def discard(site, path):
    """Remove the copy that was sent to a website (done by the website's user, whatever happened)."""
    if path and os.path.basename(path).startswith("upload-"):
        util.run(["su", "-s", "/bin/bash", site["user"], "-c", "rm -f -- %s" % shlex.quote(path)], timeout=60)


# ----------------------------------------------------------------------------- what every website has
_lock = threading.Lock()
_inv = {"status": "idle", "started": "", "finished": "", "sites": {}}


def _read_site(name):
    """{'checked': True, 'plugin': {slug: {version, status}}, 'theme': {...}} for one website, or {'checked': False}."""
    from . import wpupdate                       # late: wpupdate uses this module too
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return {"checked": False}
    found = {"checked": True, "plugin": {}, "theme": {}}
    for kind in ("plugin", "theme"):
        rc, out = wpupdate._wp(site, php, "%s list --fields=name,status,version --format=csv" % kind, 120)
        text = updates._csv(out) if rc == 0 else None
        if text is None:
            return {"checked": False}
        for row in csv.DictReader(io.StringIO(text)):
            status = (row.get("status") or "")
            if status in ("active", "inactive", "active-network") and row.get("name"):
                found[kind][row["name"]] = {"version": row.get("version") or "", "status": "active" if status.startswith("active") else "inactive"}
    return found


def inventory_state():
    with _lock:
        return copy.deepcopy(_inv)


def inventory_start(only=None):
    """Read every website's plugins and themes in the background (a few seconds each)."""
    with _lock:
        if _inv["status"] == "running":
            return Result(False, "Already looking at the websites.", "busy")
        _inv.update(status="running", started=time.strftime("%Y-%m-%d %H:%M:%S"))
    threading.Thread(target=_inventory_run, args=(only,), daemon=True).start()
    return Result(True, "Looking at the websites.")


def _inventory_run(only):
    try:
        names = list(only) if only else [n for _d, _u, n in updates._wordpress_sites()]
        with ThreadPoolExecutor(max_workers=3) as ex:
            results = list(ex.map(_read_site, names))
        with _lock:
            _inv["sites"] = dict(_inv["sites"], **dict(zip(names, results)))
    finally:
        with _lock:
            _inv["status"] = "done"
            _inv["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def inventory_refresh(names):
    """Read some websites again right now (after they were updated). Returns when done."""
    fresh = {n: _read_site(n) for n in names}
    with _lock:
        _inv["sites"] = dict(_inv["sites"], **fresh)
        _inv["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if _inv["status"] == "idle":
            _inv["status"] = "done"


def rows_for(entry, sites, names):
    """For one uploaded file: what each website has. state is update / same / newer / missing / unknown."""
    out = []
    for name in names:
        s = sites.get(name)
        if not s or not s.get("checked"):
            out.append({"site": name, "state": "unknown", "installed": "", "status": "", "can_update": False})
            continue
        have = s[entry["kind"]].get(entry["slug"])
        if not have:
            out.append({"site": name, "state": "missing", "installed": "", "status": "", "can_update": False})
            continue
        c = version_cmp(entry["version"], have["version"])
        state = "update" if c > 0 else ("same" if c == 0 else "newer")
        out.append({"site": name, "state": state, "installed": have["version"], "status": have["status"], "can_update": state == "update"})
    order = {"update": 0, "same": 1, "newer": 2, "unknown": 3, "missing": 4}
    return sorted(out, key=lambda r: (order[r["state"]], r["site"]))
