"""Keeping CP-Security itself up to date, from the panel or the command line.

    look      ask GitHub which release is the newest (nothing is changed)
    install   download that release, check its fingerprint, test the new program files, switch to them,
              restart the panel, and go back to the old version by itself if the panel does not come up

Safety, in the order it happens:
  * only the official address of this project is used, and only for a version number in the form 1.2.3;
  * the download must match the SHA256 fingerprint published with the release;
  * only program files (cpsec/ and VERSION) are taken out of the download, nothing can land anywhere else;
  * the new program files must compile and import before anything is replaced;
  * the old version is kept in /opt/cp-security.previous;
  * a small helper (started by systemd, so it survives the panel's restart) checks that the panel answers with the
    new version and otherwise puts the old files back.
"""
import compileall
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

from . import __version__, config, settings, util
from .util import Result

REPO = "Nima786/CP-Security"
API_LATEST = "https://api.github.com/repos/%s/releases/latest" % REPO
DOWNLOAD = "https://github.com/%s/releases/download/v%%s/%%s" % REPO
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_FILE = 5 * 1024 * 1024
RESULT_FILE = "update-result.json"
HELPER_FILE = "update-helper.sh"


# ----------------------------------------------------------------------------- versions
def parse_version(text):
    """'v1.2.3' or '1.2.3' -> (1, 2, 3); None when it is not in that form."""
    text = (text or "").strip().lstrip("v")
    return tuple(int(x) for x in text.split(".")) if VERSION_RE.match(text) else None


def is_newer(candidate, current):
    a, b = parse_version(candidate), parse_version(current)
    return bool(a and b and a > b)


# ----------------------------------------------------------------------------- talking to GitHub
def _open(url, opener=None, limit=MAX_DOWNLOAD):
    opener = opener or (lambda u: urllib.request.urlopen(
        urllib.request.Request(u, headers={"User-Agent": "CP-Security/%s" % __version__,
                                           "Accept": "application/vnd.github+json"}), timeout=30))
    with opener(url) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("The download is far bigger than expected, so it was refused.")
    return data


def latest(opener=None):
    """{'version', 'notes', 'published'} of the newest release. Raises ValueError with a plain message."""
    try:
        data = json.loads(_open(API_LATEST, opener, 1024 * 1024).decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Could not reach GitHub: %s" % str(exc)[:120])
    version = (data.get("tag_name") or "").lstrip("v")
    if not parse_version(version) or data.get("draft") or data.get("prerelease"):
        raise ValueError("GitHub did not name a usable release.")
    return {"version": version, "notes": (data.get("body") or "")[:4000], "published": (data.get("published_at") or "")[:10]}


# ----------------------------------------------------------------------------- the download
def fetch_release(version, opener=None):
    """The release tarball for exactly this version, checked against its published fingerprint."""
    if not parse_version(version):
        raise ValueError("That is not a version number.")
    name = "cp-security-%s.tar.gz" % version
    data = _open(DOWNLOAD % (version, name), opener)
    sums = _open(DOWNLOAD % (version, "SHA256SUMS"), opener, 64 * 1024).decode("utf-8", "replace")
    wanted = [line.split()[0] for line in sums.splitlines() if line.strip().endswith(" " + name) or line.strip().endswith("*" + name)]
    if not wanted:
        raise ValueError("Version %s has no published fingerprint, so it was not installed." % version)
    if hashlib.sha256(data).hexdigest() != wanted[0].lower():
        raise ValueError("The download does not match its published fingerprint, so it was not installed.")
    return data


def extract_program(data, version, dest):
    """Take only the program files (cpsec/... and VERSION) out of the release into dest. Nothing else, no path tricks."""
    root = "cp-security-%s/" % version
    os.makedirs(dest, exist_ok=True)
    real_dest = os.path.realpath(dest)
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            name = member.name
            if not name.startswith(root):
                continue
            rel = name[len(root):]
            if not (rel == "VERSION" or rel.startswith("cpsec/")):
                continue
            target = os.path.realpath(os.path.join(dest, rel))
            if not (target == real_dest or target.startswith(real_dest + os.sep)) or ".." in rel.split("/"):
                continue
            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile() and member.size <= MAX_FILE:
                total += member.size
                if total > 3 * MAX_DOWNLOAD:
                    raise ValueError("The release is far bigger than expected.")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    out.write(tar.extractfile(member).read())
                count += 1
    shipped = util.read_text(os.path.join(dest, "VERSION")).strip()
    if not count or shipped != version or not os.path.exists(os.path.join(dest, "cpsec", "__init__.py")):
        raise ValueError("The download is not CP-Security %s." % version)
    return count


def self_test(path):
    """The new program files must compile and the main parts must import, before anything is replaced."""
    if not compileall.compile_dir(os.path.join(path, "cpsec"), quiet=2, force=True):
        raise ValueError("The new program files do not compile.")
    code = "import cpsec, cpsec.cli, cpsec.panel.app, cpsec.panel.engine, cpsec.provision, cpsec.selfupdate; print(cpsec.__version__)"
    env = dict(os.environ, PYTHONPATH=path, PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         universal_newlines=True, timeout=60, env=env, cwd=path)
    if run.returncode != 0:
        raise ValueError("The new program files do not start: %s" % run.stdout.strip()[-160:])
    return run.stdout.strip()


# ----------------------------------------------------------------------------- switching over
def helper_script(version):
    """A tiny shell script that restarts the panel, checks it answers with the new version, and otherwise goes back.
    It is started by systemd, not by the panel, because the panel's own restart would stop anything it started itself."""
    p = config.P
    s = settings.load()
    url = "https://%s:%d/api/me" % (s["domain"], int(s["port"]))
    return """#!/bin/sh
# Written by CP-Security for one update. Safe to delete afterwards.
INSTALL=%(install)s
RESULT=%(result)s
sleep ${CPS_UPDATE_WAIT:-2}
systemctl restart cp-security-panel
i=0
while [ $i -lt ${CPS_UPDATE_TRIES:-30} ]; do
    sleep ${CPS_UPDATE_WAIT:-2}
    i=$((i + 1))
    answer=$(curl -sk --max-time 5 --resolve %(resolve)s %(url)s 2>/dev/null)
    case "$answer" in
        *'"version": "%(version)s"'*)
            printf '{"ok": true, "version": "%(version)s", "when": "%%s"}\\n' "$(date '+%%Y-%%m-%%d %%H:%%M:%%S')" > "$RESULT"
            exit 0 ;;
    esac
done
# the panel did not come up with the new version: put the old program files back
rm -rf "$INSTALL/cpsec.failed"
mv "$INSTALL/cpsec" "$INSTALL/cpsec.failed"
cp -a "$INSTALL.previous/cpsec" "$INSTALL/cpsec"
cp -a "$INSTALL.previous/VERSION" "$INSTALL/VERSION"
systemctl restart cp-security-panel cps-wplogin-feed
printf '{"ok": false, "version": "%(version)s", "when": "%%s", "message": "The new version did not start, so the old one was put back."}\\n' "$(date '+%%Y-%%m-%%d %%H:%%M:%%S')" > "$RESULT"
""" % {"install": shlex.quote(p.install_dir), "result": shlex.quote(os.path.join(p.conf_dir, RESULT_FILE)),
       "version": version, "url": shlex.quote(url),
       "resolve": shlex.quote("%s:%d:127.0.0.1" % (s["domain"], int(s["port"])))}


def _rmtree(path):
    """Remove a folder even if a file in it is marked read-only (Windows copies that mark; harmless on Linux)."""
    def unlock(func, target, _info):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(target)
        except OSError:
            pass
    shutil.rmtree(path, onerror=unlock)


def restore_previous():
    """Put the kept old version back (used when something goes wrong right after the switch)."""
    p = config.P
    previous = p.install_dir + ".previous"
    if not os.path.isdir(os.path.join(previous, "cpsec")):
        return False
    _rmtree(os.path.join(p.install_dir, "cpsec"))
    shutil.copytree(os.path.join(previous, "cpsec"), os.path.join(p.install_dir, "cpsec"))
    if os.path.exists(os.path.join(previous, "VERSION")):
        shutil.copy2(os.path.join(previous, "VERSION"), os.path.join(p.install_dir, "VERSION"))
    return True


def switch_to(new_path, version, log):
    """Keep the old version, put the new one in place, and hand the restart to the helper."""
    p = config.P
    previous = p.install_dir + ".previous"
    _rmtree(previous)
    os.makedirs(previous)
    shutil.copytree(os.path.join(p.install_dir, "cpsec"), os.path.join(previous, "cpsec"))
    for f in ("VERSION",):
        if os.path.exists(os.path.join(p.install_dir, f)):
            shutil.copy2(os.path.join(p.install_dir, f), os.path.join(previous, f))
    log("the old version %s is kept in %s" % (__version__, previous))

    staged = os.path.join(p.install_dir, "cpsec.new")
    _rmtree(staged)
    shutil.copytree(os.path.join(new_path, "cpsec"), staged, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    _rmtree(os.path.join(p.install_dir, "cpsec.old"))
    os.rename(os.path.join(p.install_dir, "cpsec"), os.path.join(p.install_dir, "cpsec.old"))
    os.rename(staged, os.path.join(p.install_dir, "cpsec"))
    shutil.copy2(os.path.join(new_path, "VERSION"), os.path.join(p.install_dir, "VERSION"))
    _rmtree(os.path.join(p.install_dir, "cpsec.old"))
    log("the new program files are in place")

    try:
        env = dict(os.environ, PYTHONPATH=p.install_dir)
        run = subprocess.run([sys.executable, "-m", "cpsec", "post-update"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True, timeout=180, env=env, cwd=p.install_dir)
        log("system files refreshed" if run.returncode == 0
            else "refreshing system files reported: " + run.stdout.strip()[-120:])
        script = os.path.join(p.conf_dir, HELPER_FILE)
        util.atomic_write(script, helper_script(version), 0o700)
        util.run(["systemctl", "restart", "cps-wplogin-feed"], timeout=60)
        rc, out = util.run(["systemd-run", "--unit=cps-self-update-%d" % int(time.time()), "--no-block", "--collect",
                            "/bin/sh", script], timeout=30)
        if rc != 0:
            raise ValueError("Could not schedule the restart: %s" % out.strip()[-120:])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        restore_previous()
        raise ValueError("%s The old version was put back." % str(exc)[:160])
    log("restarting the panel; it is checked and rolled back by itself if it does not start")


# ----------------------------------------------------------------------------- the object the panel talks to
class Updater:
    def __init__(self, opener=None):
        self.opener = opener
        self.lock = threading.Lock()
        self.data = {"latest": None, "notes": "", "published": "", "checked_at": "", "check_error": ""}
        self.job = {"status": "idle", "message": "", "log": [], "target": ""}

    # ---- what the page shows
    def state(self):
        with self.lock:
            latest_v = self.data["latest"]
            out = {
                "current": __version__,
                "latest": latest_v,
                "available": bool(latest_v and is_newer(latest_v, __version__)),
                "notes": self.data["notes"], "published": self.data["published"],
                "checked_at": self.data["checked_at"], "check_error": self.data["check_error"],
                "job": {"status": self.job["status"], "message": self.job["message"],
                        "log": list(self.job["log"]), "target": self.job["target"]},
            }
        out["last_result"] = util.read_json(os.path.join(config.P.conf_dir, RESULT_FILE), None)
        return out

    def check(self):
        try:
            found = latest(self.opener)
        except ValueError as exc:
            with self.lock:
                self.data["check_error"] = str(exc)
                self.data["checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            return Result(False, str(exc), "no_answer")
        with self.lock:
            self.data.update(latest=found["version"], notes=found["notes"], published=found["published"],
                             checked_at=time.strftime("%Y-%m-%d %H:%M:%S"), check_error="")
        if is_newer(found["version"], __version__):
            return Result(True, "Version %s is available (you have %s)." % (found["version"], __version__), "available")
        return Result(True, "You have the newest version (%s)." % __version__, "current")

    # ---- doing it
    def install(self, version=None, force=False, background=True):
        with self.lock:
            if self.job["status"] in ("working", "restarting"):
                return Result(False, "An update is already running.", "busy")
        version = (version or (self.data["latest"] or "")).lstrip("v")
        if not parse_version(version):
            return Result(False, "Look for updates first.", "unknown_version")
        if not force and not is_newer(version, __version__):
            return Result(False, "Version %s is already installed." % __version__, "not_newer")
        if not shutil.which("systemd-run") or not shutil.which("curl"):
            return Result(False, "This server lacks systemd-run or curl, so the panel cannot restart itself safely. "
                                 "Use the command line instead: security update.", "no_tools")
        if not settings.load()["domain"] or not settings.load()["port"]:
            return Result(False, "The panel's address is not set, so the restart cannot be checked.", "no_address")
        with self.lock:
            self.job = {"status": "working", "message": "Starting…", "log": [], "target": version}
        try:
            os.remove(os.path.join(config.P.conf_dir, RESULT_FILE))
        except OSError:
            pass
        if background:
            threading.Thread(target=self._work, args=(version,), daemon=True).start()
        else:
            self._work(version)
        return Result(True, "Updating to %s." % version)

    def _say(self, text, status=None):
        with self.lock:
            self.job["message"] = text
            self.job["log"].append("%s  %s" % (time.strftime("%H:%M:%S"), text))
            if status:
                self.job["status"] = status

    def _work(self, version):
        tmp = tempfile.mkdtemp(prefix="cps-update-")
        try:
            self._say("Downloading version %s and checking its fingerprint…" % version)
            data = fetch_release(version, self.opener)
            self._say("Unpacking the program files…")
            extract_program(data, version, tmp + "/new")
            self._say("Testing the new program files before anything is replaced…")
            self_test(tmp + "/new")
            self._say("Switching to the new version…")
            switch_to(tmp + "/new", version, self._say)
            self._say("The panel is restarting. This page reconnects by itself.", "restarting")
        except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as exc:
            self._say("Update stopped: %s" % str(exc)[:200], "failed")
        finally:
            _rmtree(tmp)
