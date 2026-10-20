"""Small helpers shared by every part: running commands and reading/writing files safely."""
import json
import os
import shutil
import subprocess
import time
from collections import namedtuple

# ok: did it work.  message: a plain-English sentence for the person using the tool.
# code: a short machine-readable reason ("needs_confirm", "invalid", ...) or "".
Result = namedtuple("Result", "ok message code", defaults=("",))


def run(cmd, timeout=60):
    """Run a command. Returns (exit code, combined output). Never raises."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except FileNotFoundError:
        return 127, "not installed"


def run_with_file(cmd, path, timeout=600):
    """Like run, but the file's contents are fed to the command's standard input. Used to let another user write a copy of it."""
    try:
        with open(path, "rb") as f:
            p = subprocess.run(cmd, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as exc:
        return 127, str(exc)


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def atomic_write(path, text, mode=0o644, owner=None):
    """Write a file so that nobody ever sees it half-written."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if owner and hasattr(shutil, "chown"):
        try:
            shutil.chown(tmp, *owner.split(":"))
        except (LookupError, OSError, ValueError):
            pass
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o644):
    atomic_write(path, json.dumps(data, indent=1, sort_keys=True) + "\n", mode=mode)


def backup_file(path, backup_dir):
    if os.path.exists(path):
        os.makedirs(backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, "%s/%s.%s" % (backup_dir, os.path.basename(path), stamp))


def snapshot(paths):
    """Remember the content of some files so a failed change can be undone."""
    snap = {}
    for p in paths:
        try:
            with open(p, "rb") as f:
                snap[p] = f.read()
        except OSError:
            snap[p] = None
    return snap


def restore(snap):
    for p, data in snap.items():
        try:
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                with open(p, "wb") as f:
                    f.write(data)
        except OSError:
            pass
