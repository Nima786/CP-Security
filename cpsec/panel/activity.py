"""The panel's own log: one line per login attempt and per change. The attack blocker reads the login lines."""
import datetime
import os
import re
import threading

from .. import config

_lock = threading.Lock()
_CLEAN = re.compile(r"[^\x20-\x7e]")


def _clean(value):
    return _CLEAN.sub("?", str(value))[:200].replace("\n", " ")


def write(event, **fields):
    """2026-10-19 03:20:11 LOGIN_FAILED ip=1.2.3.4 user=admin"""
    line = "%s %s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event,
                           " ".join("%s=%s" % (k, _clean(v).replace(" ", "_")) for k, v in fields.items()))
    with _lock:
        try:
            os.makedirs(os.path.dirname(config.P.panel_log), exist_ok=True)
            with open(config.P.panel_log, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass


def recent(limit=50):
    """Newest first. Only changes and logins, shown to the owner on the Settings page."""
    try:
        with open(config.P.panel_log, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 200000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        parts = ln.split(" ", 3)
        if len(parts) >= 3:
            out.append({"when": parts[0] + " " + parts[1], "event": parts[2],
                        "details": parts[3] if len(parts) > 3 else ""})
        if len(out) >= limit:
            break
    return out
