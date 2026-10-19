"""Panel settings (which sub-domain and port, who may reach it) and the panel's one admin user.

Everything is in one root-only file, /etc/cp-security/panel.json. The engine only needs the settings part.
"""
import threading

from . import config, util

DEFAULTS = {
    "domain": "",
    "port": 0,
    # "login":   anybody can reach the login page; it still needs a password and a 6-digit code
    # "trusted": only the trusted addresses can reach the panel at all
    "access": "login",
}

_lock = threading.Lock()


def _load_all():
    return util.read_json(config.P.panel_settings, {})


def load():
    data = dict(DEFAULTS)
    stored = _load_all()
    for key in DEFAULTS:
        if key in stored:
            data[key] = stored[key]
    return data


def save(changes):
    """Merge changes into the settings file (the user record is kept)."""
    with _lock:
        stored = _load_all()
        for key, value in changes.items():
            if key in DEFAULTS:
                stored[key] = value
        util.write_json(config.P.panel_settings, stored, mode=0o600)


def get_user():
    """The panel's admin: {'name', 'password_hash', 'totp_secret', 'last_counter'} or None."""
    return _load_all().get("user")


def save_user(user):
    with _lock:
        stored = _load_all()
        stored["user"] = user
        util.write_json(config.P.panel_settings, stored, mode=0o600)


def lock_ports():
    """The ports the admin lock covers: the three admin pages, plus the panel if it is trusted-only."""
    ports = list(config.ADMIN_PORTS)
    s = load()
    if s["access"] == "trusted" and isinstance(s["port"], int) and 1 <= s["port"] <= 65535:
        ports.append(s["port"])
    return ports
