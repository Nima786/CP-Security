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
    # how many saved copies of each plugin, theme and database are kept after an update (1 to 5)
    "copies_keep": 3,
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


def valid_port(p):
    return isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535


def port_choices():
    """What the owner decided on the "Open ports" page, as three sorted lists of port numbers:

    locked    extra ports that only trusted addresses may reach
    opened    admin pages (CyberPanel, ...) that the owner chose to leave open to everybody
    accepted  open ports the owner knows about, so the advisor stops mentioning them
    """
    stored = util.read_json(config.P.ports_settings, {})
    out = {}
    for key in ("locked", "opened", "accepted"):
        values = stored.get(key, []) if isinstance(stored, dict) else []
        out[key] = sorted(set(p for p in values if valid_port(p))) if isinstance(values, list) else []
    return out


def save_port_choices(choices):
    clean = {key: sorted(set(p for p in choices.get(key, []) if valid_port(p)))
             for key in ("locked", "opened", "accepted")}
    util.write_json(config.P.ports_settings, clean, mode=0o600)


def lock_ports():
    """The ports the admin lock covers: the three admin pages (unless the owner opened one), the panel
    if it is trusted-only, and any port the owner added on the "Open ports" page."""
    choices = port_choices()
    ports = [p for p in config.ADMIN_PORTS if p not in choices["opened"]]
    s = load()
    if s["access"] == "trusted" and valid_port(s["port"]) and s["port"] not in ports:
        ports.append(s["port"])
    for p in choices["locked"]:
        if p not in ports:
            ports.append(p)
    return ports
