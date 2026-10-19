"""Panel settings that the engine also needs to know (which port, who may reach it)."""
from . import config, util

DEFAULTS = {
    "domain": "",
    "port": 0,
    # "login":   anybody can reach the login page; it still needs a password and a 6-digit code
    # "trusted": only the trusted addresses can reach the panel at all
    "access": "login",
}


def load():
    data = dict(DEFAULTS)
    stored = util.read_json(config.P.panel_settings, {})
    for key in DEFAULTS:
        if key in stored:
            data[key] = stored[key]
    return data


def lock_ports():
    """The ports the admin lock covers: the three admin pages, plus the panel if it is trusted-only."""
    ports = list(config.ADMIN_PORTS)
    s = load()
    if s["access"] == "trusted" and isinstance(s["port"], int) and 1 <= s["port"] <= 65535:
        ports.append(s["port"])
    return ports
