"""Which web server runs the websites, and how the web firewall is plugged into it.

CyberPanel can run two web servers and they keep their security settings in different places:

  LiteSpeed Enterprise   conf/modsec.conf   (Apache-style file, read through httpd.conf)
  OpenLiteSpeed          conf/httpd_config.conf, inside a  "module mod_security { ... }"  block

Our own firewall settings live in one small file of our own (cps-waf/main.conf). All this module
does is add ONE line to the web server's own file that points to it, and take that line out again.
Nothing else in CyberPanel's files is touched, so CyberPanel's own pages keep working.
"""
import os
import re

from . import config, util
from .util import Result

ENTERPRISE = "enterprise"
OPENLITESPEED = "openlitespeed"
NAMES = {ENTERPRISE: "LiteSpeed Enterprise", OPENLITESPEED: "OpenLiteSpeed"}

# the old hand-made install used these names; they are cleaned up when we find them
LEGACY_WAF_DIR_NAMES = ("pb-waf",)

HOOK_COMMENT = "# CP-Security web firewall (keeps its own settings in one separate file)"
_MODULE_START = re.compile(r"^\s*module\s+mod_security\s*\{")


# ----------------------------------------------------------------------------- what is installed
def kind():
    """'enterprise', 'openlitespeed' or None when no LiteSpeed web server is found.

    CyberPanel itself decides the same way: the OpenLiteSpeed program file is the giveaway.
    """
    p = config.P
    if os.path.exists(p.lsws_bin_ols):
        return OPENLITESPEED
    if os.path.exists(p.lsws_xml) or os.path.exists(p.lsws_bin_ent):
        return ENTERPRISE
    if os.path.exists(p.ols_conf):
        return OPENLITESPEED
    return None


def info():
    k = kind()
    version = util.read_text(config.P.lsws_version).strip()[:20]
    return {"kind": k, "name": NAMES.get(k, "none found"), "version": version}


def firewall_file():
    """The file of the web server that carries its security (ModSecurity) settings."""
    return config.P.ols_conf if kind() == OPENLITESPEED else config.P.modsec_conf


def engine_installed():
    """Is ModSecurity itself present on the web server (CyberPanel can install it)?"""
    k = kind()
    if k == ENTERPRISE:
        return os.path.exists(config.P.modsec_conf)
    if k == OPENLITESPEED:
        return os.path.exists(config.P.ols_module) and _module_block(util.read_text(config.P.ols_conf)) is not None
    return False


def how_to_install_engine():
    k = kind()
    if k == OPENLITESPEED:
        return ("ModSecurity is not installed for OpenLiteSpeed yet. In CyberPanel open Security, then "
                "ModSecurity Conf, press Install, and come back here afterwards.")
    if k == ENTERPRISE:
        return ("LiteSpeed's ModSecurity settings file was not found. In CyberPanel open Security, then "
                "ModSecurity Conf, enable it, and come back here afterwards.")
    return "No LiteSpeed web server was found on this server."


# ----------------------------------------------------------------------------- text editing helpers
def _module_block(conf):
    """(start line, end line) of the mod_security block in the OpenLiteSpeed file, or None."""
    lines = conf.split("\n")
    for i, line in enumerate(lines):
        if _MODULE_START.match(line):
            in_tick = False
            for j in range(i + 1, len(lines)):
                ticks = lines[j].count("`")
                if not in_tick and lines[j].strip() == "}":
                    return i, j
                if ticks % 2:
                    in_tick = not in_tick
            return None
    return None


def _hook_line(k, include_path):
    return ("Include " if k == ENTERPRISE else "modsecurity_rules_file ") + include_path


def _is_our_line(line):
    """A line (Enterprise or OpenLiteSpeed style) that points to one of our own firewall files."""
    s = line.strip()
    m = re.match(r"^(?:Include|modsecurity_rules_file)\s+(\S+)$", s)
    if not m:
        return False
    path = m.group(1)
    return any(("/%s/" % d) in path for d in ("cps-waf",) + LEGACY_WAF_DIR_NAMES)


def add_hook_text(conf, k, include_path):
    """Return the web server file with our one line in it. Safe to run twice."""
    line = _hook_line(k, include_path)
    kept = [l for l in conf.split("\n") if not _is_our_line(l) and l.strip() != HOOK_COMMENT]
    text = "\n".join(kept)

    if k == ENTERPRISE:
        # inside the <IfModule security2_module> block when there is one, else a block of our own
        m = None
        for m in re.finditer(r"^\s*</IfModule>\s*$", text, re.M):
            pass
        opened = re.search(r"^\s*<IfModule\s+security2_module>\s*$", text, re.M)
        if opened and m and m.start() > opened.start():
            return text[:m.start()] + HOOK_COMMENT + "\n" + line + "\n" + text[m.start():]
        return text.rstrip("\n") + "\n\n<IfModule security2_module>\n" + HOOK_COMMENT + "\n" + line + "\n</IfModule>\n"

    block = _module_block(text)
    if block is None:
        return None
    lines = text.split("\n")
    lines[block[1]:block[1]] = [HOOK_COMMENT, line]
    return "\n".join(lines)


def remove_hook_text(conf):
    kept = [l for l in conf.split("\n") if not _is_our_line(l) and l.strip() != HOOK_COMMENT]
    text = "\n".join(kept)
    # an empty IfModule block we may have created is tidied away
    text = re.sub(r"\n*<IfModule security2_module>\s*</IfModule>\n*", "\n", text)
    return text


def hook_present():
    conf = util.read_text(firewall_file())
    return any(_is_our_line(l) and "cps-waf" in l for l in conf.split("\n"))


def other_rule_packs():
    """Rule collections that someone else (usually CyberPanel's own page) switched on.

    They use the same rule numbers as ours. Two copies cannot run together, so we must know.
    Returns a list of short names like 'OWASP rules (CyberPanel)'.
    """
    p = config.P
    found = []
    text = util.read_text(p.ols_conf) if kind() == OPENLITESPEED else util.read_text(p.lsws_conf + "/rules.conf")
    if kind() == ENTERPRISE:
        text += "\n" + util.read_text(p.modsec_conf)
    low = text.lower()
    if re.search(r"^\s*(include|modsecurity_rules_file)\s+\S*owasp\S*", low, re.M):
        found.append("OWASP rules switched on in CyberPanel")
    if re.search(r"^\s*(include|modsecurity_rules_file)\s+\S*comodo\S*", low, re.M):
        found.append("Comodo rules switched on in CyberPanel")
    return found


def firewall_setting(name):
    """The value of one ModSecurity directive in the web server's own file, or None."""
    text = util.read_text(firewall_file())
    m = re.search(r"^\s*%s\s+(\S+)" % re.escape(name), text, re.M | re.I)
    return m.group(1) if m else None


# ----------------------------------------------------------------------------- hooking in and out
def connect():
    """Make the web server read our firewall file. Returns a Result and does not restart anything."""
    k = kind()
    if k is None:
        return Result(False, how_to_install_engine(), "no_webserver")
    if not engine_installed():
        return Result(False, how_to_install_engine(), "no_engine")
    path = firewall_file()
    conf = util.read_text(path)
    new = add_hook_text(conf, k, config.P.waf_main)
    if new is None:
        return Result(False, "The web server's security block was not found in its settings file.", "no_block")
    if k == OPENLITESPEED:
        # the module can be installed but switched off
        new = re.sub(r"^(\s*modsecurity\s+)off\b", r"\g<1>on", new, count=1, flags=re.M | re.I)
    util.backup_file(path, config.P.backup_dir)
    util.atomic_write(path, new if new.endswith("\n") else new + "\n", 0o644, "lsadm:lsadm")
    return Result(True, "The web server now reads the CP-Security firewall file.")


def disconnect():
    path = firewall_file()
    conf = util.read_text(path)
    if not conf:
        return Result(True, "Nothing to remove.")
    util.backup_file(path, config.P.backup_dir)
    util.atomic_write(path, remove_hook_text(conf).rstrip("\n") + "\n", 0o644, "lsadm:lsadm")
    return Result(True, "The web server no longer reads the CP-Security firewall file.")


def restart():
    """Gracefully restart the web server (the same call for both kinds)."""
    return util.run([config.P.lsws_ctl, "restart"], timeout=120)
