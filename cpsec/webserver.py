"""Which web server runs the websites, and how the web firewall is plugged into it.

CyberPanel can run two web servers and they keep their security settings in different places:

  LiteSpeed Enterprise   conf/modsec.conf   (Apache-style file, read through httpd.conf)
  OpenLiteSpeed          conf/httpd_config.conf, inside a  "module mod_security { ... }"  block

Our own firewall settings live in one small file of our own (cps-waf/main.conf). All this module
does is add ONE line to the web server's own file that points to it, and take that line out again.
Nothing else in CyberPanel's files is touched, so CyberPanel's own pages keep working.
"""
import glob
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
PARK_MARK = "#CPS-PARKED# "     # put in front of a CyberPanel rule-pack line that CP-Security set aside (reversible)
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


def _pack_files():
    """The files in which CyberPanel lists its rule packs."""
    if kind() == OPENLITESPEED:
        return [config.P.ols_conf]
    return [config.P.modsec_conf, config.P.lsws_conf + "/rules.conf"]


def other_rule_packs():
    """Rule collections that CyberPanel's own page installed and listed (OWASP, Comodo) with real files behind them.

    They use the same rule numbers as ours. Two copies cannot run together, so we must know. They may be
    installed but switched off (see engine_is_on); that still clashes, but then they protect nothing.
    Returns a list of short names like 'OWASP rules switched on in CyberPanel'.
    """
    text = "\n".join(util.read_text(path) for path in _pack_files())
    found = []
    for label, word in (("OWASP rules switched on in CyberPanel", "owasp"), ("Comodo rules switched on in CyberPanel", "comodo")):
        if any(word in path.lower() and _has_files(path) for path in _included_paths(text)):
            found.append(label)
    return found


def engine_is_on():
    """Is ModSecurity switched on in the web server's own settings (the last SecRuleEngine line wins)?"""
    text = util.read_text(firewall_file())
    if kind() == OPENLITESPEED and re.search(r"^\s*modsecurity\s+off\b", text, re.M | re.I):
        return False
    values = re.findall(r"^\s*SecRuleEngine\s+(\S+)", text, re.M | re.I)
    return bool(values) and values[-1].lower() != "off"


def rule_packs_in_use():
    """Rule packs of CyberPanel that really run: listed with files behind them AND ModSecurity is on."""
    return other_rule_packs() if engine_is_on() else []


def park_rule_packs():
    """Comment out the lines that load CyberPanel's rule packs, so ours can run. Nothing is deleted.
    Returns how many lines were set aside."""
    parked = 0
    for path in _pack_files():
        text = util.read_text(path)
        lines, changed = [], 0
        for line in text.split("\n"):
            m = re.match(r"^\s*(?:include|modsecurity_rules_file)\s+(\S+)\s*$", line, re.I)
            if m and any(w in m.group(1).lower() for w in ("owasp", "comodo")) and _has_files(m.group(1)):
                lines.append(PARK_MARK + line.strip())
                changed += 1
            else:
                lines.append(line)
        if changed:
            util.backup_file(path, config.P.backup_dir)
            util.atomic_write(path, "\n".join(lines), 0o644, "lsadm:lsadm")
            parked += changed
    return parked


def unpark_rule_packs():
    """Put CyberPanel's rule-pack lines back (the opposite of park_rule_packs)."""
    restored = 0
    for path in _pack_files():
        text = util.read_text(path)
        if PARK_MARK in text:
            util.backup_file(path, config.P.backup_dir)
            restored += text.count(PARK_MARK)
            util.atomic_write(path, text.replace(PARK_MARK, ""), 0o644, "lsadm:lsadm")
    return restored


def _included_paths(text):
    """Every file or pattern that the settings text includes."""
    return re.findall(r"^\s*(?:include|modsecurity_rules_file)\s+(\S+)\s*$", text, re.M | re.I)


def _has_files(pattern):
    """Does the include really load something? CyberPanel's untouched file already names its rule folders
    (with a * pattern) although nothing is in them, and an empty folder is not an active rule pack."""
    return bool(glob.glob(config.P.at(pattern)))


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
