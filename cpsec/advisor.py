"""The advisor: looks at the whole server, notices other security tools and risky settings, and says what to do.

It only LOOKS. Nothing is changed unless a person presses a fix button, and only a few safe fixes exist.
Every finding is a small dictionary:

    id      stable name, for the interface
    level   bad   needs action now
            warn  worth fixing soon
            info  good to know
            ok    all fine
    title   one short sentence
    detail  what was found, in plain words
    advice  what to do about it ("" when nothing is needed)
    fix     None, or {"kind": "action"|"page", "id": ..., "label": ...}
"""
import datetime
import glob
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait

from . import access, blocker, config, netinfo, settings, sites, tls, util, waf, webserver
from .util import Result

LEVEL_ORDER = {"bad": 0, "warn": 1, "info": 2, "ok": 3}

# databases and caches that must never listen on the open internet
RISKY_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached",
               27017: "MongoDB", 9200: "Elasticsearch"}


def F(fid, level, title, detail="", advice="", fix=None):
    return {"id": fid, "level": level, "title": title, "detail": detail, "advice": advice, "fix": fix}


def _page(page, label):
    return {"kind": "page", "id": page, "label": label}


def _action(fid, label):
    return {"kind": "action", "id": fid, "label": label}


def _active(unit):
    rc, out = util.run(["systemctl", "is-active", unit])
    return out.strip() == "active"


def _os_name():
    text = util.read_text(config.P.at("/etc/os-release"))
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', text, re.M)
    return m.group(1) if m else ""


def _debian_family():
    return config.P.is_debian()


# ----------------------------------------------------------------------------- the web server and its firewall
def check_webserver():
    info = webserver.info()
    if info["kind"] is None:
        return [F("webserver", "warn", "No LiteSpeed web server was found",
                  "CP-Security works with LiteSpeed Enterprise and OpenLiteSpeed, the two servers CyberPanel uses.",
                  "The web firewall part cannot be used here. The attack blocker and the admin lock still work.")]
    return [F("webserver", "ok", "Web server: %s %s" % (info["name"], info["version"]), "", "")]


def check_modsecurity():
    out = []
    kind = webserver.kind()
    if kind is None:
        return out
    packs = webserver.other_rule_packs()
    ours = waf.mode()
    if packs:
        names = " and ".join(packs)
        if ours is not None:
            out.append(F("modsec_clash", "bad", "Two sets of web firewall rules are active at the same time",
                         "%s, and CP-Security's own rules are loaded as well. Both use the same rule numbers, so the "
                         "web server can refuse to start or log everything twice." % names,
                         "Keep only one. Either turn off CyberPanel's rule pack (CyberPanel, Security, ModSecurity "
                         "Rules Packs) or set the CP-Security web firewall to Off and take it out in Setup.",
                         _page("firewall", "Open the web firewall")))
        else:
            out.append(F("modsec_other", "info", "CyberPanel already has web firewall rules switched on",
                         names + ".",
                         "CP-Security will not add its own rules on top, so nothing clashes. "
                         "Its attack blocker and admin lock still work next to them."))
    elif ours is None:
        if webserver.engine_installed():
            out.append(F("modsec_missing", "info", "The CP-Security web firewall is not set up yet",
                         "ModSecurity is available on your web server, and no other rule set is using it.",
                         "Set it up from the Setup page. It starts in watch-only mode, which blocks nothing.",
                         _page("setup", "Open Setup")))
        else:
            out.append(F("modsec_engine", "info", "ModSecurity is not installed on the web server",
                         "It is the engine that the web firewall needs.", webserver.how_to_install_engine()))
    else:
        note = ""
        cp_setting = (webserver.firewall_setting("SecRuleEngine") or "").lower()
        if cp_setting == "off":
            note = (" CyberPanel's own ModSecurity page may show 'Off'. That is expected: the CP-Security setting "
                    "is read last and wins.")
        out.append(F("modsec_ours", "ok", "The web firewall is managed by CP-Security",
                     "Mode: %s.%s" % (waf.MODE_SHORT.get(ours, ours), note),
                     "Change it here, not on CyberPanel's ModSecurity page."))
    return out


def check_waf_age():
    if waf.mode() != "watch":
        return []
    since = waf.mode_since()
    if since is None:
        return []
    days = (datetime.date.today() - since).days
    if days >= 14:
        return [F("waf_watching", "info", "The web firewall has only been watching for %d days" % days,
                  "In watch-only mode it records suspicious requests but does not refuse any.",
                  "Look at what it recorded. When your own sites and plugins are not in the list of hits, "
                  "switch it to Blocking.", _page("firewall", "Open the web firewall"))]
    return []


# ----------------------------------------------------------------------------- other security tools
def check_imunify():
    p = config.P
    present = any(os.path.exists(p.at(x)) for x in ("/opt/imunify360", "/usr/bin/imunify360-agent",
                                                    "/etc/sysconfig/imunify360", "/opt/imunify-antivirus"))
    present = present or _active("imunify360") or _active("imunify-antivirus")
    if not present:
        return []
    return [F("imunify", "warn", "Imunify is installed on this server",
              "Imunify has its own firewall, its own web firewall rules and its own blocking.",
              "Do not run CP-Security's web firewall next to Imunify's: keep it Off. The admin lock and the "
              "WordPress login protection are safe to keep, they do not overlap.")]


def check_csf():
    p = config.P
    conf = util.read_text(p.at("/etc/csf/csf.conf"))
    if not conf and not _active("csf") and not _active("lfd"):
        return []
    testing = re.search(r'^TESTING\s*=\s*"?1', conf, re.M) is not None
    out = [F("csf", "warn", "CSF/LFD is installed on this server",
             "CSF is another firewall and login blocker. Two blockers watching the same logins can block the same "
             "person twice, which is harmless but confusing.",
             "A clean split: let CSF look after SSH, email and FTP, and use the CP-Security blocker for WordPress "
             "logins. The admin lock does not clash with CSF.")]
    if testing:
        out.append(F("csf_testing", "warn", "CSF is in testing mode",
                     "In testing mode CSF clears its own rules every few minutes, so it is not protecting anything.",
                     "Set TESTING to 0 in CSF's settings once you are happy with it."))
    return out


def check_blocker_and_others():
    out = []
    if not blocker.installed():
        return [F("blocker", "bad", "The attack blocker (fail2ban) is not installed",
                  "Nothing stops people from guessing passwords on your server over and over.",
                  "Install it from the Setup page.", _page("setup", "Open Setup"))]
    names = blocker.jails()
    if names is None:
        return [F("blocker", "bad", "The attack blocker is installed but not running",
                  "", "Start it from the Blocked page.", _page("blocked", "Open Blocked"))]
    ours = [n for n in names if n.startswith("cps-")]
    standard = {"sshd", "dovecot", "pure-ftpd", "postfix"}
    foreign = [n for n in names if not n.startswith("cps-") and n not in standard]
    if foreign:
        out.append(F("blocker_others", "info", "Other protections are running next to ours",
                     "Not managed by CP-Security: " + ", ".join(foreign) + ".",
                     "That is fine. They are left alone."))
    # another jail that watches WordPress logins would ban the same people twice
    clash = []
    for path in glob.glob(config.P.at("/etc/fail2ban/jail.d/*")) + [config.P.at("/etc/fail2ban/jail.local")]:
        if os.path.basename(path).startswith("cps-"):
            continue
        text = util.read_text(path).lower()
        if "wp-login" in text or "wordpress" in text:
            clash.append(os.path.basename(path))
    if clash:
        out.append(F("blocker_double", "warn", "Another protection also watches WordPress logins",
                     "Found in: " + ", ".join(sorted(clash)) + ". Both it and CP-Security would block the same visitor.",
                     "Keep one of the two so a blocked visitor is easy to find and let back in."))
    if not ours:
        out.append(F("blocker_cps", "warn", "The CP-Security protections are not switched on",
                     "The blocker is running, but none of the CP-Security protections is loaded.",
                     "Run the setup to add them.", _page("setup", "Open Setup")))
    return out


# ----------------------------------------------------------------------------- the server itself
def _ssh_values():
    """First value wins in sshd's settings, and the extra files are read before the main file."""
    files = sorted(glob.glob(config.P.sshd_config_d + "/*.conf")) + [config.P.sshd_config]
    values = {}
    for path in files:
        for line in util.read_text(path).splitlines():
            m = re.match(r"^\s*(PasswordAuthentication|PermitRootLogin)\s+(\S+)", line, re.I)
            if m:
                values.setdefault(m.group(1).lower(), m.group(2).lower())
    return values


def check_ssh():
    if not util.read_text(config.P.sshd_config):
        return []
    v = _ssh_values()
    password = v.get("passwordauthentication", "yes") == "yes"
    root = v.get("permitrootlogin", "prohibit-password")
    if password and root == "yes":
        return [F("ssh", "warn", "Anyone can try the root password over SSH",
                  "Both password logins and direct root login are allowed.",
                  "Set up an SSH key for yourself, then turn off password logins. The blocker slows guessing "
                  "down, but a key cannot be guessed.")]
    if password:
        return [F("ssh", "info", "Server logins (SSH) accept passwords",
                  "The attack blocker limits guessing, but passwords can still be tried.",
                  "When you have an SSH key set up, turn password logins off.")]
    return [F("ssh", "ok", "Server logins (SSH) need a key", "", "")]


def check_os_updates():
    p = config.P
    if _debian_family():
        conf = util.read_text(p.at("/etc/apt/apt.conf.d/20auto-upgrades"))
        on = re.search(r'Unattended-Upgrade\s+"1"', conf) is not None
    else:
        on = _active("dnf-automatic.timer") or _active("dnf-automatic-install.timer")
    if on:
        return [F("os_updates", "ok", "Security updates of the operating system install themselves", "", "")]
    return [F("os_updates", "warn", "Security updates of the operating system are not automatic",
              "Fixes for the server's own software only arrive when somebody installs them.",
              "Install updates regularly, or turn on automatic security updates "
              "(unattended-upgrades on Ubuntu, dnf-automatic on AlmaLinux). Kernel updates need a restart.")]


def check_open_services():
    rc, out = util.run(["ss", "-H", "-ltn"])
    if rc != 0:
        return []
    open_ones = {}
    for line in out.splitlines():
        m = re.search(r"(\S+):(\d+)\s+\S+\s*$", line.strip())
        if not m:
            continue
        host, port = m.group(1), int(m.group(2))
        if port in RISKY_PORTS and not (host.startswith("127.") or host in ("[::1]", "::1")):
            open_ones[port] = RISKY_PORTS[port]
    if not open_ones:
        return []
    names = ", ".join("%s (port %d)" % (n, p) for p, n in sorted(open_ones.items()))
    return [F("open_services", "bad", "A database or cache is open to the internet",
              names + " is listening on all addresses.",
              "Make it listen on 127.0.0.1 only, or close the port in the firewall. Websites on this server "
              "do not need it open from outside.")]


def check_general_firewall():
    s = settings.load()
    port = s["port"] if isinstance(s["port"], int) and s["port"] else None
    firewalld, ufw = _active("firewalld"), False
    if not firewalld:
        rc, out = util.run(["ufw", "status"])
        ufw = rc == 0 and "Status: active" in out
    out_list = []
    if firewalld or ufw:
        name = "firewalld" if firewalld else "ufw"
        out_list.append(F("firewall_general", "ok", "A general firewall (%s) is switched on" % name,
                          "The CP-Security admin lock works on top of it: the stricter of the two always applies.", ""))
        if port and tls.port_is_open(port) is False:
            out_list.append(F("panel_port_closed", "warn", "The panel port is closed in %s" % name,
                              "Port %d is not open there, so nobody can reach the panel, not even trusted addresses." % port,
                              "Open it with the button.", _action("open_panel_port", "Open port %d" % port)))
    else:
        out_list.append(F("firewall_general", "info", "No general firewall is switched on",
                          "Every port that has a program behind it can be reached from outside, except the locked "
                          "admin pages.",
                          "Switch on CyberPanel's firewall (CyberPanel, Security, Firewall) and keep only the "
                          "ports you use open."))
    return out_list


def check_lock():
    if not access.lock_is_live():
        return [F("lock", "bad", "The admin pages are NOT locked",
                  "CyberPanel, the LiteSpeed admin and the web terminal can be opened by anybody who finds them.",
                  "Re-apply the lock with the button.", _action("reapply_lock", "Lock the admin pages now"))]
    n = len(access.list_admin())
    out = [F("lock", "ok", "The admin pages are locked to %d trusted address%s" % (n, "" if n == 1 else "es"), "", "")]
    if n == 1:
        out.append(F("lock_single", "info", "Only one address is trusted",
                     "If that address changes (new internet connection, travelling) you can no longer open the admin pages.",
                     "Add a second trusted address, for example your phone's mobile network or an office.",
                     _page("access", "Open Admin access")))
    return out


def check_cloudflare(resolver=None):
    domains = sites.list_sites()[:60]
    if not domains:
        return []
    resolver = resolver or netinfo.resolve
    pool = ThreadPoolExecutor(max_workers=8)
    futures = {d: pool.submit(resolver, d) for d in domains}
    wait(list(futures.values()), timeout=10)
    pool.shutdown(wait=False)
    behind = []
    for d, fut in futures.items():
        if fut.done() and not fut.exception() and any(netinfo.is_cloudflare(i) for i in fut.result()):
            behind.append(d)
    if not behind:
        return []
    have = set(a for a, _ in access.read_list(config.P.never_list))
    missing = [r for r in netinfo.CLOUDFLARE if r not in have]
    shown = ", ".join(sorted(behind)[:4]) + (" and %d more" % (len(behind) - 4) if len(behind) > 4 else "")
    if missing:
        return [F("cloudflare", "warn", "%d website%s use Cloudflare, but Cloudflare is not on the never-block list"
                  % (len(behind), "s" if len(behind) != 1 else ""),
                  shown + ". Visitors reach your server through Cloudflare, so the blocker could block Cloudflare "
                  "itself and take those sites offline for everybody.",
                  "Add Cloudflare's addresses to the never-block list with the button.",
                  _action("add_cloudflare", "Add Cloudflare to the never-block list"))]
    return [F("cloudflare", "ok", "%d website%s use Cloudflare, and Cloudflare can never be blocked"
              % (len(behind), "s" if len(behind) != 1 else ""), shown + ".",
              "Also make sure the web server reads the visitor's real address from Cloudflare's header, otherwise "
              "the blocker sees only Cloudflare's addresses.")]


# ----------------------------------------------------------------------------- the panel and WordPress
def check_panel_access():
    s = settings.load()
    if not s["domain"]:
        return []
    if s["access"] == "trusted":
        return [F("panel_access", "ok", "The panel can only be opened from trusted addresses", "", "")]
    two = bool((settings.get_user() or {}).get("totp_enabled"))
    if two:
        return [F("panel_access", "info", "The panel's login page is open to everybody",
                  "A password and a one-time code are needed, and wrong attempts lock the visitor out.",
                  "Locking the panel to trusted addresses is stronger. You can switch in Settings.")]
    return [F("panel_access", "warn", "The panel's login page is open to everybody and has no second step",
              "Only a username and a password protect it.",
              "Either lock the panel to trusted addresses, or switch on the one-time code, in Settings.",
              _page("settings", "Open Settings"))]


def check_certificate():
    s = settings.load()
    if not s["domain"]:
        return []
    st = tls.status(s["domain"])
    if not st["found"]:
        return [F("cert", "warn", "No certificate was found for %s" % s["domain"],
                  "The panel cannot use HTTPS without it.", "Issue one in CyberPanel (SSL, Issue SSL).")]
    d = st["days_left"]
    if d is None:
        return []
    if d < 0:
        return [F("cert", "bad", "The panel's certificate has expired", "", "Renew it in CyberPanel (SSL, Issue SSL).")]
    if d < 15:
        return [F("cert", "warn", "The panel's certificate ends in %d days" % d,
                  "CyberPanel normally renews it by itself.", "If this keeps showing, renew it in CyberPanel.")]
    return [F("cert", "ok", "The panel's certificate is valid for %d more days" % d, "", "")]


def check_wordpress_updates():
    cache = util.read_json(config.P.updates_cache, {})
    found = cache.get("sites") or []
    if not cache.get("finished"):
        return [F("wp_updates", "info", "WordPress updates have not been checked yet",
                  "Most break-ins use plugins that were not updated.", "Look now.",
                  _page("updates", "Open Updates"))]
    count = sum(len(s.get("items", [])) for s in found)
    sites_n = sum(1 for s in found if s.get("items"))
    if count:
        return [F("wp_updates", "warn", "%d update%s waiting on %d website%s"
                  % (count, "" if count == 1 else "s", sites_n, "" if sites_n == 1 else "s"),
                  "Out-of-date plugins are how most WordPress sites get hacked.",
                  "Update them, after a backup. This panel only looks, it never installs.",
                  _page("updates", "See the list"))]
    return [F("wp_updates", "ok", "Everything checked is up to date", "Last look: %s." % cache.get("finished", ""), "")]


def check_baseline():
    if sites.load_baseline():
        return []
    return [F("baseline", "info", "No normal state of your websites is saved yet",
              "Without it a site that was already broken cannot be told apart from one that just broke.",
              "Save it once everything looks right.", _page("settings", "Open Settings"))]


CHECKS = (check_webserver, check_modsecurity, check_waf_age, check_imunify, check_csf, check_blocker_and_others,
          check_lock, check_general_firewall, check_ssh, check_os_updates, check_open_services, check_cloudflare,
          check_panel_access, check_certificate, check_wordpress_updates, check_baseline)


def run():
    """Every check, worst problems first. One check failing never hides the others."""
    findings = []
    for check in CHECKS:
        try:
            findings.extend(check())
        except Exception as exc:          # a broken check must not break the page
            findings.append(F(check.__name__, "info", "A check could not be done",
                              "%s: %s" % (check.__name__.replace("check_", "").replace("_", " "), str(exc)[:120])))
    findings.sort(key=lambda f: LEVEL_ORDER[f["level"]])
    counts = {lvl: sum(1 for f in findings if f["level"] == lvl) for lvl in LEVEL_ORDER}
    info = webserver.info()
    return {
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "counts": counts,
        "findings": findings,
        "server": {"os": _os_name(), "web_server": info["name"], "web_server_version": info["version"],
                   "cyberpanel": os.path.isdir(config.P.at("/usr/local/CyberCP"))},
    }


# ----------------------------------------------------------------------------- the safe fixes
def apply_fix(fix_id):
    if fix_id == "add_cloudflare":
        return access.add_never_many(netinfo.CLOUDFLARE, "Cloudflare")
    if fix_id == "reapply_lock":
        res = access.apply()
        return Result(True, "The admin pages are locked again.") if res.ok else res
    if fix_id == "open_panel_port":
        port = settings.load()["port"]
        if not isinstance(port, int) or not port:
            return Result(False, "No panel port is set.", "no_port")
        return tls.open_port(port)
    return Result(False, "Unknown fix.", "unknown")
