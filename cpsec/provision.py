"""Setting a server up: the steps, a plan you can read first, and a runner that reports progress.

Every step can be run again safely. A step looks at the server first and says what it would do
("done", "todo", "blocked", "skip"), so the Setup page can show a plan before anything changes.

Steps, in order:
  migrate   copy the lists and settings of the earlier hand-made setup (only if there was one)
  lock      the admin lock (CyberPanel, LiteSpeed admin, web terminal only for trusted addresses)
  blocker   the attack blocker (fail2ban) with its protections
  feed      the helper that copies failed WordPress logins for the blocker
  baseline  remember how every website answers today
  waf       the web firewall (OWASP rules) in watch-only mode
  retire    switch off and put away the earlier hand-made setup (only once the new one is live)

Nothing here ever deletes a file of the earlier setup: it is moved into a dated backup folder.
"""
import copy
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

from . import access, blocker, config, crs_convert, settings, sites, util, waf, webserver
from .util import Result

# the OWASP Core Rule Set, pinned: a different file would fail the checksum and be refused
CRS_VERSION = "3.3.10"
CRS_URL = "https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.10.tar.gz"
CRS_SHA256 = "59f5b0bf65333916ff5075a3fb805f4661c81184cbdcbcef18e757cc86be0ccb"
CRS_MAX_BYTES = 25 * 1024 * 1024

# Rule files we load, in order: exactly the set that was proven on the first production server. 905 is left out
# on purpose (it switches the engine off for local requests), 949 too (we use one small blocking rule of our own),
# 910 and 912 need data we do not ship, 934 and 944 (Node.js / Java) have not been tried on this engine.
CRS_ORDER = (
    "REQUEST-901-INITIALIZATION.conf", "REQUEST-911-METHOD-ENFORCEMENT.conf", "REQUEST-913-SCANNER-DETECTION.conf",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "REQUEST-921-PROTOCOL-ATTACK.conf",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf", "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf", "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
)
CRS_SETUP = (
    "# Written by CP-Security: the settings for the OWASP rules. Do not edit by hand.\n"
    'SecDefaultAction "phase:1,log,auditlog,pass"\n'
    'SecDefaultAction "phase:2,log,auditlog,pass"\n'
    "# Gentlest sensitivity (paranoia level 1) = fewest false alarms.\n"
    'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"\n'
    'SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.executing_paranoia_level=1"\n'
    "# One serious finding (score 5) is enough to count a request as an attack.\n"
    'SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"\n'
    "# WordPress and WooCommerce use these methods for the editor and the REST API.\n"
    "SecAction \"id:900200,phase:1,nolog,pass,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\"\n"
    'SecAction "id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=%s"\n'
    'SecAction "id:900010,phase:1,nolog,pass,t:none,setvar:tx.critical_anomaly_score=5,setvar:tx.error_anomaly_score=4,setvar:tx.warning_anomaly_score=3,setvar:tx.notice_anomaly_score=2"\n'
    % CRS_VERSION.replace(".", "")
)

OUR_FILE_MARK = "# Written by CP-Security"

SERVICE_FEED = "cps-wplogin-feed.service"
SERVICE_LOCK = "cps-admin-lock.service"
SERVICE_FW = "cps-firewall.service"
SERVICE_PANEL = "cp-security-panel.service"
FW_TABLE = "cps_fw"

UNIT_FEED = """[Unit]
Description=CP-Security: copies failed WordPress logins for the attack blocker
After=network.target

[Service]
Type=simple
Environment=PYTHONPATH={install_dir}
WorkingDirectory={install_dir}
ExecStart={python} -m cpsec.feed
Restart=always
RestartSec=5
Nice=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
UNIT_LOCK = """[Unit]
Description=CP-Security: only trusted addresses may open the admin pages
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {nft_file}
ExecReload={nft} -f {nft_file}
ExecStop=-{nft} delete table inet {table}

[Install]
WantedBy=multi-user.target
"""
UNIT_FW = """[Unit]
Description=CP-Security: the server firewall (only the ports on the owner's list are open)
After=network-pre.target nftables.service
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {nft_file}
ExecReload={nft} -f {nft_file}
ExecStop=-{nft} delete table inet {table}

[Install]
WantedBy=multi-user.target
"""
UNIT_PANEL = """[Unit]
Description=CP-Security panel
After=network-online.target

[Service]
Type=simple
Environment=PYTHONPATH={install_dir}
WorkingDirectory={install_dir}
ExecStart={python} -m cpsec panel run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def python_path():
    """The Python that is running us: the services must use the same one (it may be newer than the system default)."""
    exe = os.path.realpath(sys.executable) if sys.executable else ""
    return exe if exe and os.path.exists(exe) else (shutil.which("python3") or "/usr/bin/python3")


def nft_path():
    return shutil.which("nft") or "/usr/sbin/nft"


# ----------------------------------------------------------------------------- small helpers
def install_packages(names):
    """Install system packages with the server's own package manager. Returns a Result."""
    if config.P.is_debian():
        util.run(["apt-get", "update"], timeout=300)
        rc, out = util.run(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y"] + list(names),
                           timeout=900)
    else:
        if "fail2ban" in names:
            util.run(["dnf", "install", "-y", "epel-release"], timeout=600)
        rc, out = util.run(["dnf", "install", "-y"] + list(names), timeout=900)
    if rc != 0:
        return Result(False, "Installing %s failed: %s" % (", ".join(names), _tail(out)), "install_failed")
    return Result(True, "Installed %s." % ", ".join(names))


def _tail(text, n=160):
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    return (lines[-1] if lines else "no details")[:n]


def write_unit(name, text):
    util.atomic_write(config.P.systemd_dir + "/" + name, text, 0o644)


def enable_unit(name, start=True):
    util.run(["systemctl", "daemon-reload"])
    rc, out = util.run(["systemctl", "enable", "--now" if start else "--no-block", name], timeout=120)
    return rc == 0, out


def unit_enabled(name):
    rc, out = util.run(["systemctl", "is-enabled", name])
    return out.strip() == "enabled"


def unit_active(name):
    rc, out = util.run(["systemctl", "is-active", name])
    return out.strip() == "active"


def fetch_crs(url=CRS_URL, sha256=CRS_SHA256, opener=None):
    """Download the pinned rule set and check its fingerprint. Raises ValueError when anything is off."""
    opener = opener or (lambda u: urllib.request.urlopen(u, timeout=60))
    with opener(url) as response:
        data = response.read(CRS_MAX_BYTES + 1)
    if len(data) > CRS_MAX_BYTES:
        raise ValueError("The download is far bigger than expected, so it was refused.")
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("The download does not match the expected fingerprint, so it was refused.")
    return data


def extract_rules(data, dest):
    """Unpack only the rule files (rules/<name>) into dest. Nothing else, and no path tricks."""
    os.makedirs(dest, exist_ok=True)
    found = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            m = re.match(r"^[^/]+/rules/([A-Za-z0-9][A-Za-z0-9._-]*)$", member.name)
            if not m or not member.isfile() or member.size > 8 * 1024 * 1024:
                continue
            with open(os.path.join(dest, m.group(1)), "wb") as out:
                out.write(tar.extractfile(member).read())
            found += 1
    if not found:
        raise ValueError("The download did not contain any rule files.")
    return found


def render_rules(available):
    """The master rules file: setup, per-site exceptions, the OWASP files, our blocking rule, global exceptions."""
    p = config.P
    lines = ["# Written by CP-Security. The order matters: do not edit by hand.",
             "Include " + p.waf_setup, "Include " + p.waf_before]
    lines += ["Include %s/%s" % (p.waf_crs, name) for name in CRS_ORDER if name in available]
    lines += ["Include " + p.waf_block, "Include " + p.waf_after]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- the earlier hand-made setup
LEGACY_COPY = ("admin-access.list", "never-block.list", "site-baseline.json", "waf-exceptions.json", "waf-settings.json")


def legacy_items():
    """Plain-English list of what is left of the earlier setup (empty when there is none)."""
    p = config.P
    items = []
    if os.path.isdir(p.legacy_conf_dir):
        items.append("settings folder /etc/pb-security")
    for path in sorted(_glob(p.systemd_dir + "/pb-*.service")):
        items.append("service " + os.path.basename(path))
    for path in sorted(_glob(p.at("/etc/fail2ban/jail.d/pb-*")) + _glob(p.f2b_filter_dir + "/pb-*")):
        items.append("blocker file " + os.path.basename(path))
    for d in webserver.LEGACY_WAF_DIR_NAMES:
        if os.path.isdir("%s/%s" % (p.lsws_conf, d)):
            items.append("web firewall folder " + d)
    for path in sorted(_glob(p.at("/etc/pb-admin-firewall.nft*")) + _glob(p.at("/usr/local/sbin/pb-*"))
                       + _glob(p.logrotate_dir + "/pb-*") + _glob(p.at("/usr/local/lib/pb-security"))):
        items.append("file " + path[len(p.root):] if p.root else "file " + path)
    if legacy_nft_tables():
        items.append("firewall table " + ", ".join(legacy_nft_tables()))
    return items


def _glob(pattern):
    import glob
    return glob.glob(pattern)


def legacy_nft_tables():
    rc, out = util.run(["nft", "list", "tables"])
    return re.findall(r"table inet (pb_\w+)", out) if rc == 0 else []


def legacy_waf_mode():
    """('watch' | 'block', threshold) read from the earlier web firewall's blocking rule."""
    for d in webserver.LEGACY_WAF_DIR_NAMES:
        text = util.read_text("%s/%s/block-rule.conf" % (config.P.lsws_conf, d))
        m = re.search(r'^\s*SecRule\s+TX:ANOMALY_SCORE_PL1\s+"@ge\s+(\d+)"', text, re.M)
        if m:
            return "block", int(m.group(1))
    return "watch", 5


# ----------------------------------------------------------------------------- the steps
class Step:
    key = ""
    title = ""

    def state(self):
        """('done' | 'todo' | 'blocked' | 'skip', one plain sentence)"""
        raise NotImplementedError

    def describe(self):
        """What running it would do, as a list of plain sentences."""
        raise NotImplementedError

    def run(self, log):
        raise NotImplementedError


class Migrate(Step):
    key, title = "migrate", "Take over the earlier setup's lists and settings"

    def _missing(self):
        return [n for n in LEGACY_COPY
                if os.path.exists(os.path.join(config.P.legacy_conf_dir, n))
                and not os.path.exists(os.path.join(config.P.conf_dir, n))]

    def state(self):
        if not legacy_items():
            return "skip", "There is no earlier hand-made setup on this server."
        if self._missing():
            return "todo", "Your trusted addresses and settings from the earlier setup can be copied over."
        return "done", "Lists and settings were copied from the earlier setup."

    def describe(self):
        return ["Copy %s from the earlier setup (nothing is removed)." % ", ".join(self._missing() or ["nothing"])]

    def run(self, log):
        os.makedirs(config.P.conf_dir, exist_ok=True)
        for name in self._missing():
            shutil.copy2(os.path.join(config.P.legacy_conf_dir, name), os.path.join(config.P.conf_dir, name))
            log("copied " + name)
        mode, threshold = legacy_waf_mode()
        if not os.path.exists(config.P.waf_settings) and mode == "block":
            util.write_json(config.P.waf_settings, {"threshold": threshold, "mode": "block"})
            log("the earlier web firewall was in blocking mode (strictness %d): that is kept" % threshold)
        return Result(True, "Copied the lists and settings of the earlier setup.")


class Lock(Step):
    key, title = "lock", "Lock the admin pages to trusted addresses"

    def state(self):
        if not access.list_admin():
            if access.list_legacy_admin():
                return "todo", "Your trusted addresses will be copied from the earlier setup, then the lock is set up."
            return "blocked", "Add at least one trusted address first (yours), or you would lock yourself out."
        if access.lock_is_live() and os.path.exists(config.P.systemd_dir + "/" + SERVICE_LOCK) \
                and unit_enabled(SERVICE_LOCK) and unit_active(SERVICE_LOCK):
            return "done", "The admin pages are locked and the lock comes back after a restart."
        return "todo", "The admin pages are not locked by CP-Security yet."

    def describe(self):
        ports = ", ".join(str(x) for x in settings.lock_ports())
        return ["Only the %d trusted addresses may open ports %s (CyberPanel, LiteSpeed admin, web terminal, panel)."
                % (len(access.list_admin()), ports),
                "The lock is reloaded automatically after a server restart."]

    def run(self, log):
        if not access.list_admin() and access.list_legacy_admin():
            BY_KEY["migrate"].run(log)                          # bring the old trusted addresses over first
        if not access.list_admin():
            # an empty list would shut out everybody except this machine itself
            return Result(False, "There is no trusted address yet, so the lock was not set up.", "no_trusted")
        if not shutil.which("nft"):
            res = install_packages(["nftables"])
            if not res.ok:
                return res
            log(res.message)
        res = access.apply()
        if not res.ok:
            return res
        log("lock loaded")
        write_unit(SERVICE_LOCK, UNIT_LOCK.format(nft=nft_path(), nft_file=config.P.nft_file, table=access.TABLE))
        # start it as well (not only enable it): the rules are already loaded, starting re-applies the same file
        ok, out = enable_unit(SERVICE_LOCK)
        if not ok:
            return Result(False, "The lock works now, but it could not be set to start after a restart: " + _tail(out),
                          "enable_failed")
        return Result(True, "The admin pages are locked.")


class Blocker(Step):
    key, title = "blocker", "Install the attack blocker"

    def state(self):
        if not blocker.installed():
            return "todo", "The attack blocker (fail2ban) is not installed."
        names = blocker.jails()
        if names is None:
            return "todo", "The attack blocker is installed but not running."
        if not os.path.exists(config.P.f2b_jails) or not any(n.startswith("cps-") for n in names):
            return "todo", "The blocker runs, but the CP-Security protections are not added yet."
        return "done", "%d protections are running." % len(names)

    def describe(self):
        text, skipped = blocker.render_jails()
        names = [n for n in blocker.TUNABLE if n not in skipped]
        out = ["Install fail2ban if it is missing, and add its own protections only; protections that belong "
               "to someone else are left alone.",
               "Protect: " + ", ".join(config.JAIL_NAMES.get(n, n) for n in names) + "."]
        if skipped:
            out.append("Left out (no log file on this server): " + ", ".join(skipped) + ".")
        return out

    def run(self, log):
        if not blocker.installed():
            res = install_packages(["fail2ban"])
            if not res.ok:
                return res
            log(res.message)
        access.apply()                                           # writes the never-block list for the blocker
        res = blocker.write_config()
        if not res.ok:
            return res
        log("protections written")
        util.atomic_write(config.P.logrotate_dir + "/cps-wp-login", blocker.LOGROTATE % config.P.wplogin_log)
        util.atomic_write(config.P.logrotate_dir + "/cp-security-panel", blocker.LOGROTATE % config.P.panel_log)
        rc, out = util.run(["systemctl", "enable", "--now", "fail2ban"], timeout=120)
        if rc != 0:
            return Result(False, "The blocker did not start: " + _tail(out), "start_failed")
        time.sleep(2)
        names = blocker.jails()
        if names is None or not any(n.startswith("cps-") for n in names):
            return Result(False, "The blocker started, but the CP-Security protections are not loaded. "
                                 "Look at /var/log/fail2ban.log.", "not_loaded")
        return Result(True, "The attack blocker is running with %d protections." % len(names))


class Feed(Step):
    key, title = "feed", "Start the WordPress login watcher"

    def state(self):
        if blocker.feed_active() and os.path.exists(config.P.systemd_dir + "/" + SERVICE_FEED) \
                and unit_enabled(SERVICE_FEED):
            return "done", "The login watcher is running."
        return "todo", "The login watcher is not running."

    def describe(self):
        return ["Run a small helper that copies failed WordPress logins into one tidy file for the blocker.",
                "It starts again by itself after a restart."]

    def run(self, log):
        write_unit(SERVICE_FEED, UNIT_FEED.format(install_dir=config.P.install_dir, python=python_path()))
        os.makedirs(os.path.dirname(config.P.wplogin_log), exist_ok=True)
        ok, out = enable_unit(SERVICE_FEED)
        if not ok:
            return Result(False, "The login watcher did not start: " + _tail(out), "start_failed")
        time.sleep(1)
        if not unit_active(SERVICE_FEED):
            return Result(False, "The login watcher stopped right after starting.", "not_running")
        return Result(True, "The login watcher is running.")


class Baseline(Step):
    key, title = "baseline", "Remember how your websites answer today"

    def state(self):
        if sites.load_baseline():
            return "done", "Saved."
        if not sites.list_sites():
            return "skip", "No websites were found."
        return "todo", "Needed so a change can be undone if it breaks a website."

    def describe(self):
        return ["Ask each website for its home page once and write down the answer."]

    def run(self, log):
        r = sites.save_baseline()
        return Result(True, "%d of %d websites answer normally. That is now the reference." % (r["normal"], r["total"]))


class Waf(Step):
    key, title = "waf", "Set up the web firewall (watch-only)"

    def _blocker_reason(self):
        """Why the firewall cannot be installed here, or None."""
        if webserver.kind() is None:
            return "No LiteSpeed web server was found."
        if not webserver.engine_installed():
            return webserver.how_to_install_engine()
        packs = webserver.rule_packs_in_use()
        if packs:
            return ("%s, and they are running. They use the same rule numbers as ours, so CP-Security leaves the web "
                    "firewall to them. (To use CP-Security's instead, switch ModSecurity off in CyberPanel first.)"
                    % " and ".join(packs))
        p = config.P
        if any(os.path.exists(p.at(x)) for x in ("/opt/imunify360", "/usr/bin/imunify360-agent")):
            return "Imunify is installed and has its own web firewall. Two would get in each other's way."
        return None

    def state(self):
        if waf.mode() is not None:
            return "done", "The web firewall is set up (%s)." % waf.MODE_SHORT.get(waf.mode(), "")
        reason = self._blocker_reason()
        if reason:
            return "blocked", reason
        if webserver.other_rule_packs():
            return "todo", ("CyberPanel's own rule pack is installed but ModSecurity is switched off, so it protects nothing. "
                            "It will be put aside (its lines are commented out, nothing is deleted) and replaced.")
        return "todo", "The web firewall is not set up."

    def describe(self):
        aside = ["CyberPanel's own rule pack is installed (switched off). Its lines are commented out so the two sets of "
                 "rules cannot clash; they can be put back at any time."] if webserver.other_rule_packs() else []
        return aside + ["Download the OWASP rules version %s and check their fingerprint." % CRS_VERSION,
                "Use the gentlest sensitivity level, so normal visitors are not bothered.",
                "Start in watch-only mode: suspicious requests are recorded, none is refused.",
                "Restart the web server gracefully and check that your websites still answer. "
                "If one does not, everything is undone.",
                "Send one harmless test request that looks like an attack and make sure the firewall saw it."]

    def run(self, log):
        reason = self._blocker_reason()
        if reason:
            return Result(False, reason, "blocked")
        p = config.P
        paths = [webserver.firewall_file(), p.lsws_conf + "/rules.conf", p.waf_main, p.waf_rules, p.waf_block,
                 p.waf_before, p.waf_after, p.waf_setup, p.waf_settings, p.waf_exceptions]
        snap = util.snapshot(paths)
        fresh = not os.path.exists(p.waf_dir)
        tmp = tempfile.mkdtemp(prefix="cps-crs-")

        def undo(message, code):
            util.restore(snap)
            if fresh:
                shutil.rmtree(p.waf_dir, ignore_errors=True)
            else:
                shutil.rmtree(p.waf_crs + ".new", ignore_errors=True)
            waf.restart_and_check()
            return Result(False, message, code)

        try:
            log("downloading the OWASP rules %s" % CRS_VERSION)
            try:
                data = fetch_crs()
                extract_rules(data, tmp + "/rules")
            except (OSError, ValueError, tarfile.TarError) as exc:
                shutil.rmtree(p.waf_dir if fresh else p.waf_crs + ".new", ignore_errors=True)
                return Result(False, "Could not get the rules: %s" % str(exc)[:160], "download_failed")
            os.makedirs(p.waf_dir, exist_ok=True)
            report = crs_convert.convert_dir(tmp + "/rules", p.waf_crs + ".new")
            available = set(report) | set(os.listdir(p.waf_crs + ".new"))
            log("prepared %d rule files" % len(report))
            if os.path.isdir(p.waf_crs):
                shutil.rmtree(p.waf_crs)
            os.replace(p.waf_crs + ".new", p.waf_crs)

            mode, threshold = ("watch", 5)
            stored = util.read_json(p.waf_settings, {})
            if stored.get("mode") == "block":
                mode, threshold = "block", int(stored.get("threshold", 5))
            elif os.path.isdir(p.legacy_conf_dir):
                mode, threshold = legacy_waf_mode()
            util.atomic_write(p.waf_setup, CRS_SETUP, 0o640, "lsadm:lsadm")
            util.atomic_write(p.waf_rules, render_rules(available), 0o640, "lsadm:lsadm")
            util.atomic_write(p.waf_block, waf.BLOCK_TEMPLATE % (threshold, threshold) if mode == "block"
                              else waf.WATCH_BLOCK, 0o640, "lsadm:lsadm")
            waf._write_exception_files(waf.list_exceptions())
            util.atomic_write(p.waf_main, waf.render_main("On"), 0o644, "lsadm:lsadm")
            util.write_json(p.waf_settings, {"threshold": threshold, "mode": mode,
                                             "since": time.strftime("%Y-%m-%d")})
            ensure_audit_log()
            drop_audit_logrotate()
            if not os.path.isdir(p.modsec_data):
                os.makedirs(p.modsec_data, exist_ok=True)
            if webserver.other_rule_packs():
                log("setting CyberPanel's switched-off rule pack aside (%d line(s)); nothing is deleted"
                    % webserver.park_rule_packs())
            res = webserver.connect()
            if not res.ok:
                return undo(res.message, res.code)
            log("web server is reading the rules; restarting it gracefully")
            ok, bad = waf.restart_and_check()
            if not ok:
                return undo("A website stopped answering normally (%s), so everything was put back as it was."
                            % ", ".join("%s %s" % x for x in bad[:3]), "rolled_back")
            test = waf.selftest()
            log("self-test: " + test.message)
            if not test.ok:
                return undo("The firewall loaded but did not record the test attack, so it was taken out again. "
                            + test.message, test.code)
            return Result(True, "The web firewall is on in %s mode. %s" % (waf.MODE_SHORT[mode].lower(), test.message))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def drop_audit_logrotate():
    """Take away the rotation file that earlier versions wrote for the firewall's log. Returns True when one was removed.

    Found on the real server: the web server already rotates that log by itself (in 10 MB pieces, kept 30 days), and the
    system's nightly clean-up (logrotate) is not allowed to write under /usr, where the log lives. So our extra file only made
    the clean-up fail every night. The log folder is closed to everybody except root and the web server, so the copies stay
    private without it. Only a file that we wrote is removed."""
    path = config.P.logrotate_dir + "/cps-waf"
    try:
        if util.read_text(path).startswith(OUR_FILE_MARK):
            os.remove(path)
            return True
    except OSError:
        pass
    return False


def ensure_audit_log():
    """The log holds request headers (cookies), so only the web server's own user may read it."""
    path = config.P.audit_log
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a"):
            pass
        os.chmod(path, 0o600)
        if hasattr(shutil, "chown"):
            shutil.chown(path, user="nobody")
    except (OSError, LookupError):
        pass


class Retire(Step):
    key, title = "retire", "Put the earlier hand-made setup away"

    def _ready(self):
        """None when the new setup is live in every part the old one covered, else the reason it is not."""
        if legacy_nft_tables() and not access.lock_is_live():
            return "The new admin lock is not live yet."
        names = blocker.jails() or []
        if glob_any(config.P.at("/etc/fail2ban/jail.d/pb-*")) and not any(n.startswith("cps-") for n in names):
            return "The new attack protections are not running yet."
        if glob_any(config.P.systemd_dir + "/pb-*feed*") and not unit_active(SERVICE_FEED):
            return "The new login watcher is not running yet."
        legacy_waf = any(os.path.isdir("%s/%s" % (config.P.lsws_conf, d)) for d in webserver.LEGACY_WAF_DIR_NAMES)
        if legacy_waf and waf.mode() is None:
            return "The new web firewall is not set up yet."
        return None

    def state(self):
        items = legacy_items()
        if not items:
            return "skip", "Nothing of the earlier setup is left."
        # the settings folder alone (already copied) is not a reason to wait for anything
        reason = self._ready()
        if reason:
            return "blocked", reason
        return "todo", "Still there: " + ", ".join(items) + "."

    def describe(self):
        return ["Stop and switch off the earlier services, and take down its firewall table (the new lock already does the same job).",
                "Move its files into a dated backup folder inside %s. Nothing is deleted." % config.P.conf_dir]

    def run(self, log):
        p = config.P
        reason = self._ready()
        if reason:
            return Result(False, reason, "not_ready")
        backup = "%s/legacy-%s" % (p.conf_dir, time.strftime("%Y%m%d-%H%M%S"))
        os.makedirs(backup, exist_ok=True)

        def put_away(path):
            if os.path.exists(path):
                rel = os.path.relpath(path, p.root or os.sep)
                shutil.move(path, os.path.join(backup, rel.replace(os.sep, "__")))
                log("moved " + path)

        for unit in sorted(_glob(p.systemd_dir + "/pb-*.service")):
            name = os.path.basename(unit)
            util.run(["systemctl", "disable", "--now", name], timeout=120)
            put_away(unit)
        util.run(["systemctl", "daemon-reload"])
        for table in legacy_nft_tables():
            util.run(["nft", "delete", "table", "inet", table])
            log("removed the earlier firewall table " + table)
        for path in _glob(p.at("/etc/fail2ban/jail.d/pb-*")) + _glob(p.f2b_filter_dir + "/pb-*"):
            put_away(path)
        rc, out = util.run(["fail2ban-client", "-t"], timeout=90)
        if rc != 0:
            return Result(False, "The blocker rejected the cleanup: " + _tail(out) +
                          " Your files are in " + backup + ".", "f2b_rejected")
        if blocker.jails() is not None:
            util.run(["fail2ban-client", "reload"], timeout=90)
            checked = blocker.ensure_actions()
            if not checked.ok:
                return checked
        for d in webserver.LEGACY_WAF_DIR_NAMES:
            put_away("%s/%s" % (p.lsws_conf, d))
        for path in (_glob(p.at("/var/log/pb-*")) + _glob(p.at("/etc/pb-admin-firewall.nft*"))
                     + _glob(p.at("/usr/local/sbin/pb-*")) + _glob(p.logrotate_dir + "/pb-*")
                     + _glob(p.at("/usr/local/lib/pb-security"))):
            put_away(path)
        drop_audit_logrotate()
        if os.path.isdir(p.legacy_conf_dir):
            put_away(p.legacy_conf_dir)
        return Result(True, "The earlier setup was put away. Its files are in %s." % backup)


def glob_any(pattern):
    return bool(_glob(pattern))


STEPS = (Migrate(), Lock(), Blocker(), Feed(), Baseline(), Waf(), Retire())
BY_KEY = {s.key: s for s in STEPS}


# ----------------------------------------------------------------------------- the plan, and doing it
def plan():
    """What each step would do, without changing anything."""
    out = []
    for s in STEPS:
        state, note = s.state()
        out.append({"key": s.key, "title": s.title, "state": state, "note": note,
                    "will_do": s.describe() if state == "todo" else []})
    return out


class Runner:
    """Runs steps in a background thread and lets the page ask how far it is."""

    def __init__(self, steps=None, clock=time.strftime, on_log=None):
        self.steps = STEPS if steps is None else steps
        self.on_log = on_log
        self.lock = threading.Lock()
        self.job = {"status": "idle", "steps": [], "log": [], "started": "", "finished": ""}
        self._clock = clock

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.job)

    def running(self):
        return self.snapshot()["status"] == "running"

    def start(self, keys=None, background=True):
        wanted = [s for s in self.steps if keys is None or s.key in keys]
        if not wanted:
            return Result(False, "Nothing to do.", "empty")
        with self.lock:
            if self.job["status"] == "running":
                return Result(False, "Setup is already running.", "busy")
            self.job = {"status": "running", "log": [], "started": self._clock("%Y-%m-%d %H:%M:%S"), "finished": "",
                        "steps": [{"key": s.key, "title": s.title, "state": "waiting", "message": ""} for s in wanted]}
        if background:
            threading.Thread(target=self._work, args=(wanted,), daemon=True).start()
        else:
            self._work(wanted)
        return Result(True, "Setup started.")

    def _log(self, text):
        with self.lock:
            self.job["log"].append("%s  %s" % (self._clock("%H:%M:%S"), text))
            del self.job["log"][:-300]
        if self.on_log:
            self.on_log(text)

    def _set(self, index, state, message=""):
        with self.lock:
            self.job["steps"][index].update(state=state, message=message)

    def _work(self, wanted):
        failed = False
        for i, step in enumerate(wanted):
            if failed:
                self._set(i, "skipped", "Not started because an earlier step failed.")
                continue
            try:
                state, note = step.state()
                if state in ("done", "skip"):
                    self._set(i, "done" if state == "done" else "skipped", note)
                    continue
                if state == "blocked":
                    self._set(i, "failed", note)
                    self._log("%s: %s" % (step.title, note))
                    failed = True
                    continue
                self._set(i, "running")
                self._log("Starting: " + step.title)
                res = step.run(self._log)
            except Exception as exc:                          # a step must never take the panel down
                res = Result(False, "Unexpected problem: %s" % str(exc)[:160], "error")
            self._set(i, "done" if res.ok else "failed", res.message)
            self._log(("Done: " if res.ok else "FAILED: ") + res.message)
            failed = not res.ok
        with self.lock:
            self.job["status"] = "failed" if failed else "done"
            self.job["finished"] = self._clock("%Y-%m-%d %H:%M:%S")


def refresh_after_update():
    """After new program files are in place: bring the files in the system that depend on them up to date.

    Only things this tool already installed are touched: its service files, and its blocker filters and jails.
    Returns a list of plain sentences about what was refreshed."""
    p = config.P
    done = []
    wanted = (
        (SERVICE_FEED, UNIT_FEED.format(install_dir=p.install_dir, python=python_path())),
        (SERVICE_PANEL, UNIT_PANEL.format(install_dir=p.install_dir, python=python_path())),
        (SERVICE_LOCK, UNIT_LOCK.format(nft=nft_path(), nft_file=p.nft_file, table=access.TABLE)),
        (SERVICE_FW, UNIT_FW.format(nft=nft_path(), nft_file=p.fw_nft, table=FW_TABLE)),
    )
    changed = False
    for name, text in wanted:
        path = p.systemd_dir + "/" + name
        if os.path.exists(path) and util.read_text(path) != text:
            util.atomic_write(path, text, 0o644)
            done.append("service file " + name)
            changed = True
    if changed:
        util.run(["systemctl", "daemon-reload"])
    if blocker.installed() and os.path.exists(p.f2b_jails):
        res = blocker.write_config()
        done.append("blocker settings" if res.ok else "blocker settings (%s)" % res.message)
    return done


# ----------------------------------------------------------------------------- the panel's own service
def install_panel_service():
    """Write and start the panel's system service (the installer calls this once the login exists)."""
    write_unit(SERVICE_PANEL, UNIT_PANEL.format(install_dir=config.P.install_dir, python=python_path()))
    ok, out = enable_unit(SERVICE_PANEL)
    if not ok:
        return Result(False, "The panel service did not start: " + _tail(out), "start_failed")
    util.run(["systemctl", "restart", SERVICE_PANEL], timeout=60)     # so a re-run always uses the newest program files
    return Result(True, "The panel is running.")
