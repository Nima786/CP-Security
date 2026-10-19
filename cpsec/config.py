"""Where everything lives on the server.

All paths are in one object so tests can point them at a temporary folder:

    config.P = config.Paths(root=str(tmp_path))
"""
import os


class Paths:
    def __init__(self, root=""):
        j = lambda p: root + p
        self.root = root

        # our own settings and lists
        self.conf_dir = j("/etc/cp-security")
        self.backup_dir = self.conf_dir + "/backups"
        self.admin_list = self.conf_dir + "/admin-access.list"
        self.never_list = self.conf_dir + "/never-block.list"
        self.baseline = self.conf_dir + "/site-baseline.json"
        self.waf_exceptions = self.conf_dir + "/waf-exceptions.json"
        self.waf_settings = self.conf_dir + "/waf-settings.json"
        self.panel_settings = self.conf_dir + "/panel.json"
        self.tls_dir = self.conf_dir + "/tls"
        self.nft_file = self.conf_dir + "/admin-lock.nft"
        self.updates_cache = self.conf_dir + "/updates-cache.json"
        self.blocker_settings = self.conf_dir + "/blocker.json"
        self.legacy_conf_dir = j("/etc/pb-security")

        # the attack blocker (fail2ban)
        self.f2b_log = j("/var/log/fail2ban.log")
        self.f2b_ignore = j("/etc/fail2ban/jail.d/cps-never-block.local")
        self.f2b_jails = j("/etc/fail2ban/jail.d/cps-jails.local")
        self.f2b_filter_dir = j("/etc/fail2ban/filter.d")
        self.wplogin_log = j("/var/log/cps-wp-login.log")

        # the web server and its firewall
        self.lsws_root = j("/usr/local/lsws")
        self.lsws_conf = self.lsws_root + "/conf"
        self.lsws_ctl = self.lsws_root + "/bin/lswsctrl"
        self.lsws_bin_ols = self.lsws_root + "/bin/openlitespeed"     # only OpenLiteSpeed has this
        self.lsws_bin_ent = self.lsws_root + "/bin/litespeed"         # LiteSpeed Enterprise program
        self.lsws_xml = self.lsws_conf + "/httpd_config.xml"          # LiteSpeed Enterprise settings
        self.lsws_version = self.lsws_root + "/VERSION"
        self.ols_conf = self.lsws_conf + "/httpd_config.conf"         # OpenLiteSpeed settings
        self.ols_module = self.lsws_root + "/modules/mod_security.so"
        self.modsec_conf = self.lsws_conf + "/modsec.conf"            # LiteSpeed Enterprise ModSecurity file
        self.waf_dir = self.lsws_conf + "/cps-waf"
        self.waf_main = self.waf_dir + "/main.conf"
        self.waf_rules = self.waf_dir + "/rules.conf"
        self.waf_block = self.waf_dir + "/block-rule.conf"
        self.waf_before = self.waf_dir + "/exceptions-before.conf"
        self.waf_after = self.waf_dir + "/exceptions-after.conf"
        self.waf_setup = self.waf_dir + "/crs-setup.conf"
        self.waf_crs = self.waf_dir + "/crs"
        self.audit_log = self.lsws_root + "/logs/auditmodsec.log"

        # websites
        self.home_dir = j("/home")

        # the panel
        self.panel_log = j("/var/log/cp-security/panel.log")
        self.install_dir = j("/opt/cp-security")
        self.systemd_dir = j("/etc/systemd/system")
        self.logrotate_dir = j("/etc/logrotate.d")
        self.letsencrypt_live = j("/etc/letsencrypt/live")
        self.sshd_config = j("/etc/ssh/sshd_config")
        self.sshd_config_d = j("/etc/ssh/sshd_config.d")

    def at(self, path):
        """A system path as it is on this machine (tests move everything into a temporary folder)."""
        return self.root + path

    def is_debian(self):
        """Ubuntu / Debian (apt) as opposed to AlmaLinux / Rocky / CentOS (dnf)."""
        return os.path.exists(self.at("/etc/debian_version"))


P = Paths(os.environ.get("CPSEC_ROOT", ""))

# the three admin pages that are locked to trusted addresses (the panel port is added when chosen)
ADMIN_PORTS = (8090, 7080, 8888)

# friendly names for the blocker's protections
JAIL_NAMES = {
    "sshd": "Server login (SSH) guessing",
    "cps-wp-login": "WordPress login guessing",
    "cps-mail-auth": "Email password guessing",
    "cps-panel": "Security panel login guessing",
    "dovecot": "Email login (IMAP/POP) guessing",
    "pure-ftpd": "FTP password guessing",
}

PHP_TRY = ("lsphp81", "lsphp82", "lsphp80", "lsphp83")
