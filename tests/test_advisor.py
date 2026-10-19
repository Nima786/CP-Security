import datetime
import os

from cpsec import access, advisor, config, netinfo, settings, util, waf, webserver
from tests.helpers import EnvTestCase, FakeRun


def ids(findings):
    return [f["id"] for f in findings]


def by_id(findings, fid):
    return next(f for f in findings if f["id"] == fid)


class Quiet(EnvTestCase):
    """A server where every tool answers 'not active' unless the test says otherwise."""

    def setUp(self):
        super().setUp()
        self.patch("cpsec.blocker.installed", return_value=True)


class WebFirewall(Quiet):
    def test_cyberpanels_rules_next_to_ours_is_a_clash(self):
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.ols_module, "")
        self.write(config.P.at("/usr/local/lsws/conf/modsec/owasp/rules/REQUEST-901.conf"), "")
        self.write(config.P.ols_conf,
                   "module mod_security {\nmodsecurity on\n"
                   "modsecurity_rules_file /usr/local/lsws/conf/modsec/owasp/rules/REQUEST-901.conf\n}\n")
        webserver.connect()
        self.write(config.P.waf_main, waf.render_main("On"))
        self.write(config.P.waf_rules, "")
        self.write(config.P.waf_block, waf.WATCH_BLOCK)
        found = advisor.check_modsecurity()
        self.assertEqual(by_id(found, "modsec_clash")["level"], "bad")

    def test_cyberpanels_rules_alone_are_left_alone(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.at("/usr/local/lsws/conf/comodo_litespeed/x.conf"), "")
        self.write(config.P.modsec_conf, "<IfModule security2_module>\nInclude /usr/local/lsws/conf/comodo_litespeed/x.conf\n</IfModule>\n")
        found = advisor.check_modsecurity()
        self.assertEqual(ids(found), ["modsec_other"])
        self.assertIn("will not add its own rules", found[0]["advice"])

    def test_not_set_up_but_possible_points_to_setup(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, "<IfModule security2_module>\n</IfModule>\n")
        f = by_id(advisor.check_modsecurity(), "modsec_missing")
        self.assertEqual(f["fix"]["id"], "setup")

    def test_missing_engine_explains_how_to_install(self):
        self.write(config.P.lsws_bin_ols, "")
        f = by_id(advisor.check_modsecurity(), "modsec_engine")
        self.assertIn("ModSecurity Conf", f["advice"])

    def test_ours_running_and_cyberpanel_page_showing_off_is_explained(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, "<IfModule security2_module>\nSecRuleEngine Off\n</IfModule>\n")
        webserver.connect()
        self.write(config.P.waf_main, waf.render_main("On"))
        self.write(config.P.waf_rules, "")
        self.write(config.P.waf_block, waf.WATCH_BLOCK)
        f = by_id(advisor.check_modsecurity(), "modsec_ours")
        self.assertEqual(f["level"], "ok")
        self.assertIn("wins", f["detail"])

    def test_long_watch_only_suggests_blocking(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, "")
        webserver.connect()
        self.write(config.P.waf_main, waf.render_main("On"))
        self.write(config.P.waf_rules, "")
        self.write(config.P.waf_block, waf.WATCH_BLOCK)
        old = (datetime.date.today() - datetime.timedelta(days=20)).isoformat()
        util.write_json(config.P.waf_settings, {"threshold": 5, "mode": "watch", "since": old})
        self.assertEqual(ids(advisor.check_waf_age()), ["waf_watching"])
        util.write_json(config.P.waf_settings, {"threshold": 5, "mode": "watch",
                                                "since": datetime.date.today().isoformat()})
        self.assertEqual(advisor.check_waf_age(), [])


class OtherTools(Quiet):
    def test_imunify_is_spotted_by_its_files(self):
        self.assertEqual(advisor.check_imunify(), [])
        self.write(config.P.at("/opt/imunify360/x"), "")
        f = advisor.check_imunify()[0]
        self.assertEqual(f["level"], "warn")
        self.assertIn("Off", f["advice"])

    def test_csf_and_its_testing_mode(self):
        self.assertEqual(advisor.check_csf(), [])
        self.write(config.P.at("/etc/csf/csf.conf"), 'TESTING = "1"\n')
        self.assertEqual(ids(advisor.check_csf()), ["csf", "csf_testing"])
        self.write(config.P.at("/etc/csf/csf.conf"), 'TESTING = "0"\n')
        self.assertEqual(ids(advisor.check_csf()), ["csf"])

    def test_another_wordpress_jail_is_a_double_protection(self):
        self.patch("cpsec.blocker.jails", return_value=["sshd", "cps-wp-login", "wordpress-hard"])
        self.write(config.P.at("/etc/fail2ban/jail.d/wp.local"), "[wordpress-hard]\nfilter = wordpress-hard\n")
        self.write(config.P.at("/etc/fail2ban/jail.d/cps-jails.local"), "[cps-wp-login]\nfilter = cps-wp-login\n")
        found = advisor.check_blocker_and_others()
        self.assertEqual(by_id(found, "blocker_double")["level"], "warn")
        self.assertIn("wp.local", by_id(found, "blocker_double")["detail"])
        self.assertNotIn("cps-jails.local", by_id(found, "blocker_double")["detail"])
        self.assertIn("wordpress-hard", by_id(found, "blocker_others")["detail"])

    def test_blocker_missing_or_stopped(self):
        self.patch("cpsec.blocker.installed", return_value=False)
        self.assertEqual(advisor.check_blocker_and_others()[0]["level"], "bad")
        self.patch("cpsec.blocker.installed", return_value=True)
        self.patch("cpsec.blocker.jails", return_value=None)
        self.assertIn("not running", advisor.check_blocker_and_others()[0]["title"])


class TheServer(Quiet):
    def test_ssh_with_passwords_and_root(self):
        self.write(config.P.sshd_config, "PermitRootLogin yes\n")
        self.assertEqual(advisor.check_ssh()[0]["level"], "warn")

    def test_ssh_first_value_wins_and_extra_files_come_first(self):
        self.write(config.P.sshd_config, "PasswordAuthentication yes\n")
        self.write(config.P.sshd_config_d + "/50-cloud.conf", "PasswordAuthentication no\n")
        self.assertEqual(advisor.check_ssh()[0]["level"], "ok")

    def test_ssh_password_only_is_a_note(self):
        self.write(config.P.sshd_config, "PasswordAuthentication yes\nPermitRootLogin prohibit-password\n")
        self.assertEqual(advisor.check_ssh()[0]["level"], "info")

    def test_no_ssh_settings_means_nothing_to_say(self):
        self.assertEqual(advisor.check_ssh(), [])

    def test_operating_system_updates_ubuntu(self):
        self.write(config.P.at("/etc/debian_version"), "12\n")
        self.assertEqual(advisor.check_os_updates()[0]["level"], "warn")
        self.write(config.P.at("/etc/apt/apt.conf.d/20auto-upgrades"), 'APT::Periodic::Unattended-Upgrade "1";\n')
        self.assertEqual(advisor.check_os_updates()[0]["level"], "ok")

    def test_operating_system_updates_almalinux(self):
        self.fake.table.append((["systemctl", "is-active", "dnf-automatic.timer"], (0, "active\n")))
        self.assertEqual(advisor.check_os_updates()[0]["level"], "ok")

    def test_database_open_to_the_world_is_flagged_but_localhost_is_not(self):
        out = ("LISTEN 0 80 127.0.0.1:3306 0.0.0.0:*\n"
               "LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*\n"
               "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
        self.fake.table.append((["ss"], (0, out)))
        f = advisor.check_open_services()[0]
        self.assertEqual(f["level"], "bad")
        self.assertIn("Redis", f["detail"])
        self.assertNotIn("MySQL", f["detail"])

    def test_lock_missing_offers_the_fix(self):
        self.fake.table.append((["nft", "list", "table"], (1, "no such table")))
        f = advisor.check_lock()[0]
        self.assertEqual((f["level"], f["fix"]["id"]), ("bad", "reapply_lock"))

    def test_single_trusted_address_is_noted(self):
        self.fake.table.append((["nft", "list", "table"], (0, "drop")))
        access.write_list(config.P.admin_list, [("203.0.113.9", "Home")], access.ADMIN_HEADER)
        self.assertEqual(ids(advisor.check_lock()), ["lock", "lock_single"])

    def test_closed_panel_port_in_firewalld_offers_the_fix(self):
        settings.save({"domain": "panel.example.com", "port": 8443})
        self.fake.table += [(["systemctl", "is-active", "firewalld"], (0, "active\n")),
                            (["firewall-cmd", "--list-ports"], (0, "8090/tcp 25/tcp\n"))]
        f = by_id(advisor.check_general_firewall(), "panel_port_closed")
        self.assertEqual(f["fix"]["id"], "open_panel_port")
        self.fake.table[-1] = (["firewall-cmd", "--list-ports"], (0, "8090/tcp 8443/tcp\n"))
        self.assertNotIn("panel_port_closed", ids(advisor.check_general_firewall()))

    def test_no_firewall_at_all_is_a_note(self):
        self.assertEqual(advisor.check_general_firewall()[0]["level"], "info")


class Cloudflare(Quiet):
    def setUp(self):
        super().setUp()
        os.makedirs(config.P.home_dir + "/shop.example.com/public_html")
        os.makedirs(config.P.home_dir + "/plain.example.com/public_html")
        self.resolver = lambda d: ["104.21.5.5"] if d.startswith("shop") else ["203.0.113.50"]

    def test_proxied_sites_without_the_protection_get_a_warning_and_a_fix(self):
        f = advisor.check_cloudflare(self.resolver)[0]
        self.assertEqual((f["level"], f["fix"]["id"]), ("warn", "add_cloudflare"))
        self.assertIn("shop.example.com", f["detail"])
        self.assertNotIn("plain.example.com", f["detail"])

    def test_the_fix_adds_every_range_and_then_all_is_well(self):
        self.fake.table.append((["fail2ban-client", "-t"], (0, "OK")))
        self.assertTrue(advisor.apply_fix("add_cloudflare").ok)
        listed = [a for a, _ in access.read_list(config.P.never_list)]
        for r in netinfo.CLOUDFLARE:
            self.assertIn(r, listed)
        self.assertEqual(advisor.check_cloudflare(self.resolver)[0]["level"], "ok")
        self.assertFalse(advisor.apply_fix("add_cloudflare").ok, "second time: already there")

    def test_no_proxied_sites_means_no_finding(self):
        self.assertEqual(advisor.check_cloudflare(lambda d: ["203.0.113.50"]), [])

    def test_a_name_that_does_not_resolve_is_ignored(self):
        self.assertEqual(advisor.check_cloudflare(lambda d: []), [])


class PanelAndWordPress(Quiet):
    def test_open_login_page_without_a_second_step_is_a_warning(self):
        settings.save({"domain": "panel.example.com", "port": 8443, "access": "login"})
        settings.save_user({"name": "owner", "password_hash": "x"})
        self.assertEqual(advisor.check_panel_access()[0]["level"], "warn")
        settings.save_user({"name": "owner", "password_hash": "x", "totp_enabled": True})
        self.assertEqual(advisor.check_panel_access()[0]["level"], "info")
        settings.save({"access": "trusted"})
        self.assertEqual(advisor.check_panel_access()[0]["level"], "ok")

    def test_nothing_to_say_before_the_panel_is_set_up(self):
        self.assertEqual(advisor.check_panel_access(), [])
        self.assertEqual(advisor.check_certificate(), [])

    def test_certificate_states(self):
        settings.save({"domain": "panel.example.com", "port": 8443})
        self.assertEqual(advisor.check_certificate()[0]["level"], "warn")
        live = config.P.letsencrypt_live + "/panel.example.com"
        self.write(live + "/fullchain.pem", "x")
        self.write(live + "/privkey.pem", "x")
        utc_now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        end = lambda days: (utc_now + datetime.timedelta(days=days, hours=1)).strftime(
            "notAfter=%b %d %H:%M:%S %Y GMT\n")
        for days, level in ((60, "ok"), (7, "warn"), (-3, "bad")):
            self.fake.table = [(["openssl"], (0, end(days)))]
            self.assertEqual(advisor.check_certificate()[0]["level"], level, days)

    def test_wordpress_updates_states(self):
        self.assertEqual(advisor.check_wordpress_updates()[0]["level"], "info")
        util.write_json(config.P.updates_cache, {"status": "done", "finished": "2026-10-19 10:00:00", "sites": [
            {"site": "a.example.com", "checked": True, "items": [{"what": "X"}, {"what": "Y"}]},
            {"site": "b.example.com", "checked": True, "items": []}]})
        f = advisor.check_wordpress_updates()[0]
        self.assertEqual(f["level"], "warn")
        self.assertIn("2 updates", f["title"])
        util.write_json(config.P.updates_cache, {"status": "done", "finished": "2026-10-19", "sites": []})
        self.assertEqual(advisor.check_wordpress_updates()[0]["level"], "ok")


class Whole(Quiet):
    def test_a_broken_check_never_hides_the_others(self):
        def broken():
            raise RuntimeError("boom")
        broken.__name__ = "check_broken"
        original = advisor.CHECKS
        advisor.CHECKS = (broken, advisor.check_ssh)
        self.addCleanup(lambda: setattr(advisor, "CHECKS", original))
        self.write(config.P.sshd_config, "PasswordAuthentication no\n")
        report = advisor.run()
        self.assertEqual(sorted(ids(report["findings"])), ["check_broken", "ssh"])
        self.assertEqual(report["counts"]["ok"], 1)

    def test_worst_problems_come_first_and_counts_add_up(self):
        report = advisor.run()
        levels = [advisor.LEVEL_ORDER[f["level"]] for f in report["findings"]]
        self.assertEqual(levels, sorted(levels))
        self.assertEqual(sum(report["counts"].values()), len(report["findings"]))
        self.assertIn("web_server", report["server"])

    def test_unknown_fix_is_refused(self):
        self.assertEqual(advisor.apply_fix("rm -rf").code, "unknown")
