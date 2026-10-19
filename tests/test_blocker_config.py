import os
import re

from cpsec import blocker, config, util
from tests.helpers import EnvTestCase


class WithLogs(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.write(config.P.at("/var/log/mail.log"), "")
        self.write(config.P.at("/var/log/syslog"), "")
        self.fake.table.append((["fail2ban-client", "-t"], (0, "OK: configuration test is successful")))


class Numbers(WithLogs):
    def test_defaults_when_nothing_was_changed(self):
        t = blocker.tuning()
        self.assertEqual(set(t), set(blocker.TUNABLE))
        self.assertEqual(t["sshd"], {"maxretry": 4, "findtime": 600, "bantime": 3600})
        self.assertEqual(t["cps-wp-login"]["maxretry"], 8, "the numbers the first production server ran with")
        self.assertEqual(t["cps-mail-auth"]["maxretry"], 6)

    def test_changed_numbers_replace_only_what_was_changed(self):
        self.assertTrue(blocker.set_tuning({"cps-wp-login": {"maxretry": 3}}).ok)
        t = blocker.tuning()["cps-wp-login"]
        self.assertEqual((t["maxretry"], t["findtime"], t["bantime"]), (3, 600, 3600))
        self.assertIn("maxretry = 3", util.read_text(config.P.f2b_jails))

    def test_silly_values_are_refused_and_nothing_is_written(self):
        for bad in ({"sshd": {"maxretry": 0}}, {"sshd": {"bantime": 5}}, {"sshd": {"maxretry": "5"}},
                    {"sshd": {"maxretry": True}}, {"nope": {"maxretry": 5}}, {"sshd": {"colour": 5}}):
            self.assertEqual(blocker.set_tuning(bad).code, "invalid", bad)
        self.assertFalse(os.path.exists(config.P.blocker_settings))
        self.assertFalse(os.path.exists(config.P.f2b_jails))

    def test_a_rejected_config_puts_the_old_numbers_back(self):
        blocker.set_tuning({"sshd": {"maxretry": 4}})
        before = util.read_text(config.P.f2b_jails)
        self.fake.table.insert(0, (["fail2ban-client", "-t"], (1, "ERROR bad jail")))
        r = blocker.set_tuning({"sshd": {"maxretry": 9}})
        self.assertEqual((r.ok, r.code), (False, "f2b_rejected"))
        self.assertEqual(util.read_text(config.P.f2b_jails), before)
        self.assertEqual(blocker.tuning()["sshd"]["maxretry"], 4)


class JailFile(WithLogs):
    def text(self):
        return blocker.render_jails()[0]

    def test_every_protection_with_a_log_is_listed(self):
        text = self.text()
        for name in ("sshd", "cps-wp-login", "cps-mail-auth", "dovecot", "pure-ftpd", "cps-panel"):
            self.assertIn("[%s]" % name, text)

    def test_a_protection_whose_log_is_missing_is_left_out_so_the_blocker_still_starts(self):
        os.remove(config.P.at("/var/log/mail.log"))
        text, skipped = blocker.render_jails()
        self.assertEqual(sorted(skipped), ["cps-mail-auth", "dovecot"])
        self.assertNotIn("[cps-mail-auth]", text)
        self.assertIn("[sshd]", text)

    def test_almalinux_log_names_are_found(self):
        os.remove(config.P.at("/var/log/mail.log"))
        os.remove(config.P.at("/var/log/syslog"))
        self.write(config.P.at("/var/log/maillog"), "")
        self.write(config.P.at("/var/log/messages"), "")
        self.assertEqual(blocker.log_for("dovecot"), config.P.at("/var/log/maillog"))
        self.assertEqual(blocker.log_for("pure-ftpd"), config.P.at("/var/log/messages"))

    def test_only_our_own_names_and_the_named_standard_ones_are_touched(self):
        names = re.findall(r"^\[([^\]]+)\]", self.text(), re.M)
        self.assertEqual(sorted(names), sorted(blocker.TUNABLE))

    def test_ban_actions_are_set_per_protection_not_for_everybody(self):
        text = self.text()
        self.assertNotIn("[DEFAULT]", text)
        self.assertEqual(text.count("banaction = nftables-multiport"), len(blocker.TUNABLE))


class WritingIt(WithLogs):
    def test_writes_filters_jails_and_creates_the_logs_the_blocker_needs(self):
        r = blocker.write_config()
        self.assertTrue(r.ok, r.message)
        for name in blocker.OWN_FILTERS:
            self.assertIn("[Definition]", util.read_text(config.P.f2b_filter_dir + "/%s.conf" % name))
        self.assertTrue(os.path.exists(config.P.wplogin_log))
        self.assertTrue(os.path.exists(config.P.panel_log))

    def test_a_running_blocker_is_reloaded_a_stopped_one_is_not(self):
        blocker.write_config()
        self.assertEqual(self.fake.called("fail2ban-client", "reload"), [])
        self.fake.table.insert(0, (("fail2ban-client", "status"), (0, "`- Jail list:\tsshd")))
        blocker.write_config()
        self.assertEqual(len(self.fake.called("fail2ban-client", "reload")), 1)

    def test_a_blocker_that_will_not_reload_gets_the_old_files_back(self):
        blocker.write_config()
        before = util.read_text(config.P.f2b_jails)
        self.fake.table.insert(0, (["fail2ban-client", "reload"], (1, "boom")))
        self.fake.table.insert(0, (("fail2ban-client", "status"), (0, "`- Jail list:\tsshd")))
        blocker.set_tuning({"sshd": {"maxretry": 9}})
        self.assertEqual(util.read_text(config.P.f2b_jails), before)

    def test_the_filters_use_the_log_format_the_helpers_write(self):
        # the WordPress filter must match exactly what the feed writes
        sample = "2026-10-19 03:07:47 WPLOGIN 203.0.113.9 shop.example.com 200"
        regex = blocker.FILTER_WP_LOGIN.split("failregex = ")[1].split("\n")[0].replace("<HOST>", r"(?P<host>\S+)")
        self.assertTrue(re.search(regex.replace("\\\\", "\\"), sample))
        sample = "2026-10-19 03:07:47 LOGIN_FAILED ip=203.0.113.9 user=admin"
        regex = blocker.FILTER_PANEL.split("failregex = ")[1].split("\n")[0].replace("<HOST>", r"(?P<host>\S+)")
        self.assertTrue(re.search(regex.replace("\\\\", "\\"), sample))

class LikeTheFirstServer(WithLogs):
    """Things that were proven on the first production server and must not be lost."""

    def test_repeat_offenders_are_blocked_longer_every_time(self):
        text = blocker.render_jails()[0]
        self.assertEqual(text.count("bantime.increment = true"), len(blocker.TUNABLE))
        self.assertIn("bantime.maxtime = 7d", text)

    def test_the_huge_shared_system_log_is_read_from_the_end(self):
        text = blocker.render_jails()[0]
        self.assertIn("logpath = %s tail" % config.P.at("/var/log/syslog"), text)
        self.assertNotIn("mail.log tail", text)

    def test_a_401_counts_as_a_failed_login_just_like_a_200(self):
        from cpsec import feed
        line = '203.0.113.9 - - [19/Oct/2026:03:07:47 +0100] "POST /wp-login.php HTTP/1.1" 401 10 "-" "x"\n'
        self.assertIn("WPLOGIN 203.0.113.9", feed.convert(line, "a.example.com"))
        self.assertIsNone(feed.convert(line.replace(" 401 ", " 302 "), "a.example.com"))
