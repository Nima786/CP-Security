import datetime

from cpsec import blocker, config
from tests.helpers import EnvTestCase

WITH_TIME = ("1.2.3.4 \t2026-10-19 10:00:00 + 3600 = 2026-10-19 11:00:00\n"
             "5.6.7.8 \t2026-10-19 09:00:00 + -1 = 2026-10-19 09:00:00\n")


class Jails(EnvTestCase):
    def test_jail_list_is_parsed(self):
        self.fake.table.append((("fail2ban-client", "status"),
                                (0, "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, cps-wp-login\n")))
        self.assertEqual(blocker.jails(), ["sshd", "cps-wp-login"])

    def test_not_running_gives_none(self):
        self.fake.table.append((("fail2ban-client", "status"), (255, "Failed to access socket path")))
        self.assertIsNone(blocker.jails())
        self.assertIsNone(blocker.all_blocked())


class BlockedList(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.fake.table += [
            (("fail2ban-client", "status"), (0, "`- Jail list:\tsshd")),
            (("fail2ban-client", "get", "sshd", "banip", "--with-time"), (0, WITH_TIME)),
        ]

    def test_rows_carry_reason_and_end_time(self):
        rows = blocker.all_blocked()
        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(by_ip["1.2.3.4"]["why"], "Server login (SSH) guessing")
        self.assertEqual(by_ip["1.2.3.4"]["until"], "2026-10-19 11:00:00")
        self.assertEqual(by_ip["5.6.7.8"]["until"], "never")
        self.assertIsNone(by_ip["5.6.7.8"]["seconds_left"])
        self.assertEqual(rows[-1]["ip"], "5.6.7.8", "permanent blocks are listed last")

    def test_older_blocker_without_end_times_still_lists_addresses(self):
        self.fake.table.insert(0, (("fail2ban-client", "get", "sshd", "banip", "--with-time"), (1, "error")))
        self.fake.table.insert(1, (("fail2ban-client", "status", "sshd"), (0, "`- Banned IP list:\t9.9.9.9 8.8.8.8")))
        self.assertEqual(sorted(r["ip"] for r in blocker.all_blocked()), ["8.8.8.8", "9.9.9.9"])


class LettingPeopleBackIn(EnvTestCase):
    def test_unban_reports_whether_anything_changed(self):
        self.fake.table.append((("fail2ban-client", "unban", "1.2.3.4"), (0, "1")))
        self.fake.table.append((("fail2ban-client", "unban", "5.6.7.8"), (0, "0")))
        self.assertTrue(blocker.unban("1.2.3.4").ok)
        r = blocker.unban("5.6.7.8")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "not_blocked")

    def test_unban_never_passes_garbage_to_the_command(self):
        r = blocker.unban("1.2.3.4; rm -rf /")
        self.assertEqual(r.code, "invalid")
        self.assertEqual(self.fake.called("fail2ban-client", "unban"), [])


class Phrases(EnvTestCase):
    def test_nice_until(self):
        now = datetime.datetime.now()
        fmt = "%Y-%m-%d %H:%M:%S"
        self.assertEqual(blocker.nice_until("never"), "never (permanent)")
        self.assertEqual(blocker.nice_until(""), "")
        self.assertEqual(blocker.nice_until((now - datetime.timedelta(minutes=1)).strftime(fmt)), "any moment now")
        self.assertTrue(blocker.nice_until((now + datetime.timedelta(minutes=31)).strftime(fmt)).endswith("min"))
        self.assertTrue(blocker.nice_until((now + datetime.timedelta(hours=5, minutes=1)).strftime(fmt)).endswith("hours"))


class Log(EnvTestCase):
    def test_ban_events_and_summary(self):
        now = datetime.datetime.now()
        recent = now.strftime("%Y-%m-%d %H:%M:%S")
        old = (now - datetime.timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        line = "{ts},123 fail2ban.actions        [999]: NOTICE  [{jail}] Ban {ip}\n"
        self.write(config.P.f2b_log,
                   line.format(ts=recent, jail="sshd", ip="1.1.1.1") +
                   line.format(ts=recent, jail="cps-wp-login", ip="2.2.2.2") +
                   line.format(ts=old, jail="sshd", ip="1.1.1.1") +
                   "garbage line\n")
        s = blocker.recent_summary()
        self.assertEqual(s["day"]["blocks"], 2)
        self.assertEqual(s["week"]["blocks"], 3)
        self.assertEqual(s["week"]["addresses"], 2)
        self.assertEqual(s["top_addresses"][0], {"ip": "1.1.1.1", "times": 2})

    def test_recent_errors_only_counts_fresh_ones(self):
        today = datetime.date.today().isoformat()
        self.write(config.P.f2b_log, "2020-01-01 00:00:00,1 fail2ban [1]: ERROR Unhandled exception in thread\n")
        self.assertFalse(blocker.recent_errors())
        self.write(config.P.f2b_log, today + " 00:00:00,1 fail2ban [1]: ERROR Unhandled exception in thread\n")
        self.assertTrue(blocker.recent_errors())
