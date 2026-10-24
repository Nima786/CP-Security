import os

from cpsec import config, feed
from tests.helpers import EnvTestCase

FAILED = '203.0.113.9 - - [19/Oct/2026:03:07:47 +0100] "POST /wp-login.php HTTP/1.1" 200 4567 "-" "Mozilla/5.0"\n'
GOOD = '45.60.0.10 - - [19/Oct/2026:03:08:00 +0100] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0"\n'
PAGE_VIEW = '203.0.113.9 - - [19/Oct/2026:03:08:01 +0100] "GET /wp-login.php HTTP/1.1" 200 4567 "-" "x"\n'
OTHER = '203.0.113.9 - - [19/Oct/2026:03:08:02 +0100] "POST /contact HTTP/1.1" 200 12 "-" "x"\n'
WITH_QUERY = '203.0.113.10 - - [19/Oct/2026:03:08:03 +0100] "POST /wp-login.php?redirect_to=x HTTP/1.1" 200 1 "-" "x"\n'
CLOUDFLARE = '104.16.5.5 - - [19/Oct/2026:03:08:04 +0100] "POST /wp-login.php HTTP/1.1" 200 1 "-" "x"\n'
GARBAGE = 'not-an-ip - - [19/Oct/2026:03:08:05 +0100] "POST /wp-login.php HTTP/1.1" 200 1 "-" "x"\n'


class Converting(EnvTestCase):
    def test_a_failed_login_becomes_one_tidy_line(self):
        out = feed.convert(FAILED, "shop.example.com", now=1792375667)
        self.assertRegex(out, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d WPLOGIN 203\.0\.113\.9 shop\.example\.com 200\n$")

    def test_everything_else_is_ignored(self):
        for line in (GOOD, PAGE_VIEW, OTHER, CLOUDFLARE, GARBAGE, "", "garbage line\n"):
            self.assertIsNone(feed.convert(line, "a.example.com"), line)

    def test_a_query_string_after_the_page_still_counts(self):
        self.assertIn("203.0.113.10", feed.convert(WITH_QUERY, "a.example.com"))

    def test_a_strange_folder_name_cannot_inject_text_into_the_file(self):
        out = feed.convert(FAILED, "a b\nWPLOGIN 1.2.3.4 x 200")
        self.assertEqual(out.count("\n"), 1)
        self.assertIn(" unknown ", out)

    def test_the_site_name_comes_from_the_folder(self):
        self.assertEqual(feed.domain_of("/home/shop.example.com/logs/shop.example.com.access_log"), "shop.example.com")
        self.assertEqual(feed.domain_of("/var/log/x.log"), "unknown")


class Following(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.log = config.P.home_dir + "/shop.example.com/logs/shop.example.com.access_log"
        self.write(self.log, "")
        self.follower = feed.Follower()

    def append(self, text):
        with open(self.log, "a", encoding="utf-8") as f:
            f.write(text)

    def test_old_history_is_not_replayed_when_the_helper_starts(self):
        self.write(self.log, FAILED * 50)
        follower = feed.Follower()
        self.assertEqual(follower.poll(), [])
        self.append(FAILED)
        self.assertEqual(len(follower.poll()), 1)

    def test_only_new_lines_are_read_each_time(self):
        self.follower.poll()
        self.append(FAILED + GOOD + OTHER)
        self.assertEqual(len(self.follower.poll()), 1)
        self.assertEqual(self.follower.poll(), [])
        self.append(FAILED)
        self.assertEqual(len(self.follower.poll()), 1)

    def test_the_tidy_file_gets_the_lines(self):
        self.follower.poll()
        self.append(FAILED + FAILED)
        self.follower.poll()
        with open(config.P.wplogin_log, encoding="utf-8") as f:
            self.assertEqual(len(f.read().splitlines()), 2)

    def test_half_written_line_waits_for_its_end(self):
        self.follower.poll()
        self.append(FAILED[:40])
        self.assertEqual(self.follower.poll(), [])
        self.append(FAILED[40:])
        self.assertEqual(len(self.follower.poll()), 1)

    def test_a_rotated_log_is_read_from_its_start(self):
        self.follower.poll()
        self.append(FAILED * 3)
        self.follower.poll()
        os.remove(self.log)
        self.write(self.log, FAILED)
        self.assertEqual(len(self.follower.poll()), 1)

    def test_a_website_added_later_is_read_from_its_start(self):
        self.follower.poll()
        new = config.P.home_dir + "/new.example.com/logs/new.example.com.access_log"
        self.write(new, FAILED)
        out = self.follower.poll()
        self.assertEqual(len(out), 1)
        self.assertIn("new.example.com", out[0])

    def test_a_deleted_log_is_forgotten_without_errors(self):
        self.follower.poll()
        os.remove(self.log)
        self.assertEqual(self.follower.poll(), [])
        self.assertEqual(self.follower.state, {})


# Lines copied from the first real server: its LiteSpeed writes the request WITHOUT quotes and often with HTTP/2.
REAL = {
    "failed_200": "203.0.113.11 - - [09/Oct/2026:09:49:52 +0100] POST /wp-login.php HTTP/1.1 200 12210 - Mozilla/5.0\n",
    "failed_401": ("203.0.113.12 - - [16/Oct/2026:04:46:03 +0100] POST /wp-login.php HTTP/2 401 1469 "
                   "https://www.shop.example.com/wp-login.php Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\n"),
    "good_302": ("198.51.100.7 - - [17/Oct/2026:11:04:26 +0100] POST /wp-login.php HTTP/2 302 0 "
                 "https://x.example.com/wp-login.php?redirect_to=https%3A%2F%2Fx.example.com%2Fwp-admin%2F&reauth=1 Mozilla/5.0\n"),
    "admin_email": ("198.51.100.8 - - [17/Oct/2026:11:08:37 +0100] POST /wp-login.php?action=confirm_admin_email HTTP/2 302 0 "
                    "https://y.example.com/wp-login.php Mozilla/5.0\n"),
    "my_own_test": "127.0.0.1 - - [19/Oct/2026:08:46:15 +0100] POST /wp-login.php?cpsprobe=1 HTTP/2 200 12304 - curl/7.81.0\n",
}


class TheRealLogFormat(EnvTestCase):
    def test_failed_logins_are_copied_in_the_servers_own_format(self):
        for name in ("failed_200", "failed_401", "my_own_test"):
            out = feed.convert(REAL[name], "a.example.com")
            self.assertIsNotNone(out, name)
            self.assertIn("WPLOGIN", out)

    def test_good_logins_and_other_wordpress_posts_are_not_copied(self):
        for name in ("good_302", "admin_email"):
            self.assertIsNone(feed.convert(REAL[name], "a.example.com"), name)

    def test_the_whole_chain_works_on_a_file_in_that_format(self):
        log = config.P.home_dir + "/shop.example.com/logs/shop.example.com.access_log"
        self.write(log, "")
        follower = feed.Follower()
        follower.poll()
        with open(log, "a", encoding="utf-8") as f:
            f.write(REAL["failed_200"] + REAL["good_302"] + REAL["failed_401"])
        self.assertEqual(len(follower.poll()), 2)
        tidy = open(config.P.wplogin_log, encoding="utf-8").read().splitlines()
        self.assertEqual(len(tidy), 2)
        self.assertRegex(tidy[0], r"WPLOGIN 203\.0\.113\.11 shop\.example\.com 200$")

    def test_the_tidy_lines_match_the_blockers_filter(self):
        import re
        from cpsec import blocker
        regex = blocker.FILTER_WP_LOGIN.split("failregex = ")[1].split("\n")[0].replace("<HOST>", r"(?P<host>\S+)")
        line = feed.convert(REAL["failed_401"], "shop.example.com")
        match = re.search(regex.replace("\\\\", "\\"), line)
        self.assertTrue(match, line)
        self.assertEqual(match.group("host"), "203.0.113.12")


class TheOldAppLoginDoor(EnvTestCase):
    """Password guessing through xmlrpc.php: counted only where the website refuses that door."""

    REFUSED = "203.0.113.20 - - [24/Oct/2026:06:48:24 +0100] POST /xmlrpc.php HTTP/1.1 403 46 - Mozilla/5.0\n"

    def test_a_post_to_a_closed_door_is_counted_and_named(self):
        out = feed.convert(self.REFUSED, "shop.example.com")
        self.assertRegex(out, r"WPLOGIN 203\.0\.113\.20 shop\.example\.com/xmlrpc 403$")

    def test_a_doubled_slash_and_a_query_still_count(self):
        for line in (self.REFUSED.replace("POST /xmlrpc.php", "POST //xmlrpc.php"),
                     self.REFUSED.replace("POST /xmlrpc.php", "POST /xmlrpc.php?rsd")):
            self.assertIsNotNone(feed.convert(line, "shop.example.com"), line)

    def test_an_open_door_is_never_counted(self):
        # where the door is open, a wrong and a right password both answer 200: nobody may be banned for using it
        for code in ("200", "302", "405", "500"):
            self.assertIsNone(feed.convert(self.REFUSED.replace(" 403 ", " %s " % code), "shop.example.com"), code)

    def test_reading_the_door_is_not_counted(self):
        self.assertIsNone(feed.convert(self.REFUSED.replace("POST", "GET"), "shop.example.com"))

    def test_cloudflare_is_never_counted(self):
        self.assertIsNone(feed.convert(self.REFUSED.replace("203.0.113.20", "104.16.0.1"), "shop.example.com"))

    def test_the_line_still_matches_the_blockers_filter(self):
        import re
        from cpsec import blocker
        regex = blocker.FILTER_WP_LOGIN.split("failregex = ")[1].split("\n")[0].replace("<HOST>", r"(?P<host>\S+)")
        match = re.search(regex.replace("\\\\", "\\"), feed.convert(self.REFUSED, "shop.example.com"))
        self.assertTrue(match)
        self.assertEqual(match.group("host"), "203.0.113.20")
