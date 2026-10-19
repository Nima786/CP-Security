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
