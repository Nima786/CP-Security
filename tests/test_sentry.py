"""The daily watch: finding break-in signs, the baseline-then-alert logic, and the Telegram settings."""
import time
import unittest

from cpsec import config, sentry, settings, util
from tests.helpers import EnvTestCase

TOKEN = "123456789:AA" + "x" * 32


class Settings(EnvTestCase):
    def test_a_token_is_recognised_by_its_shape(self):
        self.assertTrue(sentry.valid_token(TOKEN))
        for bad in ("", "nope", "123:short", "abc:" + "x" * 40):
            self.assertFalse(sentry.valid_token(bad), bad)

    def test_chat_ids_are_cleaned_from_whatever_was_typed(self):
        self.assertEqual(sentry.clean_chats("123, -1001  456\n@mychannel"), ["123", "-1001", "456", "@mychannel"])
        self.assertEqual(sentry.clean_chats(["123", "123", "bad id", "@ab"]), ["123"])
        self.assertEqual(sentry.clean_chats(""), [])

    def test_saving_needs_a_token_and_a_chat_only_when_turned_on(self):
        self.assertTrue(sentry.save_config("", "", False).ok)             # off: anything goes, even blank
        self.assertEqual(sentry.save_config("nope", "123", True).code, "token")
        self.assertEqual(sentry.save_config(TOKEN, "", True).code, "chats")
        res = sentry.save_config(TOKEN, "123\n456", True)
        self.assertTrue(res.ok, res.message)
        s = settings.load()
        self.assertEqual((s["telegram_token"], s["telegram_chats"], s["watch_enabled"]), (TOKEN, ["123", "456"], True))
        self.assertTrue(sentry.config_ok())

    def test_config_ok_needs_both_a_valid_token_and_a_chat(self):
        sentry.save_config(TOKEN, "123", False)
        self.assertTrue(sentry.config_ok())
        sentry.save_config("", "", False)
        self.assertFalse(sentry.config_ok())


class Telegram(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.sent = []
        self.ok = True
        self.err = ""

        def fake_post(url, fields):
            self.sent.append((url, fields))
            return self.ok, self.err
        self.patch("cpsec.sentry._post", side_effect=fake_post)
        sentry.save_config(TOKEN, "111\n222", True)

    def test_a_test_message_goes_to_every_chat(self):
        res = sentry.test_message()
        self.assertTrue(res.ok, res.message)
        self.assertEqual([f["chat_id"] for _u, f in self.sent], ["111", "222"])
        self.assertIn("bot%s/sendMessage" % TOKEN, self.sent[0][0])

    def test_a_bad_chat_is_reported_with_a_hint(self):
        self.ok, self.err = False, "Bad Request: chat not found"
        res = sentry.test_message()
        self.assertFalse(res.ok)
        self.assertIn("send it any message first", res.message)

    def test_a_test_before_it_is_set_up_is_refused_without_calling_telegram(self):
        self.assertEqual(sentry.test_message(token="nope", chats="111").code, "token")
        self.assertEqual(sentry.test_message(token=TOKEN, chats="").code, "chats")
        self.assertEqual(self.sent, [])


class FakeWebsite:
    def __init__(self):
        self.core = "Success: WordPress verifies against checksums.\n"
        self.grep_hits = ""        # grep output (file paths), before the ---UPLOADS--- line
        self.upload_hits = ""      # find output (file paths), after it

    def wp(self, site, php, args, timeout=300):
        return (0, self.core) if "verify-checksums" in args else (0, "")

    def run_shell(self, user, script, timeout):
        return 0, self.grep_hits + "\n---UPLOADS---\n" + self.upload_hits


class Scanning(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.web = FakeWebsite()
        self.patch("cpsec.wpupdate._site", return_value={"docroot": "/home/s/public_html", "user": "s", "home": "/home/s"})
        self.patch("cpsec.wpupdate._php", return_value="/php")
        self.patch("cpsec.wpupdate._wp", side_effect=self.web.wp)
        self.patch("cpsec.wpupdate._shell", side_effect=self.web.run_shell)

    def test_changed_core_files_are_found(self):
        self.web.core = ("Warning: File doesn't verify against checksum: wp-admin/a.php\n"
                         "Warning: File is not in the original distribution: wp-includes/evil.php\n"
                         "Error: WordPress doesn't verify.\n")
        found = sentry._scan_site("shop.example.com")
        self.assertIn("core:wp-admin/a.php", found)
        self.assertIn("core:wp-includes/evil.php", found)

    def test_web_shells_and_php_in_uploads_are_found_but_placeholders_are_not(self):
        self.web.grep_hits = "wp-content/mu-plugins/cache.php\nwp-content/uploads/2026/x.php"
        self.web.upload_hits = "wp-content/uploads/2026/x.php\nwp-content/uploads/index.php"
        found = sentry._scan_site("shop.example.com")
        self.assertIn("shell:wp-content/mu-plugins/cache.php", found)
        self.assertIn("upload-php:wp-content/uploads/2026/x.php", found)
        self.assertNotIn("upload-php:wp-content/uploads/index.php", found, "the empty placeholder is ignored")

    def test_a_clean_website_has_no_findings(self):
        self.assertEqual(sentry._scan_site("shop.example.com"), set())

    def test_a_website_that_will_not_start_returns_none(self):
        self.patch("cpsec.wpupdate._php", return_value=None)
        self.assertIsNone(sentry._scan_site("shop.example.com"))

    def test_the_grep_cannot_be_tricked_by_folder_names(self):
        seen = {}

        def capture(user, script, timeout):
            seen["script"] = script
            return 0, "\n---UPLOADS---\n"
        self.patch("cpsec.wpupdate._shell", side_effect=capture)
        sentry._scan_site("shop.example.com")
        self.assertIn("set -f", seen["script"])                       # globbing off, so *.php stays literal
        self.assertIn("--exclude-dir=cps-backups", seen["script"])


class TheDailyRun(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.updates._wordpress_sites", return_value=[("/home/a/public_html", "a", "a.example.com"),
                                                                   ("/home/b/public_html", "b", "b.example.com")])
        self.findings = {"a.example.com": set(), "b.example.com": set()}
        self.patch("cpsec.sentry._scan_site", side_effect=lambda n: set(self.findings[n]))
        self.alerts = []
        self.patch("cpsec.sentry.send", side_effect=lambda text, **k: self.alerts.append(text) or [{"chat": "1", "ok": True, "error": ""}])
        sentry.save_config(TOKEN, "111", True)
        self.reset()
        self.addCleanup(self.reset)

    def reset(self):
        with sentry._lock:
            sentry._scan.update(status="idle", finished="", sites={})

    def test_the_first_look_learns_the_baseline_and_says_nothing(self):
        self.findings["a.example.com"] = {"upload-php:wp-content/uploads/old.php"}
        summary = sentry.run()
        self.assertTrue(summary["first_ever"])
        self.assertEqual(self.alerts, [], "the first run never alerts, even with findings")
        self.assertTrue(util.read_json(config.P.sentry_state, {}).get("baseline_done"))

    def test_a_new_finding_after_the_baseline_sends_one_alert(self):
        sentry.run()                                                   # baseline (clean)
        self.findings["b.example.com"] = {"shell:wp-content/uploads/shell.php"}
        summary = sentry.run()
        self.assertFalse(summary["first_ever"])
        self.assertEqual(summary["new"], {"b.example.com": ["shell:wp-content/uploads/shell.php"]})
        self.assertEqual(len(self.alerts), 1)
        self.assertIn("b.example.com", self.alerts[0])
        self.assertIn("back door", self.alerts[0])

    def test_the_same_finding_is_not_alerted_twice(self):
        self.findings["a.example.com"] = {"core:wp-admin/x.php"}
        sentry.run()                                                   # baseline already has it? no: first run baselines it
        sentry.run()                                                   # now it is in the baseline
        self.findings["a.example.com"].add("core:wp-admin/x.php")      # still there
        sentry.run()
        self.assertEqual(self.alerts, [], "a finding that was already there is not alerted again")

    def test_a_finding_that_goes_away_and_comes_back_alerts_again(self):
        sentry.run()                                                   # baseline clean
        self.findings["a.example.com"] = {"core:wp-admin/x.php"}
        sentry.run()                                                   # new -> alert
        self.findings["a.example.com"] = set()
        sentry.run()                                                   # gone
        self.findings["a.example.com"] = {"core:wp-admin/x.php"}
        sentry.run()                                                   # back -> alert again
        self.assertEqual(len(self.alerts), 2)

    def test_no_alert_is_sent_when_it_is_not_set_up(self):
        sentry.save_config("", "", False)
        sentry.run()
        self.findings["a.example.com"] = {"shell:x"}
        sentry.run()
        self.assertEqual(self.alerts, [], "nothing is sent when Telegram is not configured")

    def test_due_waits_a_day_between_runs(self):
        self.assertTrue(sentry.due())                                  # never run yet
        sentry.run()
        self.assertFalse(sentry.due())
        state = util.read_json(config.P.sentry_state, {})
        state["last_run_epoch"] = int(time.time()) - sentry.RUN_EVERY - 10
        util.write_json(config.P.sentry_state, state)
        self.assertTrue(sentry.due())

    def test_due_is_false_when_not_configured(self):
        sentry.save_config("", "", False)
        self.assertFalse(sentry.due())

    def test_the_page_summary_lists_websites_worst_first(self):
        self.findings = {"a.example.com": {"shell:x", "core:y"}, "b.example.com": {"upload-php:z"}}
        sentry.run()
        data = sentry.state()
        self.assertTrue(data["configured"])
        self.assertEqual(data["sites"][0]["site"], "a.example.com")
        self.assertEqual(data["sites"][0]["count"], 2)
        self.assertEqual(data["total"], 3)
        self.assertTrue(data["last_run"])


if __name__ == "__main__":
    unittest.main()
