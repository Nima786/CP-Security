"""No PHP in the uploads folder: the rule text, switching it on with a real test, and taking it off again."""
import json
import re
import threading
import time
import unittest
from unittest import mock

from cpsec import config, phpguard, wpupdate
from tests.helpers import EnvTestCase

DOMAIN = "shop.example.com"
OTHER = "blog.example.com"
THEIR_LINES = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n"


class RuleText(unittest.TestCase):
    def test_the_rule_goes_first_and_the_websites_own_lines_are_kept(self):
        new = phpguard.with_block(THEIR_LINES)
        self.assertTrue(new.startswith(phpguard.RULE))
        self.assertTrue(new.endswith(THEIR_LINES))
        self.assertEqual(new, phpguard.RULE + "\n" + THEIR_LINES)

    def test_taking_it_out_gives_back_exactly_what_was_there(self):
        for original in ("", THEIR_LINES, "Options -Indexes\n", "# one line, no newline at the end"):
            self.assertEqual(phpguard.without_block(phpguard.with_block(original)), original, repr(original))

    def test_putting_it_in_twice_changes_nothing(self):
        once = phpguard.with_block(THEIR_LINES)
        self.assertEqual(phpguard.with_block(once), once)

    def test_an_empty_file_becomes_only_the_rule(self):
        self.assertEqual(phpguard.with_block(""), phpguard.RULE)
        self.assertEqual(phpguard.without_block(phpguard.RULE).strip(), "")

    def test_a_damaged_block_is_refused_not_guessed(self):
        for bad in (phpguard.BEGIN + "\nx\n", phpguard.END + "\n", phpguard.RULE + phpguard.RULE, phpguard.END + "\n" + phpguard.BEGIN + "\n"):
            with self.assertRaises(ValueError):
                phpguard.split_block(bad)

    def test_the_rule_refuses_every_spelling_of_a_php_file(self):
        pattern = re.search(r'<FilesMatch "\(\?i\)(.*)">', phpguard.RULE).group(1)
        rx = re.compile(pattern, re.I)                       # the rule itself starts with (?i): any capital letters
        for name in ("shell.php", "SHELL.PHP", "a.php5", "a.php7", "a.phtml", "a.phar", "a.pht", "a.phps", "a.shtml", "a.shtm", "photo.jpg.php", "x.PhP"):
            self.assertTrue(rx.search(name), name)
        for name in ("photo.jpg", "doc.pdf", "archive.zip", "notes.php.txt", "style.css", "script.js", "a.phpx", "phpinfo"):
            self.assertFalse(rx.search(name), name)

    def test_the_rule_uses_the_form_the_web_server_was_seen_to_obey(self):
        self.assertIn("Require all denied", phpguard.RULE)
        self.assertEqual(phpguard.RULE.count(phpguard.BEGIN), 1)
        self.assertEqual(phpguard.RULE.count(phpguard.END), 1)


class FakeUploads:
    """A website's uploads folder and web address, behaving like LiteSpeed: a changed settings file is noticed after a few answers."""

    def __init__(self, case):
        self.case = case
        self.docroot = case.docroot
        self.dir = case.docroot + "/wp-content/uploads"
        self.rel = "/wp-content/uploads"
        self.reported_dir = self.dir
        self.htaccess = self.dir + "/.htaccess"
        self.files = {}                          # path -> text
        self.is_link = False
        self.ignores_rules = False               # the web server never applies the settings file
        self.delay = 2                           # answers that still show the old behaviour after a change
        self.already_refused = False             # something else already refuses PHP there
        self.breaks_with_rule = False            # the home page fails once the rule is in
        self.images_break = False                # pictures stop loading once the rule is in
        self.image = self.dir + "/2026/10/photo.jpg"
        self.no_write_test = False
        self.test_url_code = None                # force an odd answer for the test file's address
        self.home_code = "200"
        self.wp_fails = False
        self.polls = 0
        self.inputs = []
        self.gets = []

    def rule_in_effect(self):
        text = self.files.get(self.htaccess, "")
        return phpguard.BEGIN in text and not self.ignores_rules and self.polls > self.delay

    def su(self, cmd):
        script = cmd[5]
        if "core version" in script:
            return 0, "6.5.2\n"
        if "wp_get_upload_dir" in script:
            if self.wp_fails:
                return 1, "Error: could not load WordPress"
            return 0, "Warning: a noisy plugin\n" + json.dumps({"dir": self.reported_dir}) + "\n"
        if "__LINK__" in script:
            if self.is_link:
                return 0, "__LINK__\n"
            return (0, "__FILE__\n" + self.files[self.htaccess]) if self.htaccess in self.files else (0, "__NONE__\n")
        if script.startswith("find "):
            return 0, (self.image + "\n") if self.image else ""
        if script.startswith("rm -f --"):
            for path in list(self.files):
                if path in script:
                    del self.files[path]
        return 0, ""

    def write_input(self, cmd, data, timeout=60):
        self.inputs.append((list(cmd), data))
        script = cmd[5]
        text = data.decode("utf-8")
        if "cps-selftest-" in script and "mv -f" not in script:           # the harmless test file
            if self.no_write_test:
                return 1, "Disk quota exceeded"
            self.files[re.search(r"(\S*cps-selftest-[0-9a-f]+\.php)", script.replace("'", " ")).group(1)] = text
            return 0, ""
        if "mv -f" in script:                                             # the settings file
            if self.write_fails:
                return 1, "Permission denied"
            self.files[self.htaccess] = text
            self.polls = 0
            return 0, ""
        return 1, "unexpected"

    write_fails = False

    def curl(self, cmd):
        rc, out = self._curl(cmd)
        if "-o" in cmd and cmd[cmd.index("-o") + 1] == "/dev/null":
            return rc, out.rsplit("\n", 1)[-1]
        return rc, out

    def _curl(self, cmd):
        path = cmd[-1].split(DOMAIN, 1)[1]
        if "cps-selftest-" in path:
            self.gets.append(path)
            tests = [p for p in self.files if p.endswith(path.split("/")[-1])]
            if not tests:
                return 0, "not found\n404"
            self.polls += 1
            if self.test_url_code:
                return 0, "odd\n" + self.test_url_code
            if self.already_refused or self.rule_in_effect():
                return 0, "<h1>403 Forbidden</h1>\n403"
            return 0, "CPS-RAN-%s\n200" % re.search(r"cps-selftest-([0-9a-f]+)", path).group(1)
        if path.startswith(self.rel + "/2026/"):
            return 0, ("gone\n404" if self.images_break and self.rule_in_effect() else "JPEG\n200")
        if path == "/wp-login.php":
            return 0, "login\n200"
        broken = self.breaks_with_rule and self.rule_in_effect()
        return 0, "<html>home</html>\n" + ("500" if broken else self.home_code)


class GuardCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.docroot = "/home/%s/public_html" % DOMAIN                  # a made-up server path: nothing is created on this computer
        self.write(config.P.lsws_root + "/lsphp81/bin/php", "")
        self.site = FakeUploads(self)
        self.fake.table += [(["su"], self.site.su), (["curl"], self.site.curl)]
        self.patch("cpsec.util.run_with_input", side_effect=self.site.write_input)
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", DOMAIN)])
        self.patch("cpsec.phpguard._sleep")
        wpupdate._php_cache.clear()
        self.reset()
        self.addCleanup(self.reset)

    def reset(self):
        with phpguard._lock:
            phpguard._scan.update(status="idle", finished="", sites={})
            phpguard._job.update(status="idle", action="", items=[], started="", finished="")

    def wait(self, state):
        for _ in range(300):
            if state()["status"] != "running":
                return
            time.sleep(0.02)
        self.fail("it did not finish")

    def no_test_file_left(self):
        return [p for p in self.site.files if "cps-selftest-" in p] == []


class SwitchingItOn(GuardCase):
    def test_a_good_switch_on_adds_the_rule_after_proving_it_works(self):
        res = phpguard.enable_one(DOMAIN, progress=lambda text: None)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.site.files[self.site.htaccess], phpguard.RULE)
        self.assertTrue(self.no_test_file_left())
        self.assertGreater(len(self.site.gets), 3, "the test asks again until the web server has noticed the change")

    def test_the_test_file_runs_before_and_is_refused_after(self):
        seen = []
        original = self.site.curl

        def watch(cmd):
            rc, out = original(cmd)
            if "cps-selftest-" in cmd[-1]:
                seen.append(out.rsplit("\n", 1)[-1])
            return rc, out
        self.fake.table.insert(0, (["curl"], watch))
        phpguard.enable_one(DOMAIN)
        self.assertEqual(seen[0], "200")
        self.assertEqual(seen[-1], "403")

    def test_the_websites_own_lines_in_the_file_are_kept(self):
        self.site.files[self.site.htaccess] = THEIR_LINES
        res = phpguard.enable_one(DOMAIN)
        self.assertTrue(res.ok, res.message)
        text = self.site.files[self.site.htaccess]
        self.assertTrue(text.endswith(THEIR_LINES))
        self.assertIn(phpguard.RULE, text)

    def test_everything_is_done_as_the_websites_own_user(self):
        phpguard.enable_one(DOMAIN)
        for cmd, _data in self.site.inputs:
            self.assertEqual(cmd[:5], ["su", "-s", "/bin/bash", "shopuser", "-c"])
        sus = [c for c in self.fake.calls if c[:1] == ["su"]]
        self.assertTrue(sus)
        self.assertTrue(all(c[3] == "shopuser" for c in sus))

    def test_it_is_not_done_twice(self):
        self.site.files[self.site.htaccess] = phpguard.RULE
        writes = len(self.site.inputs)
        res = phpguard.enable_one(DOMAIN)
        self.assertTrue(res.ok)
        self.assertIn("already on", res.message)
        self.assertEqual(len(self.site.inputs), writes, "nothing was written, not even a test file")

    def test_a_web_server_that_ignores_the_file_gets_it_taken_out_again(self):
        self.site.ignores_rules = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "not_applied"))
        self.assertNotIn(self.site.htaccess, self.site.files, "there was no file before, so there is none now")
        self.assertTrue(self.no_test_file_left())

    def test_a_failed_switch_on_brings_back_the_old_file_exactly(self):
        self.site.files[self.site.htaccess] = THEIR_LINES
        self.site.ignores_rules = True
        res = phpguard.enable_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(self.site.files[self.site.htaccess], THEIR_LINES)

    def test_a_website_that_gets_worse_is_put_back(self):
        self.site.breaks_with_rule = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "regression"))
        self.assertIn("home page now answers 500", res.message)
        self.assertNotIn(self.site.htaccess, self.site.files)
        self.assertTrue(self.no_test_file_left())

    def test_pictures_that_stop_loading_get_the_rule_taken_out(self):
        self.site.images_break = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "regression"))
        self.assertIn("pictures", res.message)
        self.assertNotIn(self.site.htaccess, self.site.files)

    def test_a_website_without_any_picture_is_still_tested(self):
        self.site.image = ""
        self.assertTrue(phpguard.enable_one(DOMAIN).ok)

    def test_something_else_already_refusing_php_there_is_accepted(self):
        self.site.already_refused = True
        res = phpguard.enable_one(DOMAIN)
        self.assertTrue(res.ok, res.message)
        self.assertIn(phpguard.BEGIN, self.site.files[self.site.htaccess])

    def test_a_website_that_is_already_failing_is_not_touched(self):
        self.site.home_code = "503"
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "unhealthy"))
        self.assertEqual(self.site.inputs, [])

    def test_an_uploads_folder_outside_the_web_folder_needs_nothing(self):
        self.site.reported_dir = "/home/elsewhere/uploads"
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "unsupported"))
        self.assertEqual(self.site.inputs, [])

    def test_a_website_that_will_not_start_is_refused_before_anything_is_written(self):
        self.site.wp_fails = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "facts"))
        self.assertEqual(self.site.inputs, [])

    def test_a_link_in_place_of_the_settings_file_is_left_alone(self):
        self.site.is_link = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "unsafe"))
        self.assertEqual(self.site.inputs, [])

    def test_damaged_lines_of_ours_are_not_guessed_at(self):
        self.site.files[self.site.htaccess] = phpguard.BEGIN + "\nhalf\n"
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "damaged"))
        self.assertEqual(self.site.files[self.site.htaccess], phpguard.BEGIN + "\nhalf\n")
        self.assertEqual(self.site.inputs, [])

    def test_a_test_file_that_cannot_be_saved_changes_nothing(self):
        self.site.no_write_test = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertNotIn(self.site.htaccess, self.site.files)

    def test_an_odd_answer_for_the_test_file_means_no_proof_and_no_change(self):
        self.site.test_url_code = "404"
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "no_test"))
        self.assertNotIn(self.site.htaccess, self.site.files)
        self.assertTrue(self.no_test_file_left())

    def test_a_settings_file_that_cannot_be_written_is_reported(self):
        self.site.write_fails = True
        res = phpguard.enable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertTrue(self.no_test_file_left())

    def test_an_unknown_website_is_refused(self):
        self.assertEqual(phpguard.enable_one("nope.example.com").code, "not_found")


class SwitchingItOff(GuardCase):
    def test_removing_gives_back_the_websites_own_lines(self):
        self.site.files[self.site.htaccess] = phpguard.with_block(THEIR_LINES)
        res = phpguard.disable_one(DOMAIN)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.site.files[self.site.htaccess], THEIR_LINES)

    def test_a_file_that_held_only_our_lines_goes_away(self):
        self.site.files[self.site.htaccess] = phpguard.RULE
        self.assertTrue(phpguard.disable_one(DOMAIN).ok)
        self.assertNotIn(self.site.htaccess, self.site.files)

    def test_off_when_it_was_never_on_is_fine_and_changes_nothing(self):
        self.assertIn("already off", phpguard.disable_one(DOMAIN).message)
        self.site.files[self.site.htaccess] = THEIR_LINES
        self.assertIn("already off", phpguard.disable_one(DOMAIN).message)
        self.assertEqual(self.site.files[self.site.htaccess], THEIR_LINES)
        self.assertEqual(self.site.inputs, [])

    def test_a_link_or_damaged_lines_are_refused(self):
        self.site.is_link = True
        self.assertEqual(phpguard.disable_one(DOMAIN).code, "unsafe")
        self.site.is_link = False
        self.site.files[self.site.htaccess] = phpguard.BEGIN + "\n"
        self.assertEqual(phpguard.disable_one(DOMAIN).code, "damaged")

    def test_an_unknown_website_is_refused(self):
        self.assertEqual(phpguard.disable_one("nope.example.com").code, "not_found")

    def test_a_write_that_fails_is_reported(self):
        self.site.files[self.site.htaccess] = phpguard.with_block(THEIR_LINES)
        self.site.write_fails = True
        res = phpguard.disable_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))


class SeeingTheWebsites(GuardCase):
    def status(self):
        return phpguard._inspect(DOMAIN)["status"]

    def test_off_on_and_changed_are_told_apart(self):
        self.assertEqual(self.status(), "off")
        self.site.files[self.site.htaccess] = THEIR_LINES
        self.assertEqual(self.status(), "off")
        self.site.files[self.site.htaccess] = phpguard.with_block(THEIR_LINES)
        self.assertEqual(self.status(), "on")
        self.site.files[self.site.htaccess] = phpguard.RULE.replace("Require all denied", "Require all granted")
        self.assertEqual(self.status(), "changed")
        self.site.files[self.site.htaccess] = phpguard.BEGIN + "\n"
        info = phpguard._inspect(DOMAIN)
        self.assertEqual(info["status"], "changed")
        self.assertIn("damaged", info["problem"])

    def test_cases_that_cannot_be_used_say_why(self):
        self.site.reported_dir = "/elsewhere/uploads"
        info = phpguard._inspect(DOMAIN)
        self.assertEqual(info["status"], "unsupported")
        self.assertIn("web address", info["problem"])
        self.site.reported_dir = self.site.dir
        self.site.is_link = True
        self.assertEqual(self.status(), "unsupported")
        self.site.is_link = False
        self.site.wp_fails = True
        info = phpguard._inspect(DOMAIN)
        self.assertEqual((info["checked"], info["status"]), (False, "unknown"))

    def test_the_page_lists_every_website_after_a_look(self):
        phpguard.scan_start()
        self.wait(phpguard.scan_state)
        state = phpguard.state()
        self.assertEqual(state["scan"]["status"], "done")
        self.assertEqual([(s["site"], s["status"]) for s in state["sites"]], [(DOMAIN, "off")])

    def test_a_website_that_cannot_be_looked_at_does_not_hide_the_others(self):
        with mock.patch.object(phpguard, "_inspect", side_effect=RuntimeError("boom")):
            phpguard.scan_start()
            self.wait(phpguard.scan_state)
        row = phpguard.state()["sites"][0]
        self.assertEqual((row["checked"], row["status"]), (False, "unknown"))
        self.assertIn("failed", row["problem"])

    def test_two_looks_at_once_are_refused(self):
        gate, started = threading.Event(), threading.Event()

        def slow(name):
            started.set()
            gate.wait(5)
            return {"site": name, "checked": True, "status": "off", "problem": ""}

        with mock.patch.object(phpguard, "_inspect", side_effect=slow):
            self.assertTrue(phpguard.scan_start().ok)
            self.assertTrue(started.wait(5))
            self.assertEqual(phpguard.scan_start().code, "busy")
            gate.set()
            self.wait(phpguard.scan_state)

    def test_the_page_follows_a_switch_on_straight_away(self):
        phpguard.scan_start()
        self.wait(phpguard.scan_state)
        phpguard.enable_one(DOMAIN)
        self.assertEqual(phpguard.state()["sites"][0]["status"], "on")
        phpguard.disable_one(DOMAIN)
        self.assertEqual(phpguard.state()["sites"][0]["status"], "off")


class TheJob(GuardCase):
    def test_only_known_actions_and_websites_are_accepted(self):
        for action, names in (("explode", [DOMAIN]), ("enable", []), ("enable", None), ("enable", ["nope.example.com"]), ("enable", [DOMAIN, "nope.example.com"])):
            self.assertEqual(phpguard.start(action, names).code, "invalid", (action, names))
        self.assertEqual(phpguard.job_state()["status"], "idle")

    def test_a_job_switches_on_and_off_and_reports_each_website(self):
        self.assertTrue(phpguard.start("enable", [DOMAIN, DOMAIN]).ok)
        self.wait(phpguard.job_state)
        job = phpguard.job_state()
        self.assertEqual([(i["site"], i["status"]) for i in job["items"]], [(DOMAIN, "done")])
        self.assertEqual(job["counts"]["done"], 1)
        self.assertIn(phpguard.BEGIN, self.site.files[self.site.htaccess])
        self.assertTrue(phpguard.start("disable", [DOMAIN]).ok)
        self.wait(phpguard.job_state)
        self.assertNotIn(self.site.htaccess, self.site.files)

    def test_one_website_failing_does_not_stop_the_next(self):
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", DOMAIN), (self.docroot + "2", "bloguser", OTHER)])
        calls = []

        def fake(name, progress=None):
            calls.append(name)
            if name == DOMAIN:
                raise RuntimeError("boom")
            return phpguard.Result(True, "fine")

        with mock.patch.object(phpguard, "enable_one", side_effect=fake):
            phpguard.start("enable", [DOMAIN, OTHER])
            self.wait(phpguard.job_state)
        items = phpguard.job_state()["items"]
        self.assertEqual(calls, [DOMAIN, OTHER])
        self.assertEqual([i["status"] for i in items], ["failed", "done"])
        self.assertIn("Unexpected problem", items[0]["message"])

    def test_a_second_job_while_one_runs_is_refused(self):
        gate, started = threading.Event(), threading.Event()

        def slow(name, progress=None):
            started.set()
            gate.wait(5)
            return phpguard.Result(True, "fine")

        with mock.patch.object(phpguard, "enable_one", side_effect=slow):
            self.assertTrue(phpguard.start("enable", [DOMAIN]).ok)
            self.assertTrue(started.wait(5))
            self.assertEqual(phpguard.start("disable", [DOMAIN]).code, "busy")
            gate.set()
            self.wait(phpguard.job_state)

    def test_a_failure_is_shown_with_its_reason(self):
        self.site.ignores_rules = True
        phpguard.start("enable", [DOMAIN])
        self.wait(phpguard.job_state)
        item = phpguard.job_state()["items"][0]
        self.assertEqual(item["status"], "failed")
        self.assertIn("did not apply the rule", item["message"])


if __name__ == "__main__":
    unittest.main()
