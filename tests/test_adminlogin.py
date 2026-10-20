"""One-click login: the helper file, the signed links, putting the helper on a website and taking it off again."""
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from cpsec import adminlogin, config, wpupdate
from tests.helpers import EnvTestCase

DOMAIN = "shop.example.com"
OTHER = "blog.example.com"


def unpack(token):
    """(payload dict, signature) of a link's code, without checking anything."""
    body, _, sig = token.rpartition(".")
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))), sig


def sign(secret, payload):
    """A link code made by hand, so a test can send the website something the panel itself would never make."""
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    return body + "." + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


class FakeSite:
    """One WordPress website on a pretend server: its must-use folder, what WP-CLI says, and what its address answers.

    The website behaves the way the helper file should make it behave (that part is checked for real, with PHP,
    in TheHelperItself below): it only answers a link when the helper file is in its folder and carries the matching secret."""

    def __init__(self, case):
        self.case = case
        self.home_url = "https://" + DOMAIN
        self.mu = case.docroot + "/wp-content/mu-plugins"
        self.mu_reported = self.mu
        self.final = self.mu + "/" + adminlogin.HELPER_NAME
        self.new, self.old = self.final + ".new", self.final + ".old"
        self.files = {self.mu + "/wp-on-demand-image-resizer.off": "<?php // the owner's own file"}
        self.admins = [(2, "sara", "Sara"), (1, "owner", "Shop Owner")]      # not in order on purpose
        self.accounts = {"owner": True, "sara": True, "writer": False}      # login -> is an administrator
        self.wp_fails = False
        self.lint_ok = True
        self.write_fails = False
        self.switch_fails = False
        self.remove_fails = False
        self.su_fails = False
        self.helper_loaded = True              # the website really runs the helper file that is in its folder
        self.breaks_with_helper = False        # the home page fails as soon as the helper file is there
        self.home_code = "200"
        self.used = set()
        self.inputs = []                       # (command, data) of everything piped into a command

    # ---- WP-CLI and the shell, as the website's own user
    def su(self, cmd):
        script = cmd[5]
        if "core version" in script:
            return 0, "6.5.2\n"
        if self.su_fails:
            return 1, "su: failure"
        if "WPMU_PLUGIN_DIR" in script:
            if self.wp_fails:
                return 1, "Error: could not load WordPress"
            return 0, "Warning: a noisy plugin\n" + json.dumps({"home": self.home_url, "mu": self.mu_reported}) + "\n"
        if "--fields=ID,user_login" in script:
            rows = "".join("%d,%s,%s\n" % a for a in self.admins)
            return 0, "Warning: a noisy plugin\n\ufeffID,user_login,display_name\n" + rows
        if "sha256sum" in script:
            text = self.files.get(self.final)
            if text is None:
                return 0, "MISSING\n"
            return 0, "%s  %s\n" % (hashlib.sha256(text.encode()).hexdigest(), self.final)
        if " -l " in script:
            return (0, "No syntax errors detected in x\n") if self.lint_ok else (255, "PHP Parse error: syntax error\n")
        if "test ! -e" in script:                                   # taking the helper off
            if self.remove_fails:
                return 1, "rm: cannot remove: Operation not permitted\n"
            for path in (self.final, self.new, self.old):
                self.files.pop(path, None)
            return 0, "gone\n"
        if "else rm -f" in script:                                  # putting back what was there before
            if self.old in self.files:
                self.files[self.final] = self.files.pop(self.old)
            else:
                self.files.pop(self.final, None)
            self.files.pop(self.new, None)
            return 0, ""
        if script.startswith("set -e;"):                            # switching the new file on
            if self.switch_fails:
                return 1, "mv: Permission denied\n"
            if self.final in self.files:
                self.files[self.old] = self.files[self.final]
            self.files[self.final] = self.files.pop(self.new)
            return 0, ""
        if script.startswith("rm -f"):
            for path in (self.new, self.old):
                if path in script:
                    self.files.pop(path, None)
        return 0, ""

    def write_input(self, cmd, data, timeout=60):
        self.inputs.append((list(cmd), data))
        if self.write_fails:
            return 1, "Disk quota exceeded"
        self.files[self.new] = data.decode("utf-8")
        return 0, ""

    # ---- what the website's address answers
    def curl(self, cmd):
        path = cmd[-1].split(DOMAIN, 1)[1]
        if path.startswith("/?cps-login="):
            code, body = self.answer_link(path.split("=", 1)[1])
        elif path == "/wp-login.php":
            code, body = "200", "login"
        else:
            broken = self.breaks_with_helper and self.final in self.files
            code, body = ("500" if broken else self.home_code), "<html>home</html>"
        return 0, body + "\n" + code

    def answer_link(self, token):
        text = self.files.get(self.final)
        match = re.search(r"\$secret = '([0-9a-f]+)';", text or "")
        if not match or not self.helper_loaded:
            return "200", "<html>home</html>"                       # nobody looks at the link
        secret = match.group(1)
        body, _, sig = token.rpartition(".")
        if not hmac.compare_digest(hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest(), sig):
            return "200", "<html>home</html>"
        data, _sig = unpack(token)
        if data["e"] - time.time() < 0 or data["e"] - time.time() > 300 or data["n"] in self.used:
            return "410", "<p>This one-time login link has expired or was already used.</p>"
        self.used.add(data["n"])
        if not self.accounts.get(data["u"]):
            return "403", "<p>not an administrator</p>"
        return "302", ""


class SiteCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.docroot = "%s/%s/public_html" % (config.P.home_dir, DOMAIN)
        os.makedirs(self.docroot)
        self.write(config.P.lsws_root + "/lsphp81/bin/php", "")
        self.site = FakeSite(self)
        self.fake.table += [(["su"], self.site.su), (["curl"], self.site.curl)]
        self.patch("cpsec.util.run_with_input", side_effect=self.site.write_input)
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", DOMAIN)])
        wpupdate._php_cache.clear()
        self.reset()
        self.addCleanup(self.reset)

    def reset(self):
        with adminlogin._lock:
            adminlogin._scan.update(status="idle", finished="", sites={})
            adminlogin._job.update(status="idle", action="", items=[], started="", finished="")

    def wait(self, state):
        for _ in range(300):
            if state()["status"] != "running":
                return
            time.sleep(0.02)
        self.fail("it did not finish")

    def install(self):
        res = adminlogin.install_one(DOMAIN)
        self.assertTrue(res.ok, res.message)
        return adminlogin._entry(DOMAIN)["secret"]

    def everything_run(self):
        """Every command line the panel ran or piped, as one text (to prove a secret never appears in one)."""
        return " ".join(" ".join(c) for c in self.fake.calls) + " ".join(" ".join(c) for c, _d in self.site.inputs)


class TheHelperFileAndTheLinks(unittest.TestCase):
    def test_the_file_holds_the_websites_secret_and_no_placeholder_is_left(self):
        text = adminlogin.render("ab" * 32)
        self.assertNotIn("@@", text)
        self.assertIn("$secret = '%s';" % ("ab" * 32), text)
        self.assertTrue(text.startswith("<?php"))

    def test_every_website_gets_a_different_file(self):
        self.assertNotEqual(adminlogin.render("aa" * 32), adminlogin.render("bb" * 32))
        self.assertEqual(adminlogin.fingerprint("x"), hashlib.sha256(b"x").hexdigest())

    def test_a_link_says_who_until_when_and_carries_a_number_nobody_can_guess(self):
        secret = "cd" * 32
        token = adminlogin.make_token(secret, "owner", now=1000)
        data, sig = unpack(token)
        self.assertEqual((data["u"], data["e"]), ("owner", 1000 + adminlogin.TOKEN_SECONDS))
        self.assertEqual(adminlogin.TOKEN_SECONDS, 60)
        self.assertNotIn("t", data)
        body = token.rpartition(".")[0]
        self.assertEqual(sig, hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest())
        self.assertNotEqual(data["n"], unpack(adminlogin.make_token(secret, "owner", now=1000))[0]["n"])
        self.assertRegex(token, r"^[A-Za-z0-9_\-]{20,2000}\.[a-f0-9]{64}$")           # what the helper accepts

    def test_a_link_can_open_a_dashboard_page_but_never_another_address(self):
        secret = "cd" * 32
        self.assertEqual(unpack(adminlogin.make_token(secret, "owner", "plugins.php"))[0]["t"], "plugins.php")
        self.assertEqual(unpack(adminlogin.make_token(secret, "owner", "update-core.php?force-check=1"))[0]["t"], "update-core.php?force-check=1")
        for bad in ("https://evil.example.net/", "//evil.example.net", "../wp-config.php", "plugins.php#x", "a/b.php", "evil\\x.php", "x.php\nLocation: y", ""):
            self.assertNotIn("t", unpack(adminlogin.make_token(secret, "owner", bad))[0], bad)


class SeeingAWebsite(SiteCase):
    def test_a_website_without_the_helper_is_missing_and_its_administrators_are_listed_lowest_first(self):
        info = adminlogin._inspect(DOMAIN)
        self.assertEqual((info["checked"], info["status"], info["home"]), (True, "missing", "https://shop.example.com"))
        self.assertEqual([a["login"] for a in info["admins"]], ["owner", "sara"])
        self.assertEqual(info["admins"][0], {"login": "owner", "name": "Shop Owner"})

    def test_the_file_is_told_apart_from_a_changed_or_unreadable_one(self):
        site = wpupdate._site(DOMAIN)
        self.assertEqual(adminlogin._file_state(site, self.site.final, ""), "missing")
        secret = self.install()
        self.assertEqual(adminlogin._file_state(site, self.site.final, secret), "installed")
        self.assertEqual(adminlogin._file_state(site, self.site.final, "00" * 32), "changed")        # the panel's copy of the secret does not match
        self.assertEqual(adminlogin._file_state(site, self.site.final, ""), "changed")               # the panel forgot the secret
        self.site.files[self.site.final] += "\n// edited by somebody\n"
        self.assertEqual(adminlogin._file_state(site, self.site.final, secret), "changed")
        self.site.su_fails = True
        self.assertEqual(adminlogin._file_state(site, self.site.final, secret), "unknown")

    def test_a_website_that_will_not_start_is_reported_not_guessed(self):
        self.site.wp_fails = True
        info = adminlogin._inspect(DOMAIN)
        self.assertFalse(info["checked"])
        self.assertEqual(info["status"], "unknown")
        self.assertTrue(info["problem"])

    def test_a_must_use_folder_outside_the_website_is_not_supported(self):
        self.site.mu_reported = "/var/www/shared/mu-plugins"
        info = adminlogin._inspect(DOMAIN)
        self.assertEqual(info["status"], "unsupported")
        self.assertIn("outside its own folder", info["problem"])

    def test_the_page_lists_every_website_and_the_account_it_will_log_in_as(self):
        adminlogin.scan_start()
        self.wait(adminlogin.scan_state)
        state = adminlogin.state()
        self.assertEqual(state["scan"]["status"], "done")
        row = state["sites"][0]
        self.assertEqual((row["site"], row["status"], row["login"]), (DOMAIN, "missing", "owner"))
        self.assertEqual(adminlogin.state(["unknown.example.com"])["sites"][0]["checked"], False)

    def test_a_website_that_cannot_be_looked_at_does_not_hide_the_others(self):
        with mock.patch.object(adminlogin, "_inspect", side_effect=RuntimeError("boom")):
            adminlogin.scan_start()
            self.wait(adminlogin.scan_state)
        row = adminlogin.state()["sites"][0]
        self.assertEqual((row["checked"], row["status"]), (False, "unknown"))
        self.assertIn("failed", row["problem"])

    def test_two_looks_at_once_are_refused(self):
        gate, started = threading.Event(), threading.Event()

        def slow(name):
            started.set()
            gate.wait(5)
            return {"site": name, "checked": True, "home": "", "status": "missing", "admins": [], "problem": ""}

        with mock.patch.object(adminlogin, "_inspect", side_effect=slow):
            self.assertTrue(adminlogin.scan_start().ok)
            self.assertTrue(started.wait(5))
            again = adminlogin.scan_start()
            self.assertFalse(again.ok)
            self.assertEqual(again.code, "busy")
            gate.set()
            self.wait(adminlogin.scan_state)


class SwitchingItOn(SiteCase):
    def test_a_good_install_puts_the_tested_file_in_place_and_remembers_the_secret(self):
        res = adminlogin.install_one(DOMAIN, progress=lambda text: None)
        self.assertTrue(res.ok, res.message)
        secret = adminlogin._entry(DOMAIN)["secret"]
        self.assertRegex(secret, r"^[a-f0-9]{64}$")
        self.assertEqual(self.site.files[self.site.final], adminlogin.render(secret))
        self.assertNotIn(self.site.new, self.site.files)
        self.assertNotIn(self.site.old, self.site.files)
        self.assertIn(self.site.mu + "/wp-on-demand-image-resizer.off", self.site.files)          # the owner's own file is left alone
        self.assertEqual(adminlogin._file_state(wpupdate._site(DOMAIN), self.site.final, secret), "installed")

    def test_the_secret_is_written_by_the_websites_own_user_and_never_appears_on_a_command_line(self):
        secret = self.install()
        cmd, data = self.site.inputs[0]
        self.assertEqual(cmd[:5], ["su", "-s", "/bin/bash", "shopuser", "-c"])
        self.assertIn(secret.encode(), data)
        self.assertIn("umask 077", cmd[5])
        self.assertNotIn(secret, self.everything_run())

    def test_the_panels_copy_of_the_secret_is_private(self):
        self.install()
        path = config.P.adminlogin_file
        self.assertIn("secret", self.read(path))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_it_is_tested_with_a_link_that_has_already_expired(self):
        self.install()
        links = [c[-1] for c in self.fake.called("curl") if "cps-login=" in c[-1]]
        self.assertEqual(len(links), 1)
        data, _sig = unpack(links[0].split("cps-login=")[1])
        self.assertLess(data["e"], time.time())

    def test_a_mistake_in_the_file_changes_nothing(self):
        self.site.lint_ok = False
        res = adminlogin.install_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "lint")
        self.assertNotIn(self.site.final, self.site.files)
        self.assertNotIn(self.site.new, self.site.files)
        self.assertEqual(adminlogin._entry(DOMAIN), {})

    def test_a_helper_that_the_website_does_not_load_is_taken_out_again(self):
        self.site.helper_loaded = False
        res = adminlogin.install_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "selftest")
        self.assertIn("did not answer the test link", res.message)
        self.assertNotIn(self.site.final, self.site.files)
        self.assertNotIn(self.site.old, self.site.files)
        self.assertEqual(adminlogin._entry(DOMAIN), {})
        self.assertIn(self.site.mu + "/wp-on-demand-image-resizer.off", self.site.files)

    def test_a_website_that_gets_worse_with_the_helper_is_put_back(self):
        self.site.breaks_with_helper = True
        res = adminlogin.install_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "selftest")
        self.assertIn("home page now answers 500", res.message)
        self.assertNotIn(self.site.final, self.site.files)

    def test_a_failed_reinstall_brings_back_the_helper_that_worked(self):
        secret = self.install()
        before = self.site.files[self.site.final]
        self.site.helper_loaded = False
        res = adminlogin.install_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(self.site.files[self.site.final], before)
        self.assertNotIn(self.site.old, self.site.files)
        self.assertEqual(adminlogin._entry(DOMAIN)["secret"], secret)                      # the old secret still matches the old file

    def test_a_reinstall_that_works_replaces_the_secret(self):
        first = self.install()
        second = self.install()
        self.assertNotEqual(first, second)
        self.assertEqual(self.site.files[self.site.final], adminlogin.render(second))
        self.assertNotIn(self.site.old, self.site.files)

    def test_a_website_that_is_already_failing_is_not_touched(self):
        self.site.home_code = "503"
        res = adminlogin.install_one(DOMAIN)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "unhealthy")
        self.assertEqual(self.site.inputs, [])
        self.assertEqual(self.site.files, {self.site.mu + "/wp-on-demand-image-resizer.off": "<?php // the owner's own file"})

    def test_a_folder_outside_the_website_is_refused_before_anything_is_written(self):
        self.site.mu_reported = "/var/www/shared/mu-plugins"
        res = adminlogin.install_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "unsupported"))
        self.assertEqual(self.site.inputs, [])

    def test_a_website_that_will_not_start_is_refused_before_anything_is_written(self):
        self.site.wp_fails = True
        res = adminlogin.install_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "facts"))
        self.assertEqual(self.site.inputs, [])

    def test_a_file_that_cannot_be_written_is_reported(self):
        self.site.write_fails = True
        res = adminlogin.install_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertIn("Disk quota exceeded", res.message)
        self.assertEqual(adminlogin._entry(DOMAIN), {})

    def test_a_file_that_cannot_be_moved_into_place_is_put_back(self):
        self.site.switch_fails = True
        res = adminlogin.install_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertNotIn(self.site.final, self.site.files)
        self.assertEqual(adminlogin._entry(DOMAIN), {})

    def test_an_unknown_website_is_refused(self):
        res = adminlogin.install_one("nope.example.com")
        self.assertEqual((res.ok, res.code), (False, "not_found"))

    def test_the_page_shows_it_as_installed_straight_away(self):
        adminlogin.scan_start()
        self.wait(adminlogin.scan_state)
        self.install()
        self.assertEqual(adminlogin.state()["sites"][0]["status"], "installed")


class SwitchingItOff(SiteCase):
    def test_removing_takes_the_file_and_forgets_the_secret_but_leaves_the_rest(self):
        self.install()
        self.site.files[self.site.old] = "left over"
        res = adminlogin.remove_one(DOMAIN, progress=lambda text: None)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.site.files, {self.site.mu + "/wp-on-demand-image-resizer.off": "<?php // the owner's own file"})
        self.assertNotIn("secret", adminlogin._entry(DOMAIN))
        self.assertEqual(adminlogin._file_state(wpupdate._site(DOMAIN), self.site.final, ""), "missing")

    def test_a_failed_removal_keeps_what_is_needed_to_try_again(self):
        secret = self.install()
        self.site.remove_fails = True
        res = adminlogin.remove_one(DOMAIN)
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertEqual(adminlogin._entry(DOMAIN)["secret"], secret)

    def test_removing_where_there_is_nothing_is_fine(self):
        self.assertTrue(adminlogin.remove_one(DOMAIN).ok)

    def test_removing_from_an_unknown_website_is_refused(self):
        self.assertEqual(adminlogin.remove_one("nope.example.com").code, "not_found")

    def test_removing_needs_to_know_where_the_folder_is(self):
        self.site.wp_fails = True
        self.assertEqual(adminlogin.remove_one(DOMAIN).code, "facts")


class ChoosingTheAccount(SiteCase):
    def look(self):
        adminlogin.scan_start()
        self.wait(adminlogin.scan_state)

    def test_an_administrator_of_that_website_can_be_chosen(self):
        self.look()
        res = adminlogin.set_user(DOMAIN, "sara")
        self.assertTrue(res.ok, res.message)
        self.assertEqual(adminlogin.state()["sites"][0]["login"], "sara")

    def test_somebody_who_is_not_an_administrator_cannot_be_chosen(self):
        self.look()
        for bad in ("writer", "", "root", "owner; rm -rf /"):
            res = adminlogin.set_user(DOMAIN, bad)
            self.assertEqual((res.ok, res.code), (False, "invalid"), bad)
        self.assertEqual(adminlogin.state()["sites"][0]["login"], "owner")

    def test_an_unknown_website_is_refused(self):
        self.assertEqual(adminlogin.set_user("nope.example.com", "owner").code, "not_found")

    def test_a_choice_for_an_account_that_was_deleted_falls_back_to_the_first_administrator(self):
        self.look()
        adminlogin.set_user(DOMAIN, "sara")
        self.site.admins = [(1, "owner", "Shop Owner")]
        self.look()
        self.assertEqual(adminlogin.state()["sites"][0]["login"], "owner")


class TheLink(SiteCase):
    def test_a_website_without_the_helper_gets_no_link(self):
        res, url = adminlogin.make_link(DOMAIN)
        self.assertEqual((res.ok, res.code, url), (False, "not_installed", ""))

    def test_the_link_opens_the_website_logged_in_as_the_first_administrator(self):
        secret = self.install()
        res, url = adminlogin.make_link(DOMAIN)
        self.assertTrue(res.ok, res.message)
        self.assertTrue(url.startswith("https://shop.example.com/?cps-login="), url)
        data, sig = unpack(url.split("cps-login=")[1])
        self.assertEqual(data["u"], "owner")
        body = url.split("cps-login=")[1].rpartition(".")[0]
        self.assertEqual(sig, hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest())
        self.assertAlmostEqual(data["e"], time.time() + 60, delta=5)
        self.assertEqual(self.site.answer_link(url.split("cps-login=")[1])[0], "302")

    def test_the_chosen_account_and_a_dashboard_page_are_used(self):
        self.install()
        adminlogin.scan_start()
        self.wait(adminlogin.scan_state)
        adminlogin.set_user(DOMAIN, "sara")
        res, url = adminlogin.make_link(DOMAIN, "plugins.php")
        data, _sig = unpack(url.split("cps-login=")[1])
        self.assertEqual((data["u"], data["t"]), ("sara", "plugins.php"))

    def test_a_link_works_once(self):
        self.install()
        _res, url = adminlogin.make_link(DOMAIN)
        token = url.split("cps-login=")[1]
        self.assertEqual(self.site.answer_link(token)[0], "302")
        self.assertEqual(self.site.answer_link(token)[0], "410")

    def test_a_link_for_another_page_address_is_refused(self):
        self.install()
        for bad in ("https://evil.example.net", "../x.php", "plugins.php#a"):
            res, url = adminlogin.make_link(DOMAIN, bad)
            self.assertEqual((res.ok, res.code, url), (False, "invalid", ""), bad)

    def test_a_changed_helper_file_gets_no_link(self):
        self.install()
        self.site.files[self.site.final] += "\n// somebody was here\n"
        res, url = adminlogin.make_link(DOMAIN)
        self.assertEqual((res.ok, res.code, url), (False, "not_installed", ""))

    def test_a_helper_removed_behind_the_panels_back_gets_no_link(self):
        self.install()
        adminlogin.scan_start()
        self.wait(adminlogin.scan_state)
        del self.site.files[self.site.final]
        res, url = adminlogin.make_link(DOMAIN)
        self.assertEqual((res.ok, res.code, url), (False, "not_installed", ""))

    def test_a_website_without_an_administrator_gets_no_link(self):
        self.install()
        self.site.admins = []
        res, url = adminlogin.make_link(DOMAIN)
        self.assertEqual((res.ok, res.code, url), (False, "no_admin", ""))

    def test_an_odd_home_address_falls_back_to_the_website_name(self):
        self.install()
        self.site.home_url = "javascript:alert(1)"
        res, url = adminlogin.make_link(DOMAIN)
        self.assertTrue(res.ok, res.message)
        self.assertTrue(url.startswith("https://shop.example.com/?cps-login="), url)

    def test_a_link_for_an_unknown_website_is_refused(self):
        res, url = adminlogin.make_link("nope.example.com")
        self.assertEqual((res.ok, res.code, url), (False, "not_found", ""))

    def test_the_link_is_made_even_if_the_page_had_not_finished_looking(self):
        self.install()
        self.assertEqual(adminlogin.scan_state()["sites"], {})
        res, url = adminlogin.make_link(DOMAIN)
        self.assertTrue(res.ok, res.message)


class TheJob(SiteCase):
    def test_only_known_actions_and_websites_are_accepted(self):
        for action, names in (("explode", [DOMAIN]), ("install", []), ("install", ["nope.example.com"]), ("install", [DOMAIN, "nope.example.com"]), ("install", None)):
            res = adminlogin.start(action, names)
            self.assertEqual((res.ok, res.code), (False, "invalid"), (action, names))
        self.assertEqual(adminlogin.job_state()["status"], "idle")

    def test_an_install_job_goes_through_the_websites_and_reports_each(self):
        self.assertTrue(adminlogin.start("install", [DOMAIN, DOMAIN]).ok)               # a name twice counts once
        self.wait(adminlogin.job_state)
        job = adminlogin.job_state()
        self.assertEqual([(i["site"], i["status"]) for i in job["items"]], [(DOMAIN, "done")])
        self.assertEqual(job["counts"]["done"], 1)
        self.assertIn(adminlogin.HELPER_NAME, "".join(self.site.files))

    def test_a_remove_job_takes_it_off_again(self):
        self.install()
        adminlogin.start("remove", [DOMAIN])
        self.wait(adminlogin.job_state)
        self.assertEqual(adminlogin.job_state()["items"][0]["status"], "done")
        self.assertNotIn(self.site.final, self.site.files)

    def test_one_website_failing_does_not_stop_the_next(self):
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", DOMAIN), (self.docroot + "2", "blog", OTHER)])
        calls = []

        def fake(name, progress=None):
            calls.append(name)
            if name == DOMAIN:
                raise RuntimeError("boom")
            return adminlogin.Result(True, "fine")

        with mock.patch.object(adminlogin, "install_one", side_effect=fake):
            adminlogin.start("install", [DOMAIN, OTHER])
            self.wait(adminlogin.job_state)
        items = adminlogin.job_state()["items"]
        self.assertEqual(calls, [DOMAIN, OTHER])
        self.assertEqual([i["status"] for i in items], ["failed", "done"])
        self.assertIn("Unexpected problem", items[0]["message"])

    def test_a_second_job_while_one_runs_is_refused(self):
        gate, started = threading.Event(), threading.Event()

        def slow(name, progress=None):
            started.set()
            gate.wait(5)
            return adminlogin.Result(True, "fine")

        with mock.patch.object(adminlogin, "install_one", side_effect=slow):
            self.assertTrue(adminlogin.start("install", [DOMAIN]).ok)
            self.assertTrue(started.wait(5))
            again = adminlogin.start("remove", [DOMAIN])
            self.assertEqual((again.ok, again.code), (False, "busy"))
            gate.set()
            self.wait(adminlogin.job_state)

    def test_a_failure_is_shown_with_its_reason(self):
        self.site.lint_ok = False
        adminlogin.start("install", [DOMAIN])
        self.wait(adminlogin.job_state)
        item = adminlogin.job_state()["items"][0]
        self.assertEqual(item["status"], "failed")
        self.assertIn("PHP check", item["message"])


PHP = shutil.which("php") or next((p for p in ("/usr/local/lsws/lsphp81/bin/php", "/usr/local/lsws/lsphp82/bin/php") if os.path.exists(p)), None)

HARNESS = r'''<?php
// Stands in for WordPress just enough to run the helper file, and says what the helper asked it to do.
define('ABSPATH', __DIR__ . '/');
$GLOBALS['actions'] = array();
function add_action($name, $fn, $priority = 10) { $GLOBALS['actions'][$name][] = $fn; }
function nocache_headers() {}
function cps_state() { $s = json_decode(@file_get_contents(getenv('CPS_STATE')), true); return is_array($s) ? $s : array(); }
function get_transient($key) { $s = cps_state(); return isset($s[$key]) ? $s[$key] : false; }
function set_transient($key, $value, $ttl) { $s = cps_state(); $s[$key] = $value; file_put_contents(getenv('CPS_STATE'), json_encode($s)); }
function wp_die($message, $title = '', $args = array()) { echo 'DIE ' . (isset($args['response']) ? $args['response'] : 500) . ' ' . trim(strip_tags($message)) . "\n"; throw new Exception('die'); }
function get_user_by($field, $login) {
    $users = json_decode(getenv('CPS_USERS'), true);
    if (!isset($users[$login])) { return false; }
    $o = new stdClass; $o->ID = $users[$login]['id']; $o->user_login = $login; $o->admin = $users[$login]['admin'];
    return $o;
}
function user_can($user, $cap) { return $cap === 'manage_options' && $user->admin; }
function wp_set_current_user($id, $login = '') { echo "CURRENT $id\n"; }
function wp_set_auth_cookie($id, $remember = false, $secure = '') { echo "COOKIE $id " . ($secure ? 'secure' : 'plain') . "\n"; }
function do_action($name) { echo "ACTION $name\n"; }
function is_ssl() { return true; }
function admin_url($path = '') { return 'https://site.test/wp-admin/' . $path; }
function wp_safe_redirect($url) { echo "REDIRECT $url\n"; }
if (getenv('CPS_TOKEN') !== false) { $_GET['cps-login'] = getenv('CPS_TOKEN'); }
require getenv('CPS_HELPER');
try { foreach ($GLOBALS['actions']['init'] as $fn) { $fn(); } } catch (Exception $e) {}
echo "END\n";
'''


@unittest.skipUnless(PHP, "PHP is not installed here; the helper is checked for real on the server")
class TheHelperItself(unittest.TestCase):
    """The helper file run by real PHP against a stand-in for WordPress: what it accepts and what it refuses."""

    SECRET = "ef" * 32

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.helper = os.path.join(self.dir, "helper.php")
        self.harness = os.path.join(self.dir, "harness.php")
        self.state = os.path.join(self.dir, "state.json")
        with open(self.helper, "w", encoding="utf-8", newline="\n") as f:
            f.write(adminlogin.render(self.SECRET))
        with open(self.harness, "w", encoding="utf-8", newline="\n") as f:
            f.write(HARNESS)
        self.users = {"owner": {"id": 7, "admin": True}, "writer": {"id": 8, "admin": False}}

    def visit(self, token=None):
        env = dict(os.environ, CPS_HELPER=self.helper, CPS_STATE=self.state, CPS_USERS=json.dumps(self.users))
        env.pop("CPS_TOKEN", None)
        if token is not None:
            env["CPS_TOKEN"] = token
        p = subprocess.run([PHP, "-d", "display_errors=1", "-d", "error_reporting=-1", self.harness], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
        self.assertNotRegex(p.stdout, r"(?i)warning|notice|deprecated|fatal|parse error")
        return p.stdout

    def silent(self, out):
        self.assertEqual(out, "END\n")

    def test_the_file_has_no_mistakes(self):
        p = subprocess.run([PHP, "-l", self.helper], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("No syntax errors", p.stdout)

    def test_a_good_link_signs_the_administrator_in_and_opens_the_dashboard(self):
        out = self.visit(adminlogin.make_token(self.SECRET, "owner"))
        self.assertEqual(out.splitlines(), ["CURRENT 7", "COOKIE 7 secure", "ACTION wp_login", "REDIRECT https://site.test/wp-admin/"])

    def test_a_link_can_open_a_chosen_dashboard_page(self):
        out = self.visit(adminlogin.make_token(self.SECRET, "owner", "update-core.php?force-check=1"))
        self.assertIn("REDIRECT https://site.test/wp-admin/update-core.php?force-check=1", out)

    def test_a_signed_link_asking_for_another_address_still_stays_on_the_dashboard(self):
        payload = {"u": "owner", "e": int(time.time()) + 30, "n": "1" * 24, "t": "https://evil.example.net/"}
        out = self.visit(sign(self.SECRET, payload))
        self.assertIn("REDIRECT https://site.test/wp-admin/\n", out)
        self.assertNotIn("evil", out)

    def test_a_link_works_once(self):
        token = adminlogin.make_token(self.SECRET, "owner")
        self.assertIn("COOKIE 7", self.visit(token))
        again = self.visit(token)
        self.assertIn("DIE 410", again)
        self.assertNotIn("COOKIE", again)

    def test_an_expired_link_is_refused_with_the_expired_page(self):
        out = self.visit(adminlogin.make_token(self.SECRET, "owner", ttl=-5))
        self.assertIn("DIE 410 This one-time login link has expired", out)
        self.assertNotIn("COOKIE", out)

    def test_a_link_made_to_last_long_is_refused(self):
        self.assertIn("DIE 410", self.visit(adminlogin.make_token(self.SECRET, "owner", ttl=1000)))

    def test_a_link_signed_with_another_secret_is_ignored_without_a_word(self):
        self.silent(self.visit(adminlogin.make_token("00" * 32, "owner")))

    def test_a_link_that_was_changed_is_ignored_without_a_word(self):
        token = adminlogin.make_token(self.SECRET, "owner")
        data, _sig = unpack(token)
        other = sign("00" * 32, dict(data, u="writer")).split(".")[0]
        self.silent(self.visit(other + "." + token.rpartition(".")[2]))

    def test_nonsense_and_missing_links_are_ignored_without_a_word(self):
        for bad in ("", "abc", "a" * 30, "a" * 30 + "." + "b" * 64, "a" * 30 + "." + "0" * 63, "a" * 30 + "." + "0" * 65, "../../etc/passwd", "x" * 5000 + "." + "0" * 64):
            self.silent(self.visit(bad))
        self.silent(self.visit(None))

    def test_a_link_for_somebody_who_is_not_an_administrator_is_refused(self):
        for who in ("writer", "nobody"):
            out = self.visit(adminlogin.make_token(self.SECRET, who))
            self.assertIn("DIE 403", out, who)
            self.assertNotIn("COOKIE", out)


if __name__ == "__main__":
    unittest.main()
