"""Bot protection: the three switches, proved on a pretend website that behaves like LiteSpeed did on the real server."""
import re
import threading
import time
import unittest
from unittest import mock

from cpsec import botguard
from tests.helpers import EnvTestCase

DOMAIN = "shop.example.com"
OTHER = "blog.example.com"
THEIRS = "# BEGIN WordPress\nRewriteEngine On\nRewriteRule . /index.php [L]\n# END WordPress\n"
HEADERS = "# BEGIN CP-Security headers\n<IfModule mod_headers.c>\n</IfModule>\n# END CP-Security headers\n"
PRIVATE = re.compile(r"(?i)(\.(log|sql|sql\.gz|sqlite3?|bak|backup|old|orig|save|swp|swo|ini)|~|^wp-config\.php.+|^error_log|^php_errorlog)$")


class RuleText(unittest.TestCase):
    def test_each_switch_is_one_marked_block_put_first(self):
        for key in botguard.KEYS:
            begin, end = botguard.markers(key)
            new = botguard.with_block(THEIRS, key)
            self.assertTrue(new.startswith(begin + "\n"), key)
            self.assertIn(end + "\n", new)
            self.assertTrue(new.endswith(THEIRS), key)

    def test_taking_it_out_gives_back_exactly_what_was_there(self):
        for key in botguard.KEYS:
            for original in ("", THEIRS, HEADERS + THEIRS, "Options -Indexes"):
                self.assertEqual(botguard.without_block(botguard.with_block(original, key), key), original, (key, original))

    def test_switches_never_touch_each_other_or_the_headers_block(self):
        text = HEADERS + THEIRS
        for key in botguard.KEYS:
            text = botguard.with_block(text, key)
        self.assertEqual([botguard.status_in(text, k) for k in botguard.KEYS], ["on", "on", "on"])
        text = botguard.without_block(text, "files")
        self.assertEqual([botguard.status_in(text, k) for k in botguard.KEYS], ["on", "off", "on"])
        self.assertIn(HEADERS, text)
        self.assertTrue(text.endswith(THEIRS))

    def test_putting_it_in_twice_changes_nothing(self):
        once = botguard.with_block(THEIRS, "users")
        self.assertEqual(botguard.with_block(once, "users"), once)

    def test_on_off_changed_and_damaged(self):
        self.assertEqual(botguard.status_in(THEIRS, "xmlrpc"), "off")
        self.assertEqual(botguard.status_in(botguard.with_block(THEIRS, "xmlrpc"), "xmlrpc"), "on")
        edited = botguard.with_block(THEIRS, "xmlrpc").replace("Require all denied", "Require all granted")
        self.assertEqual(botguard.status_in(edited, "xmlrpc"), "changed")
        begin, end = botguard.markers("xmlrpc")
        for bad in (begin + "\n", end + "\n", botguard.block("xmlrpc") * 2, end + "\n" + begin + "\n"):
            self.assertEqual(botguard.status_in(bad, "xmlrpc"), "changed")
            with self.assertRaises(ValueError):
                botguard.with_block(bad, "xmlrpc")

    def test_the_private_file_rule_hides_what_bots_ask_for_and_nothing_a_visitor_needs(self):
        pattern = re.search(r'<FilesMatch "\(\?i\)(.*)">', botguard.RULES["files"]["lines"]).group(1)
        rx = re.compile(pattern, re.I)
        for name in ("debug.log", "error_log", "php_errorlog", "backup.sql", "db.sql.gz", "site.sqlite", "wp-config.php.bak",
                     "wp-config.php~", "wp-config.php.save", "wp-config.php.orig", "wp-config.php.txt", "wp-config.old", "php.ini",
                     "index.php.swp", "DEBUG.LOG"):
            self.assertTrue(rx.search(name), name)
        for name in ("photo.jpg", "style.css", "app.js", "catalogue.pdf", "product.zip", "robots.txt", "sitemap.xml",
                     "wp-config.php", "index.php", "font.woff2", "logo.svg", "login.html"):
            self.assertFalse(rx.search(name), name)

    def test_the_hidden_file_rule_keeps_the_certificate_folder_open(self):
        rx = re.compile(re.search(r"RewriteRule (\S+) - \[F\]", botguard.RULES["files"]["lines"]).group(1))
        for path in (".env", ".git/config", "wp-content/.secret", ".htpasswd", ".user.ini", "a/.svn/entries", ".well-knownx"):
            self.assertTrue(rx.search(path), path)
        for path in (".well-known/acme-challenge/token", ".well-known", "wp-content/uploads/photo.jpg", "a.b/c", "index.php"):
            self.assertFalse(rx.search(path), path)

    def test_signed_in_people_and_the_dashboard_are_left_out_of_the_account_name_rule(self):
        lines = botguard.RULES["users"]["lines"]
        self.assertEqual(lines.count("RewriteCond %{HTTP_COOKIE} !wordpress_logged_in_ [NC]"), 2)
        self.assertIn("!^/wp-admin/", lines)
        self.assertIn("(/|%2F)wp(/|%2F)v2(/|%2F)users", lines)


class FakeWebsite:
    """The website's settings file, its folder and its answers. Like LiteSpeed, a changed settings file is noticed a few answers later."""

    def __init__(self, case):
        self.docroot = "/home/%s/public_html" % DOMAIN
        self.ht = self.docroot + "/.htaccess"
        self.files = {}                       # path -> text (the website's folder)
        self.dirs = set()
        self.active = ""                      # the settings file as the web server applies it right now
        self.delay = 2
        self.since_change = 0
        self.is_link = False
        self.ignores = False                  # the web server never applies the settings file
        self.home_code = "200"
        self.breaks_home = False              # the home page fails once any block of ours is applied
        self.breaks_rest = False              # the REST door breaks once the account-name block is applied
        self.ignores_cookie = False           # the account-name block also refuses signed-in people
        self.blocks_well_known = False        # the hidden-file block also refuses .well-known
        self.door_open = True
        self.users = ["mehdi"]
        self.write_fails = False
        self.test_file_fails = False
        self.inputs = []

    # ---- what is applied
    def on(self, key):
        return not self.ignores and botguard.status_in(self.active, key) == "on"

    def tick(self):
        self.since_change += 1
        if self.since_change > self.delay:
            self.active = self.files.get(self.ht, "")

    # ---- the shell, as the website's user
    def su(self, cmd):
        script = cmd[5]
        if "__LINK__" in script:
            if self.is_link:
                return 0, "__LINK__\n"
            return (0, "__FILE__\n" + self.files[self.ht]) if self.ht in self.files else (0, "__NONE__\n")
        if "echo MADE" in script:
            wk = self.docroot + "/.well-known"
            if wk in self.dirs:
                return 0, "DIR\n"
            self.dirs.add(wk)
            return 0, "MADE\n"
        if script.startswith("rmdir --"):
            wk = self.docroot + "/.well-known"
            if not any(p.startswith(wk + "/") for p in self.files):
                self.dirs.discard(wk)
            return 0, ""
        if script.startswith("rm -f --"):
            for path in list(self.files):
                if (" '%s'" % path) in script or (" %s" % path) in script.replace("'", ""):
                    if path in script.replace("'", "").split():
                        del self.files[path]
                        if path == self.ht:
                            self.since_change = 0
            return 0, ""
        return 0, ""

    def write_input(self, cmd, data, timeout=60):
        self.inputs.append((list(cmd), data))
        script = cmd[5]
        text = data.decode("utf-8")
        if "mv -f" in script:
            if self.write_fails:
                return 1, "Permission denied"
            self.files[self.ht] = text
            self.since_change = 0
            return 0, ""
        m = re.search(r"cat > '?([^' ]+)'?$", script)
        if m:
            if self.test_file_fails:
                return 1, "Disk quota exceeded"
            self.files[m.group(1)] = text
            return 0, ""
        return 1, "unexpected"

    # ---- the website's answers
    def answer(self, method, path, query, cookie):
        signed_in = "wordpress_logged_in_" in (cookie or "")
        if path.rstrip("/") == "/xmlrpc.php":
            if self.on("xmlrpc"):
                return "403", "Forbidden", {}
            if not self.door_open:
                return "403", "Forbidden", {}
            return ("200", "<methodResponse/>", {}) if method == "POST" else ("405", "XML-RPC server accepts POST requests only.", {})
        rest_users = path.startswith("/wp-json/wp/v2/users") or re.search(r"(^|&)rest_route=(/|%2F)wp(/|%2F)v2(/|%2F)users", query, re.I)
        if rest_users:
            if self.on("users") and (not signed_in or self.ignores_cookie):
                return "403", "Forbidden", {}
            return "200", "[" + ",".join('{"id":%d,"slug":"%s"}' % (i + 1, u) for i, u in enumerate(self.users)) + "]", {}
        if re.search(r"(^|&)author=[0-9]", query) and not path.startswith("/wp-admin/"):
            if self.on("users") and not signed_in:
                return "403", "Forbidden", {}
            return ("301", "", {"location": "https://%s/author/%s/" % (DOMAIN, self.users[0])}) if self.users else ("404", "", {})
        if path.rstrip("/") == "/wp-json":
            return ("403", "Forbidden", {}) if self.breaks_rest and self.on("users") else ("200", "{}", {})
        full = self.docroot + path
        if full in self.files:
            rel = path.lstrip("/")
            name = rel.split("/")[-1]
            hidden = re.search(r"(^|/)\.(?!well-known(/|$))", rel) or (self.blocks_well_known and rel.startswith(".well-known/"))
            if self.on("files") and (PRIVATE.search(name) or hidden):
                return "403", "Forbidden", {}
            return "200", self.files[full], {}
        if path in ("", "/"):
            broken = self.breaks_home and any(self.on(k) for k in botguard.KEYS)
            return ("500" if broken else self.home_code), "<html>home</html>", {}
        if path == "/wp-login.php":
            return "200", "login", {}
        return "404", "not found", {}

    def curl(self, cmd):
        self.tick()
        url = cmd[-1]
        rest = url.split(DOMAIN, 1)[1] if DOMAIN in url else "/"
        path, _, query = rest.partition("?")
        method = "POST" if "POST" in cmd else "GET"
        cookie = cmd[cmd.index("-b") + 1] if "-b" in cmd else ""
        code, body, heads = self.answer(method, path, query, cookie)
        if "-D" in cmd:
            return 0, "HTTP/2 %s\r\n" % code + "".join("%s: %s\r\n" % kv for kv in heads.items()) + "\r\n" + code
        if "-o" in cmd and cmd[cmd.index("-o") + 1] == "/dev/null":
            return 0, code
        return 0, body + "\n" + code


class GuardCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.site = FakeWebsite(self)
        self.fake.table += [(["su"], self.site.su), (["curl"], self.site.curl)]
        self.patch("cpsec.util.run_with_input", side_effect=self.site.write_input)
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.site.docroot, "shopuser", DOMAIN)])
        self.patch("cpsec.botguard._sleep")
        self.reset()
        self.addCleanup(self.reset)

    def reset(self):
        with botguard._lock:
            botguard._scan.update(status="idle", finished="", sites={})
            botguard._job.update(status="idle", action="", rule="", items=[], started="", finished="")

    def wait(self, state):
        for _ in range(300):
            if state()["status"] != "running":
                return
            time.sleep(0.02)
        self.fail("it did not finish")

    def text(self):
        return self.site.files.get(self.site.ht)

    def no_test_files(self):
        return [p for p in self.site.files if "cps-selftest" in p] == []


class SwitchingOn(GuardCase):
    def test_closing_the_old_door_is_proved_and_kept(self):
        self.site.files[self.site.ht] = HEADERS + THEIRS
        res = botguard.enable_one(DOMAIN, "xmlrpc", progress=lambda s: None)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.text(), botguard.block("xmlrpc") + HEADERS + THEIRS)

    def test_hiding_private_files_is_proved_with_test_files_that_are_removed(self):
        self.site.files[self.site.ht] = THEIRS
        res = botguard.enable_one(DOMAIN, "files")
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.text(), botguard.block("files") + THEIRS)
        self.assertTrue(self.no_test_files())
        self.assertNotIn(self.site.docroot + "/.well-known", self.site.dirs, "the folder made only for the test is taken away again")

    def test_an_existing_certificate_folder_is_kept(self):
        self.site.dirs.add(self.site.docroot + "/.well-known")
        self.assertTrue(botguard.enable_one(DOMAIN, "files").ok)
        self.assertIn(self.site.docroot + "/.well-known", self.site.dirs)
        self.assertTrue(self.no_test_files())

    def test_hiding_account_names_is_proved_and_kept(self):
        res = botguard.enable_one(DOMAIN, "users")
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.text(), botguard.block("users"))

    def test_a_file_that_did_not_exist_is_created_with_only_the_block(self):
        self.assertTrue(botguard.enable_one(DOMAIN, "xmlrpc").ok)
        self.assertEqual(self.text(), botguard.block("xmlrpc"))

    def test_it_is_not_done_twice(self):
        self.site.files[self.site.ht] = botguard.with_block(THEIRS, "users")
        writes = len(self.site.inputs)
        res = botguard.enable_one(DOMAIN, "users")
        self.assertTrue(res.ok)
        self.assertIn("already on", res.message)
        self.assertEqual(len(self.site.inputs), writes)

    def test_everything_runs_as_the_websites_own_user(self):
        botguard.enable_one(DOMAIN, "files")
        for cmd, _data in self.site.inputs:
            self.assertEqual(cmd[:5], ["su", "-s", "/bin/bash", "shopuser", "-c"])
        sus = [c for c in self.fake.calls if c[:1] == ["su"]]
        self.assertTrue(sus and all(c[3] == "shopuser" for c in sus))


class PuttingBack(GuardCase):
    def setUp(self):
        super().setUp()
        self.site.files[self.site.ht] = HEADERS + THEIRS

    def check_put_back(self, key, code):
        res = botguard.enable_one(DOMAIN, key)
        self.assertEqual((res.ok, res.code), (False, code), res.message)
        self.assertEqual(self.text(), HEADERS + THEIRS, "the settings file is exactly as it was")
        self.assertTrue(self.no_test_files())
        return res

    def test_a_web_server_that_ignores_the_file_gets_it_back(self):
        self.site.ignores = True
        for key in botguard.KEYS:
            self.check_put_back(key, "not_applied")

    def test_a_website_that_gets_worse_gets_it_back(self):
        self.site.breaks_home = True
        res = self.check_put_back("xmlrpc", "regression")
        self.assertIn("home page now answers 500", res.message)

    def test_a_broken_rest_door_gets_the_account_name_block_taken_out(self):
        self.site.breaks_rest = True
        res = self.check_put_back("users", "regression")
        self.assertIn("REST door", res.message)

    def test_signed_in_people_who_are_refused_get_the_account_name_block_taken_out(self):
        self.site.ignores_cookie = True
        res = self.check_put_back("users", "regression")
        self.assertIn("signed in", res.message)

    def test_a_refused_certificate_folder_gets_the_private_file_block_taken_out(self):
        self.site.blocks_well_known = True
        res = self.check_put_back("files", "regression")
        self.assertIn("certificate", res.message)

    def test_a_file_that_did_not_exist_is_removed_again(self):
        del self.site.files[self.site.ht]
        self.site.ignores = True
        res = botguard.enable_one(DOMAIN, "users")
        self.assertFalse(res.ok)
        self.assertNotIn(self.site.ht, self.site.files)


class Refusing(GuardCase):
    def test_a_website_that_is_already_failing_is_not_touched(self):
        self.site.home_code = "503"
        res = botguard.enable_one(DOMAIN, "xmlrpc")
        self.assertEqual((res.ok, res.code), (False, "unhealthy"))
        self.assertEqual(self.site.inputs, [])

    def test_a_link_in_place_of_the_settings_file_is_left_alone(self):
        self.site.is_link = True
        for fn in (botguard.enable_one, botguard.disable_one):
            self.assertEqual(fn(DOMAIN, "xmlrpc").code, "unsafe")
        self.assertEqual(self.site.inputs, [])

    def test_damaged_lines_of_ours_are_not_guessed_at(self):
        begin, _end = botguard.markers("files")
        self.site.files[self.site.ht] = begin + "\nhalf\n" + THEIRS
        for fn in (botguard.enable_one, botguard.disable_one):
            self.assertEqual(fn(DOMAIN, "files").code, "damaged")
        self.assertEqual(self.text(), begin + "\nhalf\n" + THEIRS)

    def test_a_test_file_that_cannot_be_saved_changes_nothing(self):
        self.site.files[self.site.ht] = THEIRS
        self.site.test_file_fails = True
        res = botguard.enable_one(DOMAIN, "files")
        self.assertEqual((res.ok, res.code), (False, "no_test"))
        self.assertEqual(self.text(), THEIRS)

    def test_a_settings_file_that_cannot_be_written_is_reported(self):
        self.site.write_fails = True
        res = botguard.enable_one(DOMAIN, "files")
        self.assertEqual((res.ok, res.code), (False, "write"))
        self.assertTrue(self.no_test_files())

    def test_unknown_websites_and_switches_are_refused(self):
        self.assertEqual(botguard.enable_one("nope.example.com", "xmlrpc").code, "not_found")
        self.assertEqual(botguard.enable_one(DOMAIN, "everything").code, "invalid")
        self.assertEqual(botguard.disable_one("nope.example.com", "xmlrpc").code, "not_found")
        self.assertEqual(botguard.disable_one(DOMAIN, "everything").code, "invalid")


class SwitchingOff(GuardCase):
    def test_only_that_switchs_block_is_taken_out(self):
        text = HEADERS + THEIRS
        for key in botguard.KEYS:
            text = botguard.with_block(text, key)
        self.site.files[self.site.ht] = text
        res = botguard.disable_one(DOMAIN, "users", progress=lambda s: None)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.text(), botguard.without_block(text, "users"))
        self.assertIn(HEADERS, self.text())
        self.assertEqual([botguard.status_in(self.text(), k) for k in botguard.KEYS], ["on", "on", "off"])

    def test_a_file_that_held_only_our_block_goes_away(self):
        self.site.files[self.site.ht] = botguard.block("xmlrpc")
        self.assertTrue(botguard.disable_one(DOMAIN, "xmlrpc").ok)
        self.assertNotIn(self.site.ht, self.site.files)

    def test_off_when_it_was_never_on_changes_nothing(self):
        self.assertIn("already off", botguard.disable_one(DOMAIN, "files").message)
        self.site.files[self.site.ht] = THEIRS
        self.assertIn("already off", botguard.disable_one(DOMAIN, "files").message)
        self.assertEqual(self.text(), THEIRS)
        self.assertEqual(self.site.inputs, [])

    def test_a_write_that_fails_is_reported(self):
        self.site.files[self.site.ht] = botguard.with_block(THEIRS, "files")
        self.site.write_fails = True
        self.assertEqual(botguard.disable_one(DOMAIN, "files").code, "write")


class SeeingTheWebsites(GuardCase):
    def test_what_a_stranger_can_see_is_reported_for_each_switch(self):
        self.site.files[self.site.docroot + "/wp-content/debug.log"] = "PHP Warning: in /home/shop/..."
        info = botguard._inspect(DOMAIN)
        self.assertTrue(info["checked"])
        r = info["rules"]
        self.assertEqual({k: r[k]["status"] for k in botguard.KEYS}, {"xmlrpc": "off", "files": "off", "users": "off"})
        self.assertTrue(r["xmlrpc"]["open"])
        self.assertEqual(r["files"]["exposed"], ["/wp-content/debug.log"])
        self.assertEqual(r["users"]["shown"], ["mehdi"])

    def test_a_website_that_already_refuses_the_door_and_shows_no_names_is_said_so(self):
        self.site.door_open = False
        self.site.users = []
        r = botguard._inspect(DOMAIN)["rules"]
        self.assertFalse(r["xmlrpc"]["open"])
        self.assertEqual(r["users"]["shown"], [])
        self.assertEqual(r["files"]["exposed"], [])

    def test_after_switching_on_nothing_is_shown_any_more(self):
        self.site.files[self.site.docroot + "/wp-content/debug.log"] = "x"
        for key in botguard.KEYS:
            self.assertTrue(botguard.enable_one(DOMAIN, key).ok, key)
        for _ in range(4):
            self.site.tick()
        r = botguard._inspect(DOMAIN)["rules"]
        self.assertEqual({k: r[k]["status"] for k in botguard.KEYS}, {"xmlrpc": "on", "files": "on", "users": "on"})
        self.assertFalse(r["xmlrpc"]["open"])
        self.assertEqual(r["files"]["exposed"], [])
        self.assertEqual(r["users"]["shown"], [])

    def test_a_settings_file_that_cannot_be_read_is_left_alone(self):
        self.site.is_link = True
        info = botguard._inspect(DOMAIN)
        self.assertFalse(info["checked"])
        self.assertEqual({info["rules"][k]["status"] for k in botguard.KEYS}, {"unsupported"})

    def test_the_page_lists_every_website_after_a_look_and_follows_changes(self):
        botguard.scan_start()
        self.wait(botguard.scan_state)
        state = botguard.state()
        self.assertEqual(state["scan"]["status"], "done")
        self.assertEqual([r["key"] for r in state["rules"]], list(botguard.KEYS))
        self.assertEqual(state["sites"][0]["rules"]["users"]["shown"], ["mehdi"])
        botguard.enable_one(DOMAIN, "users")
        row = botguard.state()["sites"][0]["rules"]["users"]
        self.assertEqual((row["status"], row["shown"]), ("on", []))
        botguard.disable_one(DOMAIN, "users")
        self.assertEqual(botguard.state()["sites"][0]["rules"]["users"]["status"], "off")

    def test_a_website_that_cannot_be_looked_at_does_not_hide_the_others(self):
        with mock.patch.object(botguard, "_inspect", side_effect=RuntimeError("boom")):
            botguard.scan_start()
            self.wait(botguard.scan_state)
        row = botguard.state()["sites"][0]
        self.assertFalse(row["checked"])
        self.assertIn("failed", row["problem"])


class TheJob(GuardCase):
    def test_only_known_actions_switches_and_websites_are_accepted(self):
        for action, key, names in (("explode", "xmlrpc", [DOMAIN]), ("enable", "nope", [DOMAIN]), ("enable", "xmlrpc", []),
                                   ("enable", "xmlrpc", None), ("enable", "xmlrpc", ["nope.example.com"])):
            self.assertEqual(botguard.start(action, key, names).code, "invalid", (action, key, names))
        self.assertEqual(botguard.job_state()["status"], "idle")

    def test_a_job_switches_on_and_off_and_reports_each_website(self):
        self.assertTrue(botguard.start("enable", "xmlrpc", [DOMAIN, DOMAIN]).ok)
        self.wait(botguard.job_state)
        job = botguard.job_state()
        self.assertEqual((job["rule"], [(i["site"], i["status"]) for i in job["items"]]), ("xmlrpc", [(DOMAIN, "done")]))
        self.assertEqual(botguard.status_in(self.text(), "xmlrpc"), "on")
        self.assertTrue(botguard.start("disable", "xmlrpc", [DOMAIN]).ok)
        self.wait(botguard.job_state)
        self.assertNotIn(self.site.ht, self.site.files)

    def test_one_website_failing_does_not_stop_the_next(self):
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.site.docroot, "shopuser", DOMAIN), ("/home/b/public_html", "b", OTHER)])
        calls = []

        def fake(name, key, progress=None):
            calls.append(name)
            if name == DOMAIN:
                raise RuntimeError("boom")
            return botguard.Result(True, "fine")

        with mock.patch.object(botguard, "enable_one", side_effect=fake):
            botguard.start("enable", "files", [DOMAIN, OTHER])
            self.wait(botguard.job_state)
        items = botguard.job_state()["items"]
        self.assertEqual(calls, [DOMAIN, OTHER])
        self.assertEqual([i["status"] for i in items], ["failed", "done"])

    def test_a_second_job_while_one_runs_is_refused(self):
        gate, started = threading.Event(), threading.Event()

        def slow(name, key, progress=None):
            started.set()
            gate.wait(5)
            return botguard.Result(True, "fine")

        with mock.patch.object(botguard, "enable_one", side_effect=slow):
            self.assertTrue(botguard.start("enable", "users", [DOMAIN]).ok)
            self.assertTrue(started.wait(5))
            self.assertEqual(botguard.start("disable", "users", [DOMAIN]).code, "busy")
            gate.set()
            self.wait(botguard.job_state)


if __name__ == "__main__":
    unittest.main()
