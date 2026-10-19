import json
import os
import re
from types import SimpleNamespace
from unittest import mock

from cpsec import config, headers, htfile
from tests.helpers import EnvTestCase

REAL_OWNER = headers._owner          # the tests below replace it for most checks; this one keeps the real thing

WP = "# BEGIN WordPress\nRewriteEngine On\nRewriteRule . /index.php [L]\n# END WordPress\n"
SAFE = {"nosniff", "frame", "referrer", "permissions", "hide_powered"}


class FakeWebServer:
    """Answers curl like LiteSpeed would: it reads the site's .htaccess and sends the headers it asks for."""

    def __init__(self, case):
        self.case = case
        self.status = {}                    # domain -> status to answer with (default 200)
        self.ignore_htaccess = set()        # domains whose .htaccess the server does not read
        self.only = {}                      # domain -> set of header names the server really sends
        self.down = set()                   # domains that do not answer at all
        self.stale = {}                     # domain -> how many more answers still use the OLD .htaccess (LiteSpeed caches it)
        self.snapshot = {}

    def __call__(self, cmd):
        domain = cmd[cmd.index("--resolve") + 1].split(":")[0]
        if domain in self.down:
            return 7, ""
        path = "%s/%s/public_html/.htaccess" % (config.P.home_dir, domain)
        sent = {"server": "LiteSpeed", "x-powered-by": "PHP/8.3"}
        if self.stale.get(domain, 0) > 0:
            self.stale[domain] -= 1
            text = self.snapshot.get(domain)
        elif os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            self.snapshot[domain] = text
        else:
            text = self.snapshot[domain] = None
        if text is not None and domain not in self.ignore_htaccess:
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                m = re.match(r'\s*Header\s+(?:always\s+)?(set|merge|unset)\s+"?([\w-]+)"?(?:\s+"([^"]*)")?', line, re.I)
                if not m:
                    continue
                op, name, value = m.group(1).lower(), m.group(2).lower(), m.group(3) or ""
                if op == "unset":
                    sent.pop(name, None)
                elif name in self.only.get(domain, {name}):
                    sent[name] = value
        lines = ["HTTP/2 %s " % self.status.get(domain, "200")] + ["%s: %s" % kv for kv in sent.items()]
        return 0, "\r\n".join(lines) + "\r\n\r\n"


class HeadersCase(EnvTestCase):
    domains = ("shop.example.com", "blog.example.com")

    def setUp(self):
        super().setUp()
        self.write(config.P.lsws_xml, "<config/>")                     # LiteSpeed Enterprise
        for d in self.domains:
            os.makedirs(self.root_of(d))
            self.write_ht(d, WP)
        self.web = FakeWebServer(self)
        self.fake.table.append((["curl"], self.web))
        # the file work normally runs as another user in another process; here it is called directly,
        # but the request still goes through JSON like it would over the pipe
        self.patch("cpsec.headers._owner", return_value=(1000, 1000))
        self.patch("cpsec.headers._run_as_owner", side_effect=lambda uid, gid, req: json.loads(json.dumps(htfile.handle(json.loads(json.dumps(req))))))
        self.pauses = []
        self.patch("cpsec.headers._sleep", side_effect=self.pauses.append)        # no real waiting in tests
        headers._live.clear()
        self.addCleanup(headers._live.clear)

    def root_of(self, domain):
        return "%s/%s/public_html" % (config.P.home_dir, domain)

    def write_ht(self, domain, text):
        with open(self.root_of(domain) + "/.htaccess", "wb") as f:
            f.write(text.encode("utf-8", errors="surrogateescape"))

    def ht(self, domain):
        with open(self.root_of(domain) + "/.htaccess", "rb") as f:
            return f.read().decode("utf-8", errors="surrogateescape")

    def row(self, domain):
        return next(r for r in headers.state(start_check=False)["sites"] if r["domain"] == domain)

    def chips(self, domain):
        return {c["id"]: c for c in self.row(domain)["chips"]}


class Choices(HeadersCase):
    def test_the_safe_headers_are_on_by_default_and_the_risky_ones_off(self):
        d = headers.load()["defaults"]
        self.assertEqual({k for k in headers.FLAGS if d.get(k)}, SAFE)
        self.assertEqual((d["hsts"], d["hsts_subdomains"], d["csp_upgrade"]), (0, False, False))
        self.assertEqual(self.row("shop.example.com")["status"], "none")

    def test_defaults_are_validated_and_saved(self):
        self.assertTrue(headers.set_defaults({"hsts": 604800, "frame": False}).ok)
        d = headers.load()["defaults"]
        self.assertEqual((d["hsts"], d["frame"]), (604800, False))
        for bad in ({"hsts": 12345}, {"hsts": True}, {"frame": "yes"}, {"nope": True}, {"exclude": True}):
            self.assertEqual(headers.set_defaults(bad).code, "invalid", bad)
        self.assertEqual(headers.load()["defaults"]["hsts"], 604800, "a refused change leaves the saved choices alone")

    def test_one_website_can_differ_and_can_go_back_to_the_default(self):
        self.assertTrue(headers.set_site("shop.example.com", {"frame": False, "hsts": 86400}).ok)
        eff = headers.effective(headers.load(), "shop.example.com")
        self.assertEqual((eff["frame"], eff["hsts"]), (False, 86400))
        self.assertTrue(headers.effective(headers.load(), "blog.example.com")["frame"])
        self.assertTrue(headers.set_site("shop.example.com", {"frame": None, "hsts": None}).ok)
        self.assertEqual(headers.load()["sites"], {})
        self.assertEqual(headers.set_site("nobody.example.com", {"frame": False}).code, "unknown_site")
        self.assertEqual(headers.set_site("shop.example.com", {"hsts": 5}).code, "invalid")

    def test_a_damaged_settings_file_falls_back_to_the_defaults(self):
        self.write(config.P.headers_settings, '{"defaults": {"hsts": "x", "frame": 3}, "sites": {"a": 5}}')
        self.assertEqual(headers.load(), {"defaults": headers.DEFAULTS, "sites": {}})


class Applying(HeadersCase):
    def test_applying_writes_one_block_and_the_website_really_sends_the_headers(self):
        res = headers.apply(["shop.example.com"])
        self.assertTrue(res.ok, res.message)
        text = self.ht("shop.example.com")
        self.assertTrue(text.startswith(htfile.BEGIN))
        self.assertTrue(text.endswith(WP), "the website's own lines are untouched")
        for line in ('Header always set X-Content-Type-Options "nosniff"', 'Header always set X-Frame-Options "SAMEORIGIN"',
                     'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                     'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
                     "Header always unset X-Powered-By"):
            self.assertIn(line, text)
        self.assertNotIn("Strict-Transport-Security", text)
        self.assertNotIn("Content-Security-Policy", text)
        row = self.row("shop.example.com")
        self.assertEqual(row["status"], "applied")
        chips = self.chips("shop.example.com")
        self.assertTrue(all(chips[i]["source"] == "ours" and chips[i]["seen"] for i in SAFE))
        self.assertEqual(chips["hsts"]["source"], "none")
        self.assertEqual(self.row("blog.example.com")["status"], "none", "other websites are not touched")
        self.assertEqual(self.ht("blog.example.com"), WP)

    def test_applying_twice_changes_nothing_and_says_so(self):
        headers.apply()
        before = {d: self.ht(d) for d in self.domains}
        res = headers.apply()
        self.assertTrue(res.ok)
        self.assertIn("2 needed no change", res.message)
        self.assertEqual({d: self.ht(d) for d in self.domains}, before)

    def test_the_backup_keeps_the_original_file(self):
        headers.apply(["shop.example.com"])
        folder = "%s/htaccess/shop.example.com" % config.P.backup_dir
        names = os.listdir(folder)
        self.assertEqual(len(names), 1)
        with open(os.path.join(folder, names[0]), encoding="utf-8") as f:
            self.assertEqual(f.read(), WP)

    def test_hsts_and_content_rules_only_when_switched_on(self):
        headers.set_defaults({"hsts": 604800, "hsts_subdomains": True, "csp_upgrade": True})
        headers.apply(["shop.example.com"])
        text = self.ht("shop.example.com")
        self.assertIn('Header always set Strict-Transport-Security "max-age=604800; includeSubDomains" env=HTTPS', text)
        self.assertIn('Header always merge Content-Security-Policy "upgrade-insecure-requests"', text)
        headers.set_defaults({"hsts_subdomains": False})
        headers.apply(["shop.example.com"])
        self.assertIn('"max-age=604800" env=HTTPS', self.ht("shop.example.com"))
        self.assertEqual(self.row("shop.example.com")["status"], "applied")

    def test_changing_the_choices_makes_the_status_out_of_date_until_applied(self):
        headers.apply()
        headers.set_defaults({"referrer": False})
        self.assertEqual(self.row("shop.example.com")["status"], "outdated")
        headers.apply()
        self.assertNotIn("Referrer-Policy", self.ht("shop.example.com"))
        self.assertEqual(self.row("shop.example.com")["status"], "applied")

    def test_switching_everything_off_and_applying_takes_the_block_away(self):
        headers.apply()
        headers.set_defaults({k: False for k in SAFE})
        headers.apply()
        self.assertEqual(self.ht("shop.example.com"), WP)
        self.assertEqual(self.row("shop.example.com")["status"], "off")

    def test_a_header_the_website_sets_itself_is_left_alone(self):
        own = 'Header always set X-Frame-Options "DENY"\n' + WP
        self.write_ht("shop.example.com", own)
        headers.apply(["shop.example.com"])
        text = self.ht("shop.example.com")
        self.assertNotIn("SAMEORIGIN", text)
        self.assertTrue(text.endswith(own), "their line is exactly as it was")
        self.assertEqual(self.chips("shop.example.com")["frame"]["source"], "site")
        self.assertEqual(self.row("shop.example.com")["status"], "applied")

    def test_a_website_that_sets_everything_itself_gets_no_block(self):
        own = "".join('Header always set %s "x"\n' % i["name"] for i in headers.ITEMS if i["id"] in SAFE) + WP
        self.write_ht("shop.example.com", own)
        res = headers.apply(["shop.example.com"])
        self.assertTrue(res.ok)
        self.assertEqual(self.ht("shop.example.com"), own)
        self.assertEqual(self.row("shop.example.com")["status"], "own")

    def test_taking_over_the_websites_own_lines_and_giving_them_back(self):
        own = 'Header always set X-Frame-Options "DENY"\n' + WP
        self.write_ht("shop.example.com", own)
        res = headers.apply(["shop.example.com"], take_over=True)
        self.assertTrue(res.ok, res.message)
        self.assertIn("took over 1 line", res.message)
        text = self.ht("shop.example.com")
        self.assertIn('SAMEORIGIN', text)
        self.assertIn(htfile.TAKEN + 'Header always set X-Frame-Options "DENY"', text)
        self.assertEqual(self.chips("shop.example.com")["frame"]["source"], "ours")
        self.assertEqual(self.row("shop.example.com")["status"], "applied")
        self.assertTrue(headers.remove(["shop.example.com"]).ok)
        self.assertEqual(self.ht("shop.example.com"), own, "exactly as it was before CP-Security")

    def test_removing_takes_only_our_block_off(self):
        headers.apply()
        res = headers.remove()
        self.assertTrue(res.ok, res.message)
        for d in self.domains:
            self.assertEqual(self.ht(d), WP)
            self.assertEqual(self.row(d)["status"], "none")

    def test_a_website_without_an_htaccess_gets_one_and_loses_it_again(self):
        os.remove(self.root_of("shop.example.com") + "/.htaccess")
        headers.apply(["shop.example.com"])
        self.assertTrue(self.ht("shop.example.com").startswith(htfile.BEGIN))
        headers.remove(["shop.example.com"])
        self.assertFalse(os.path.exists(self.root_of("shop.example.com") + "/.htaccess"))

    def test_a_website_left_alone_is_not_touched(self):
        headers.set_site("shop.example.com", {"exclude": True})
        res = headers.apply()
        self.assertTrue(res.ok)
        self.assertEqual(self.ht("shop.example.com"), WP)
        self.assertEqual(self.row("shop.example.com")["status"], "excluded")
        self.assertIn(htfile.BEGIN, self.ht("blog.example.com"))

    def test_only_websites_on_this_server_can_be_named(self):
        for bad in (["../../etc"], ["shop.example.com", "evil.example.com"], ["shop.example.com/.."]):
            self.assertEqual(headers.apply(bad).code, "unknown_site", bad)
            self.assertEqual(headers.remove(bad).code, "unknown_site", bad)
        self.assertEqual(self.ht("shop.example.com"), WP)


class Safety(HeadersCase):
    def test_a_website_that_stops_answering_gets_its_file_back(self):
        domain = "shop.example.com"
        original_fetch = headers.fetch
        calls = []

        def fetch_then_break(d):
            calls.append(d)
            res = original_fetch(d)
            if len(calls) >= 2:                          # the answer after the change
                self.web.status[d] = "500"
                res = original_fetch(d)
            return res
        with mock.patch("cpsec.headers.fetch", fetch_then_break):
            res = headers.apply([domain])
        self.assertFalse(res.ok)
        self.assertIn("stopped answering", res.message)
        self.assertEqual(self.ht(domain), WP)

    def test_the_web_server_is_given_time_to_notice_the_new_file(self):
        """LiteSpeed re-reads .htaccess only every few seconds: an answer right after the change is still the old one."""
        headers.fetch("shop.example.com")                       # the server has now seen the old file
        self.web.stale["shop.example.com"] = 3
        res = headers.apply(["shop.example.com"])
        self.assertTrue(res.ok, res.message)
        self.assertGreaterEqual(len(self.pauses), 2, "it waited and asked again")
        self.assertIn(htfile.BEGIN, self.ht("shop.example.com"), "and did not undo a good change")
        self.assertEqual(self.chips("shop.example.com")["frame"]["seen"], True)

    def test_taking_over_waits_until_our_value_replaces_the_old_one(self):
        own = 'Header always set X-Frame-Options "DENY"\n' + WP
        self.write_ht("shop.example.com", own)
        headers.fetch("shop.example.com")                       # the server has seen the old file (DENY)
        self.web.stale["shop.example.com"] = 3
        res = headers.apply(["shop.example.com"], take_over=True)
        self.assertTrue(res.ok, res.message)
        self.assertNotIn("Not seen yet", res.message)
        self.assertEqual(headers._live_of("shop.example.com")["headers"]["x-frame-options"], "SAMEORIGIN")
        self.assertGreaterEqual(len(self.pauses), 2)

    def test_removing_waits_until_the_headers_really_stop(self):
        headers.apply(["shop.example.com"])
        headers.fetch("shop.example.com")
        self.pauses.clear()
        self.web.stale["shop.example.com"] = 3
        res = headers.remove(["shop.example.com"])
        self.assertTrue(res.ok, res.message)
        self.assertGreaterEqual(len(self.pauses), 2)
        self.assertEqual(self.chips("shop.example.com")["frame"]["seen"], False, "the page shows the real, final state")

    def test_a_broken_website_is_noticed_as_soon_as_it_breaks_without_waiting_the_full_time(self):
        headers.fetch("shop.example.com")
        calls = []
        real = headers.fetch

        def fetch(d):
            calls.append(d)
            if len(calls) >= 2:
                self.web.status[d] = "500"
            return real(d)
        with mock.patch("cpsec.headers.fetch", fetch):
            res = headers.apply(["shop.example.com"])
        self.assertFalse(res.ok)
        self.assertLessEqual(len(self.pauses), 1, "no long wait for a website that already failed")
        self.assertEqual(self.ht("shop.example.com"), WP)

    def test_a_web_server_that_ignores_the_headers_gets_the_file_put_back(self):
        self.web.ignore_htaccess.add("shop.example.com")
        res = headers.apply(["shop.example.com"])
        self.assertFalse(res.ok)
        self.assertIn("did not send the headers", res.message)
        self.assertEqual(self.ht("shop.example.com"), WP)

    def test_some_headers_missing_is_kept_but_reported(self):
        self.web.only["shop.example.com"] = {"x-content-type-options", "x-frame-options"}
        res = headers.apply(["shop.example.com"])
        self.assertTrue(res.ok, res.message)
        self.assertIn("Not seen yet", res.message)
        self.assertIn(htfile.BEGIN, self.ht("shop.example.com"))

    def test_a_website_that_cannot_be_asked_is_still_changed_but_not_confirmed(self):
        self.web.down.add("shop.example.com")
        res = headers.apply(["shop.example.com"])
        self.assertTrue(res.ok)
        self.assertIn("not confirmed", res.message)
        self.assertIn(htfile.BEGIN, self.ht("shop.example.com"))

    def test_a_damaged_block_is_reported_and_the_file_is_not_touched(self):
        broken = htfile.BEGIN + "\nHeader set X-A 1\n" + WP
        self.write_ht("shop.example.com", broken)
        self.assertEqual(self.row("shop.example.com")["status"], "error")
        res = headers.apply(["shop.example.com"])
        self.assertFalse(res.ok)
        self.assertIn("damaged", res.message)
        self.assertEqual(self.ht("shop.example.com"), broken)

    def test_one_failing_website_does_not_stop_the_others(self):
        self.write_ht("shop.example.com", htfile.BEGIN + "\n")
        res = headers.apply()
        self.assertFalse(res.ok)
        self.assertIn("1 could not be changed", res.message)
        self.assertIn("Applied to 1 website", res.message)
        self.assertIn(htfile.BEGIN, self.ht("blog.example.com"))

    def test_a_folder_owned_by_a_system_account_is_refused(self):
        self.patch("cpsec.headers._owner", side_effect=htfile.Refused("The website's folder belongs to a system account"))
        res = headers.apply(["shop.example.com"])
        self.assertFalse(res.ok)
        self.assertIn("system account", res.message)
        self.assertEqual(self.ht("shop.example.com"), WP)

    def test_the_owner_check_refuses_root_and_system_accounts(self):
        for uid in (0, 33, 99):
            with mock.patch("cpsec.headers.os.stat", return_value=SimpleNamespace(st_uid=uid, st_gid=uid)):
                with self.assertRaises(htfile.Refused):
                    REAL_OWNER("/home/x/public_html")
        with mock.patch("cpsec.headers.os.stat", return_value=SimpleNamespace(st_uid=1001, st_gid=65534)), \
                mock.patch("cpsec.headers._primary_group", return_value=None):
            self.assertEqual(REAL_OWNER("/home/x/public_html"), (1001, 65534), "falls back to the folder's group")
        with mock.patch("cpsec.headers.os.stat", return_value=SimpleNamespace(st_uid=1001, st_gid=65534)), \
                mock.patch("cpsec.headers._primary_group", return_value=1001):
            self.assertEqual(REAL_OWNER("/home/x/public_html"), (1001, 1001), "the user's own group wins")

    def test_nonsense_website_names_in_the_folder_list_are_skipped(self):
        self.assertFalse(headers._safe_domain("a b"))
        self.assertFalse(headers._safe_domain(".hidden"))
        self.assertFalse(headers._safe_domain("a/../b"))
        self.assertTrue(headers._safe_domain("shop.example-1.com"))


class OtherWebServers(HeadersCase):
    def test_openlitespeed_is_told_it_is_not_supported_yet_and_nothing_is_written(self):
        self.write(config.P.lsws_bin_ols, "")                           # the giveaway of OpenLiteSpeed
        st = headers.state(start_check=False)
        self.assertFalse(st["supported"])
        self.assertEqual(st["web_server"], "OpenLiteSpeed")
        res = headers.apply()
        self.assertEqual((res.ok, res.code), (False, "unsupported"))
        self.assertIn("OpenLiteSpeed", res.message)
        self.assertEqual(self.ht("shop.example.com"), WP)

    def test_enterprise_is_supported(self):
        st = headers.state(start_check=False)
        self.assertEqual((st["supported"], st["web_server"]), (True, "LiteSpeed Enterprise"))


class Looking(HeadersCase):
    def test_fetch_reads_the_status_and_every_header(self):
        res = headers.fetch("shop.example.com")
        self.assertEqual(res["status"], "200")
        self.assertEqual(res["headers"]["server"], "LiteSpeed")

    def test_fetch_gives_none_when_the_website_does_not_answer(self):
        self.web.down.add("shop.example.com")
        self.assertIsNone(headers.fetch("shop.example.com"))

    def test_the_page_data_lists_every_website_and_what_it_sends(self):
        headers.apply(["shop.example.com"])
        headers.check_all()
        st = headers.state(start_check=False)
        self.assertEqual([r["domain"] for r in st["sites"]], sorted(self.domains))
        self.assertEqual(st["counts"], {"applied": 1, "none": 1})
        self.assertEqual([i["id"] for i in st["items"]], [i["id"] for i in headers.ITEMS])
        self.assertEqual(st["hsts_choices"][0], {"seconds": 0, "text": "Off"})
        chips = self.chips("blog.example.com")
        self.assertEqual((chips["nosniff"]["seen"], chips["hide_powered"]["seen"]), (False, False))

    def test_a_header_sent_by_something_else_is_noticed(self):
        self.write_ht("blog.example.com", "")
        orig = self.web.__call__

        def with_extra(cmd):
            rc, out = orig(cmd)
            return rc, out.replace("\r\n\r\n", "\r\nx-frame-options: DENY\r\n\r\n")
        self.fake.table[-1] = (["curl"], with_extra)
        headers.check_all(["blog.example.com"])
        self.assertEqual(self.chips("blog.example.com")["frame"]["source"], "other")

    def test_the_summary_for_the_advisor_needs_no_web_requests(self):
        headers.apply(["shop.example.com"])
        self.fake.calls.clear()
        self.assertEqual(headers.summary(), {"total": 2, "needs": 1, "applied": 1})
        self.assertEqual(self.fake.called("curl"), [])

    def test_a_background_look_is_started_once_and_not_again_while_recent(self):
        started = []
        fake_thread = lambda target, daemon: mock.Mock(start=lambda: started.append(1))       # noqa: E731
        with mock.patch("cpsec.headers.threading.Thread", side_effect=fake_thread):
            self.assertTrue(headers.refresh_async())
            self.assertFalse(headers.refresh_async(), "one look at a time")
        headers._checking[0] = False
        headers.check_all()
        with mock.patch("cpsec.headers.threading.Thread", side_effect=fake_thread):
            self.assertFalse(headers.refresh_async(), "a recent look is not repeated")
        self.assertEqual(started, [1])
