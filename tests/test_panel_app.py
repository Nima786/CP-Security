import json

from cpsec import config, settings
from cpsec.panel import auth
from cpsec.panel.app import App, Request
from cpsec.panel.engine import DemoEngine
from tests.helpers import EnvTestCase

PASSWORD = "correct horse battery"
HOST = "panel.example.com"


class PanelCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.secret = auth.new_totp_secret()
        settings.save({"domain": HOST, "port": 9443, "access": "login"})
        settings.save_user({"name": "admin", "password_hash": auth.hash_password(PASSWORD, n=16),
                            "totp_secret": self.secret, "last_counter": 0})
        self.now = [1_700_000_000.0]
        self.engine = DemoEngine()
        self.app = App(self.engine, secure_cookies=True, allowed_hosts=[HOST], sleep=lambda s: None,
                       clock=lambda: self.now[0])
        self.csrf = ""
        self.cookie = ""

    # ---- helpers
    def request(self, method, path, body=None, headers=None, ip="45.60.0.10", host=HOST, raw=None):
        h = {"host": host}
        if self.cookie:
            h["cookie"] = self.cookie
        if method == "POST" and self.csrf:
            h["x-csrf-token"] = self.csrf
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        resp = self.app.handle(Request(method, path, h, data, ip))
        try:
            payload = json.loads(resp.body.decode()) if resp.ctype == "application/json" else None
        except ValueError:
            payload = None
        return resp, payload

    def code(self):
        """A fresh code: each login moves the clock on by one 30-second step."""
        self.now[0] += 30
        return auth.totp_now(self.secret, now=self.now[0])

    def login(self, ip="45.60.0.10"):
        resp, data = self.request("POST", "/api/login",
                                  {"username": "admin", "password": PASSWORD, "code": self.code()}, ip=ip)
        self.assertEqual(resp.status, 200, data)
        self.cookie = dict(resp.headers)["Set-Cookie"].split(";")[0]
        self.csrf = data["csrf"]
        return resp


class Protection(PanelCase):
    def test_every_response_carries_the_security_headers(self):
        resp, _ = self.request("GET", "/")
        headers = dict(resp.headers)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("Strict-Transport-Security", headers)
        resp, _ = self.request("GET", "/api/overview")
        self.assertEqual(dict(resp.headers)["Cache-Control"], "no-store")

    def test_the_page_files_are_served_without_signing_in(self):
        for path, ctype in (("/", "text/html"), ("/app.js", "application/javascript"), ("/app.css", "text/css"),
                            ("/favicon.svg", "image/svg+xml")):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 200, path)
            self.assertTrue(resp.ctype.startswith(ctype), path)
            self.assertGreater(len(resp.body), 100, path)

    def test_the_page_never_uses_inline_scripts_or_styles(self):
        page = self.request("GET", "/")[0].body.decode()
        self.assertNotIn("<script>", page)
        self.assertNotIn("style=", page)
        self.assertNotIn("onclick=", page)
        script = self.request("GET", "/app.js")[0].body.decode()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("eval(", script)

    def test_other_host_names_are_refused(self):
        resp, _ = self.request("GET", "/", host="evil.example.net")
        self.assertEqual(resp.status, 421)
        resp, _ = self.request("GET", "/", host=HOST + ":9443")
        self.assertEqual(resp.status, 200)

    def test_nothing_works_without_signing_in(self):
        for method, path in (("GET", "/api/overview"), ("GET", "/api/blocked"), ("GET", "/api/access"),
                             ("GET", "/api/firewall"), ("GET", "/api/settings"), ("POST", "/api/blocked/unblock-all"),
                             ("POST", "/api/firewall/mode"), ("GET", "/api/activity")):
            resp, data = self.request(method, path, {} if method == "POST" else None)
            self.assertEqual(resp.status, 401, path)
            self.assertEqual(data["code"], "signed_out")

    def test_unknown_things(self):
        self.assertEqual(self.request("GET", "/nothing")[0].status, 404)
        self.assertEqual(self.request("GET", "/api/login")[0].status, 405)
        self.assertEqual(self.request("GET", "/../../etc/passwd")[0].status, 404)

    def test_an_internal_error_never_leaks_details(self):
        self.login()
        self.engine.overview = lambda refresh=False: 1 / 0
        resp, data = self.request("GET", "/api/overview")
        self.assertEqual(resp.status, 500)
        self.assertNotIn("division", json.dumps(data))
        self.assertNotIn("Traceback", json.dumps(data))

    def test_bad_requests(self):
        self.login()
        resp, data = self.request("POST", "/api/blocked/unblock", raw=b"{not json")
        self.assertEqual(resp.status, 400)
        resp, _ = self.request("POST", "/api/blocked/unblock", raw=b"[1,2]")
        self.assertEqual(resp.status, 400)
        resp, _ = self.request("POST", "/api/blocked/unblock", raw=b'{"ip":"' + b"a" * 70000 + b'"}')
        self.assertEqual(resp.status, 400)


class SigningIn(PanelCase):
    def test_a_good_login_sets_a_locked_down_cookie(self):
        resp = self.login()
        cookie = dict(resp.headers)["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
            self.assertIn(flag, cookie)
        resp, data = self.request("GET", "/api/me")
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"], "admin")
        self.assertEqual(data["client_ip"], "45.60.0.10")

    def test_me_when_signed_out(self):
        resp, data = self.request("GET", "/api/me")
        self.assertEqual(resp.status, 200)
        self.assertFalse(data["authenticated"])
        self.assertNotIn("csrf", data)

    def test_wrong_password_username_or_code_all_look_the_same(self):
        good = {"username": "admin", "password": PASSWORD, "code": self.code()}
        for change in ({"password": "wrong wrong wrong"}, {"username": "root"}, {"code": "000000"}, {"code": ""}):
            resp, data = self.request("POST", "/api/login", dict(good, **change))
            self.assertEqual(resp.status, 401)
            self.assertEqual(data["message"], "Wrong username, password or code.")

    def test_a_code_cannot_be_used_twice(self):
        code = self.code()
        body = {"username": "admin", "password": PASSWORD, "code": code}
        self.assertEqual(self.request("POST", "/api/login", body)[0].status, 200)
        self.assertEqual(self.request("POST", "/api/login", body)[0].status, 401)

    def test_five_wrong_tries_lock_the_address_out_and_are_logged_for_the_blocker(self):
        bad = {"username": "admin", "password": "nope nope nope", "code": "123456"}
        for _ in range(5):
            self.assertEqual(self.request("POST", "/api/login", bad, ip="9.9.9.9")[0].status, 401)
        resp, data = self.request("POST", "/api/login", bad, ip="9.9.9.9")
        self.assertEqual(resp.status, 429)
        self.assertEqual(data["code"], "locked")
        self.assertIn("Retry-After", dict(resp.headers))
        # even the right answers are refused while locked
        good = {"username": "admin", "password": PASSWORD, "code": self.code()}
        self.assertEqual(self.request("POST", "/api/login", good, ip="9.9.9.9")[0].status, 429)
        self.assertEqual(self.request("POST", "/api/login", good, ip="45.60.0.10")[0].status, 200)
        log = self.read(config.P.panel_log)
        self.assertEqual(log.count("LOGIN_FAILED ip=9.9.9.9"), 5)

    def test_the_log_line_format_is_what_the_blocker_expects(self):
        self.request("POST", "/api/login", {"username": "admin\nINJECTED", "password": "x", "code": "1"}, ip="8.8.4.4")
        line = self.read(config.P.panel_log).splitlines()[-1]
        self.assertRegex(line, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d LOGIN_FAILED ip=8\.8\.4\.4 user=")
        self.assertEqual(len(self.read(config.P.panel_log).splitlines()), 1, "a newline in the username cannot forge a line")

    def test_signing_out_ends_the_session(self):
        self.login()
        self.assertEqual(self.request("POST", "/api/logout", {})[0].status, 200)
        self.assertEqual(self.request("GET", "/api/overview")[0].status, 401)

    def test_an_idle_session_expires(self):
        self.login()
        self.now[0] += 1900
        self.assertEqual(self.request("GET", "/api/overview")[0].status, 401)


class ChangingThings(PanelCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_changes_need_the_secret_token(self):
        saved, self.csrf = self.csrf, ""
        resp, data = self.request("POST", "/api/blocked/unblock-all", {})
        self.assertEqual((resp.status, data["code"]), (403, "csrf"))
        self.csrf = "wrong-token"
        self.assertEqual(self.request("POST", "/api/blocked/unblock-all", {})[0].status, 403)
        self.csrf = saved
        self.assertEqual(self.request("POST", "/api/blocked/unblock-all", {})[0].status, 200)

    def test_requests_from_another_website_are_refused(self):
        resp, data = self.request("POST", "/api/blocked/unblock-all", {}, headers={"origin": "https://evil.example.net"})
        self.assertEqual(resp.status, 403)
        resp, _ = self.request("POST", "/api/blocked/unblock-all", {}, headers={"origin": "https://" + HOST})
        self.assertEqual(resp.status, 200)

    def test_unblocking(self):
        resp, data = self.request("GET", "/api/blocked")
        ip = data["rows"][0]["ip"]
        resp, data = self.request("POST", "/api/blocked/unblock", {"ip": ip})
        self.assertTrue(data["ok"])
        resp, data = self.request("POST", "/api/blocked/unblock", {"ip": ip})
        self.assertEqual((resp.status, data["code"]), (400, "not_blocked"))

    def test_removing_the_address_you_are_using_needs_confirmation(self):
        resp, data = self.request("POST", "/api/access/remove", {"address": "45.60.0.10"})
        self.assertEqual((resp.status, data["code"]), (409, "needs_confirm"))
        resp, data = self.request("POST", "/api/access/remove", {"address": "45.60.0.10", "confirmed": True})
        self.assertTrue(data["ok"])

    def test_use_my_current_address_as_home(self):
        resp, data = self.request("POST", "/api/access/home", {}, ip="93.184.216.34")
        self.assertTrue(data["ok"], data)
        resp, data = self.request("GET", "/api/access", ip="93.184.216.34")
        self.assertEqual([t["address"] for t in data["trusted"] if t["is_home"]], ["93.184.216.34"])
        self.assertTrue(data["client_ip_trusted"])

    def test_a_private_address_cannot_become_home(self):
        resp, data = self.request("POST", "/api/access/home", {}, ip="192.168.1.20")
        self.assertEqual((resp.status, data["code"]), (400, "invalid"))

    def test_blocking_mode_needs_the_word_block(self):
        resp, data = self.request("POST", "/api/firewall/mode", {"mode": "block"})
        self.assertEqual((resp.status, data["code"]), (400, "needs_confirm"))
        self.assertEqual(self.engine.mode, "watch")
        resp, data = self.request("POST", "/api/firewall/mode", {"mode": "block", "confirm": "BLOCK", "threshold": 10})
        self.assertTrue(data["ok"])
        self.assertEqual((self.engine.mode, self.engine.threshold), ("block", 10))
        resp, data = self.request("POST", "/api/firewall/mode", {"mode": "block", "confirm": "BLOCK", "threshold": "abc"})
        self.assertEqual(data["code"], "invalid")

    def test_firewall_page_has_everything_the_interface_needs(self):
        resp, data = self.request("GET", "/api/firewall")
        for key in ("mode", "threshold", "exceptions", "summary", "recent"):
            self.assertIn(key, data)

    def test_exceptions_round_trip(self):
        body = {"scope": "site", "host": "shop.example.com", "rule": "942100"}
        self.assertTrue(self.request("POST", "/api/firewall/exception", body)[1]["ok"])
        self.assertEqual(self.request("POST", "/api/firewall/exception", body)[1]["code"], "exists")
        self.assertTrue(self.request("POST", "/api/firewall/exception/remove", {"index": 0})[1]["ok"])
        self.assertEqual(self.request("POST", "/api/firewall/exception/remove", {"index": "x"})[0].status, 400)

    def test_updates_page(self):
        self.assertEqual(self.request("GET", "/api/updates")[1]["status"], "idle")
        self.assertTrue(self.request("POST", "/api/updates/refresh", {})[1]["ok"])
        self.assertEqual(self.request("GET", "/api/updates")[1]["status"], "done")

    def test_changes_are_written_to_the_activity_log(self):
        self.request("POST", "/api/blocked/unblock-all", {})
        events = self.request("GET", "/api/activity")[1]["events"]
        self.assertIn("UNBLOCK_ALL", [e["event"] for e in events])
        self.assertIn("LOGIN", [e["event"] for e in events])


class Settings(PanelCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_changing_the_password(self):
        other = App(self.engine, allowed_hosts=[HOST], sleep=lambda s: None, clock=lambda: self.now[0],
                    sessions=self.app.sessions, limiter=self.app.limiter)
        resp, data = self.request("POST", "/api/settings/password", {"current": "not it at all!!", "new": "a brand new passphrase"})
        self.assertEqual(data["code"], "bad_password")
        resp, data = self.request("POST", "/api/settings/password", {"current": PASSWORD, "new": "short"})
        self.assertEqual(data["code"], "weak_password")
        other_cookie_session = self.app.sessions.create("admin", "1.2.3.4")[0]
        resp, data = self.request("POST", "/api/settings/password", {"current": PASSWORD, "new": "a brand new passphrase"})
        self.assertTrue(data["ok"], data)
        self.assertIsNone(self.app.sessions.get(other_cookie_session), "other devices are signed out")
        self.assertEqual(self.request("GET", "/api/settings")[0].status, 200, "this device stays signed in")
        self.assertTrue(auth.verify_password("a brand new passphrase", settings.get_user()["password_hash"]))

    def test_trusted_only_mode_warns_before_locking_you_out(self):
        resp, data = self.request("POST", "/api/settings/access", {"access": "trusted"}, ip="93.184.216.99")
        self.assertEqual((resp.status, data["code"]), (409, "needs_confirm"))
        self.assertEqual(settings.load()["access"], "login")
        resp, data = self.request("POST", "/api/settings/access", {"access": "trusted", "confirmed": True}, ip="93.184.216.99")
        self.assertTrue(data["ok"])
        self.assertEqual(settings.load()["access"], "trusted")
        resp, data = self.request("POST", "/api/settings/access", {"access": "nonsense"})
        self.assertEqual(resp.status, 400)

    def test_trusted_only_from_a_trusted_address_needs_no_confirmation(self):
        resp, data = self.request("POST", "/api/settings/access", {"access": "trusted"}, ip="45.60.0.10")
        self.assertTrue(data["ok"], data)

    def test_new_authenticator_key(self):
        resp, data = self.request("POST", "/api/settings/2fa/start", {"password": "wrong wrong wrong"})
        self.assertEqual(data["code"], "bad_password")
        resp, data = self.request("POST", "/api/settings/2fa/start", {"password": PASSWORD})
        new_secret = data["secret"]
        self.assertTrue(data["uri"].startswith("otpauth://"))
        self.assertEqual(settings.get_user()["totp_secret"], self.secret, "nothing changes until confirmed")
        self.assertEqual(self.request("POST", "/api/settings/2fa/confirm", {"code": "000000"})[1]["code"], "bad_code")
        self.now[0] += 30
        code = auth.totp_now(new_secret, now=self.now[0])
        self.assertTrue(self.request("POST", "/api/settings/2fa/confirm", {"code": code})[1]["ok"])
        self.assertEqual(settings.get_user()["totp_secret"], new_secret)
        self.assertEqual(self.request("POST", "/api/settings/2fa/confirm", {"code": code})[1]["code"], "no_pending")
