import json
import threading

from cpsec import config, settings
from cpsec.panel import auth
from cpsec.panel.app import App, Request
from cpsec.panel.engine import DemoEngine
from tests.helpers import EnvTestCase

PASSWORD = "correct horse battery"
HOST = "panel.example.com"


class PanelCase(EnvTestCase):
    twofa = False                       # most tests use the plain username + password login

    def setUp(self):
        super().setUp()
        self.secret = auth.new_totp_secret()
        settings.save({"domain": HOST, "port": 9443, "access": "login"})
        user = {"name": "admin", "password_hash": auth.hash_password(PASSWORD, n=16), "totp_enabled": self.twofa, "last_counter": 0}
        if self.twofa:
            user["totp_secret"] = self.secret
        settings.save_user(user)
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
        body = {"username": "admin", "password": PASSWORD}
        if self.twofa:
            body["code"] = self.code()
        resp, data = self.request("POST", "/api/login", body, ip=ip)
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

    def test_a_wrong_username_or_password_look_the_same(self):
        good = {"username": "admin", "password": PASSWORD}
        for change in ({"password": "wrong wrong wrong"}, {"username": "root"}, {"password": ""}, {"username": "ADMIN"}):
            resp, data = self.request("POST", "/api/login", dict(good, **change))
            self.assertEqual(resp.status, 401)
            self.assertEqual(data["message"], "Wrong username or password.")

    def test_no_code_is_asked_for_unless_the_owner_turned_it_on(self):
        self.assertFalse(self.request("GET", "/api/me")[1]["twofa"])
        self.assertEqual(self.request("POST", "/api/login", {"username": "admin", "password": PASSWORD})[0].status, 200)

    def test_five_wrong_tries_lock_the_address_out_and_are_logged_for_the_blocker(self):
        bad = {"username": "admin", "password": "nope nope nope", "code": "123456"}
        for _ in range(5):
            self.assertEqual(self.request("POST", "/api/login", bad, ip="9.9.9.9")[0].status, 401)
        resp, data = self.request("POST", "/api/login", bad, ip="9.9.9.9")
        self.assertEqual(resp.status, 429)
        self.assertEqual(data["code"], "locked")
        self.assertIn("Retry-After", dict(resp.headers))
        # even the right answers are refused while locked
        good = {"username": "admin", "password": PASSWORD}
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


class TwoStepLogin(PanelCase):
    twofa = True

    def test_the_login_page_learns_that_a_code_is_needed(self):
        self.assertTrue(self.request("GET", "/api/me")[1]["twofa"])

    def test_the_password_alone_is_not_enough(self):
        resp, data = self.request("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        self.assertEqual((resp.status, data["message"]), (401, "Wrong username, password or code."))
        resp, data = self.request("POST", "/api/login", {"username": "admin", "password": PASSWORD, "code": "000000"})
        self.assertEqual(resp.status, 401)

    def test_a_code_cannot_be_used_twice(self):
        body = {"username": "admin", "password": PASSWORD, "code": self.code()}
        self.assertEqual(self.request("POST", "/api/login", body)[0].status, 200)
        self.assertEqual(self.request("POST", "/api/login", body)[0].status, 401)

    def test_a_good_code_signs_in(self):
        self.login()
        self.assertTrue(self.request("GET", "/api/me")[1]["authenticated"])


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
        _ = App(self.engine, allowed_hosts=[HOST], sleep=lambda s: None, clock=lambda: self.now[0],
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

    def test_turning_the_optional_code_on_and_off(self):
        resp, data = self.request("POST", "/api/settings/2fa/start", {"password": "wrong wrong wrong"})
        self.assertEqual(data["code"], "bad_password")
        resp, data = self.request("POST", "/api/settings/2fa/start", {"password": PASSWORD})
        new_secret = data["secret"]
        self.assertTrue(data["uri"].startswith("otpauth://"))
        self.assertFalse(settings.get_user().get("totp_enabled"), "nothing changes until confirmed")
        self.assertEqual(self.request("POST", "/api/settings/2fa/confirm", {"code": "000000"})[1]["code"], "bad_code")
        self.now[0] += 30
        code = auth.totp_now(new_secret, now=self.now[0])
        self.assertTrue(self.request("POST", "/api/settings/2fa/confirm", {"code": code})[1]["ok"])
        self.assertTrue(settings.get_user()["totp_enabled"])
        self.assertEqual(self.request("POST", "/api/settings/2fa/confirm", {"code": code})[1]["code"], "no_pending")
        self.assertEqual(self.request("POST", "/api/settings/2fa/disable", {"password": "nope nope nope"})[1]["code"], "bad_password")
        self.assertTrue(self.request("POST", "/api/settings/2fa/disable", {"password": PASSWORD})[1]["ok"])
        self.assertFalse(settings.get_user()["totp_enabled"])
        self.assertNotIn("totp_secret", settings.get_user())


class AdvisorAndSetup(PanelCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_the_advisor_needs_a_session_and_lists_worst_problems_first(self):
        self.cookie = ""
        self.assertEqual(self.request("GET", "/api/advisor")[0].status, 401)
        self.login()
        resp, data = self.request("GET", "/api/advisor")
        self.assertEqual(resp.status, 200)
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
        levels = [order[f["level"]] for f in data["findings"]]
        self.assertEqual(levels, sorted(levels))
        self.assertEqual(sum(data["counts"].values()), len(data["findings"]))
        self.assertIn("web_server", data["server"])

    def test_a_fix_button_does_its_job_and_the_finding_goes_away(self):
        _, before = self.request("GET", "/api/advisor")
        self.assertIn("cloudflare", [f["id"] for f in before["findings"]])
        resp, data = self.request("POST", "/api/advisor/fix", {"id": "add_cloudflare"})
        self.assertTrue(data["ok"], data)
        _, after = self.request("GET", "/api/advisor?refresh=1")
        self.assertNotIn("cloudflare", [f["id"] for f in after["findings"]])

    def test_an_unknown_fix_is_refused(self):
        resp, data = self.request("POST", "/api/advisor/fix", {"id": "format-the-disk"})
        self.assertEqual((resp.status, data["ok"]), (400, False))

    def test_the_setup_page_shows_a_plan(self):
        resp, data = self.request("GET", "/api/setup")
        self.assertEqual(resp.status, 200)
        keys = [s["key"] for s in data["plan"]]
        self.assertEqual(keys, ["migrate", "lock", "blocker", "feed", "baseline", "waf", "retire"])
        self.assertIn("web_server", data["server"])

    def test_setup_runs_in_the_background_and_reports_progress(self):
        import time
        resp, data = self.request("POST", "/api/setup/run", {})
        self.assertTrue(data["ok"], data)
        for _ in range(100):
            _, state = self.request("GET", "/api/setup")
            if state["job"]["status"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(state["job"]["status"], "done")
        self.assertTrue(all(s["state"] == "done" for s in state["job"]["steps"]))
        self.assertTrue(state["job"]["log"])
        _, again = self.request("POST", "/api/setup/run", {})
        self.assertFalse(again["ok"], "nothing is left to do")

    def test_only_known_steps_can_be_asked_for(self):
        for keys in (["format"], "all", [1], {"a": 1}):
            resp, data = self.request("POST", "/api/setup/run", {"keys": keys})
            self.assertEqual(resp.status, 400, keys)

    def test_the_setup_start_is_written_to_the_activity_log(self):
        self.request("POST", "/api/setup/run", {"keys": ["retire"]})
        _, data = self.request("GET", "/api/activity")
        self.assertTrue(any(e["event"] == "SETUP_START" for e in data["events"]))

    def test_blocker_numbers_round_trip_and_silly_ones_are_refused(self):
        _, data = self.request("GET", "/api/settings/blocker")
        self.assertEqual(data["tuning"]["sshd"]["maxretry"], 4)
        self.assertIn("sshd", data["names"])
        resp, ok = self.request("POST", "/api/settings/blocker", {"changes": {"sshd": {"maxretry": 3}}})
        self.assertTrue(ok["ok"], ok)
        _, data = self.request("GET", "/api/settings/blocker")
        self.assertEqual(data["tuning"]["sshd"]["maxretry"], 3)
        for bad in ({"sshd": {"maxretry": 0}}, {"sshd": {"maxretry": "5"}}, {"nope": {"maxretry": 3}}):
            resp, data = self.request("POST", "/api/settings/blocker", {"changes": bad})
            self.assertEqual(resp.status, 400, bad)
        self.assertEqual(self.request("POST", "/api/settings/blocker", {"changes": "x"})[0].status, 400)

    def test_the_never_block_list_can_be_edited(self):
        resp, data = self.request("POST", "/api/access/never/add", {"address": "45.60.0.77", "label": "Office"})
        self.assertTrue(data["ok"], data)
        _, state = self.request("GET", "/api/access")
        self.assertIn("45.60.0.77", [n["address"] for n in state["never_block"]])
        self.assertFalse(self.request("POST", "/api/access/never/add", {"address": "10.0.0.1"})[1]["ok"])
        self.assertTrue(self.request("POST", "/api/access/never/remove", {"address": "45.60.0.77"})[1]["ok"])
        self.assertEqual(self.request("POST", "/api/access/never/remove", {"address": "45.60.0.77"})[0].status, 400)

    def test_the_open_ports_page_lists_doors_and_every_choice_works(self):
        _, data = self.request("GET", "/api/ports")
        self.assertTrue(data["supported"])
        self.assertTrue(data["client_ip_trusted"])
        rows = {r["port"]: r for r in data["ports"]}
        self.assertEqual(rows[6379]["level"], "bad")
        self.assertEqual(rows[5000]["level"], "warn")
        self.assertEqual(rows[8090]["locked_by"], "default")

        resp, res = self.request("POST", "/api/ports/lock", {"port": 5000, "confirmed": True})
        self.assertTrue(res["ok"], res)
        rows = {r["port"]: r for r in self.request("GET", "/api/ports")[1]["ports"]}
        self.assertEqual((rows[5000]["status"], rows[5000]["locked_by"]), ("locked", "you"))
        resp, res = self.request("POST", "/api/ports/lock", {"port": 80, "confirmed": True})
        self.assertEqual((resp.status, res["code"]), (400, "protected"))
        resp, res = self.request("POST", "/api/ports/lock", {"port": 22})
        self.assertEqual((resp.status, res["code"]), (409, "needs_confirm"))

        self.assertTrue(self.request("POST", "/api/ports/unlock", {"port": 5000})[1]["ok"])
        resp, res = self.request("POST", "/api/ports/unlock", {"port": 8090})
        self.assertEqual((resp.status, res["code"]), (409, "needs_confirm"))
        self.assertTrue(self.request("POST", "/api/ports/unlock", {"port": 8090, "confirmed": True})[1]["ok"])

        self.assertTrue(self.request("POST", "/api/ports/accept", {"port": 6379})[1]["ok"])
        rows = {r["port"]: r for r in self.request("GET", "/api/ports")[1]["ports"]}
        self.assertEqual((rows[6379]["level"], rows[6379]["ignored"]), ("info", True))
        self.assertTrue(self.request("POST", "/api/ports/accept", {"port": 6379, "accepted": False})[1]["ok"])

    def test_updates_are_started_by_hand_and_the_list_follows(self):
        self.request("POST", "/api/updates/refresh", {})
        self.engine.WP_DEMO_SECONDS = 0.01
        self.assertEqual(self.request("GET", "/api/wpupdate")[1]["status"], "idle")
        woo = {"site": "shop.example.com", "kind": "plugin", "slug": "woocommerce"}
        resp, res = self.request("POST", "/api/wpupdate/start", {"items": [woo]})
        self.assertEqual((resp.status, res["code"]), (409, "needs_confirm"))
        for bad in ([], "x", [{"site": "shop.example.com", "kind": "core", "slug": "x"}], [{"site": "nope", "kind": "plugin", "slug": "x"}]):
            resp, res = self.request("POST", "/api/wpupdate/start", {"items": bad, "confirmed": True})
            self.assertEqual(resp.status, 400, bad)
        items = [woo, {"site": "shop.example.com", "kind": "theme", "slug": "bricks"},
                 {"site": "blog.example.com", "kind": "plugin", "slug": "old-gallery"}]
        resp, res = self.request("POST", "/api/wpupdate/start", {"items": items, "confirmed": True})
        self.assertTrue(res["ok"], res)
        import time as _t
        _t.sleep(0.15)
        job = self.request("GET", "/api/wpupdate")[1]
        self.assertEqual(job["status"], "done")
        self.assertEqual([i["status"] for i in job["items"]], ["done", "restored", "failed"])
        self.assertIn("old version", job["items"][1]["message"])
        self.assertEqual(job["counts"]["done"], 1)
        left = {(s["site"], i["slug"]) for s in self.request("GET", "/api/updates")[1]["sites"] for i in s["items"]}
        self.assertNotIn(("shop.example.com", "woocommerce"), left, "an updated item leaves the waiting list")
        self.assertIn(("shop.example.com", "bricks"), left, "a failed or put-back item is still waiting")
        self.assertEqual(self.request("POST", "/api/wpupdate/stop", {})[1]["code"], "none")
        log = self.request("GET", "/api/activity")[1]["events"]
        self.assertTrue(any(e["event"] == "WP_UPDATE_START" for e in log))

    def test_careful_updates_are_marked_in_the_list(self):
        self.request("POST", "/api/updates/refresh", {})
        items = {i["slug"]: i for s in self.request("GET", "/api/updates")[1]["sites"] for i in s["items"]}
        self.assertTrue(items["woocommerce"]["careful"])
        self.assertTrue(items["bricks"]["careful"])
        self.assertFalse(items["wordpress-seo"]["careful"])

    def test_stopping_skips_the_rest(self):
        self.request("POST", "/api/updates/refresh", {})
        self.engine.WP_DEMO_SECONDS = 0.2
        items = [{"site": "shop.example.com", "kind": "plugin", "slug": "woocommerce"}, {"site": "shop.example.com", "kind": "plugin", "slug": "wordpress-seo"},
                 {"site": "blog.example.com", "kind": "plugin", "slug": "woocommerce"}]
        self.request("POST", "/api/wpupdate/start", {"items": items, "confirmed": True})
        self.assertTrue(self.request("POST", "/api/wpupdate/stop", {})[1]["ok"])
        import time as _t
        _t.sleep(0.8)
        job = self.request("GET", "/api/wpupdate")[1]
        self.assertEqual(job["status"], "done")
        self.assertEqual([i["status"] for i in job["items"]], ["done", "skipped", "skipped"])

    def test_the_server_firewall_page_and_every_button_work(self):
        _, data = self.request("GET", "/api/serverfw")
        self.assertFalse(data["loaded"])
        self.assertEqual(data["truth"]["cyberpanel"]["level"], "bad")
        self.assertEqual(data["truth"]["verdict"]["level"], "bad")
        self.assertTrue(data["suggestions"])
        self.assertEqual(data["pending"], None)

        resp, res = self.request("POST", "/api/serverfw/add", {"name": "Tunnel", "proto": "tcp", "address": "", "port": "4445"})
        self.assertTrue(res["ok"], res)
        resp, res = self.request("POST", "/api/serverfw/add", {"name": "Tunnel", "proto": "tcp", "address": "", "port": "4445"})
        self.assertEqual((resp.status, res["code"]), (400, "exists"))
        resp, res = self.request("POST", "/api/serverfw/add", {"name": "Bad", "proto": "icmp", "port": "1"})
        self.assertEqual((resp.status, res["code"]), (400, "invalid"))
        self.assertTrue(self.request("POST", "/api/serverfw/import", {})[1]["ok"])
        self.assertTrue(self.request("POST", "/api/serverfw/suggested", {})[1]["ok"])

        resp, res = self.request("POST", "/api/serverfw/power", {"action": "on"})
        self.assertEqual((resp.status, res["code"]), (409, "needs_confirm"))
        resp, res = self.request("POST", "/api/serverfw/power", {"action": "on", "confirmed": True})
        self.assertEqual((resp.status, res["code"]), (200, "pending"))
        data = self.request("GET", "/api/serverfw")[1]
        self.assertTrue(data["loaded"])
        self.assertGreater(data["pending"]["seconds_left"], 100)
        self.assertEqual(self.request("POST", "/api/serverfw/power", {"action": "on", "confirmed": True})[1]["code"], "pending")
        self.assertTrue(self.request("POST", "/api/serverfw/keep", {})[1]["ok"])
        self.assertEqual(self.request("POST", "/api/serverfw/keep", {})[1]["code"], "none")

        rid = self.request("GET", "/api/serverfw")[1]["rules"][0]["id"]
        resp, res = self.request("POST", "/api/serverfw/remove", {"id": rid})
        if res["code"] == "needs_confirm":
            self.assertTrue(self.request("POST", "/api/serverfw/remove", {"id": rid, "confirmed": True})[1]["ok"])
        self.assertTrue(self.request("POST", "/api/serverfw/power", {"action": "reload"})[1]["ok"])
        self.assertTrue(self.request("POST", "/api/serverfw/power", {"action": "off"})[1]["ok"])
        self.assertFalse(self.request("GET", "/api/serverfw")[1]["loaded"])
        self.assertEqual(self.request("POST", "/api/serverfw/power", {"action": "explode"})[1]["code"], "invalid")

    def test_turning_the_demo_firewall_on_can_be_undone(self):
        self.request("POST", "/api/serverfw/power", {"action": "on", "confirmed": True})
        before = len(self.request("GET", "/api/serverfw")[1]["rules"])
        self.assertGreater(before, 0)
        self.assertTrue(self.request("POST", "/api/serverfw/undo", {})[1]["ok"])
        data = self.request("GET", "/api/serverfw")[1]
        self.assertEqual((data["loaded"], len(data["rules"]), data["pending"]), (False, 0, None))

    def test_the_server_firewall_routes_refuse_nonsense_and_are_logged(self):
        for path, body in (("/api/serverfw/suggested", {"keys": "tcp::80"}), ("/api/serverfw/suggested", {"keys": [5]})):
            resp, res = self.request("POST", path, body)
            self.assertEqual(resp.status, 400, (path, body))
        resp, res = self.request("POST", "/api/serverfw/remove", {"id": "x"})
        self.assertEqual((resp.status, res["code"]), (400, "missing"))
        self.request("POST", "/api/serverfw/power", {"action": "off"})
        _, log = self.request("GET", "/api/activity")
        self.assertTrue(any(e["event"] == "FW_POWER" for e in log["events"]))

    def test_the_security_headers_page_and_every_choice_work(self):
        _, data = self.request("GET", "/api/headers")
        self.assertTrue(data["supported"])
        rows = {r["domain"]: r for r in data["sites"]}
        self.assertEqual(rows["blog.example.com"]["status"], "applied")
        self.assertEqual(rows["shop.example.com"]["status"], "none")
        self.assertEqual(rows["old.example.com"]["status"], "error")
        self.assertEqual({i["id"] for i in data["items"] if data["defaults"].get(i["id"])},
                         {"nosniff", "frame", "referrer", "permissions", "hide_powered"})

        self.assertTrue(self.request("POST", "/api/headers/defaults", {"changes": {"hsts": 604800}})[1]["ok"])
        self.assertEqual(self.request("GET", "/api/headers")[1]["defaults"]["hsts"], 604800)
        resp, res = self.request("POST", "/api/headers/defaults", {"changes": {"hsts": 7}})
        self.assertEqual((resp.status, res["code"]), (400, "invalid"))

        resp, res = self.request("POST", "/api/headers/apply", {"domains": ["shop.example.com"]})
        self.assertTrue(res["ok"], res)
        rows = {r["domain"]: r for r in self.request("GET", "/api/headers")[1]["sites"]}
        self.assertEqual(rows["shop.example.com"]["status"], "applied")
        self.assertEqual(rows["blog.example.com"]["status"], "outdated", "the new HSTS choice reaches it only when applied")

        resp, res = self.request("POST", "/api/headers/site", {"domain": "shop.example.com", "changes": {"frame": False}, "apply": True})
        self.assertTrue(res["ok"], res)
        resp, res = self.request("POST", "/api/headers/site", {"domain": "shop.example.com", "changes": {"exclude": True}})
        self.assertIn("left alone", res["message"])
        resp, res = self.request("POST", "/api/headers/remove", {"all": True})
        self.assertFalse(res["ok"])                              # the demo's damaged website cannot be changed
        self.assertIn("1 could not be changed", res["message"])
        self.assertTrue(self.request("POST", "/api/headers/check", {})[1]["ok"])

    def test_the_security_headers_routes_refuse_nonsense_and_are_logged(self):
        for path, body in (("/api/headers/apply", {}), ("/api/headers/apply", {"domains": []}),
                           ("/api/headers/apply", {"domains": "shop.example.com"}), ("/api/headers/remove", {"domains": [5]}),
                           ("/api/headers/site", {"domain": "shop.example.com", "changes": "x"}),
                           ("/api/headers/site", {"domain": "shop.example.com", "changes": {"frame": "yes"}})):
            resp, res = self.request("POST", path, body)
            self.assertEqual(resp.status, 400, (path, body))
        resp, res = self.request("POST", "/api/headers/apply", {"domains": ["nobody.example.com"]})
        self.assertEqual((resp.status, res["code"]), (400, "unknown_site"))
        self.request("POST", "/api/headers/apply", {"all": True})
        _, log = self.request("GET", "/api/activity")
        self.assertTrue(any(e["event"] == "HEADERS_APPLY" for e in log["events"]))

    def test_the_open_ports_routes_refuse_nonsense_and_are_logged(self):
        for body in ({}, {"port": "abc"}, {"port": True}, {"port": -1}, {"port": 99999}):
            resp, res = self.request("POST", "/api/ports/lock", body)
            self.assertEqual(resp.status, 400, body)
            self.assertFalse(res["ok"])
        self.request("POST", "/api/ports/lock", {"port": 5000, "confirmed": True})
        _, log = self.request("GET", "/api/activity")
        self.assertTrue(any(e["event"] == "PORT_LOCK" for e in log["events"]))

    def test_the_firewall_self_test_and_the_saved_baseline(self):
        self.assertTrue(self.request("POST", "/api/firewall/selftest", {})[1]["ok"])
        self.assertTrue(self.request("POST", "/api/settings/baseline", {})[1]["ok"])

    def test_settings_tell_the_page_about_the_second_step_and_the_server(self):
        _, data = self.request("GET", "/api/settings")
        self.assertIs(data["twofa"], False)
        self.assertEqual(data["server"]["web_server_kind"], "openlitespeed")
        self.assertTrue(data["server"]["certificate"]["found"])

    def test_new_changes_still_need_the_secret_token(self):
        self.csrf = ""
        for path in ("/api/advisor/fix", "/api/setup/run", "/api/settings/blocker", "/api/access/never/add",
                     "/api/firewall/selftest", "/api/settings/baseline", "/api/ports/lock", "/api/ports/unlock",
                     "/api/ports/accept", "/api/headers/defaults", "/api/headers/check", "/api/headers/apply",
                     "/api/headers/remove", "/api/headers/site", "/api/serverfw/add", "/api/serverfw/remove",
                     "/api/serverfw/power", "/api/serverfw/keep", "/api/serverfw/undo", "/api/serverfw/import",
                     "/api/serverfw/suggested", "/api/wpupdate/start", "/api/wpupdate/stop"):
            self.assertEqual(self.request("POST", path, {})[0].status, 403, path)


class LiveDataRoutes(PanelCase):
    """Every page's data, read from the real engine (not the demo one) on a pretend server.
    A mistake that only shows with real data would otherwise first appear on a customer's server."""

    def setUp(self):
        super().setUp()
        from cpsec.panel.engine import LiveEngine
        self.engine = LiveEngine()
        self.app = App(self.engine, secure_cookies=True, allowed_hosts=[HOST], sleep=lambda s: None,
                       clock=lambda: self.now[0])
        self.patch("cpsec.blocker.installed", return_value=False)
        self.login()

    def test_every_page_answers_without_an_internal_error(self):
        paths = ["/api/me", "/api/overview", "/api/blocked", "/api/access", "/api/ports", "/api/headers", "/api/serverfw", "/api/wpupdate", "/api/firewall",
                 "/api/updates",
                 "/api/settings", "/api/settings/blocker", "/api/activity", "/api/advisor", "/api/setup",
                 "/api/overview?refresh=1", "/api/advisor?refresh=1"]
        for path in paths:
            resp, data = self.request("GET", path)
            from cpsec.panel import activity
            self.assertEqual(resp.status, 200, "%s -> %s %s | log: %s" % (path, resp.status, data, activity.recent(3)))

    def test_the_setup_plan_and_the_advisor_describe_a_bare_server(self):
        _, setup = self.request("GET", "/api/setup")
        self.assertEqual([s["key"] for s in setup["plan"]],
                         ["migrate", "lock", "blocker", "feed", "baseline", "waf", "retire"])
        _, advice = self.request("GET", "/api/advisor")
        self.assertTrue(advice["findings"])
        self.assertEqual(sum(advice["counts"].values()), len(advice["findings"]))

    def test_a_change_on_a_bare_server_is_refused_politely_not_with_a_crash(self):
        for path, body in (("/api/firewall/mode", {"mode": "watch"}), ("/api/blocked/unblock", {"ip": "45.60.0.99"}),
                           ("/api/access/never/add", {"address": "45.60.0.98"}), ("/api/firewall/selftest", {})):
            resp, data = self.request("POST", path, body)
            self.assertIn(resp.status, (200, 400, 409), "%s -> %s %s" % (path, resp.status, data))
            self.assertIn("ok", data)


class TheOverviewDoesNotWait(PanelCase):
    """Asking all websites takes seconds: the page must appear at once and the answers arrive in the background."""

    def setUp(self):
        super().setUp()
        from cpsec.panel.engine import LiveEngine
        self.engine = LiveEngine()
        self.app = App(self.engine, secure_cookies=True, allowed_hosts=[HOST], sleep=lambda s: None,
                       clock=lambda: self.now[0])
        self.patch("cpsec.blocker.installed", return_value=False)
        self.gate = threading.Event()
        self.asked = []

        def slow_check(domains=None):
            self.asked.append(1)
            self.gate.wait(10)
            return [("a.example.com", "200"), ("b.example.com", "500")]
        self.patch("cpsec.sites.check_sites", side_effect=slow_check)
        self.login()

    def tearDown(self):
        self.gate.set()
        super().tearDown()

    def test_the_first_page_comes_back_while_the_websites_are_still_being_asked(self):
        import time
        started = time.time()
        resp, data = self.request("GET", "/api/overview")
        self.assertLess(time.time() - started, 3, "must not wait for the websites")
        self.assertEqual(resp.status, 200)
        self.assertTrue(data["sites_pending"])
        self.assertTrue(data["sites_checking"])
        row = [r for r in data["rows"] if r["key"] == "sites"][0]
        self.assertIn("Checking", row["text"])

    def test_when_the_answers_are_in_they_show_up(self):
        self.request("GET", "/api/overview")
        self.gate.set()
        for _ in range(100):
            _, data = self.request("GET", "/api/overview")
            if not data["sites_checking"] and not data["sites_pending"]:
                break
            import time
            time.sleep(0.05)
        self.assertFalse(data["sites_pending"])
        self.assertEqual(data["sites"]["total"], 2)
        self.assertTrue(data["sites_checked_at"])

    def test_asking_again_shows_the_old_answers_at_once_and_refreshes_behind_them(self):
        # the new check stays blocked on purpose, so the old answers are the only ones that can be shown
        self.engine._site_results = [("a.example.com", "200")]
        self.engine._site_checked_at = 1.0
        resp, data = self.request("GET", "/api/overview?refresh=1")
        self.assertFalse(data["sites_pending"], "the old answers are shown, not a blank page")
        self.assertEqual(data["sites"]["total"], 1)
        self.assertGreaterEqual(len(self.asked), 1, "a new check was started")

    def test_one_slow_check_does_not_start_a_second_one(self):
        self.request("GET", "/api/overview")
        self.request("GET", "/api/overview?refresh=1")
        self.request("GET", "/api/overview?refresh=1")
        self.assertEqual(len(self.asked), 1)

    def test_a_failing_check_never_takes_the_panel_down(self):
        self.gate.set()
        self.patch("cpsec.sites.check_sites", side_effect=RuntimeError("boom"))
        self.engine._check_sites_now()
        resp, data = self.request("GET", "/api/overview")
        self.assertEqual(resp.status, 200)

    def test_the_advice_and_the_overview_do_not_block_each_other(self):
        import time
        self.engine._advice_lock.acquire()
        try:
            started = time.time()
            resp, _ = self.request("GET", "/api/overview")
            self.assertEqual(resp.status, 200)
            self.assertLess(time.time() - started, 3)
        finally:
            self.engine._advice_lock.release()


class PanelUpdateRoutes(PanelCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_the_state_tells_the_page_what_to_show(self):
        resp, data = self.request("GET", "/api/update")
        self.assertEqual(resp.status, 200)
        for key in ("current", "latest", "available", "notes", "job"):
            self.assertIn(key, data)

    def test_checking_returns_the_new_state_too(self):
        resp, data = self.request("POST", "/api/update/check", {})
        self.assertTrue(data["ok"])
        self.assertIn("available", data["state"])

    def test_installing_needs_an_explicit_yes_and_the_secret_token(self):
        self.assertEqual(self.request("POST", "/api/update/install", {"version": "9.9.9"})[0].status, 400)
        self.csrf = ""
        self.assertEqual(self.request("POST", "/api/update/install", {"version": "9.9.9", "confirm": True})[0].status, 403)

    def test_installing_runs_and_is_written_to_the_activity_log(self):
        resp, data = self.request("POST", "/api/update/install", {"version": "9.9.9", "confirm": True})
        self.assertTrue(data["ok"], data)
        _, state = self.request("GET", "/api/update")
        self.assertIn(state["job"]["status"], ("working", "restarting", "done"))
        _, log = self.request("GET", "/api/activity")
        self.assertTrue(any(e["event"] == "UPDATE_INSTALL" for e in log["events"]))

    def test_the_version_is_known_to_the_page_from_the_start(self):
        _, me = self.request("GET", "/api/me")
        from cpsec import __version__
        self.assertEqual(me["version"], __version__)
