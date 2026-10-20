"""The panel's brain: turns a request into a response. No sockets here, so it is easy to test.

Rules every route follows:
* nothing but the login and the page files works without a valid session;
* every change needs the session's secret token in a header (CSRF protection);
* the engine decides what is allowed; this file only checks who is asking and what they sent.
"""
import hmac
import json
import os
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .. import __version__, provision, settings
from . import activity, auth

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
SECURITY_HEADERS = [
    ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]
MAX_BODY = 64 * 1024
COOKIE = "cps_session"


class Request:
    def __init__(self, method, path, headers=None, body=b"", ip="0.0.0.0"):
        parts = urlsplit(path)
        self.method = method.upper()
        self.path = parts.path
        self.query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        ip = ip or "0.0.0.0"
        self.ip = ip[7:] if ip.startswith("::ffff:") else ip
        self.cookies = {}
        for piece in self.headers.get("cookie", "").split(";"):
            if "=" in piece:
                k, _, v = piece.strip().partition("=")
                self.cookies[k] = v

    def json(self):
        if not self.body:
            return {}
        if len(self.body) > MAX_BODY:
            raise BadRequest("That request is too large.")
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BadRequest("That request could not be read.")
        if not isinstance(data, dict):
            raise BadRequest("That request could not be read.")
        return data


class Response:
    def __init__(self, status=200, body=b"", ctype="application/json", headers=None):
        self.status, self.body, self.ctype = status, body, ctype
        self.headers = list(headers or [])


class BadRequest(Exception):
    pass


def _json(status, data, headers=None):
    return Response(status, json.dumps(data).encode("utf-8"), "application/json", headers)


def _result(res, **extra):
    status = 200 if res.ok else (409 if res.code == "needs_confirm" else 400)
    return _json(status, dict({"ok": res.ok, "message": res.message, "code": res.code}, **extra))


def _text(value, limit=200):
    return value.strip()[:limit] if isinstance(value, str) else ""


def _website_list(body):
    """None for 'all websites', or the list of names in the request."""
    if body.get("all") is True:
        return None
    names = body.get("domains")
    if not isinstance(names, list) or not names or len(names) > 300 or not all(isinstance(n, str) for n in names):
        raise BadRequest("Choose which websites.")
    return [n.strip()[:100] for n in names]


def _port_number(value):
    """A port number from a request; 0 when it is not one (the engine then answers 'not a port')."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return 0


class App:
    def __init__(self, engine, sessions=None, limiter=None, secure_cookies=True, allowed_hosts=None,
                 sleep=time.sleep, clock=time.time):
        self.engine = engine
        self.clock = clock
        self.sessions = sessions or auth.SessionStore(clock=clock)
        self.limiter = limiter or auth.LoginLimiter(clock=clock)
        self.secure_cookies = secure_cookies
        self.allowed_hosts = set(h.lower() for h in (allowed_hosts or []))
        self.sleep = sleep
        self._pending_2fa = {}
        self._pending_lock = threading.Lock()
        self._static = {}
        self._dummy_hash = None

        # (method, path) -> (handler, needs a session)
        self.routes = {
            ("POST", "/api/login"): (self.api_login, False),
            ("GET", "/api/me"): (self.api_me, False),
            ("POST", "/api/logout"): (self.api_logout, True),
            ("GET", "/api/overview"): (self.api_overview, True),
            ("GET", "/api/blocked"): (self.api_blocked, True),
            ("POST", "/api/blocked/unblock"): (self.api_unblock, True),
            ("POST", "/api/blocked/unblock-all"): (self.api_unblock_all, True),
            ("POST", "/api/blocked/engine"): (self.api_blocking_switch, True),
            ("GET", "/api/access"): (self.api_access, True),
            ("POST", "/api/access/add"): (self.api_access_add, True),
            ("POST", "/api/access/remove"): (self.api_access_remove, True),
            ("POST", "/api/access/home"): (self.api_access_home, True),
            ("POST", "/api/access/never/add"): (self.api_never_add, True),
            ("POST", "/api/access/never/remove"): (self.api_never_remove, True),
            ("GET", "/api/wpupdate"): (self.api_wpupdate, True),
            ("POST", "/api/wpupdate/start"): (self.api_wpupdate_start, True),
            ("POST", "/api/wpupdate/stop"): (self.api_wpupdate_stop, True),
            ("GET", "/api/serverfw"): (self.api_serverfw, True),
            ("POST", "/api/serverfw/add"): (self.api_serverfw_add, True),
            ("POST", "/api/serverfw/remove"): (self.api_serverfw_remove, True),
            ("POST", "/api/serverfw/power"): (self.api_serverfw_power, True),
            ("POST", "/api/serverfw/keep"): (self.api_serverfw_keep, True),
            ("POST", "/api/serverfw/undo"): (self.api_serverfw_undo, True),
            ("POST", "/api/serverfw/import"): (self.api_serverfw_import, True),
            ("POST", "/api/serverfw/suggested"): (self.api_serverfw_suggested, True),
            ("GET", "/api/headers"): (self.api_headers, True),
            ("POST", "/api/headers/defaults"): (self.api_headers_defaults, True),
            ("POST", "/api/headers/check"): (self.api_headers_check, True),
            ("POST", "/api/headers/apply"): (self.api_headers_apply, True),
            ("POST", "/api/headers/remove"): (self.api_headers_remove, True),
            ("POST", "/api/headers/site"): (self.api_headers_site, True),
            ("GET", "/api/ports"): (self.api_ports, True),
            ("POST", "/api/ports/lock"): (self.api_ports_lock, True),
            ("POST", "/api/ports/unlock"): (self.api_ports_unlock, True),
            ("POST", "/api/ports/accept"): (self.api_ports_accept, True),
            ("GET", "/api/advisor"): (self.api_advisor, True),
            ("POST", "/api/advisor/fix"): (self.api_advisor_fix, True),
            ("GET", "/api/setup"): (self.api_setup, True),
            ("POST", "/api/setup/run"): (self.api_setup_run, True),
            ("POST", "/api/firewall/selftest"): (self.api_waf_selftest, True),
            ("GET", "/api/settings/blocker"): (self.api_blocker_get, True),
            ("POST", "/api/settings/blocker"): (self.api_blocker_set, True),
            ("POST", "/api/settings/baseline"): (self.api_baseline, True),
            ("GET", "/api/firewall"): (self.api_waf, True),
            ("POST", "/api/firewall/mode"): (self.api_waf_mode, True),
            ("POST", "/api/firewall/exception"): (self.api_waf_exception_add, True),
            ("POST", "/api/firewall/exception/remove"): (self.api_waf_exception_remove, True),
            ("GET", "/api/update"): (self.api_update, True),
            ("POST", "/api/update/check"): (self.api_update_check, True),
            ("POST", "/api/update/install"): (self.api_update_install, True),
            ("GET", "/api/updates"): (self.api_updates, True),
            ("POST", "/api/updates/refresh"): (self.api_updates_refresh, True),
            ("GET", "/api/settings"): (self.api_settings, True),
            ("POST", "/api/settings/password"): (self.api_password, True),
            ("POST", "/api/settings/access"): (self.api_settings_access, True),
            ("POST", "/api/settings/2fa/start"): (self.api_2fa_start, True),
            ("POST", "/api/settings/2fa/confirm"): (self.api_2fa_confirm, True),
            ("POST", "/api/settings/2fa/disable"): (self.api_2fa_disable, True),
            ("GET", "/api/activity"): (self.api_activity, True),
        }

    # ------------------------------------------------------------------ entry point
    def handle(self, req):
        try:
            resp = self._route(req)
        except BadRequest as exc:
            resp = _json(400, {"ok": False, "message": str(exc), "code": "bad_request"})
        except Exception as exc:                                  # never show internals to the browser
            activity.write("ERROR", where=req.path, error=type(exc).__name__)
            resp = _json(500, {"ok": False, "message": "Something went wrong inside the panel.", "code": "error"})
        resp.headers.extend(SECURITY_HEADERS)
        if self.secure_cookies:
            resp.headers.append(("Strict-Transport-Security", "max-age=31536000"))
        resp.headers.append(("Cache-Control", "no-store" if req.path.startswith("/api/") else "no-cache"))
        return resp

    @staticmethod
    def _host_name(header):
        """'Example.com:8443' -> 'example.com', '[::1]:8443' -> '::1'"""
        host = header.strip().lower()
        if host.startswith("["):
            return host[1:host.find("]")] if "]" in host else host
        if host.count(":") == 1:
            return host.split(":")[0]
        return host

    def _host_ok(self, req):
        """Only answer to our own address: stops other sites from steering a browser at the panel."""
        if not self.allowed_hosts:
            return True
        return self._host_name(req.headers.get("host", "")) in self.allowed_hosts

    def _route(self, req):
        if not self._host_ok(req):
            return _json(421, {"ok": False, "message": "Unknown address.", "code": "bad_host"})
        if req.method == "GET" and req.path in STATIC:
            return self._static_file(req.path)
        route = self.routes.get((req.method, req.path))
        if route is None:
            known = any(p == req.path for _, p in self.routes)
            return _json(405 if known else 404, {"ok": False, "message": "Not found.", "code": "not_found"})
        handler, needs_session = route
        token = req.cookies.get(COOKIE)
        session = self.sessions.get(token)
        if needs_session:
            if session is None:
                return _json(401, {"ok": False, "message": "Please sign in.", "code": "signed_out"})
            if req.method != "GET":
                problem = self._csrf_problem(req, session)
                if problem:
                    return _json(403, {"ok": False, "message": problem, "code": "csrf"})
        if session is not None:
            session["token"] = token
        return handler(req, session)

    def _csrf_problem(self, req, session):
        sent = req.headers.get("x-csrf-token", "")
        if not sent or not hmac.compare_digest(sent.encode(), session["csrf"].encode()):
            return "Your page is out of date. Reload it and try again."
        origin = req.headers.get("origin")
        if origin and urlsplit(origin).netloc.lower() != req.headers.get("host", "").lower():
            return "That request came from another website."
        return None

    def _static_file(self, path):
        if path not in self._static:
            name, ctype = STATIC[path]
            try:
                with open(os.path.join(WEB_DIR, name), "rb") as f:
                    self._static[path] = (f.read(), ctype)
            except OSError:
                return Response(404, b"Not found", "text/plain")
        body, ctype = self._static[path]
        return Response(200, body, ctype)

    # ------------------------------------------------------------------ sign in and out
    def _dummy(self):
        if self._dummy_hash is None:
            self._dummy_hash = auth.hash_password("not-a-real-password")
        return self._dummy_hash

    def api_login(self, req, session):
        wait = self.limiter.seconds_locked(req.ip)
        if wait:
            return _json(429, {"ok": False, "code": "locked", "retry_after": wait,
                               "message": "Too many wrong tries. Try again in %d minutes." % (wait // 60 + 1)},
                         [("Retry-After", str(wait))])
        body = req.json()
        username, password, code = _text(body.get("username"), 60), str(body.get("password") or "")[:200], _text(body.get("code"), 12)
        user = settings.get_user()
        twofa = bool(user and user.get("totp_enabled") and user.get("totp_secret"))
        counter, ok = None, False
        if user:
            pw_ok = auth.verify_password(password, user["password_hash"])
            name_ok = hmac.compare_digest(username.encode(), user["name"].encode())
            if pw_ok and name_ok:
                if twofa:                                   # the second step is only asked when the owner turned it on
                    counter = auth.verify_totp(user["totp_secret"], code, user.get("last_counter", 0), now=self.clock())
                    ok = counter is not None
                else:
                    ok = True
        else:
            auth.verify_password(password, self._dummy())      # same effort whether or not the user exists
        if not ok:
            self.limiter.failed(req.ip)
            activity.write("LOGIN_FAILED", ip=req.ip, user=username[:30])
            self.sleep(0.5)
            return _json(401, {"ok": False, "code": "bad_login",
                               "message": "Wrong username, password or code." if twofa else "Wrong username or password."})
        if counter is not None:
            user["last_counter"] = counter
            settings.save_user(user)
        self.limiter.succeeded(req.ip)
        token, csrf = self.sessions.create(user["name"], req.ip)
        activity.write("LOGIN", ip=req.ip, user=user["name"])
        cookie = "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (COOKIE, token, self.sessions.absolute)
        if self.secure_cookies:
            cookie += "; Secure"
        return _json(200, {"ok": True, "csrf": csrf}, [("Set-Cookie", cookie)])

    def api_logout(self, req, session):
        self.sessions.destroy(session["token"])
        activity.write("LOGOUT", ip=req.ip, user=session["user"])
        clear = "%s=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" % COOKIE
        return _json(200, {"ok": True}, [("Set-Cookie", clear)])

    def api_me(self, req, session):
        user = settings.get_user()
        twofa = bool(user and user.get("totp_enabled") and user.get("totp_secret"))
        if session is None:
            return _json(200, {"authenticated": False, "version": __version__, "twofa": twofa})
        s = settings.load()
        return _json(200, {"authenticated": True, "user": session["user"], "csrf": session["csrf"],
                           "client_ip": req.ip, "version": __version__, "demo": bool(self.engine.demo),
                           "domain": s["domain"], "access": s["access"], "twofa": twofa})

    # ------------------------------------------------------------------ overview and blocked
    def api_overview(self, req, session):
        return _json(200, self.engine.overview(refresh=req.query.get("refresh") == "1"))

    def api_blocked(self, req, session):
        return _json(200, self.engine.blocked())

    def api_unblock(self, req, session):
        ip = _text(req.json().get("ip"), 64)
        res = self.engine.unblock(ip)
        activity.write("UNBLOCK", ip=req.ip, target=ip, ok=res.ok)
        return _result(res)

    def api_unblock_all(self, req, session):
        res = self.engine.unblock_all()
        activity.write("UNBLOCK_ALL", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_blocking_switch(self, req, session):
        running = bool(req.json().get("running"))
        res = self.engine.set_blocking_running(running)
        activity.write("BLOCKING_ON" if running else "BLOCKING_OFF", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ admin access
    def api_access(self, req, session):
        data = self.engine.access_state()
        data["client_ip"] = req.ip
        data["client_ip_trusted"] = any(t["address"] == req.ip for t in data["trusted"])
        return _json(200, data)

    def api_access_add(self, req, session):
        b = req.json()
        res = self.engine.access_add(_text(b.get("address"), 64), _text(b.get("label"), 60))
        activity.write("ACCESS_ADD", ip=req.ip, target=_text(b.get("address"), 64), ok=res.ok)
        return _result(res)

    def api_access_remove(self, req, session):
        b = req.json()
        res = self.engine.access_remove(_text(b.get("address"), 64), req.ip, bool(b.get("confirmed")))
        activity.write("ACCESS_REMOVE", ip=req.ip, target=_text(b.get("address"), 64), ok=res.ok)
        return _result(res)

    def api_access_home(self, req, session):
        address = _text(req.json().get("address"), 64) or req.ip
        res = self.engine.access_set_home(address)
        activity.write("ACCESS_HOME", ip=req.ip, target=address, ok=res.ok)
        return _result(res)

    def api_never_add(self, req, session):
        b = req.json()
        res = self.engine.never_add(_text(b.get("address"), 64), _text(b.get("label"), 60))
        activity.write("NEVER_BLOCK_ADD", ip=req.ip, target=_text(b.get("address"), 64), ok=res.ok)
        return _result(res)

    def api_never_remove(self, req, session):
        b = req.json()
        many = b.get("addresses")
        if isinstance(many, list) and many:
            addresses = [_text(a, 64) for a in many[:200]]
            res = self.engine.never_remove_many(addresses)
            activity.write("NEVER_BLOCK_REMOVE", ip=req.ip, target="%d addresses" % len(addresses), ok=res.ok)
            return _result(res)
        address = _text(b.get("address"), 64)
        res = self.engine.never_remove(address)
        activity.write("NEVER_BLOCK_REMOVE", ip=req.ip, target=address, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ open ports
    def api_ports(self, req, session):
        data = self.engine.ports_state()
        data["client_ip"] = req.ip
        data["client_ip_trusted"] = any(t["address"] == req.ip for t in self.engine.access_state()["trusted"])
        return _json(200, data)

    def api_ports_lock(self, req, session):
        b = req.json()
        port = _port_number(b.get("port"))
        res = self.engine.ports_lock(port, req.ip, bool(b.get("confirmed")))
        activity.write("PORT_LOCK", ip=req.ip, target=str(port), ok=res.ok)
        return _result(res)

    def api_ports_unlock(self, req, session):
        b = req.json()
        port = _port_number(b.get("port"))
        res = self.engine.ports_unlock(port, bool(b.get("confirmed")))
        activity.write("PORT_UNLOCK", ip=req.ip, target=str(port), ok=res.ok)
        return _result(res)

    def api_ports_accept(self, req, session):
        b = req.json()
        port = _port_number(b.get("port"))
        res = self.engine.ports_accept(port, bool(b.get("accepted", True)))
        activity.write("PORT_ACCEPT" if b.get("accepted", True) else "PORT_UNACCEPT", ip=req.ip, target=str(port), ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ manual updates of plugins and themes
    def api_wpupdate(self, req, session):
        return _json(200, self.engine.wpupdate_state())

    def api_wpupdate_start(self, req, session):
        b = req.json()
        items = b.get("items")
        if not b.get("confirmed"):
            return _json(409, {"ok": False, "code": "needs_confirm", "message": "Please confirm that you want to start these updates."})
        res = self.engine.wpupdate_start(items)
        activity.write("WP_UPDATE_START", ip=req.ip, count=len(items) if isinstance(items, list) else 0, ok=res.ok)
        return _result(res)

    def api_wpupdate_stop(self, req, session):
        res = self.engine.wpupdate_stop()
        activity.write("WP_UPDATE_STOP", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ server firewall
    def api_serverfw(self, req, session):
        return _json(200, self.engine.serverfw_state())

    def api_serverfw_add(self, req, session):
        b = req.json()
        res = self.engine.serverfw_add(_text(b.get("name"), 60), _text(b.get("proto"), 8), _text(b.get("address"), 64),
                                       _text(b.get("port"), 20))
        activity.write("FW_ADD", ip=req.ip, target="%s/%s" % (_text(b.get("port"), 20), _text(b.get("proto"), 8)), ok=res.ok)
        return _result(res)

    def api_serverfw_remove(self, req, session):
        b = req.json()
        rule_id = b.get("id") if isinstance(b.get("id"), int) and not isinstance(b.get("id"), bool) else 0
        res = self.engine.serverfw_remove(rule_id, bool(b.get("confirmed")))
        activity.write("FW_REMOVE", ip=req.ip, target=str(rule_id), ok=res.ok)
        return _result(res)

    def api_serverfw_power(self, req, session):
        b = req.json()
        action = _text(b.get("action"), 10)
        res = self.engine.serverfw_power(action, bool(b.get("add_in_use", True)), bool(b.get("confirmed")))
        activity.write("FW_POWER", ip=req.ip, action=action, ok=res.ok)
        return _result(res)

    def api_serverfw_keep(self, req, session):
        res = self.engine.serverfw_keep()
        activity.write("FW_KEEP", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_serverfw_undo(self, req, session):
        res = self.engine.serverfw_undo()
        activity.write("FW_UNDO", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_serverfw_import(self, req, session):
        res = self.engine.serverfw_import()
        activity.write("FW_IMPORT", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_serverfw_suggested(self, req, session):
        keys = req.json().get("keys")
        if keys is not None and (not isinstance(keys, list) or not all(isinstance(k, str) for k in keys) or len(keys) > 300):
            raise BadRequest("Those choices could not be read.")
        res = self.engine.serverfw_add_suggested(None if keys is None else [k[:120] for k in keys])
        activity.write("FW_SUGGESTED", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ security headers
    def api_headers(self, req, session):
        return _json(200, self.engine.headers_state())

    def api_headers_defaults(self, req, session):
        changes = req.json().get("changes")
        res = self.engine.headers_defaults(changes if isinstance(changes, dict) else {})
        activity.write("HEADERS_DEFAULTS", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_headers_check(self, req, session):
        return _result(self.engine.headers_check())

    def api_headers_apply(self, req, session):
        b = req.json()
        res = self.engine.headers_apply(_website_list(b), bool(b.get("take_over")))
        activity.write("HEADERS_APPLY", ip=req.ip, target="all" if b.get("all") else _text(",".join(_website_list(b) or []), 120),
                       ok=res.ok)
        return _result(res)

    def api_headers_remove(self, req, session):
        b = req.json()
        res = self.engine.headers_remove(_website_list(b))
        activity.write("HEADERS_REMOVE", ip=req.ip, target="all" if b.get("all") else _text(",".join(_website_list(b) or []), 120),
                       ok=res.ok)
        return _result(res)

    def api_headers_site(self, req, session):
        b = req.json()
        domain = _text(b.get("domain"), 100)
        changes = b.get("changes")
        if not isinstance(changes, dict) or not all(v is None or isinstance(v, (bool, int)) for v in changes.values()):
            raise BadRequest("Those choices could not be read.")
        res = self.engine.headers_site(domain, changes, bool(b.get("apply")), bool(b.get("take_over")))
        activity.write("HEADERS_SITE", ip=req.ip, target=domain, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ advisor and setup
    def api_advisor(self, req, session):
        return _json(200, self.engine.advisor_report(refresh=req.query.get("refresh") == "1"))

    def api_advisor_fix(self, req, session):
        fix_id = _text(req.json().get("id"), 40)
        res = self.engine.advisor_fix(fix_id)
        activity.write("ADVISOR_FIX", ip=req.ip, fix=fix_id, ok=res.ok)
        return _result(res)

    def api_setup(self, req, session):
        return _json(200, self.engine.setup_state())

    def api_setup_run(self, req, session):
        keys = req.json().get("keys")
        if keys is not None:
            if not isinstance(keys, list) or not all(isinstance(k, str) and k in provision.BY_KEY for k in keys):
                return _json(400, {"ok": False, "code": "invalid", "message": "Unknown setup step."})
        res = self.engine.setup_start(keys)
        activity.write("SETUP_START", ip=req.ip, steps=",".join(keys) if keys else "all", ok=res.ok)
        return _result(res)

    def api_waf_selftest(self, req, session):
        res = self.engine.waf_selftest()
        activity.write("FIREWALL_SELFTEST", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ settings: blocker numbers and the saved baseline
    def api_blocker_get(self, req, session):
        return _json(200, self.engine.blocker_settings())

    def api_blocker_set(self, req, session):
        changes = req.json().get("changes")
        if not isinstance(changes, dict) or not all(isinstance(v, dict) for v in changes.values()):
            return _json(400, {"ok": False, "code": "invalid", "message": "Nothing to save."})
        res = self.engine.blocker_set(changes)
        activity.write("BLOCKER_SETTINGS", ip=req.ip, ok=res.ok)
        return _result(res)

    def api_baseline(self, req, session):
        res = self.engine.baseline_save()
        activity.write("BASELINE_SAVED", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ web firewall
    def api_waf(self, req, session):
        data = self.engine.waf_state()
        if data["installed"]:
            data["summary"] = self.engine.waf_summary()
            data["recent"] = self.engine.waf_recent()
        return _json(200, data)

    def api_waf_mode(self, req, session):
        b = req.json()
        mode = _text(b.get("mode"), 10)
        if mode == "block" and b.get("confirm") != "BLOCK":
            return _json(400, {"ok": False, "code": "needs_confirm", "message": "Type BLOCK to confirm."})
        threshold = b.get("threshold")
        try:
            threshold = int(threshold) if threshold not in (None, "") else None
        except (TypeError, ValueError):
            return _json(400, {"ok": False, "code": "invalid", "message": "The strictness must be a number."})
        res = self.engine.waf_set_mode(mode, threshold)
        activity.write("FIREWALL_MODE", ip=req.ip, mode=mode, ok=res.ok)
        return _result(res)

    def api_waf_exception_add(self, req, session):
        b = req.json()
        res = self.engine.waf_add_exception(_text(b.get("scope"), 10), _text(b.get("host"), 120), _text(b.get("rule"), 20))
        activity.write("FIREWALL_EXCEPTION", ip=req.ip, scope=_text(b.get("scope"), 10),
                       host=_text(b.get("host"), 120), rule=_text(b.get("rule"), 20), ok=res.ok)
        return _result(res)

    def api_waf_exception_remove(self, req, session):
        try:
            index = int(req.json().get("index"))
        except (TypeError, ValueError):
            return _json(400, {"ok": False, "code": "invalid", "message": "Which exception?"})
        res = self.engine.waf_remove_exception(index)
        activity.write("FIREWALL_EXCEPTION_REMOVED", ip=req.ip, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ the panel's own updates
    def api_update(self, req, session):
        return _json(200, self.engine.update_state())

    def api_update_check(self, req, session):
        res = self.engine.update_check()
        activity.write("UPDATE_CHECK", ip=req.ip, ok=res.ok)
        return _result(res, state=self.engine.update_state())

    def api_update_install(self, req, session):
        b = req.json()
        if b.get("confirm") is not True:
            return _json(400, {"ok": False, "code": "needs_confirm", "message": "Please confirm the update."})
        version = _text(b.get("version"), 20)
        res = self.engine.update_install(version)
        activity.write("UPDATE_INSTALL", ip=req.ip, version=version, ok=res.ok)
        return _result(res)

    # ------------------------------------------------------------------ WordPress updates
    def api_updates(self, req, session):
        return _json(200, self.engine.updates_state())

    def api_updates_refresh(self, req, session):
        b = req.json()
        site = _text(b.get("site"), 100) if isinstance(b, dict) else ""
        return _result(self.engine.updates_refresh(site or None))

    # ------------------------------------------------------------------ settings
    def api_settings(self, req, session):
        s = settings.load()
        user = settings.get_user() or {}
        return _json(200, {"domain": s["domain"], "port": s["port"], "access": s["access"],
                           "user": session["user"], "version": __version__, "client_ip": req.ip,
                           "twofa": bool(user.get("totp_enabled") and user.get("totp_secret")),
                           "server": self.engine.server_info(),
                           "client_ip_trusted": any(t["address"] == req.ip for t in self.engine.access_state()["trusted"])})

    def api_password(self, req, session):
        b = req.json()
        user = settings.get_user()
        if not user or not auth.verify_password(str(b.get("current") or ""), user["password_hash"]):
            self.sleep(0.5)
            return _json(400, {"ok": False, "code": "bad_password", "message": "The current password is not right."})
        new = str(b.get("new") or "")
        problem = auth.password_problem(new, user["name"])
        if problem:
            return _json(400, {"ok": False, "code": "weak_password", "message": problem})
        user["password_hash"] = auth.hash_password(new)
        settings.save_user(user)
        self.sessions.destroy_all(except_token=session["token"])
        activity.write("PASSWORD_CHANGED", ip=req.ip, user=user["name"])
        return _json(200, {"ok": True, "message": "Password changed. Other devices were signed out.", "code": ""})

    def api_settings_access(self, req, session):
        b = req.json()
        mode = _text(b.get("access"), 10)
        if mode not in ("login", "trusted"):
            return _json(400, {"ok": False, "code": "invalid", "message": "Unknown choice."})
        trusted_now = any(t["address"] == req.ip for t in self.engine.access_state()["trusted"])
        if mode == "trusted" and not trusted_now and not b.get("confirmed"):
            return _json(409, {"ok": False, "code": "needs_confirm",
                               "message": "Your current address (%s) is not on the trusted list, so you would be "
                                          "locked out of this panel." % req.ip})
        old = settings.load()["access"]
        settings.save({"access": mode})
        res = self.engine.access_reapply()
        if not res.ok:
            settings.save({"access": old})
            self.engine.access_reapply()
            return _result(res)
        activity.write("PANEL_ACCESS", ip=req.ip, mode=mode)
        return _json(200, {"ok": True, "code": "", "message": "Saved. The panel is now reachable by: " +
                           ("everyone with the login." if mode == "login" else "trusted addresses only.")})

    def api_2fa_start(self, req, session):
        user = settings.get_user()
        if not user or not auth.verify_password(str(req.json().get("password") or ""), user["password_hash"]):
            self.sleep(0.5)
            return _json(400, {"ok": False, "code": "bad_password", "message": "The password is not right."})
        secret = auth.new_totp_secret()
        with self._pending_lock:
            self._pending_2fa[session["token"]] = secret
        return _json(200, {"ok": True, "secret": secret, "uri": auth.otpauth_uri(secret, user["name"]), "code": "",
                           "message": "Add this key to your authenticator app, then type the 6-digit code it shows."})

    def api_2fa_confirm(self, req, session):
        with self._pending_lock:
            secret = self._pending_2fa.get(session["token"])
        user = settings.get_user()
        if not secret or not user:
            return _json(400, {"ok": False, "code": "no_pending", "message": "Start again."})
        counter = auth.verify_totp(secret, _text(req.json().get("code"), 12), now=self.clock())
        if counter is None:
            return _json(400, {"ok": False, "code": "bad_code", "message": "That code is not right. Try the next one."})
        user["totp_secret"], user["totp_enabled"], user["last_counter"] = secret, True, counter
        settings.save_user(user)
        with self._pending_lock:
            self._pending_2fa.pop(session["token"], None)
        self.sessions.destroy_all(except_token=session["token"])
        activity.write("TOTP_ENABLED", ip=req.ip, user=user["name"])
        return _json(200, {"ok": True, "message": "Two-step login is on. Other devices were signed out.", "code": ""})

    def api_2fa_disable(self, req, session):
        user = settings.get_user()
        if not user or not auth.verify_password(str(req.json().get("password") or ""), user["password_hash"]):
            self.sleep(0.5)
            return _json(400, {"ok": False, "code": "bad_password", "message": "The password is not right."})
        user["totp_enabled"] = False
        user.pop("totp_secret", None)
        settings.save_user(user)
        activity.write("TOTP_DISABLED", ip=req.ip, user=user["name"])
        return _json(200, {"ok": True, "message": "Two-step login is off.", "code": ""})

    def api_activity(self, req, session):
        return _json(200, {"events": activity.recent(50)})
