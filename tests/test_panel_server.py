"""Starts the panel the way the system service does (real HTTPS on a real port) and talks to it.

Earlier tests called the panel's brain directly, which missed a crash in the start-up code. This one cannot.
"""
import argparse
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import unittest

from cpsec import config, installer, settings
from cpsec.panel import auth
from cpsec.panel import cli as panel_cli
from cpsec.panel.engine import DemoEngine
from cpsec.panel.server import serve_in_thread
from tests.helpers import EnvTestCase

DOMAIN = "sec.example.com"
PASSWORD = "a long enough password"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make a throw-away certificate")
class RealPanel(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        live = "%s/%s" % (config.P.letsencrypt_live, DOMAIN)
        self.write(live + "/placeholder", "")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", live + "/privkey.pem",
                        "-out", live + "/fullchain.pem", "-days", "2", "-subj", "/CN=" + DOMAIN],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        settings.save({"domain": DOMAIN, "port": self.port, "access": "trusted"})
        settings.save_user({"name": "owner", "password_hash": auth.hash_password(PASSWORD, n=16),
                            "totp_enabled": False, "last_counter": 0})

    def start(self, **overrides):
        args = argparse.Namespace(allow_host=None, cert=None, key=None, port=None, host="127.0.0.1", insecure=False)
        for k, v in overrides.items():
            setattr(args, k, v)
        server, paths = panel_cli._build_server(args, DemoEngine(), secure=True)
        serve_in_thread(server)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, paths

    def call(self, method, path, body=None, headers=None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=10)
        h = {"Host": DOMAIN}
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        if data:
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        raw = resp.read()
        return resp, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw)



@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make a throw-away certificate")
class RealStart(RealPanel):
    def test_the_panel_starts_finds_its_certificate_and_answers_over_https(self):
        _, (cert, key) = self.start()
        self.assertTrue(cert.endswith("/%s/fullchain.pem" % DOMAIN), "found where CyberPanel puts it")
        self.assertTrue(installer.wait_for_panel(DOMAIN, self.port, tries=3, pause=0.2),
                        "the installer's own check must agree that the panel is up")
        resp, data = self.call("GET", "/api/me")
        self.assertEqual(resp.status, 200)
        self.assertIs(data["authenticated"], False)

    def test_signing_in_works_over_the_real_connection(self):
        self.start()
        resp, data = self.call("POST", "/api/login", {"username": "owner", "password": PASSWORD})
        self.assertEqual((resp.status, data["ok"]), (200, True), data)
        cookie = resp.getheader("Set-Cookie")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        resp, me = self.call("GET", "/api/me", headers={"Cookie": cookie.split(";")[0]})
        self.assertIs(me["authenticated"], True)
        page, body = self.call("GET", "/")
        self.assertEqual(page.status, 200)
        self.assertIn(b"CP-Security", body)

    def test_another_host_name_is_refused(self):
        self.start()
        resp, _ = self.call("GET", "/api/me", headers={"Host": "evil.example.net"})
        self.assertEqual(resp.status, 421)

    def test_a_renewed_certificate_can_be_loaded_into_the_running_panel(self):
        server, (cert, key) = self.start()
        server.reload_certificate(cert, key)
        self.assertEqual(self.call("GET", "/api/me")[0].status, 200)

    def test_plain_http_to_the_https_port_does_not_crash_it(self):
        self.start()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: sec.example.com\r\n\r\n")
            try:
                s.recv(100)
            except OSError:
                pass
        self.assertEqual(self.call("GET", "/api/me")[0].status, 200, "still serving afterwards")

    def plain(self, raw):
        """Send raw bytes over a plain (not TLS) connection and return everything the panel answers."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(raw)
            out = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    out += chunk
            except OSError:
                pass
        return out.decode("latin-1")

    def test_typing_http_sends_the_browser_on_to_https(self):
        self.start()
        out = self.plain(b"GET /api/me?x=1 HTTP/1.1\r\nHost: sec.example.com:%d\r\n\r\n" % self.port)
        self.assertTrue(out.startswith("HTTP/1.1 301 "), out)
        self.assertIn("Location: https://sec.example.com:%d/api/me?x=1\r\n" % self.port, out)
        self.assertIn("X-Content-Type-Options: nosniff", out)

    def test_the_redirect_never_points_at_a_host_the_request_made_up(self):
        self.start()
        out = self.plain(b"GET / HTTP/1.1\r\nHost: evil.example.net\r\n\r\n")
        self.assertIn("Location: https://sec.example.com:%d/\r\n" % self.port, out)
        self.assertNotIn("evil", out)
        out = self.plain(b"GET http://evil.example.net/x HTTP/1.1\r\nHost: sec.example.com\r\n\r\n")
        self.assertIn("Location: https://sec.example.com:%d/\r\n" % self.port, out)

    def test_other_methods_get_a_redirect_that_keeps_the_method_and_head_has_no_body(self):
        self.start()
        out = self.plain(b"POST /api/login HTTP/1.1\r\nHost: sec.example.com\r\nContent-Length: 0\r\n\r\n")
        self.assertTrue(out.startswith("HTTP/1.1 308 "), out)
        out = self.plain(b"HEAD / HTTP/1.1\r\nHost: sec.example.com\r\n\r\n")
        self.assertTrue(out.startswith("HTTP/1.1 301 "), out)
        self.assertTrue(out.endswith("\r\n\r\n"), "a HEAD answer has no body")

    def test_nonsense_on_the_port_gets_a_short_refusal_and_https_keeps_working(self):
        self.start()
        out = self.plain(b"\x00\x01\x02 garbage\r\n\r\n")
        self.assertTrue(out.startswith("HTTP/1.1 301 ") or out.startswith("HTTP/1.1 308 ") or out == "", out)
        self.assertEqual(self.call("GET", "/api/me")[0].status, 200)

    def test_the_redirect_address_is_built_only_from_trusted_names(self):
        from cpsec.panel.server import https_location
        ok = {"sec.example.com"}
        self.assertEqual(https_location("sec.example.com", "/a b\r\nX: y", ok, 8091), "https://sec.example.com:8091/abX:y")
        self.assertNotIn("\r", https_location("sec.example.com", "/a\r\nSet-Cookie: x=1", ok, 8091))
        self.assertNotIn("\n", https_location("sec.example.com", "/a\r\nSet-Cookie: x=1", ok, 8091))
        self.assertEqual(https_location("Sec.Example.com:8091", "/", ok, 443), "https://sec.example.com/")
        self.assertEqual(https_location("x", "//evil.example.net/", ok, 8091), "https://sec.example.com:8091//evil.example.net/")
        self.assertIsNone(https_location("sec.example.com", "/", set(), 8091))

    def test_without_a_certificate_the_failure_is_a_clear_message_not_a_crash_in_our_code(self):
        shutil.rmtree("%s/%s" % (config.P.letsencrypt_live, DOMAIN))
        with self.assertRaises((OSError, FileNotFoundError)):
            self.start()


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make a throw-away certificate")
class UploadingOverTheRealConnection(RealPanel):
    """A zip is sent as the raw body over real HTTPS: checked before it is read, written to disk in pieces, never kept half-done."""

    PLUGIN = b"<?php\n/*\nPlugin Name: Big One\nVersion: 2.5\n*/\n"

    def make_zip(self, padding=0):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("bigone/bigone.php", self.PLUGIN)
            if padding:
                z.writestr("bigone/data.bin", bytes(range(256)) * (padding // 256))
        return buf.getvalue()

    def sign_in(self):
        self.server, _ = self.start()
        resp, data = self.call("POST", "/api/login", {"username": "owner", "password": PASSWORD})
        return resp.getheader("Set-Cookie").split(";")[0], data["csrf"]

    def send(self, body, cookie="", csrf="", declared=None, extra=None, name="Big One 2.5.zip"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=15)
        headers = {"Host": DOMAIN, "Content-Type": "application/zip", "X-File-Name": name}
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        headers.update(extra or {})
        conn.putrequest("POST", "/api/uploads/upload", skip_accept_encoding=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body) if declared is None else declared))
        conn.endheaders()
        return conn, body

    def finish(self, conn, body):
        try:
            conn.send(body)
        except OSError:
            pass
        resp = conn.getresponse()
        raw = resp.read()
        return resp, (json.loads(raw) if raw[:1] == b"{" else raw)

    def leftovers(self):
        import os
        folder = self.server.app.engine.upload_dir()
        return [n for n in os.listdir(folder) if n.startswith("up-")]

    def test_a_file_is_streamed_to_disk_checked_and_listed(self):
        cookie, csrf = self.sign_in()
        body = self.make_zip(padding=3 * 1024 * 1024)
        conn, body = self.send(body, cookie, csrf)
        resp, data = self.finish(conn, body)
        self.assertEqual((resp.status, data["ok"]), (200, True), data)
        self.assertIn("Big One 2.5 is ready", data["message"])
        self.assertEqual(self.leftovers(), [], "the temporary file is gone")
        listing = self.call("GET", "/api/uploads", headers={"Cookie": cookie})[1]
        self.assertEqual([(z["name"], z["version"]) for z in listing["zips"]], [("Big One", "2.5")])

    def test_nobody_can_upload_without_signing_in_and_nothing_is_written(self):
        cookie, csrf = self.sign_in()
        for cookie_, csrf_, status in (("", "", 401), (cookie, "", 403), (cookie, "wrong", 403)):
            conn, body = self.send(self.make_zip(), cookie_, csrf_)
            resp, data = self.finish(conn, body)
            self.assertEqual(resp.status, status, (cookie_, csrf_))
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.call("GET", "/api/uploads", headers={"Cookie": cookie})[1]["zips"], [])

    def test_a_huge_file_is_refused_from_its_header_alone(self):
        cookie, csrf = self.sign_in()
        conn, _ = self.send(b"", cookie, csrf, declared=5 * 1024 * 1024 * 1024)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        self.assertIn(b"200 MB", resp.read())

    def test_a_missing_length_is_refused(self):
        cookie, csrf = self.sign_in()
        conn, body = self.send(b"", cookie, csrf, declared=0)
        resp, data = self.finish(conn, body)
        self.assertEqual(resp.status, 411)

    def test_an_upload_that_is_cut_short_leaves_nothing_behind(self):
        cookie, csrf = self.sign_in()
        conn, _ = self.send(b"", cookie, csrf, declared=100000)
        self.addCleanup(conn.close)
        conn.send(b"PK\x03\x04 only a few bytes")
        conn.sock.shutdown(socket.SHUT_WR)
        try:
            resp = conn.getresponse()
            self.assertIn(resp.status, (400,))
        except (http.client.HTTPException, OSError):
            pass
        import time
        time.sleep(0.3)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.call("GET", "/api/uploads", headers={"Cookie": cookie})[1]["zips"], [])

    def test_something_that_is_not_a_plugin_is_refused_after_arriving_and_removed(self):
        cookie, csrf = self.sign_in()
        conn, body = self.send(b"this is not a zip file at all", cookie, csrf)
        resp, data = self.finish(conn, body)
        self.assertEqual(resp.status, 400)
        self.assertIn("not a zip file", data["message"])
        self.assertEqual(self.leftovers(), [])

    def test_the_panel_still_answers_afterwards(self):
        cookie, csrf = self.sign_in()
        conn, body = self.send(self.make_zip(), cookie, csrf)
        self.finish(conn, body)
        self.assertEqual(self.call("GET", "/api/me", headers={"Cookie": cookie})[0].status, 200)
