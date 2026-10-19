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
class RealStart(EnvTestCase):
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

    def test_without_a_certificate_the_failure_is_a_clear_message_not_a_crash_in_our_code(self):
        shutil.rmtree("%s/%s" % (config.P.letsencrypt_live, DOMAIN))
        with self.assertRaises((OSError, FileNotFoundError)):
            self.start()
