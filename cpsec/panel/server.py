"""The network part: HTTPS in front of App.handle(). Standard library only.

Hardening built in: a short timeout on every connection (slow-loris), a size limit on requests,
the TLS handshake happens in the connection's own thread (a stalled handshake cannot block others).
"""
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .app import MAX_BODY, Request

CONNECTION_TIMEOUT = 20


def make_tls_context(cert_file, key_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, address, app, tls_context=None):
        host = address[0]
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.app = app
        self.tls_context = tls_context
        super().__init__(address, PanelHandler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)   # one socket for IPv4 and IPv6
            except (AttributeError, OSError):
                pass
        super().server_bind()

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(CONNECTION_TIMEOUT)
            if self.tls_context is not None:
                request = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            self.shutdown_request(request)
            return
        super().process_request_thread(request, client_address)

    def reload_certificate(self, cert_file, key_file):
        """Called after the certificate was renewed: new connections use the new one."""
        self.tls_context = make_tls_context(cert_file, key_file)


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "CP-Security"
    sys_version = ""
    timeout = CONNECTION_TIMEOUT
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):          # the panel keeps its own, more useful log
        pass

    def _serve(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._send(413, b'{"ok": false, "message": "That request is too large."}', "application/json", [])
            return
        body = self.rfile.read(length) if length else b""
        req = Request(self.command, self.path, dict(self.headers.items()), body, self.client_address[0])
        resp = self.server.app.handle(req)
        self._send(resp.status, resp.body, resp.ctype, resp.headers)

    def _send(self, status, body, ctype, headers):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    do_GET = do_POST = _serve

    def do_PUT(self):
        self._send(405, b'{"ok": false, "message": "Not allowed."}', "application/json", [])

    do_DELETE = do_PATCH = do_PUT


def serve_in_thread(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
