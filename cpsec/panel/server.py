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
TLS_HANDSHAKE = 0x16            # the first byte of every TLS connection; plain HTTP starts with a letter
MAX_PLAIN_REQUEST = 8192


def https_location(host_header, target, allowed_hosts, port):
    """Where to send a browser that used plain http, or None when there is no safe place.

    The host comes from the panel's own configured names, never from the request, so nobody can use the
    redirect to send people to another site. The path is kept (cleaned) so a bookmark still lands where it should.
    """
    host = (host_header or "").strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1:host.find("]")]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    if allowed_hosts:
        if host not in allowed_hosts:
            host = sorted(allowed_hosts)[0]
    else:
        return None
    path = target if target.startswith("/") else "/"
    path = "".join(c for c in path if 32 < ord(c) < 127)[:2000] or "/"
    netloc = "[%s]" % host if ":" in host else host
    if port != 443:
        netloc += ":%d" % port
    return "https://%s%s" % (netloc, path)


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
                first = request.recv(1, socket.MSG_PEEK)          # look at the first byte without taking it
                if not first:
                    self.shutdown_request(request)
                    return
                if first[0] != TLS_HANDSHAKE:
                    # somebody typed http:// : send them to the https:// address instead of an error
                    self._redirect_plain_http(request)
                    self.shutdown_request(request)
                    return
                request = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            self.shutdown_request(request)
            return
        super().process_request_thread(request, client_address)

    def _redirect_plain_http(self, sock):
        """Answer a plain-http request on the https port with a permanent redirect. Nothing else is served."""
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < MAX_PLAIN_REQUEST:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
            lines = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            method = parts[0].upper() if parts and parts[0] else "GET"
            target = parts[1] if len(parts) > 1 else "/"
            host = ""
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "host":
                    host = value
                    break
            where = https_location(host, target, self.app.allowed_hosts, self.server_address[1])
            if where is None:
                body, status = b"This address only speaks HTTPS.\n", b"400 Bad Request"
                extra = b""
            else:
                body = ("This panel uses HTTPS. Go to %s\n" % where).encode("ascii", "replace")
                status = b"301 Moved Permanently" if method in ("GET", "HEAD") else b"308 Permanent Redirect"
                extra = b"Location: " + where.encode("ascii", "replace") + b"\r\nCache-Control: max-age=86400\r\n"
            head = (b"HTTP/1.1 " + status + b"\r\n" + extra +
                    b"Content-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n")
            sock.sendall(head + (b"" if method == "HEAD" else body))
        except (OSError, UnicodeError):
            pass

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
