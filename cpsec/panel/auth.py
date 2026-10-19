"""Passwords, one-time codes, sessions and login throttling. Standard library only."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 128 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12


# ----------------------------------------------------------------------------- passwords
def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password, n=SCRYPT_N):
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=SCRYPT_MAXMEM, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (n, SCRYPT_R, SCRYPT_P, _b64(salt), _b64(dk))


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=SCRYPT_MAXMEM, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(expected))
    except (ValueError, TypeError, AttributeError):
        return False


def password_problem(password, username=""):
    """None when the password is acceptable, otherwise a plain-English reason."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return "Use at least %d characters." % MIN_PASSWORD_LENGTH
    if len(set(password)) < 5:
        return "That password is too repetitive."
    if username and username.lower() in password.lower():
        return "The password must not contain the username."
    return None


# ----------------------------------------------------------------------------- one-time codes (RFC 6238)
def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _hotp(secret, counter, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def totp_now(secret, now=None, step=30):
    return _hotp(secret, int((time.time() if now is None else now) // step))


def verify_totp(secret, code, last_counter=0, now=None, step=30, window=1):
    """Returns the matching time-step counter, or None. A counter that was already used is refused."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    current = int((time.time() if now is None else now) // step)
    for counter in range(current - window, current + window + 1):
        if counter > last_counter and hmac.compare_digest(_hotp(secret, counter), code):
            return counter
    return None


def otpauth_uri(secret, username, issuer="CP-Security"):
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (
        quote(issuer), quote(username), secret, quote(issuer))


# ----------------------------------------------------------------------------- sessions
class SessionStore:
    """Logged-in browsers, kept in memory only (restarting the panel logs everybody out)."""

    def __init__(self, idle=1800, absolute=12 * 3600, clock=time.time):
        self.idle, self.absolute, self.clock = idle, absolute, clock
        self._items = {}
        self._lock = threading.Lock()

    def create(self, username, ip):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        now = self.clock()
        with self._lock:
            self._purge(now)
            self._items[token] = {"user": username, "ip": ip, "csrf": csrf, "created": now, "seen": now}
        return token, csrf

    def get(self, token):
        if not token:
            return None
        now = self.clock()
        with self._lock:
            s = self._items.get(token)
            if not s:
                return None
            if now - s["seen"] > self.idle or now - s["created"] > self.absolute:
                del self._items[token]
                return None
            s["seen"] = now
            return dict(s)

    def destroy(self, token):
        with self._lock:
            self._items.pop(token, None)

    def destroy_all(self, except_token=None):
        with self._lock:
            for t in [t for t in self._items if t != except_token]:
                del self._items[t]

    def _purge(self, now):
        for t in [t for t, s in self._items.items() if now - s["seen"] > self.idle or now - s["created"] > self.absolute]:
            del self._items[t]


# ----------------------------------------------------------------------------- login throttling
class LoginLimiter:
    """Five wrong tries within ten minutes lock an address out for fifteen minutes."""

    def __init__(self, max_failures=5, window=600, lockout=900, clock=time.time):
        self.max_failures, self.window, self.lockout, self.clock = max_failures, window, lockout, clock
        self._failures = {}
        self._locked = {}
        self._lock = threading.Lock()

    def seconds_locked(self, ip):
        now = self.clock()
        with self._lock:
            until = self._locked.get(ip, 0)
            if until <= now:
                self._locked.pop(ip, None)
                return 0
            return int(until - now) + 1

    def failed(self, ip):
        now = self.clock()
        with self._lock:
            recent = [t for t in self._failures.get(ip, []) if now - t < self.window] + [now]
            self._failures[ip] = recent
            if len(recent) >= self.max_failures:
                self._locked[ip] = now + self.lockout
                self._failures.pop(ip, None)

    def succeeded(self, ip):
        with self._lock:
            self._failures.pop(ip, None)
