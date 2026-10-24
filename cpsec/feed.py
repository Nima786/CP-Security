"""The login watcher: copies failed WordPress logins into one tidy file for the attack blocker.

Why it exists: the blocker (fail2ban 0.11) can crash on web-server log lines that attack traffic
makes short or odd, and a crashed blocker silently protects nothing. This helper reads the websites'
logs itself, keeps only well-formed "POST /wp-login.php" lines that WordPress answered with its login
form again (200) or with "unauthorized" (401), which is what a wrong password looks like, and writes them
in a fixed format:

    2026-10-19 03:07:47 WPLOGIN 203.0.113.9 shop.example.com 200

A correct password gets a redirect (302), so it is never copied. Cloudflare's own addresses are never
copied either, so the blocker can never shut Cloudflare out.

The old app-login door (xmlrpc.php) is counted too, but only where the website REFUSES it (403): a sender that keeps
posting passwords to a closed door is a bot by definition, and nobody who uses that door for real is ever counted
(where it is open, its answer cannot tell a wrong password from a right one). Those lines name the door:

    2026-10-24 06:48:24 WPLOGIN 203.0.113.9 shop.example.com/xmlrpc 403

Run as a service:  python3 -m cpsec.feed
"""
import glob
import ipaddress
import os
import re
import sys
import time

from . import config, netinfo

# The request may or may not be in quotes: CyberPanel's LiteSpeed writes it without, the usual "combined" format with.
LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "?POST /wp-login\.php(?:\?[^ "]*)? HTTP/[\d.]+"? (\d{3}) ')
XMLRPC = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "?POST /+xmlrpc\.php(?:\?[^ "]*)? HTTP/[\d.]+"? (\d{3}) ')
LOG_GLOB = "/home/*/logs/*.access_log"
POLL_SECONDS = 2.0


def domain_of(path):
    """/home/shop.example.com/logs/shop.example.com.access_log -> shop.example.com"""
    parts = path.replace("\\", "/").split("/")
    try:
        return parts[parts.index("logs") - 1]
    except (ValueError, IndexError):
        return "unknown"


def clean_domain(text):
    return text if re.match(r"^[A-Za-z0-9.-]{1,253}$", text) else "unknown"


def convert(line, domain, now=None):
    """One web-server log line -> one tidy line, or None when it is not a failed login."""
    door = ""
    m = LINE.match(line)
    if not m or m.group(2) not in ("200", "401"):
        m = XMLRPC.match(line)
        if not m or m.group(2) != "403":
            return None
        door = "/xmlrpc"
    ip = m.group(1)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if netinfo.is_cloudflare(ip):
        return None
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    return "%s WPLOGIN %s %s%s %s\n" % (stamp, ip, clean_domain(domain), door, m.group(2))


class Follower:
    """Reads only what was added to the logs since the last look."""

    def __init__(self, pattern=None, out_path=None):
        self.pattern = pattern or config.P.at(LOG_GLOB)
        self.out_path = out_path or config.P.wplogin_log
        self.state = {}          # path -> (inode, offset)
        self.first_pass = True

    def poll(self, now=None):
        """Look once. Returns the tidy lines that were written."""
        written = []
        seen = set()
        for path in glob.glob(self.pattern):
            seen.add(path)
            try:
                st = os.stat(path)
                inode, size = st.st_ino, st.st_size
            except OSError:
                continue
            known = self.state.get(path)
            if known is None:
                # a log we have not seen: start at its end on the very first look (do not replay history),
                # at its start for logs that appear later (a new website)
                offset = size if self.first_pass else 0
            elif known[0] != inode or size < known[1]:
                offset = 0                                   # rotated or emptied: read the new one from its start
            else:
                offset = known[1]
            if size > offset:
                offset, lines = self._read(path, offset)
                domain = domain_of(path)
                for line in lines:
                    out = convert(line, domain, now)
                    if out:
                        written.append(out)
            self.state[path] = (inode, offset)
        for gone in set(self.state) - seen:
            del self.state[gone]
        self.first_pass = False
        if written:
            os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
            with open(self.out_path, "a", encoding="utf-8") as f:
                f.write("".join(written))
        return written

    @staticmethod
    def _read(path, offset, limit=8 * 1024 * 1024):
        """Complete lines only; a half-written last line waits for the next look."""
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read(limit)
        except OSError:
            return offset, []
        end = data.rfind(b"\n")
        if end < 0:
            return offset, []
        text = data[:end + 1].decode("utf-8", "replace")
        return offset + end + 1, text.splitlines()


def main():
    follower = Follower()
    os.makedirs(os.path.dirname(follower.out_path), exist_ok=True)
    while True:
        try:
            follower.poll()
        except Exception as exc:                                # keep running whatever happens to one log
            print("feed: %s" % exc, file=sys.stderr)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
