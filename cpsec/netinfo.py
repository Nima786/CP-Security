"""Small network questions: where does a name point to, is that address Cloudflare, which addresses are ours."""
import ipaddress
import re
import socket

from . import util

# https://www.cloudflare.com/ips-v4 and /ips-v6 (checked October 2026). These change very rarely.
CLOUDFLARE_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
CLOUDFLARE_V6 = (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)
CLOUDFLARE = CLOUDFLARE_V4 + CLOUDFLARE_V6
_NETS = [ipaddress.ip_network(n) for n in CLOUDFLARE]

DOMAIN_OK = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_domain(text):
    """The domain in lower case, or None when it is not a plain host name (no scheme, no path, no port)."""
    text = (text or "").strip().lower().rstrip(".")
    return text if DOMAIN_OK.match(text) else None


def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _NETS)


def resolve(domain):
    """The IPv4 addresses a name points to ([] when it does not exist)."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted(set(i[4][0] for i in infos))


def local_addresses():
    """IPv4 addresses on this machine's network cards."""
    rc, out = util.run(["ip", "-4", "-o", "addr", "show"])
    return sorted(set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))) if rc == 0 else []


def check_domain(domain, resolver=None, locals_=None):
    """What the installer needs to know before asking for a certificate.

    -> {'ips', 'points_here', 'cloudflare', 'exists'}
    'points_here' is None when this machine's own addresses could not be read.
    """
    ips = (resolver or resolve)(domain)
    mine = local_addresses() if locals_ is None else locals_
    return {
        "exists": bool(ips),
        "ips": ips,
        "cloudflare": any(is_cloudflare(i) for i in ips),
        "points_here": (any(i in mine for i in ips) if mine else None) if ips else False,
    }
