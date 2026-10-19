"""HTTPS for the panel: finding the certificate, knowing when it runs out, and getting one.

Getting a certificate uses CyberPanel itself. It creates a small website for the sub-domain and asks
Let's Encrypt for the certificate, which is the same thing you would do by hand in CyberPanel. That
works the same on LiteSpeed Enterprise and OpenLiteSpeed, and CyberPanel renews it automatically.
"""
import datetime
import os
import re
import shutil

from . import config, util
from .util import Result


def candidates(domain):
    """(certificate file, key file) pairs worth looking at, best first."""
    p = config.P
    live = "%s/%s" % (p.letsencrypt_live, domain)
    return [
        (live + "/fullchain.pem", live + "/privkey.pem"),                  # where CyberPanel puts them
        (p.tls_dir + "/fullchain.pem", p.tls_dir + "/privkey.pem"),        # a copy placed by hand
        ("%s/.acme.sh/%s_ecc/fullchain.cer" % (p.at("/root"), domain),
         "%s/.acme.sh/%s_ecc/%s.key" % (p.at("/root"), domain, domain)),
        ("%s/.acme.sh/%s/fullchain.cer" % (p.at("/root"), domain),
         "%s/.acme.sh/%s/%s.key" % (p.at("/root"), domain, domain)),
    ]


def find(domain):
    """(certificate file, key file) or None."""
    for cert, key in candidates(domain):
        if os.path.exists(cert) and os.path.exists(key):
            return cert, key
    return None


def expiry(cert_file):
    """When the certificate ends (a datetime in UTC) or None."""
    rc, out = util.run(["openssl", "x509", "-enddate", "-noout", "-in", cert_file])
    m = re.search(r"notAfter=(.+)", out)
    if rc != 0 or not m:
        return None
    try:
        return datetime.datetime.strptime(" ".join(m.group(1).split()), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def days_left(cert_file, now=None):
    end = expiry(cert_file)
    if end is None:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    return int((end - now).total_seconds() // 86400)


def mtime_of(domain):
    """A number that changes when the certificate is renewed (the panel watches it to reload)."""
    found = find(domain)
    if not found:
        return 0.0
    try:
        return os.path.getmtime(found[0])
    except OSError:
        return 0.0


def status(domain):
    """{'found', 'cert', 'days_left'} for the settings page and the advisor."""
    found = find(domain) if domain else None
    return {"found": bool(found), "cert": found[0] if found else "",
            "days_left": days_left(found[0]) if found else None}


# ----------------------------------------------------------------------------- asking for one
def cyberpanel_available():
    return shutil.which("cyberpanel") is not None


def site_exists(domain):
    return os.path.isdir("%s/%s" % (config.P.home_dir, domain))


def get_certificate(domain, email, package="Default", owner="admin", php="8.1"):
    """Create the sub-domain's website in CyberPanel (if needed) and issue the certificate.

    Takes up to a minute. Returns a Result; the certificate files are found with find().
    """
    if find(domain):
        return Result(True, "A certificate for %s is already on this server, so it will be used." % domain, "have_cert")
    if not cyberpanel_available():
        return Result(False, "CyberPanel's command-line tool was not found. Create the website and certificate "
                             "for %s in CyberPanel by hand, then run the setup again." % domain, "no_cyberpanel")
    if not site_exists(domain):
        rc, out = util.run(["cyberpanel", "createWebsite", "--package", package, "--owner", owner,
                            "--domainName", domain, "--email", email, "--php", php], timeout=300)
        if rc != 0 or '"success": 0' in out or '"success":0' in out:
            return Result(False, "CyberPanel could not create the website for %s: %s" % (domain, _last_line(out)),
                          "create_failed")
    rc, out = util.run(["cyberpanel", "issueSSL", "--domainName", domain], timeout=300)
    if find(domain):
        return Result(True, "A certificate was issued for %s." % domain, "issued")
    return Result(False, "The certificate could not be issued (%s). The most common reasons: the name does not "
                         "point to this server yet, or Cloudflare's orange-cloud proxy is switched on for it."
                  % _last_line(out), "issue_failed")


def _last_line(text):
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    return (lines[-1] if lines else "no details")[:160]


# ----------------------------------------------------------------------------- the server's own firewall
def open_port(port):
    """Let the port through firewalld or ufw when one of them is switched on. Returns a Result.

    The admin lock (our own small firewall table) decides WHO may use the port; this only makes sure the
    general-purpose firewall does not shut it for everybody.
    """
    port = int(port)
    rc, out = util.run(["systemctl", "is-active", "firewalld"])
    if out.strip() == "active":
        rc1, _ = util.run(["firewall-cmd", "--permanent", "--add-port=%d/tcp" % port])
        rc2, _ = util.run(["firewall-cmd", "--add-port=%d/tcp" % port])
        if rc1 == 0 and rc2 == 0:
            return Result(True, "Port %d is open in firewalld." % port, "firewalld")
        return Result(False, "firewalld did not accept the port. Open %d/tcp there by hand." % port, "firewalld_failed")
    rc, out = util.run(["ufw", "status"])
    if rc == 0 and "Status: active" in out:
        rc1, _ = util.run(["ufw", "allow", "%d/tcp" % port])
        if rc1 == 0:
            return Result(True, "Port %d is open in ufw." % port, "ufw")
        return Result(False, "ufw did not accept the port. Open %d/tcp there by hand." % port, "ufw_failed")
    return Result(True, "No other firewall is switched on, nothing to open.", "none")


def port_is_open(port):
    """True/False when firewalld or ufw is on; None when neither is (nothing in the way)."""
    port = int(port)
    rc, out = util.run(["systemctl", "is-active", "firewalld"])
    if out.strip() == "active":
        rc, listed = util.run(["firewall-cmd", "--list-ports"])
        return ("%d/tcp" % port) in listed.split()
    rc, out = util.run(["ufw", "status"])
    if rc == 0 and "Status: active" in out:
        return bool(re.search(r"^%d(/tcp)?\s+ALLOW" % port, out, re.M))
    return None
