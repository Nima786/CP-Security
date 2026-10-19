"""Admin access: which addresses may open CyberPanel, the LiteSpeed admin page and the web terminal.

Everybody else is shut out of those pages by a small firewall table. The same list also feeds the
attack blocker, which never blocks a trusted address.
"""
import ipaddress
import os

from . import blocker, config, settings, util
from .util import Result

TABLE = "cps_lock"

ADMIN_HEADER = (
    "# Addresses that may open the admin pages (CyberPanel, LiteSpeed admin, web terminal).\n"
    "# Everybody else is shut out. Change this list with the 'security' menu or the panel.\n"
    "# One per line:   address | label\n"
)
NEVER_HEADER = (
    "# Addresses that the automatic blocker must NEVER block (for example Cloudflare).\n"
    "# One per line:   address | label\n"
)


# ----------------------------------------------------------------------------- the lists
def read_list(path):
    items = []
    for line in util.read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addr, _, label = line.partition("|")
        items.append((addr.strip(), label.strip()))
    return items


def write_list(path, items, header):
    body = header + "".join("%s | %s\n" % (a, l) for a, l in items)
    util.atomic_write(path, body)


def check_address(text):
    """Return (clean address, None) or (None, friendly error)."""
    text = (text or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None, "That does not look like an internet address. It should look like 203.0.113.25"
    too_wide = (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32)
    if too_wide:
        return None, "That covers far too many addresses. Please use a single address."
    if net.is_private or net.is_loopback or net.is_link_local:
        return None, ("That is a private address (it only exists inside a home or office network, "
                      "the server never sees it). Search Google for 'what is my IP' to get the public one.")
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address), None
    return str(net), None


def list_admin():
    return [{"address": a, "label": l, "is_home": l.lower().startswith("home")}
            for a, l in read_list(config.P.admin_list)]


def list_legacy_admin():
    """Trusted addresses of the earlier hand-made setup (not yet copied over), or an empty list."""
    return [{"address": a, "label": l} for a, l in read_list(config.P.legacy_conf_dir + "/admin-access.list")]


def list_never_block():
    return [{"address": a, "label": l} for a, l in read_list(config.P.never_list)]


# ----------------------------------------------------------------------------- applying it
def build_nft(items, ports):
    v4, v6 = ["127.0.0.1"], ["::1"]
    for addr, _ in items:
        try:
            net = ipaddress.ip_network(addr, strict=False)
        except ValueError:
            continue
        target = v4 if net.version == 4 else v6
        if addr not in target:
            target.append(addr)
    plist = ", ".join(str(p) for p in ports)
    return "\n".join([
        "#!/usr/sbin/nft -f",
        "# Written by CP-Security. Change it with the menu or the panel, not by hand.",
        "add table inet %s" % TABLE,
        "flush table inet %s" % TABLE,
        "table inet %s {" % TABLE,
        "    chain input {",
        "        type filter hook input priority -1; policy accept;",
        "        tcp dport { %s } ip saddr { %s } accept" % (plist, ", ".join(v4)),
        "        tcp dport { %s } ip6 saddr { %s } accept" % (plist, ", ".join(v6)),
        "        tcp dport { %s } drop" % plist,
        "    }",
        "}",
        "",
    ])


def _write_f2b_ignore(admin, never):
    seen, addrs = set(), []
    for a in ["127.0.0.1/8", "::1"] + [x for x, _ in admin] + [x for x, _ in never]:
        if a not in seen:
            seen.add(a)
            addrs.append(a)
    util.atomic_write(config.P.f2b_ignore,
                      "[DEFAULT]\n# Written by CP-Security: addresses the blocker never blocks.\n"
                      "ignoreip = %s\n" % " ".join(addrs))


def apply():
    """Load the admin lock and the never-block list. Returns a Result."""
    admin = read_list(config.P.admin_list)
    never = read_list(config.P.never_list)

    tmp = config.P.nft_file + ".new"
    util.atomic_write(tmp, build_nft(admin, settings.lock_ports()))
    rc, out = util.run(["nft", "-c", "-f", tmp])
    if rc != 0:
        os.remove(tmp)
        return Result(False, "The firewall did not accept the list: " + out.strip()[:200], "nft_rejected")
    util.backup_file(config.P.nft_file, config.P.backup_dir)
    os.replace(tmp, config.P.nft_file)
    rc, out = util.run(["nft", "-f", config.P.nft_file])
    if rc != 0:
        return Result(False, "Could not load the firewall: " + out.strip()[:200], "nft_failed")

    if blocker.installed():
        old = util.read_text(config.P.f2b_ignore, None) if os.path.exists(config.P.f2b_ignore) else None
        _write_f2b_ignore(admin, never)
        rc, out = util.run(["fail2ban-client", "-t"], timeout=90)
        if rc != 0:
            if old is not None:
                util.atomic_write(config.P.f2b_ignore, old)
            return Result(False, "The blocker rejected the never-block list: " + out.strip()[-200:], "f2b_rejected")
        if blocker.jails() is not None:
            util.run(["fail2ban-client", "reload"], timeout=90)
    return Result(True, "ok")


def lock_is_live():
    rc, out = util.run(["nft", "list", "table", "inet", TABLE])
    return rc == 0 and "drop" in out


def _commit(new_items, done_message):
    old_items = read_list(config.P.admin_list)
    if not new_items:
        return Result(False, "At least one address must stay on the list.", "last_address")
    write_list(config.P.admin_list, new_items, ADMIN_HEADER)
    res = apply()
    if not res.ok:
        write_list(config.P.admin_list, old_items, ADMIN_HEADER)
        apply()
        return Result(False, "Nothing was changed. " + res.message, res.code)
    # a newly trusted address is let out of any block it was in
    if blocker.jails() is not None:
        old_set = set(a for a, _ in old_items)
        for a, _ in new_items:
            if a not in old_set and "/" not in a:
                util.run(["fail2ban-client", "unban", a])
    rc, out = util.run(["nft", "list", "table", "inet", TABLE])
    live = all(a in out for a, _ in new_items if "/" not in a)
    msg = done_message if live else done_message + " (The live rules do not show every address yet: run a health check.)"
    return Result(True, msg)


# ----------------------------------------------------------------------------- the "never block" list
def _commit_never(new_items, done_message):
    old = read_list(config.P.never_list)
    write_list(config.P.never_list, new_items, NEVER_HEADER)
    res = apply()
    if not res.ok:
        write_list(config.P.never_list, old, NEVER_HEADER)
        apply()
        return Result(False, "Nothing was changed. " + res.message, res.code)
    return Result(True, done_message)


def add_never(address, label=""):
    addr, err = check_address(address)
    if err:
        return Result(False, err, "invalid")
    items = read_list(config.P.never_list)
    if any(a == addr for a, _ in items):
        return Result(False, "%s is already on the list." % addr, "exists")
    label = " ".join((label or "").replace("|", " ").split())[:60] or "Added from the panel"
    return _commit_never(items + [(addr, label)], "%s will never be blocked automatically." % addr)


def add_never_many(addresses, label):
    """Add known-good ranges in one go (for example Cloudflare's). Wide ranges are allowed here on purpose."""
    items = read_list(config.P.never_list)
    have = set(a for a, _ in items)
    fresh = []
    for a in addresses:
        try:
            net = str(ipaddress.ip_network(a, strict=False))
        except ValueError:
            continue
        if net not in have:
            fresh.append((net, label))
            have.add(net)
    if not fresh:
        return Result(False, "They are all on the list already.", "exists")
    return _commit_never(items + fresh, "%d %s addresses were added to the never-block list." % (len(fresh), label))


def remove_never(address):
    items = read_list(config.P.never_list)
    if not any(a == address for a, _ in items):
        return Result(False, "%s is not on the list." % address, "missing")
    return _commit_never([x for x in items if x[0] != address], "%s can be blocked again if it misbehaves." % address)


# ----------------------------------------------------------------------------- the actions
def add_admin(address, label=""):
    addr, err = check_address(address)
    if err:
        return Result(False, err, "invalid")
    items = read_list(config.P.admin_list)
    if any(a == addr for a, _ in items):
        return Result(False, "%s is already on the list." % addr, "exists")
    label = " ".join((label or "").replace("|", " ").split())[:60] or "Added from the panel"
    return _commit(items + [(addr, label)], "%s can now open the admin pages." % addr)


def remove_admin(address, caller_ip=None, confirmed=False):
    items = read_list(config.P.admin_list)
    if not any(a == address for a, _ in items):
        return Result(False, "%s is not on the list." % address, "missing")
    if len(items) == 1:
        return Result(False, "You cannot remove the last address.", "last_address")
    if caller_ip and address == caller_ip and not confirmed:
        return Result(False, "That is the address you are using right now. Removing it will lock you out "
                             "of the admin pages (the panel too, if it is set to trusted-only).", "needs_confirm")
    return _commit([x for x in items if x[0] != address], "%s was removed." % address)


def set_home(address):
    """Replace the 'Home' entry (or add one). This is what to use when the home internet address changes."""
    addr, err = check_address(address)
    if err:
        return Result(False, err, "invalid")
    items = read_list(config.P.admin_list)
    new_items, placed, old = [], False, None
    for a, l in items:
        if l.lower().startswith("home"):
            if not placed:
                new_items.append((addr, l))
                placed, old = True, a
        else:
            new_items.append((a, l))
    if not placed:
        new_items.append((addr, "Home Wi-Fi"))
    msg = "CyberPanel and the other admin pages now open from %s." % addr
    if old and old != addr:
        msg += " (The old address %s was removed.)" % old
    return _commit(new_items, msg)
