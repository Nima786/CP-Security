"""The server firewall: only the ports on the owner's list are open to the internet.

Why this exists: CyberPanel's Firewall page controls a program called firewalld. On many servers (including the
first one this was built for) that program is not installed, yet the page still shows "ON" and keeps a list of
rules. Nothing is enforced, so any port with a program behind it can be reached. This module tells the truth
about that, and gives the owner a firewall that really works, with the same kind of list (name, TCP or UDP,
address, port), plus on / off / reload.

How it works: one nftables table of its own (`cps_fw`). When it is on, anything that is not on the list is dropped
(replies to connections the server started, the server itself, ping, DHCP, the server login and the admin pages
are always allowed). The admin lock (access.py) is a separate table and stays stricter for the admin pages.

Safety: turning it on starts a 2-minute timer (a systemd timer, so it survives a panel restart). Unless the owner
presses "Keep it", everything goes back to how it was. A wrong list can therefore never lock anyone out for long.
Turning it off, adding a port and reloading never need that net: they only open more.
"""
import ipaddress
import json
import os
import re
import time

from . import config, ports, provision, settings, util
from .util import Result

TABLE = provision.FW_TABLE
CONFIRM_SECONDS = 120
MAX_RULES = 300
REVERT_UNIT = "cps-fw-revert"
PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
_now = time.time                    # tests replace this


# ----------------------------------------------------------------------------- one rule
def check_rule(name, proto, address, port):
    """Return (clean rule dict, None) or (None, friendly error)."""
    name = " ".join(re.sub(r"[^A-Za-z0-9 ._-]", " ", str(name or "")).split())[:40].strip() or "Added from the panel"
    proto = str(proto or "").strip().lower()
    if proto not in ("tcp", "udp"):
        return None, "Choose TCP or UDP. (Websites, mail and logins use TCP; DNS and web/3 traffic use UDP as well.)"
    address = str(address or "").strip()
    if address in ("", "0.0.0.0/0", "::/0", "0.0.0.0", "any", "all"):
        address = ""
    else:
        try:
            net = ipaddress.ip_network(address, strict=False)
        except ValueError:
            return None, "That does not look like an internet address. Leave it empty for everybody, or use 203.0.113.25 or 203.0.113.0/24."
        address = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        if net.prefixlen == 0:
            address = ""
    m = PORT_RE.match(str(port or "").strip())
    if not m:
        return None, "The port must be a number from 1 to 65535, or a range like 40110-40210."
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
        return None, "The port must be a number from 1 to 65535, or a range like 40110-40210."
    return {"name": name, "proto": proto, "address": address, "port": str(lo) if lo == hi else "%d-%d" % (lo, hi)}, None


def _span(port):
    lo, _, hi = port.partition("-")
    return int(lo), int(hi or lo)


def covers(rule, proto, port):
    lo, hi = _span(rule["port"])
    return rule["proto"] == proto and lo <= port <= hi


def describe(rule):
    who = "everybody" if not rule["address"] else rule["address"]
    return "%s %s for %s" % (rule["proto"].upper(), rule["port"], who)


# ----------------------------------------------------------------------------- the saved list
def load():
    data = util.read_json(config.P.fw_settings, {})
    data = data if isinstance(data, dict) else {}
    rules = []
    for r in data.get("rules", []) if isinstance(data.get("rules"), list) else []:
        if not isinstance(r, dict):
            continue
        clean, err = check_rule(r.get("name"), r.get("proto"), r.get("address"), r.get("port"))
        if clean and isinstance(r.get("id"), int):
            clean["id"] = r["id"]
            clean["source"] = r.get("source") if r.get("source") in ("you", "cyberpanel", "in use", "other firewall") else "you"
            rules.append(clean)
    pending = data.get("pending") if isinstance(data.get("pending"), dict) else None
    if pending is not None:
        prev = pending.get("previous") if isinstance(pending.get("previous"), dict) else {}
        pending = {"until": float(pending.get("until") or 0), "action": str(pending.get("action") or "on"),
                   "previous": {"enabled": bool(prev.get("enabled")), "rules": prev.get("rules") if isinstance(prev.get("rules"), list) else []}}
    stored = data.get("next_id") if isinstance(data.get("next_id"), int) else 1
    next_id = max(max([r["id"] for r in rules], default=0) + 1, stored)
    return {"enabled": bool(data.get("enabled")), "rules": rules, "next_id": next_id, "pending": pending}


def save(cfg):
    util.write_json(config.P.fw_settings, {"enabled": cfg["enabled"], "rules": cfg["rules"], "next_id": cfg["next_id"],
                                           "pending": cfg["pending"]}, mode=0o600)


def _add(cfg, clean, source):
    """Add a checked rule unless the same one is there. Returns True if it was added."""
    for r in cfg["rules"]:
        if (r["proto"], r["address"], r["port"]) == (clean["proto"], clean["address"], clean["port"]):
            return False
    cfg["rules"].append(dict(clean, id=cfg["next_id"], source=source))
    cfg["next_id"] += 1
    return True


# ----------------------------------------------------------------------------- what is always open
def ssh_ports():
    rc, out = util.run(["sshd", "-T"])
    found = sorted(set(int(p) for p in re.findall(r"^port (\d+)$", out, re.M))) if rc == 0 else []
    if not found:
        live = ports.listening() or []
        found = sorted(set(r["port"] for r in live if "sshd" in r["programs"] and r["reach"] != "server"))
    return found or [22]


def always_open_ports():
    """TCP ports the firewall always lets through (the admin lock and the login decide who may use them)."""
    out = set(ssh_ports()) | set(settings.lock_ports())
    panel = settings.load()["port"]
    if settings.valid_port(panel):
        out.add(panel)
    return sorted(out)


def builtin_rows():
    ssh = ssh_ports()
    admin = sorted(set(settings.lock_ports()) | ({settings.load()["port"]} if settings.valid_port(settings.load()["port"]) else set()))
    return [
        {"name": "Replies to connections the server started", "what": "Updates, mail it sends, anything the server asks for.", "port": ""},
        {"name": "The server talking to itself", "what": "Websites, databases and caches reach each other inside the server.", "port": ""},
        {"name": "Ping and network messages", "what": "Needed for the network to work (and for you to test it).", "port": ""},
        {"name": "Automatic network settings (DHCP)", "what": "Without this a server that renews its address automatically could lose its connection.", "port": ""},
        {"name": "Server login (SSH)", "what": "Always open so you can never lock yourself out. Limit it to your own addresses on the Open ports page.",
         "port": ", ".join(str(p) for p in ssh)},
        {"name": "Admin pages and this panel", "what": "Always open here; the admin lock decides who may use them.",
         "port": ", ".join(str(p) for p in admin)},
    ]


# ----------------------------------------------------------------------------- the nftables text
def _addr_match(address):
    if not address:
        return ""
    return ("ip6 saddr %s " if ":" in address else "ip saddr %s ") % address


def build_nft(rules, always, table=TABLE, test_source=None, counting=True):
    """The whole firewall as one nft file. Reloading it replaces the old table in one step.

    test_source: for tests on a live server only. If given, the table only judges packets from that one address
    (everything else is accepted at once) and does not trust the loopback, so the real traffic is never touched.
    counting: also remember which ports were refused (per port, for an hour) so the page can show them."""
    lines = [
        "#!/usr/sbin/nft -f",
        "# Written by CP-Security. Change it on the Server firewall page, not by hand.",
        "add table inet %s" % table,
        "flush table inet %s" % table,
        "table inet %s {" % table,
    ]
    if counting:
        lines += ["    set refused_tcp { type inet_service; flags dynamic,timeout; timeout 1h; size 256; counter; }",
                  "    set refused_udp { type inet_service; flags dynamic,timeout; timeout 1h; size 256; counter; }"]
    lines += [
        "    chain input {",
        "        type filter hook input priority 10; policy accept;",
    ]
    if test_source:
        lines.append("        ip saddr != %s accept" % test_source)
    lines += [
        "        ct state established,related accept",
        "        ct state invalid drop",
    ]
    if not test_source:
        lines.append('        iifname "lo" accept')
    lines += [
        "        meta l4proto icmp accept",
        "        meta l4proto ipv6-icmp accept",
        "        udp sport 67 udp dport 68 accept",
        "        udp dport 546 accept",
    ]
    if always:
        lines.append('        tcp dport { %s } accept comment "always open"' % ", ".join(str(p) for p in always))
    for r in rules:
        lines.append("        %s%s dport %s accept comment \"%s\"" % (_addr_match(r["address"]), r["proto"], r["port"], r["name"]))
    if counting:
        lines += ["        tcp flags & (syn | ack) == syn update @refused_tcp { tcp dport timeout 1h }",
                  "        meta l4proto udp update @refused_udp { udp dport timeout 1h }"]
    lines += ["        counter drop", "    }", "}", ""]
    return "\n".join(lines)


# ----------------------------------------------------------------------------- what is true right now
def is_loaded():
    rc, out = util.run(["nft", "list", "table", "inet", TABLE])
    return rc == 0 and ("table inet %s" % TABLE) in out and "drop" in out


def cyberpanel_rules():
    """CyberPanel's own list of firewall rules as [(name, proto, address, port)], or None if it cannot be read."""
    if not os.path.isdir(config.P.at("/usr/local/CyberCP")):
        return None
    rc, out = util.run(["mysql", "-N", "-B", "-e",
                        "select name,proto,ipAddress,port from cyberpanel.firewall_firewallrules order by id"], timeout=20)
    if rc != 0:
        return None
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            rows.append(tuple(parts))
    return rows


def truth():
    """What is really protecting this server, compared with what CyberPanel's Firewall page says."""
    rc, out = util.run(["systemctl", "status", "firewalld"])
    # CyberPanel shows OFF only when this text contains the word "dead". A program that is missing altogether
    # gives another text, so the page says ON although nothing is running.
    page_says_on = "dead" not in out
    rc2, active = util.run(["systemctl", "is-active", "firewalld"])
    firewalld_running = active.strip() == "active"
    rc3, installed = util.run(["systemctl", "cat", "firewalld"])
    firewalld_installed = rc3 == 0
    rc4, ufw = util.run(["ufw", "status"])
    ufw_on = rc4 == 0 and "Status: active" in ufw
    csf_on = os.path.exists(config.P.at("/etc/csf/csf.conf")) and util.run(["systemctl", "is-active", "lfd"])[1].strip() == "active"
    cfg = load()
    loaded = is_loaded()
    others = [n for n, on in (("firewalld", firewalld_running), ("ufw", ufw_on), ("CSF", csf_on)) if on]
    listed = cyberpanel_rules()
    has_cp = os.path.isdir(config.P.at("/usr/local/CyberCP"))

    if has_cp and page_says_on and not firewalld_running:
        cp = ("bad", "CyberPanel's Firewall page says ON, but the program behind it (firewalld) is %s. "
                     "The rules on that page are only a list: nothing is enforced."
              % ("not running" if firewalld_installed else "not installed"))
    elif has_cp and firewalld_running:
        cp = ("ok", "CyberPanel's Firewall page is working: firewalld is running.")
    elif has_cp:
        cp = ("info", "CyberPanel's Firewall page says OFF, and that is true.")
    else:
        cp = ("info", "CyberPanel was not found on this server.")

    protected = loaded or bool(others)
    if loaded:
        verdict = ("ok", "The CP-Security firewall is ON. Only the ports on the list are open.")
    elif others:
        verdict = ("ok", "A firewall (%s) is running." % ", ".join(others))
    else:
        verdict = ("bad", "No firewall is running. Every port that has a program behind it can be reached from the internet, "
                          "except the admin pages that the admin lock protects.")
    return {
        "protected": protected, "verdict": {"level": verdict[0], "text": verdict[1]},
        "cyberpanel": {"present": has_cp, "page_says_on": page_says_on, "firewalld_installed": firewalld_installed,
                       "firewalld_running": firewalld_running, "rules_listed": None if listed is None else len(listed),
                       "level": cp[0], "text": cp[1]},
        "ours": {"enabled": cfg["enabled"], "loaded": loaded},
        "others": others,
    }


# ----------------------------------------------------------------------------- suggestions
def _other_firewall_accepts():
    """Accept rules for incoming ports that other tools put in iptables: [(proto, address, port, comment)]."""
    found = []
    for tool in ("iptables", "ip6tables"):
        rc, out = util.run([tool, "-S", "INPUT"])
        if rc != 0:
            continue
        for line in out.splitlines():
            if not line.startswith("-A INPUT") or not line.rstrip().endswith("-j ACCEPT"):
                continue
            proto = re.search(r"-p (tcp|udp)\b", line)
            dport = re.search(r"--dport (\d+(?::\d+)?)", line)
            if not proto or not dport or " -i lo" in line or "ESTABLISHED" in line:
                continue
            src = re.search(r"-s (\S+)", line)
            address = src.group(1) if src else ""
            if address.startswith("127.") or address in ("::1/128", "::1"):
                continue
            if address.endswith("/32") or address.endswith("/128"):
                address = address.rsplit("/", 1)[0]
            comment = re.search(r'--comment "?([^"]+)"?', line)
            found.append((proto.group(1), address, dport.group(1).replace(":", "-"), comment.group(1) if comment else ""))
    return found


def _udp_listening():
    rc, out = util.run(["ss", "-H", "-lunp"])
    found = {}
    if rc != 0:
        return found
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[3]:
            continue
        host, _, number = parts[3].rpartition(":")
        if not number.isdigit() or ports._scope(host) == "server":
            continue
        port = int(number)
        if port >= 32768:                    # random high ports opened for a moment, not services
            continue
        names = re.findall(r'\("([^"]+)",pid=', line)
        found.setdefault(port, names)
    return found


def suggestions(cfg=None):
    """Things that would stop working when the firewall is switched on, as ready-to-add rules."""
    cfg = cfg or load()
    always = set(always_open_ports())
    out, seen = [], set()

    def covered(proto, port):
        return (proto == "tcp" and port in always) or any(covers(r, proto, port) for r in cfg["rules"])

    def offer(name, proto, address, port, why):
        clean, err = check_rule(name, proto, address, port)
        if err:
            return
        key = "%s:%s:%s" % (clean["proto"], clean["address"], clean["port"])
        if key in seen:
            return
        seen.add(key)
        out.append(dict(clean, key=key, why=why))

    for item in ports.listening() or []:
        if item["reach"] == "server" or covered("tcp", item["port"]):
            continue
        name = ports._identify(item["port"], item["programs"])[0]
        offer(name, "tcp", "", item["port"], "In use right now%s" % (" by " + ", ".join(item["programs"]) if item["programs"] else ""))
    for port, names in sorted(_udp_listening().items()):
        if covered("udp", port):
            continue
        offer("%s (UDP)" % (names[0] if names else "Port %d" % port), "udp", "", port,
              "In use right now%s" % (" by " + ", ".join(names) if names else ""))
    for proto, address, port, comment in _other_firewall_accepts():
        lo, hi = _span(port)
        if any(covers(r, proto, lo) and r["address"] == address for r in cfg["rules"]):
            continue
        offer(comment or "Allowed by another firewall rule", proto, address, port, "Another program already allows this in the firewall")
    return out


def add_suggested(keys=None):
    cfg = load()
    added = 0
    for s in suggestions(cfg):
        if keys is not None and s["key"] not in keys:
            continue
        clean, err = check_rule(s["name"], s["proto"], s["address"], s["port"])
        if clean and len(cfg["rules"]) < MAX_RULES and _add(cfg, clean, "other firewall" if s["why"].startswith("Another") else "in use"):
            added += 1
    save(cfg)
    if cfg["enabled"] and is_loaded():
        reload_live(cfg)
    return Result(True, "Added %d rule%s." % (added, "" if added == 1 else "s")) if added else Result(False, "There is nothing to add.", "none")


def import_cyberpanel():
    listed = cyberpanel_rules()
    if listed is None:
        return Result(False, "CyberPanel's list could not be read on this server.", "unreadable")
    cfg = load()
    always = set(always_open_ports())
    added = skipped = 0
    for name, proto, address, port in listed:
        clean, err = check_rule(name, proto, address, port)
        if err:
            skipped += 1
            continue
        lo, hi = _span(clean["port"])
        if clean["proto"] == "tcp" and lo == hi and lo in always:
            skipped += 1                        # the server login and admin pages are already always open
            continue
        if len(cfg["rules"]) >= MAX_RULES:
            break
        if _add(cfg, clean, "cyberpanel"):
            added += 1
        else:
            skipped += 1
    save(cfg)
    if cfg["enabled"] and is_loaded():
        reload_live(cfg)
    return Result(True, "Copied %d rule%s from CyberPanel's list (%d were already here or always open)." % (added, "" if added == 1 else "s", skipped))


# ----------------------------------------------------------------------------- loading it
def _write_and_check(cfg):
    tmp = config.P.fw_nft + ".new"
    for counting in (True, False):               # an older firewall program may not know the per-port counters
        util.atomic_write(tmp, build_nft(cfg["rules"], always_open_ports(), counting=counting))
        rc, out = util.run(["nft", "-c", "-f", tmp])
        if rc == 0:
            break
    if rc != 0:
        os.remove(tmp)
        return Result(False, "The firewall program did not accept the list: " + out.strip()[:200], "nft_rejected")
    util.backup_file(config.P.fw_nft, config.P.backup_dir)
    os.replace(tmp, config.P.fw_nft)
    return Result(True, "ok")


def reload_live(cfg):
    """Write the list and load it into the running firewall in one step."""
    res = _write_and_check(cfg)
    if not res.ok:
        return res
    rc, out = util.run(["nft", "-f", config.P.fw_nft])
    if rc != 0:
        return Result(False, "The firewall could not be loaded: " + out.strip()[:200], "nft_failed")
    if not is_loaded():
        return Result(False, "The firewall was loaded but the system does not show it. Nothing is protected.", "not_loaded")
    return Result(True, "ok")


def _unit_on():
    """Make the firewall come back after a restart of the server. Returns True if that worked."""
    provision.write_unit(provision.SERVICE_FW, provision.UNIT_FW.format(nft=provision.nft_path(), nft_file=config.P.fw_nft, table=TABLE))
    ok, out = provision.enable_unit(provision.SERVICE_FW, start=False)
    return ok


def _unit_off():
    util.run(["systemctl", "disable", provision.SERVICE_FW], timeout=60)


def _start_undo_timer():
    util.run(["systemctl", "stop", REVERT_UNIT + ".timer"])
    cmd = ["systemd-run", "--unit=" + REVERT_UNIT, "--on-active=%d" % CONFIRM_SECONDS, "--collect",
           "--setenv=PYTHONPATH=" + config.P.install_dir, provision.python_path(), "-m", "cpsec", "serverfw", "revert"]
    rc, out = util.run(cmd, timeout=30)
    return rc == 0


def _stop_undo_timer():
    util.run(["systemctl", "stop", REVERT_UNIT + ".timer"])
    util.run(["systemctl", "reset-failed", REVERT_UNIT + ".service"])


def refused(limit=15):
    """Ports the firewall refused during the last hour, busiest first, as
    [{'proto', 'port', 'packets', 'programs'}]. None when the firewall is off or cannot count."""
    if not is_loaded():
        return None
    counts, answered = {}, False
    for proto in ("tcp", "udp"):
        rc, out = util.run(["nft", "-j", "list", "set", "inet", TABLE, "refused_" + proto])
        if rc != 0:
            continue
        answered = True
        try:
            data = json.loads(out)
        except ValueError:
            continue
        for item in data.get("nftables", []) if isinstance(data, dict) else []:
            for elem in (item.get("set") or {}).get("elem", []):
                el = elem.get("elem") if isinstance(elem, dict) and "elem" in elem else elem
                val = el.get("val") if isinstance(el, dict) else el
                packets = ((el.get("counter") or {}).get("packets", 0)) if isinstance(el, dict) else 0
                if isinstance(val, int) and not isinstance(val, bool):
                    counts[(proto, val)] = counts.get((proto, val), 0) + int(packets or 0)
    if not answered:
        return None
    tcp_programs = {r["port"]: r["programs"] for r in ports.listening() or []}
    udp_programs = _udp_listening()
    rows = [{"proto": proto, "port": port, "packets": n,
             "programs": (tcp_programs if proto == "tcp" else udp_programs).get(port, [])}
            for (proto, port), n in counts.items()]
    rows.sort(key=lambda r: (-r["packets"], r["port"]))
    return rows[:limit]


def policy():
    """A function (proto, port) -> is it allowed through? None when the firewall is not loaded."""
    if not is_loaded():
        return None
    always, rules = set(always_open_ports()), load()["rules"]
    return lambda proto, port: (proto == "tcp" and port in always) or any(covers(r, proto, port) for r in rules)


# ----------------------------------------------------------------------------- state for the page
def _listening_public():
    return [r for r in (ports.listening() or []) if r["reach"] != "server"]


def state():
    cfg = load()
    pending = cfg["pending"]
    if pending and _now() > pending["until"] + 15:        # the timer did not fire: undo it ourselves
        revert()
        cfg = load()
        pending = None
    t = truth()
    live_ports = {r["port"]: r for r in _listening_public()}
    rows = []
    for r in cfg["rules"]:
        lo, hi = _span(r["port"])
        users = sorted({name for p, item in live_ports.items() if r["proto"] == "tcp" and lo <= p <= hi for name in item["programs"]})
        rows.append(dict(r, in_use=bool(users), used_by=users, text=describe(r)))
    return {
        "truth": t, "enabled": cfg["enabled"], "loaded": t["ours"]["loaded"], "refused": refused(),
        "rules": rows, "builtin": builtin_rows(), "suggestions": suggestions(cfg),
        "cyberpanel_rules": t["cyberpanel"]["rules_listed"],
        "pending": None if not pending else {"seconds_left": max(0, int(pending["until"] - _now())), "action": pending["action"]},
        "confirm_seconds": CONFIRM_SECONDS, "max_rules": MAX_RULES,
    }


# ----------------------------------------------------------------------------- the owner's actions
def add_rule(name, proto, address, port):
    clean, err = check_rule(name, proto, address, port)
    if err:
        return Result(False, err, "invalid")
    cfg = load()
    if len(cfg["rules"]) >= MAX_RULES:
        return Result(False, "The list is full (%d rules)." % MAX_RULES, "full")
    snapshot = json.loads(json.dumps(cfg))
    if not _add(cfg, clean, "you"):
        return Result(False, "That rule is already on the list.", "exists")
    save(cfg)
    if cfg["enabled"]:
        res = reload_live(cfg)
        if not res.ok:
            save(snapshot)
            return Result(False, "Nothing was changed. " + res.message, res.code)
        return Result(True, "%s is open." % describe(clean))
    return Result(True, "Saved: %s. The firewall is off, so this applies when you turn it on." % describe(clean))


def remove_rule(rule_id, confirmed=False):
    cfg = load()
    rule = next((r for r in cfg["rules"] if r["id"] == rule_id), None)
    if rule is None:
        return Result(False, "That rule does not exist.", "missing")
    if cfg["enabled"] and not confirmed:
        lo, hi = _span(rule["port"])
        busy = [(p, item) for p, item in ((r["port"], r) for r in _listening_public()) if rule["proto"] == "tcp" and lo <= p <= hi and not rule["address"]]
        if busy:
            names = ", ".join("%d (%s)" % (p, ", ".join(item["programs"]) or "a program") for p, item in busy[:4])
            return Result(False, "%s is in use right now: %s. If you remove this rule, nobody outside can reach it any more." % (describe(rule), names), "needs_confirm")
    snapshot = json.loads(json.dumps(cfg))
    cfg["rules"] = [r for r in cfg["rules"] if r["id"] != rule_id]
    save(cfg)
    if cfg["enabled"]:
        res = reload_live(cfg)
        if not res.ok:
            save(snapshot)
            return Result(False, "Nothing was changed. " + res.message, res.code)
        return Result(True, "%s is closed." % describe(rule))
    return Result(True, "Removed: %s." % describe(rule))


def turn_on(add_in_use=True):
    cfg = load()
    if cfg["pending"]:
        return Result(False, "A change is waiting for your answer. Press 'Keep it' or 'Undo' first.", "pending")
    if add_in_use:
        for s in suggestions(cfg):
            clean, _ = check_rule(s["name"], s["proto"], s["address"], s["port"])
            if clean and len(cfg["rules"]) < MAX_RULES:
                _add(cfg, clean, "other firewall" if s["why"].startswith("Another") else "in use")
    previous = {"enabled": cfg["enabled"], "rules": json.loads(json.dumps(load()["rules"]))}
    cfg["enabled"] = True
    cfg["pending"] = {"until": _now() + CONFIRM_SECONDS, "action": "on", "previous": previous}
    res = reload_live(cfg)
    if not res.ok:
        util.run(["nft", "delete", "table", "inet", TABLE])
        return Result(False, "The firewall was not switched on. " + res.message, res.code)
    save(cfg)
    if not _start_undo_timer():
        util.run(["nft", "delete", "table", "inet", TABLE])
        cfg["enabled"], cfg["pending"] = previous["enabled"], None
        save(cfg)
        return Result(False, "The firewall was not switched on, because the automatic undo could not be set up "
                             "(it protects you from locking yourself out).", "no_timer")
    # it is made permanent only when the owner presses "Keep it": a restart during the 2 minutes comes back with it off
    return Result(True, "The firewall is ON. Press 'Keep it' within %d minutes, or it switches itself off again." % (CONFIRM_SECONDS // 60), "pending")


def turn_off():
    cfg = load()
    util.run(["nft", "delete", "table", "inet", TABLE])
    util.run(["systemctl", "stop", provision.SERVICE_FW])
    _unit_off()
    _stop_undo_timer()
    cfg["enabled"], cfg["pending"] = False, None
    save(cfg)
    return Result(True, "The firewall is OFF. Every port with a program behind it can be reached again (the admin lock still works).")


def reload_now():
    cfg = load()
    if not cfg["enabled"]:
        return Result(False, "The firewall is off, so there is nothing to reload. Turn it on first.", "off")
    res = reload_live(cfg)
    if not res.ok:
        return res
    return Result(True, "The firewall was reloaded from your list (%d rule%s)." % (len(cfg["rules"]), "" if len(cfg["rules"]) == 1 else "s"))


def confirm():
    cfg = load()
    if not cfg["pending"]:
        return Result(False, "Nothing is waiting for an answer.", "none")
    _stop_undo_timer()
    cfg["pending"] = None
    save(cfg)
    if not _unit_on():
        return Result(True, "Kept. The firewall is on now, but it could not be set to start again after a restart of the server.")
    return Result(True, "Kept. The firewall stays on, also after a restart of the server.")


def revert():
    """Go back to how things were before the last 'turn on' (the timer calls this; so can the owner)."""
    cfg = load()
    pending = cfg["pending"]
    if not pending:
        return Result(True, "Nothing to undo.")
    prev = pending["previous"]
    cfg["pending"] = None
    cfg["rules"] = []
    for r in prev["rules"]:
        clean, _ = check_rule(r.get("name"), r.get("proto"), r.get("address"), r.get("port"))
        if clean and isinstance(r.get("id"), int):
            cfg["rules"].append(dict(clean, id=r["id"], source=r.get("source") or "you"))
    cfg["enabled"] = prev["enabled"]
    save(cfg)
    _stop_undo_timer()
    if prev["enabled"]:
        res = reload_live(cfg)
        return Result(res.ok, "The change was undone; the firewall is back to its earlier list." if res.ok else res.message, res.code)
    util.run(["nft", "delete", "table", "inet", TABLE])
    _unit_off()
    return Result(True, "The change was undone; the firewall is off again.")


def power(action, add_in_use=True, confirmed=False):
    if action == "on":
        if not confirmed:
            return Result(False, "Please confirm that you want to switch the firewall on.", "needs_confirm")
        return turn_on(add_in_use)
    if action == "off":
        return turn_off()
    if action == "reload":
        return reload_now()
    return Result(False, "Unknown action.", "invalid")
