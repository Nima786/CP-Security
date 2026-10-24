"""Daily watch: once a day it checks every website for signs of a break-in and sends a Telegram message only when
something new turns up.

What it looks for, as the website's own user (never as root):
* WordPress's own files that do not match the official ones (changed or added core files) \u2014 `wp core verify-checksums`.
* Files that look like a planted back door (a "web shell"): PHP that hides itself with eval+base64 and the like, known
  shell signatures, or an uploader that writes files; and any PHP file sitting in the uploads folder (where only pictures
  and documents belong). This is exactly the kind of thing the October break-in left behind.

How it stays quiet and useful:
* The first look just learns what is normally there (a baseline) and says nothing. After that, only NEW things raise an alert.
* Telegram messages go to one or more chat IDs that the owner sets on the page, through a bot token the owner provides.
* Nothing is ever changed or removed; it only looks and tells.
"""
import copy
import json
import re
import shlex
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import config, settings, updates, util
from .util import Result

TIMEOUT = 20
RUN_EVERY = 24 * 3600
# High-signal signs of a planted back door. Kept tight on purpose: honest plugin and library code (minifiers, PDF
# makers, polyfills) uses eval and preg_replace in ways that a loose pattern would wrongly flag. These patterns look for
# code running attacker input, or well-known shell names, which legitimate code almost never contains. (ERE, no quote chars.)
SHELL_PATTERNS = "|".join([
    r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode)\s*\(",
    r"(eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)",
    r"\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^]]*\]\s*\(",     # calling a function named by the visitor: $_GET[x](...)
    r"\$\{\s*\$_(POST|GET|REQUEST|COOKIE)",                      # a variable named by the visitor
    r"\bFilesMan\b|c99shell|r57shell|\bb374k\b|WSOshell|phpspy|JablukShell|edoced_46esab",
])
# Where a stranger can drop a file WITHOUT already running code in a plugin: the uploads folder, the must-use plugins
# folder (WordPress loads it automatically), the wp-content root and wp-config.php. Scanning whole plugin/theme trees
# (full of honest vendor libraries) only produces false alarms; out-of-date plugins are covered by the Known holes page.
SHELL_SCOPE = "wp-content/mu-plugins wp-content/uploads"
_lock = threading.Lock()
_scan = {"status": "idle", "finished": "", "sites": {}}


# ----------------------------------------------------------------------------- settings
def _settings():
    s = settings.load()
    return {"enabled": bool(s.get("watch_enabled")), "token": s.get("telegram_token") or "",
            "chats": [c for c in (s.get("telegram_chats") or []) if isinstance(c, str)]}


def valid_token(token):
    return bool(re.match(r"^\d{6,}:[A-Za-z0-9_-]{30,}$", token or ""))


def clean_chats(raw):
    """A list of chat IDs from whatever the owner typed (one per line or comma-separated). Keeps only sensible ones."""
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    out = []
    for c in raw or []:
        c = str(c).strip()
        if re.match(r"^-?\d{1,20}$", c) or re.match(r"^@[A-Za-z0-9_]{4,64}$", c):
            if c not in out:
                out.append(c)
    return out


def config_ok():
    s = _settings()
    return valid_token(s["token"]) and bool(s["chats"])


def save_config(token, chats, enabled):
    token = (token or "").strip()
    if not token:
        token = _settings()["token"]                 # blank means "keep the token that is already saved"
    chats = clean_chats(chats)
    if enabled and not valid_token(token):
        return Result(False, "That does not look like a bot token. It looks like 123456789:AA... from BotFather.", "token")
    if enabled and not chats:
        return Result(False, "Add at least one Telegram ID to send alerts to.", "chats")
    settings.save({"telegram_token": token, "telegram_chats": chats, "watch_enabled": bool(enabled)})
    return Result(True, "Saved.")


# ----------------------------------------------------------------------------- Telegram
def _post(url, fields):
    """(ok, error). Never raises. (Tests replace this.)"""
    try:
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "CP-Security"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read(100000).decode("utf-8", "replace"))
            return bool(body.get("ok")), "" if body.get("ok") else (body.get("description") or "refused")
    except urllib.error.HTTPError as exc:
        try:
            return False, json.loads(exc.read(100000).decode("utf-8", "replace")).get("description") or ("error %s" % exc.code)
        except Exception:
            return False, "error %s" % exc.code
    except Exception as exc:
        return False, str(exc)[:120]


def send(text, token=None, chats=None):
    """Send one message to every chat. Returns a list of {chat, ok, error}."""
    s = _settings()
    token = token if token is not None else s["token"]
    chats = chats if chats is not None else s["chats"]
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    out = []
    for chat in chats:
        ok, err = _post(url, {"chat_id": chat, "text": text, "disable_web_page_preview": "true"})
        out.append({"chat": chat, "ok": ok, "error": err})
    return out


def test_message(token=None, chats=None):
    token = (token if token is not None else _settings()["token"]).strip()
    chats = clean_chats(chats) if chats is not None else _settings()["chats"]
    if not valid_token(token):
        return Result(False, "That does not look like a bot token.", "token")
    if not chats:
        return Result(False, "Add at least one Telegram ID first.", "chats")
    results = send("CP-Security test message. If you can read this, alerts are set up correctly.", token, chats)
    good = [r["chat"] for r in results if r["ok"]]
    bad = [r for r in results if not r["ok"]]
    if not bad:
        return Result(True, "Sent to %d chat%s. Check your Telegram." % (len(good), "" if len(good) == 1 else "s"))
    first = bad[0]
    hint = ""
    if "chat not found" in first["error"].lower():
        hint = " The ID %s was not found \u2014 open a chat with your bot and send it any message first." % first["chat"]
    return Result(False, "Could not send to %d of %d (%s).%s" % (len(bad), len(results), first["error"], hint), "send")


# ----------------------------------------------------------------------------- looking at one website
def _scan_site(name):
    """A set of finding strings for one website, or None if it could not be read."""
    from . import wpupdate
    site = wpupdate._site(name)
    php = wpupdate._php(site) if site else None
    if not php:
        return None
    findings = set()
    rc, out = wpupdate._wp(site, php, "core verify-checksums", 300)
    for line in (out or "").splitlines():
        low = line.lower()
        if "doesn't verify against checksum" in low or "not in the original distribution" in low:
            path = line.rsplit(": ", 1)[-1].strip()
            if path:
                findings.add("core:" + path)
    q = shlex.quote
    pat = q(SHELL_PATTERNS)
    script = ("cd %s 2>/dev/null || exit 0; set -f; "
              "{ grep -rIlE --include=*.php --exclude-dir=cps-backups --exclude-dir=node_modules %s %s 2>/dev/null; "
              "find wp-content -maxdepth 1 -type f -name *.php 2>/dev/null -exec grep -lE %s {} +; "
              "grep -lE %s wp-config.php 2>/dev/null; } | sort -u | head -200; "
              "echo ---UPLOADS---; "
              "find wp-content/uploads -maxdepth 6 -type f \\( -iname *.php -o -iname *.phtml -o -iname *.phar \\) 2>/dev/null | head -200"
              % (q(site["docroot"]), pat, SHELL_SCOPE, pat, pat))
    rc, out = wpupdate._shell(site["user"], script, 180)
    section = "shell"
    for line in (out or "").splitlines():
        line = line.strip()
        if line == "---UPLOADS---":
            section = "upload-php"
            continue
        if not line:
            continue
        if section == "upload-php" and line.endswith("index.php"):
            continue                                 # the empty placeholder WordPress itself puts in every folder
        findings.add("%s:%s" % (section, line))
    return findings


def describe(finding):
    """A plain sentence for one finding string."""
    kind, _, path = finding.partition(":")
    if kind == "core":
        return "A WordPress system file was changed or added: %s" % path
    if kind == "upload-php":
        return "A program (PHP file) is sitting in the uploads folder: %s" % path
    return "A file looks like a planted back door: %s" % path


# ----------------------------------------------------------------------------- the look, with a baseline
def _names():
    return sorted(n for _d, _u, n in updates._wordpress_sites())


def _load_state():
    data = util.read_json(config.P.sentry_state, {})
    return data if isinstance(data, dict) else {}


def scan_state():
    with _lock:
        return copy.deepcopy(_scan)


def _scan_one_safe(name):
    try:
        found = _scan_site(name)
    except Exception as exc:
        return name, {"checked": False, "problem": "Checking this website failed (%s)." % str(exc)[:80], "findings": []}
    if found is None:
        return name, {"checked": False, "problem": "WordPress could not be started on this website.", "findings": []}
    return name, {"checked": True, "problem": "", "findings": sorted(found)}


def run(alert=True, progress=None):
    """Look at every website now. Alert (when set up) only on findings that are new since last time. Returns a summary."""
    say = progress or (lambda t: None)
    with _lock:
        if _scan["status"] == "running":
            return {"ok": False, "busy": True}
        _scan["status"] = "running"
    try:
        state = _load_state()
        prev_sites = state.get("sites") or {}
        first_ever = not state.get("last_run")
        try:
            names = _names()
        except (ImportError, OSError):
            names = []
        say("Checking %d website%s" % (len(names), "" if len(names) == 1 else "s"))
        with ThreadPoolExecutor(max_workers=2) as ex:
            results = dict(ex.map(_scan_one_safe, names))
        new_by_site = {}
        sites_out = {}
        for name, res in results.items():
            old = set((prev_sites.get(name) or {}).get("findings") or [])
            now = set(res["findings"])
            fresh = sorted(now - old)
            if res["checked"] and fresh and not first_ever:
                new_by_site[name] = fresh
            sites_out[name] = {"checked": res["checked"], "problem": res["problem"], "findings": res["findings"],
                               "count": len(res["findings"])}
        sent = None
        if alert and new_by_site and config_ok():
            say("Sending a Telegram alert")
            sent = send(_alert_text(new_by_site))
        new_state = {"last_run": time.strftime("%Y-%m-%d %H:%M:%S"), "last_run_epoch": int(time.time()),
                     "sites": {n: {"findings": r["findings"]} for n, r in sites_out.items()},
                     "baseline_done": True}
        util.write_json(config.P.sentry_state, new_state)
        with _lock:
            _scan["sites"] = sites_out
        return {"ok": True, "first_ever": first_ever, "new": new_by_site, "sent": sent,
                "total_findings": sum(s["count"] for s in sites_out.values())}
    finally:
        with _lock:
            _scan["status"] = "done"
            _scan["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _alert_text(new_by_site):
    lines = ["\u26a0 CP-Security found something new on your server:", ""]
    for site in sorted(new_by_site):
        lines.append("\u2022 %s" % site)
        for f in new_by_site[site][:20]:
            lines.append("   - " + describe(f))
        if len(new_by_site[site]) > 20:
            lines.append("   - \u2026and %d more" % (len(new_by_site[site]) - 20))
    lines += ["", "Check these on the Daily watch page of your CP-Security panel."]
    return "\n".join(lines)


def state(names=None):
    """For the page: settings, when it last ran, and what is being watched on each website."""
    names = names if names is not None else _names()
    s = _settings()
    stored = _load_state()
    scan = scan_state()
    prev = stored.get("sites") or {}
    sites = []
    for name in names:
        live = scan["sites"].get(name)
        if live is not None:
            checked, problem, findings = live["checked"], live["problem"], live["findings"]
        else:
            findings = (prev.get(name) or {}).get("findings") or []
            checked, problem = (name in prev), ""
        sites.append({"site": name, "checked": checked, "problem": problem, "count": len(findings),
                      "findings": [{"text": describe(f), "kind": f.split(":", 1)[0]} for f in findings]})
    sites.sort(key=lambda r: (-r["count"], r["site"]))
    return {"enabled": s["enabled"], "has_token": valid_token(s["token"]), "chats": s["chats"],
            "last_run": stored.get("last_run", ""), "baseline_done": bool(stored.get("baseline_done")),
            "configured": config_ok(), "scan": {"status": scan["status"], "finished": scan["finished"]},
            "sites": sites, "total": sum(r["count"] for r in sites)}


def scan_start(alert=True):
    with _lock:
        if _scan["status"] == "running":
            return Result(False, "A check is already running.", "busy")
    threading.Thread(target=lambda: run(alert=alert), daemon=True).start()
    return Result(True, "Checking the websites now.")


def due():
    """True when a daily run is overdue (used by the panel's background loop)."""
    if not config_ok():
        return False
    return time.time() - (_load_state().get("last_run_epoch") or 0) >= RUN_EVERY


def main():
    """Run one scan-and-alert (for a daily timer, or by hand)."""
    print(run())


if __name__ == "__main__":
    main()
