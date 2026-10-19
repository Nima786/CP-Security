"""What the panel is allowed to ask of the engine.

LiveEngine does the real work on this server. DemoEngine answers with made-up data kept in memory, so the
interface can be designed, tested and photographed on any computer.

Every method returns plain data (dicts, lists) or a util.Result.
"""
import copy
import datetime
import threading
import time

from .. import (access, advisor, blocker, config, health, provision, settings, sites, tls, updates, util, waf,
                webserver)
from ..util import Result

BUSY = Result(False, "Setup is running right now. Try again when it has finished.", "busy")


class LiveEngine:
    demo = False

    def __init__(self):
        self._lock = threading.RLock()          # one change at a time: they restart services
        self._overview = None
        self._overview_at = 0.0
        self._advice = None
        self._advice_at = 0.0
        self._job_lock = threading.Lock()
        self._updates = util.read_json(config.P.updates_cache, {"status": "idle", "sites": [], "finished": ""})
        self.runner = provision.Runner()

    def _guard(self):
        """While the setup runs, other changes wait: both would be restarting the same services."""
        return BUSY if self.runner.running() else None

    # ------------------------------------------------------------------ advisor
    def advisor_report(self, refresh=False):
        with self._lock:
            if refresh or self._advice is None or time.time() - self._advice_at > 120:
                self._advice = advisor.run()
                self._advice_at = time.time()
            return self._advice

    def advisor_fix(self, fix_id):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return advisor.apply_fix(fix_id)

    # ------------------------------------------------------------------ setup
    def setup_state(self):
        job = self.runner.snapshot()
        steps = provision.plan() if job["status"] != "running" else []
        return {"plan": steps, "job": job, "server": self.server_info()}

    def setup_start(self, keys):
        res = self.runner.start(keys)
        self._changed()
        return res

    def server_info(self):
        info = webserver.info()
        s = settings.load()
        return {"web_server": info["name"], "web_server_version": info["version"],
                "web_server_kind": info["kind"], "panel_domain": s["domain"], "panel_port": s["port"],
                "certificate": tls.status(s["domain"]) if s["domain"] else None}

    # ------------------------------------------------------------------ blocker settings, never-block list, baseline
    def blocker_settings(self):
        return {"tuning": blocker.tuning(), "limits": blocker.LIMITS,
                "names": {n: config.JAIL_NAMES.get(n, n) for n in blocker.TUNABLE},
                "missing_logs": [n for n in blocker.TUNABLE if n != "sshd" and not blocker.log_for(n)]}

    def blocker_set(self, changes):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return blocker.set_tuning(changes)

    def never_add(self, address, label):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return access.add_never(address, label)

    def never_remove(self, address):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return access.remove_never(address)

    def baseline_save(self):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            r = sites.save_baseline()
            return Result(True, "Saved: %d of %d websites answer normally. That is the reference from now on."
                          % (r["normal"], r["total"]))

    def waf_selftest(self):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            return waf.selftest()

    # ------------------------------------------------------------------ overview
    def overview(self, refresh=False):
        with self._lock:
            if refresh or self._overview is None or time.time() - self._overview_at > 45:
                self._overview = health.overview()
                self._overview_at = time.time()
            return self._overview

    def _changed(self):
        self._overview = None
        self._advice = None

    # ------------------------------------------------------------------ blocked
    def blocked(self):
        rows = blocker.all_blocked()
        return {"running": rows is not None, "rows": rows or [], "summary": blocker.recent_summary()}

    def unblock(self, ip):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return blocker.unban(ip)

    def unblock_all(self):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return blocker.unban_all()

    def set_blocking_running(self, running):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return blocker.set_running(bool(running))

    # ------------------------------------------------------------------ admin access
    def access_state(self):
        return {"trusted": access.list_admin(), "never_block": access.list_never_block(),
                "lock_live": access.lock_is_live()}

    def access_add(self, address, label):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return access.add_admin(address, label)

    def access_remove(self, address, caller_ip, confirmed):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return access.remove_admin(address, caller_ip, confirmed)

    def access_set_home(self, address):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return access.set_home(address)

    def access_reapply(self):
        with self._lock:
            return access.apply()

    # ------------------------------------------------------------------ web firewall
    def waf_state(self):
        m = waf.mode()
        return {"installed": m is not None, "mode": m, "text": waf.MODE_TEXT.get(m, "not set up"),
                "threshold": waf.threshold(), "exceptions": waf.list_exceptions()}

    def waf_summary(self):
        return waf.summary()

    def waf_recent(self):
        return waf.recent()

    def waf_set_mode(self, mode, threshold):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return waf.set_mode(mode, threshold)

    def waf_add_exception(self, scope, host, rule):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return waf.add_exception(scope, host, rule)

    def waf_remove_exception(self, index):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return waf.remove_exception(index)

    # ------------------------------------------------------------------ updates (read-only, slow: runs in the background)
    def updates_state(self):
        with self._job_lock:
            return copy.deepcopy(self._updates)

    def updates_refresh(self):
        with self._job_lock:
            if self._updates.get("status") == "running":
                return Result(False, "Already looking.", "busy")
            self._updates = dict(self._updates, status="running", started=time.strftime("%Y-%m-%d %H:%M:%S"))
        threading.Thread(target=self._updates_job, daemon=True).start()
        return Result(True, "Started looking for updates.")

    def _updates_job(self):
        try:
            found = updates.waiting()
            state = {"status": "done", "sites": found, "finished": time.strftime("%Y-%m-%d %H:%M:%S")}
        except Exception as exc:                      # a failed look must never take the panel down
            state = {"status": "failed", "sites": [], "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                     "error": str(exc)[:200]}
        with self._job_lock:
            self._updates = state
        try:
            util.write_json(config.P.updates_cache, state)
        except OSError:
            pass


class DemoEngine:
    """Made-up data. Changes are kept in memory so every button does something visible."""
    demo = True

    def __init__(self):
        self._lock = threading.RLock()
        now = datetime.datetime.now()
        fmt = "%Y-%m-%d %H:%M:%S"
        self.blocked_rows = [
            {"ip": "203.0.113.14", "jail": "cps-wp-login", "why": "WordPress login guessing",
             "until": (now + datetime.timedelta(minutes=41)).strftime(fmt), "until_text": "in 41 min", "seconds_left": 2460},
            {"ip": "203.0.113.15", "jail": "sshd", "why": "Server login (SSH) guessing",
             "until": (now + datetime.timedelta(hours=5)).strftime(fmt), "until_text": "in 5 hours", "seconds_left": 18000},
            {"ip": "203.0.113.16", "jail": "cps-mail-auth", "why": "Email password guessing",
             "until": "never", "until_text": "never (permanent)", "seconds_left": None},
        ]
        self.trusted = [{"address": "45.60.0.10", "label": "Home Wi-Fi", "is_home": True},
                        {"address": "45.60.0.20", "label": "This server", "is_home": False},
                        {"address": "45.60.0.30", "label": "Added by owner", "is_home": False}]
        self.never = [{"address": "104.16.0.0/13", "label": "Cloudflare"}, {"address": "172.64.0.0/13", "label": "Cloudflare"}]
        self.mode = "watch"
        self.threshold = 5
        self.exceptions = []
        self.running = True
        self.updates = {"status": "idle", "sites": [], "finished": ""}
        self.sites = [{"domain": d, "code": "200", "ok": True} for d in
                      ("shop.example.com", "blog.example.com", "staging.example.com", "example.org")]
        self.sites.append({"domain": "old.example.com", "code": "500", "ok": False})
        self.tuning = blocker.tuning()
        self.fixed = set()
        self.setup_done = {"migrate": "skip", "lock": "done", "blocker": "done", "feed": "done", "baseline": "done",
                           "waf": "done", "retire": "todo"}
        self.job = {"status": "idle", "steps": [], "log": [], "started": "", "finished": ""}
        self.server = {"web_server": "OpenLiteSpeed", "web_server_version": "1.8.3", "web_server_kind": "openlitespeed",
                       "panel_domain": "security.example.com", "panel_port": 9443,
                       "certificate": {"found": True, "cert": "/etc/letsencrypt/live/security.example.com/fullchain.pem",
                                       "days_left": 71}}

    # ------------------------------------------------------------------ advisor (made-up findings)
    def advisor_report(self, refresh=False):
        def f(fid, level, title, detail="", advice="", fix=None):
            return {"id": fid, "level": level, "title": title, "detail": detail, "advice": advice, "fix": fix}
        found = [
            f("modsec_other", "info", "CyberPanel already has web firewall rules switched on",
              "OWASP rules switched on in CyberPanel.",
              "CP-Security will not add its own rules on top, so nothing clashes."),
            f("cloudflare", "warn", "2 websites use Cloudflare, but Cloudflare is not on the never-block list",
              "shop.example.com, blog.example.com. Visitors reach your server through Cloudflare, so the blocker "
              "could block Cloudflare itself and take those sites offline for everybody.",
              "Add Cloudflare's addresses to the never-block list with the button.",
              {"kind": "action", "id": "add_cloudflare", "label": "Add Cloudflare to the never-block list"}),
            f("wp_updates", "warn", "3 updates waiting on 2 websites",
              "Out-of-date plugins are how most WordPress sites get hacked.",
              "Update them, after a backup. This panel only looks, it never installs.",
              {"kind": "page", "id": "updates", "label": "See the list"}),
            f("ssh", "info", "Server logins (SSH) accept passwords",
              "The attack blocker limits guessing, but passwords can still be tried.",
              "When you have an SSH key set up, turn password logins off."),
            f("os_updates", "warn", "Security updates of the operating system are not automatic",
              "Fixes for the server's own software only arrive when somebody installs them.",
              "Install updates regularly, or turn on automatic security updates."),
            f("lock", "ok", "The admin pages are locked to %d trusted addresses" % len(self.trusted)),
            f("panel_access", "ok", "The panel can only be opened from trusted addresses"),
            f("cert", "ok", "The panel's certificate is valid for 71 more days"),
            f("webserver", "ok", "Web server: OpenLiteSpeed 1.8.3"),
        ]
        found = [x for x in found if x["id"] not in self.fixed]
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
        found.sort(key=lambda x: order[x["level"]])
        return {"checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "counts": {lvl: sum(1 for x in found if x["level"] == lvl) for lvl in order},
                "findings": found,
                "server": {"os": "Ubuntu 22.04.5 LTS", "web_server": "OpenLiteSpeed", "web_server_version": "1.8.3",
                           "cyberpanel": True}}

    def advisor_fix(self, fix_id):
        if fix_id == "add_cloudflare":
            self.fixed.add("cloudflare")
            self.never.append({"address": "173.245.48.0/20", "label": "Cloudflare"})
            return Result(True, "15 Cloudflare addresses were added to the never-block list.")
        return Result(False, "Unknown fix.", "unknown")

    # ------------------------------------------------------------------ setup (a pretend run, so the page can be designed)
    def server_info(self):
        return copy.deepcopy(self.server)

    def setup_state(self):
        job = copy.deepcopy(self.job)
        if job["status"] == "running":
            return {"plan": [], "job": job, "server": self.server_info()}
        titles = {"migrate": "Take over the earlier setup's lists and settings", "lock": "Lock the admin pages to trusted addresses",
                  "blocker": "Install the attack blocker", "feed": "Start the WordPress login watcher",
                  "baseline": "Remember how your websites answer today", "waf": "Set up the web firewall (watch-only)",
                  "retire": "Put the earlier hand-made setup away"}
        notes = {"done": "Already in place.", "skip": "Nothing to do on this server.",
                 "todo": "Not set up yet.", "blocked": "Waiting for something else first."}
        plan = [{"key": k, "title": titles[k], "state": self.setup_done[k], "note": notes[self.setup_done[k]],
                 "will_do": ["Does what the title says, safely, and undoes itself if something goes wrong."]
                 if self.setup_done[k] == "todo" else []} for k in titles]
        return {"plan": plan, "job": job, "server": self.server_info()}

    def setup_start(self, keys):
        todo = [k for k, v in self.setup_done.items() if v == "todo" and (keys is None or k in keys)]
        if not todo:
            return Result(False, "Nothing to do.", "empty")
        titles = dict((s["key"], s["title"]) for s in self.setup_state()["plan"])
        self.job = {"status": "running", "log": [], "started": time.strftime("%Y-%m-%d %H:%M:%S"), "finished": "",
                    "steps": [{"key": k, "title": titles[k], "state": "waiting", "message": ""} for k in todo]}

        def work():
            for i, k in enumerate(todo):
                self.job["steps"][i]["state"] = "running"
                self.job["log"].append("%s  Starting: %s" % (time.strftime("%H:%M:%S"), titles[k]))
                time.sleep(0.8)
                self.job["steps"][i].update(state="done", message="Done.")
                self.setup_done[k] = "done"
            self.job["status"] = "done"
            self.job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        threading.Thread(target=work, daemon=True).start()
        return Result(True, "Setup started.")

    # ------------------------------------------------------------------ settings pages
    def blocker_settings(self):
        return {"tuning": copy.deepcopy(self.tuning), "limits": blocker.LIMITS,
                "names": {n: config.JAIL_NAMES.get(n, n) for n in blocker.TUNABLE}, "missing_logs": []}

    def blocker_set(self, changes):
        for jail, values in (changes or {}).items():
            if jail not in self.tuning:
                return Result(False, "Unknown protection: %s" % jail, "invalid")
            for key, value in values.items():
                if key not in blocker.LIMITS or isinstance(value, bool) or not isinstance(value, int) \
                        or not blocker.LIMITS[key][0] <= value <= blocker.LIMITS[key][1]:
                    return Result(False, "%s must be a whole number in range." % key, "invalid")
                self.tuning[jail][key] = value
        return Result(True, "Saved. The blocker uses the new numbers now.")

    def never_add(self, address, label):
        addr, err = access.check_address(address)
        if err:
            return Result(False, err, "invalid")
        if any(n["address"] == addr for n in self.never):
            return Result(False, "%s is already on the list." % addr, "exists")
        self.never.append({"address": addr, "label": label or "Added from the panel"})
        return Result(True, "%s will never be blocked automatically." % addr)

    def never_remove(self, address):
        if not any(n["address"] == address for n in self.never):
            return Result(False, "%s is not on the list." % address, "missing")
        self.never = [n for n in self.never if n["address"] != address]
        return Result(True, "%s can be blocked again if it misbehaves." % address)

    def baseline_save(self):
        return Result(True, "Saved: 4 of 5 websites answer normally. That is the reference from now on.")

    def waf_selftest(self):
        if self.mode == "off":
            return Result(False, "The web firewall is not switched on, so there is nothing to test.", "not_active")
        return Result(True, "The firewall saw the test request.", "seen")

    def overview(self, refresh=False):
        rows = [
            {"key": "blocker", "label": "Attack blocker", "status": "ok" if self.running else "bad",
             "text": "Running, 5 protections on, %d addresses blocked right now" % len(self.blocked_rows) if self.running
             else "Not running. Automatic blocking is off."},
            {"key": "feed", "label": "Login watcher", "status": "ok", "text": "Copying WordPress login attempts for the blocker"},
            {"key": "lock", "label": "Admin pages", "status": "ok",
             "text": "Locked: only %d trusted addresses can open them" % len(self.trusted)},
            {"key": "waf", "label": "Web firewall", "status": "off" if self.mode == "off" else "ok", "text": waf.MODE_TEXT[self.mode]},
            {"key": "sites", "label": "Websites", "status": "ok",
             "text": "4 of 5 answering normally (1 was already giving an error before the protection, unchanged)"},
        ]
        problems = sum(1 for r in rows if r["status"] == "bad")
        return {"checked_at": time.strftime("%Y-%m-%d %H:%M:%S"), "problems": problems, "rows": rows,
                "sites": {"total": 5, "normal": 4, "new_problems": [], "old_problems": [{"domain": "old.example.com", "code": "500"}],
                          "sites": self.sites},
                "blocked_24h": 37, "waf_mode": self.mode}

    def blocked(self):
        return {"running": self.running, "rows": copy.deepcopy(self.blocked_rows) if self.running else [],
                "summary": {"day": {"blocks": 37, "addresses": 21, "by_reason": [
                    {"jail": "cps-wp-login", "why": "WordPress login guessing", "count": 24},
                    {"jail": "sshd", "why": "Server login (SSH) guessing", "count": 9},
                    {"jail": "cps-mail-auth", "why": "Email password guessing", "count": 4}]},
                    "week": {"blocks": 212, "addresses": 96, "by_reason": [
                        {"jail": "cps-wp-login", "why": "WordPress login guessing", "count": 150},
                        {"jail": "sshd", "why": "Server login (SSH) guessing", "count": 48},
                        {"jail": "cps-mail-auth", "why": "Email password guessing", "count": 14}]},
                    "top_addresses": [{"ip": "203.0.113.14", "times": 6}, {"ip": "203.0.113.13", "times": 4}]}}

    def unblock(self, ip):
        with self._lock:
            before = len(self.blocked_rows)
            self.blocked_rows = [r for r in self.blocked_rows if r["ip"] != ip]
            if len(self.blocked_rows) < before:
                return Result(True, "%s can get in again." % ip)
            return Result(False, "%s was not blocked right now." % ip, "not_blocked")

    def unblock_all(self):
        self.blocked_rows = []
        return Result(True, "Everybody can get in again.")

    def set_blocking_running(self, running):
        self.running = bool(running)
        return Result(True, "Automatic blocking is on again." if running else "Automatic blocking is stopped. Nobody is blocked any more.")

    def access_state(self):
        return {"trusted": copy.deepcopy(self.trusted), "never_block": copy.deepcopy(self.never), "lock_live": True}

    def access_add(self, address, label):
        addr, err = access.check_address(address)
        if err:
            return Result(False, err, "invalid")
        if any(t["address"] == addr for t in self.trusted):
            return Result(False, "%s is already on the list." % addr, "exists")
        self.trusted.append({"address": addr, "label": label or "Added from the panel", "is_home": False})
        return Result(True, "%s can now open the admin pages." % addr)

    def access_remove(self, address, caller_ip, confirmed):
        if len(self.trusted) == 1:
            return Result(False, "You cannot remove the last address.", "last_address")
        if address == caller_ip and not confirmed:
            return Result(False, "That is the address you are using right now. Removing it will lock you out.", "needs_confirm")
        self.trusted = [t for t in self.trusted if t["address"] != address]
        return Result(True, "%s was removed." % address)

    def access_set_home(self, address):
        addr, err = access.check_address(address)
        if err:
            return Result(False, err, "invalid")
        for t in self.trusted:
            if t["is_home"]:
                t["address"] = addr
                return Result(True, "CyberPanel and the other admin pages now open from %s." % addr)
        self.trusted.append({"address": addr, "label": "Home Wi-Fi", "is_home": True})
        return Result(True, "CyberPanel and the other admin pages now open from %s." % addr)

    def access_reapply(self):
        return Result(True, "ok")

    def waf_state(self):
        return {"installed": True, "mode": self.mode, "text": waf.MODE_TEXT[self.mode], "threshold": self.threshold,
                "exceptions": copy.deepcopy(self.exceptions)}

    def waf_summary(self):
        def period(n):
            return {"requests": n, "addresses": max(1, n // 4), "blocked": 0 if self.mode != "block" else n // 3,
                    "rules": [{"rule": "942100", "message": "SQL Injection Attack Detected via libinjection", "count": n // 3},
                              {"rule": "920440", "message": "URL file extension is restricted by policy", "count": n // 4},
                              {"rule": "941100", "message": "XSS Attack Detected via libinjection", "count": n // 6}],
                    "sites": [{"site": "shop.example.com", "count": n // 2}, {"site": "blog.example.com", "count": n // 5}]}
        return {"mode": self.mode, "trusted_hits": 2, "periods": {"day": period(48), "week": period(310)}}

    def waf_recent(self):
        return [
            {"host": "shop.example.com", "path": "/wp-admin/admin-ajax.php", "rule": "942100",
             "message": "SQL Injection Attack Detected via libinjection", "count": 3,
             "last": time.strftime("%Y-%m-%d %H:%M:%S"), "trusted": True, "blocked": False},
            {"host": "blog.example.com", "path": "/phpinfo.php.old", "rule": "920440",
             "message": "URL file extension is restricted by policy", "count": 5,
             "last": time.strftime("%Y-%m-%d %H:%M:%S"), "trusted": False, "blocked": False},
        ]

    def waf_set_mode(self, mode, threshold):
        if mode not in waf.MODE_TEXT:
            return Result(False, "Unknown mode.", "invalid")
        self.mode = mode
        if threshold:
            self.threshold = int(threshold)
        return Result(True, "The web firewall is now: " + waf.MODE_TEXT[mode] + ".")

    def waf_add_exception(self, scope, host, rule):
        entry = {"site": "*" if scope == "all" else host, "rule": "ALL" if scope == "site_off" else str(rule)}
        if entry in self.exceptions:
            return Result(False, "That exception already exists.", "exists")
        self.exceptions.append(entry)
        return Result(True, "Exception added.")

    def waf_remove_exception(self, index):
        if not (0 <= index < len(self.exceptions)):
            return Result(False, "That exception does not exist.", "missing")
        self.exceptions.pop(index)
        return Result(True, "Exception removed.")

    def updates_state(self):
        return copy.deepcopy(self.updates)

    def updates_refresh(self):
        self.updates = {"status": "done", "finished": time.strftime("%Y-%m-%d %H:%M:%S"), "sites": [
            {"site": "shop.example.com", "checked": True, "items": [
                {"what": "WooCommerce", "from": "10.0.4", "to": "11.2.1", "kind": "plugin"},
                {"what": "Yoast SEO", "from": "28.2", "to": "28.7", "kind": "plugin"}]},
            {"site": "blog.example.com", "checked": True, "items": [
                {"what": "WordPress itself", "from": "", "to": "6.8.11", "kind": "core-minor"}]},
            {"site": "staging.example.com", "checked": True, "items": []},
            {"site": "example.org", "checked": False, "items": []}]}
        return Result(True, "Started looking for updates.")
