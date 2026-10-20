"""What the panel is allowed to ask of the engine.

LiveEngine does the real work on this server. DemoEngine answers with made-up data kept in memory, so the
interface can be designed, tested and photographed on any computer.

Every method returns plain data (dicts, lists) or a util.Result.
"""
import copy
import datetime
import threading
import time

from .. import (__version__, access, advisor, blocker, config, headers, health, htfile, ports, provision,
                selfupdate, serverfw, settings, sites, tls, updates, util, waf, webserver, wpupdate)
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
        self._site_results = None           # last answers of the websites; None until the first check has finished
        self._site_checked_at = 0.0
        self._site_checking = False
        self._state_lock = threading.Lock()
        self._overview_lock = threading.Lock()      # reading pages never waits for a change that restarts services
        self._advice_lock = threading.Lock()
        self._job_lock = threading.Lock()
        self._updates = util.read_json(config.P.updates_cache, {"status": "idle", "sites": [], "finished": ""})
        self.runner = provision.Runner()
        self.updater = selfupdate.Updater()

    def _guard(self):
        """While the setup runs, other changes wait: both would be restarting the same services."""
        return BUSY if self.runner.running() else None

    # ------------------------------------------------------------------ advisor
    def advisor_report(self, refresh=False):
        with self._advice_lock:
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
    # Asking all websites takes 4-10 seconds. The page must not wait for it: show the last answers at once and
    # refresh them in the background (every 5 minutes, or when "Check again" is pressed).
    def _spawn(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def _check_sites_now(self):
        try:
            results = sites.check_sites()
        except Exception:                                   # a failed look must never take the panel down
            results = None
        with self._state_lock:
            if results is not None:
                self._site_results = results
                self._site_checked_at = time.time()
            self._site_checking = False
            self._overview = None                           # the next request is built with the fresh answers

    def _start_site_check(self):
        with self._state_lock:
            if self._site_checking:
                return
            self._site_checking = True
        self._spawn(self._check_sites_now)

    def warm_up(self):
        """Called once when the panel starts, so the first visitor does not wait."""
        self._start_site_check()
        self._spawn(self._update_loop)

    def _update_loop(self):
        """Look for a newer version when the panel starts and then twice a day."""
        while True:
            try:
                self.updater.check()
            except Exception:
                pass
            time.sleep(12 * 3600)

    # ------------------------------------------------------------------ the panel's own updates
    def update_state(self):
        return self.updater.state()

    def update_check(self):
        return self.updater.check()

    def update_install(self, version):
        busy = self._guard()
        if busy:
            return busy
        return self.updater.install(version)

    def overview(self, refresh=False):
        with self._overview_lock:
            if refresh or self._site_results is None or time.time() - self._site_checked_at > 300:
                self._start_site_check()
            if refresh or self._overview is None or time.time() - self._overview_at > 45:
                self._overview = health.overview(self._site_results, sites_pending=self._site_results is None)
                self._overview_at = time.time()
            data = dict(self._overview)
            data["sites_checking"] = self._site_checking
            data["sites_checked_at"] = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._site_checked_at))
                                        if self._site_checked_at else "")
            return data

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

    # ------------------------------------------------------------------ open ports
    def ports_state(self):
        return ports.state()

    def ports_lock(self, port, caller_ip, confirmed):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return ports.lock(port, caller_ip, confirmed)

    def ports_unlock(self, port, confirmed):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return ports.unlock(port, confirmed)

    def ports_accept(self, port, accepted):
        with self._lock:
            self._changed()
            return ports.accept(port, accepted)

    # ------------------------------------------------------------------ server firewall
    def serverfw_state(self):
        return serverfw.state()

    def _fw_change(self, fn, *args):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return fn(*args)

    def serverfw_add(self, name, proto, address, port):
        return self._fw_change(serverfw.add_rule, name, proto, address, port)

    def serverfw_remove(self, rule_id, confirmed):
        return self._fw_change(serverfw.remove_rule, rule_id, confirmed)

    def serverfw_power(self, action, add_in_use, confirmed):
        return self._fw_change(serverfw.power, action, add_in_use, confirmed)

    def serverfw_keep(self):
        return self._fw_change(serverfw.confirm)

    def serverfw_undo(self):
        return self._fw_change(serverfw.revert)

    def serverfw_import(self):
        return self._fw_change(serverfw.import_cyberpanel)

    def serverfw_add_suggested(self, keys):
        return self._fw_change(serverfw.add_suggested, keys)

    # ------------------------------------------------------------------ security headers
    def headers_state(self):
        return headers.state()

    def headers_defaults(self, changes):
        with self._lock:
            self._changed()
            return headers.set_defaults(changes)

    def headers_check(self):
        n = headers.check_all()
        return Result(True, "Asked %d website%s what they send." % (n, "" if n == 1 else "s"))

    def headers_apply(self, domains, take_over):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return headers.apply(domains, take_over)

    def headers_remove(self, domains):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            return headers.remove(domains)

    def headers_site(self, domain, changes, apply_now, take_over=False):
        busy = self._guard()
        if busy:
            return busy
        with self._lock:
            self._changed()
            res = headers.set_site(domain, changes)
            if not res.ok:
                return res
            if changes.get("exclude") is True:
                done = headers.remove([domain])
                return Result(done.ok, "%s is left alone from now on. %s" % (domain, done.message.split(": ", 1)[-1]), done.code)
            return headers.apply([domain], take_over) if apply_now else res

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

    # ------------------------------------------------------------------ manual updates of plugins and themes
    def wpupdate_state(self):
        return wpupdate.state()

    def wpupdate_start(self, items):
        busy = self._guard()
        if busy:
            return busy
        with self._job_lock:
            titles = {(s["site"], i["kind"], i.get("slug", "")): i["what"] for s in self._updates.get("sites", []) for i in s.get("items", [])}
        return wpupdate.start(items, titles, on_item=self._wpupdate_logged, on_done=self._wpupdate_done)

    def wpupdate_stop(self):
        return wpupdate.stop()

    def _wpupdate_logged(self, item):
        from . import activity
        activity.write("WP_UPDATE", site=item["site"], kind=item["kind"], slug=item["slug"], status=item["status"])

    def _wpupdate_done(self, touched):
        """Look at the websites again so the list shows what is still waiting."""
        for name in touched:
            entry = updates.look_one(name)
            if entry is None:
                continue
            with self._job_lock:
                sites_list = [s for s in self._updates.get("sites", []) if s["site"] != name] + [entry]
                self._updates = dict(self._updates, sites=sorted(sites_list, key=lambda s: s["site"]))
                state = self._updates
            try:
                util.write_json(config.P.updates_cache, state)
            except OSError:
                pass

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

    # ------------------------------------------------------------------ the panel's own updates (pretend)
    def update_state(self):
        job = copy.deepcopy(self.update_job)
        if job["status"] == "working" and time.time() - self.update_started > 2.5:
            job.update(status="restarting", message="The panel is restarting. This page reconnects by itself.")
        if job["status"] in ("working", "restarting") and time.time() - self.update_started > 5:
            self.demo_version = self.demo_latest
            job.update(status="done", message="Updated.")
            self.update_job = job
        return {"current": self.demo_version, "latest": self.demo_latest,
                "available": self.demo_version != self.demo_latest, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "check_error": "", "published": "2026-10-19", "last_result": None, "job": job,
                "notes": "* Made-up release notes for the demo.\n* Faster Overview.\n* WP Updates now lists themes."}

    def update_check(self):
        return Result(True, "Version %s is available (you have %s)." % (self.demo_latest, self.demo_version)
                      if self.demo_version != self.demo_latest else "You have the newest version (%s)." % self.demo_version)

    def update_install(self, version):
        self.update_job = {"status": "working", "message": "Downloading and checking…", "log": ["demo: nothing is installed"],
                           "target": self.demo_latest}
        self.update_started = time.time()
        return Result(True, "Updating to %s." % self.demo_latest)

    def __init__(self):
        self._lock = threading.RLock()
        self.demo_version, self.demo_latest = __version__, "9.9.9"
        self.update_job = {"status": "idle", "message": "", "log": [], "target": ""}
        self.update_started = 0.0
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
        self.port_choices = {"locked": [], "opened": [], "accepted": []}
        self.fw_enabled, self.fw_rules, self.fw_next, self.fw_pending_until, self.fw_previous = False, [], 1, 0.0, None
        self.wp_job = None
        self.h_cfg = {"defaults": dict(headers.DEFAULTS), "sites": {}}
        self.h_sites = {d: {"own": list(own), "taken": [], "block": "", "error": err} for d, own, err in (
            ("blog.example.com", [], ""), ("example.org", [], ""), ("old.example.com", [],
             "The CP-Security lines in this website's .htaccess are damaged (a start or end line is missing or repeated). "
             "Nothing was changed. Fix or delete them by hand first."),
            ("shop.example.com", ["x-frame-options", "strict-transport-security"], ""),
            ("staging.example.com", [], ""))}
        self.h_sites["blog.example.com"]["block"] = self._demo_block("blog.example.com")
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
              "Update them one at a time on the WordPress updates page: a copy is saved first and nothing updates by itself.",
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
                "sites_checking": False, "sites_checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
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

    # ------------------------------------------------------------------ open ports (made-up server)
    DEMO_LISTENING = [
        (21, "everyone", ["pure-ftpd"]), (22, "everyone", ["sshd"]), (25, "everyone", ["master"]),
        (53, "everyone", ["pdns_server"]), (80, "everyone", ["litespeed"]), (443, "everyone", ["litespeed"]),
        (465, "everyone", ["master"]), (587, "everyone", ["master"]), (993, "everyone", ["dovecot"]),
        (3306, "server", ["mariadbd"]), (5000, "everyone", ["node"]), (6379, "everyone", ["redis-server"]),
        (7080, "everyone", ["litespeed"]), (8081, "everyone", ["pdns_server"]), (8090, "everyone", ["lscpd"]),
        (8888, "everyone", ["python3"]),
    ]

    def _demo_lock_set(self):
        s = set(p for p in config.ADMIN_PORTS if p not in self.port_choices["opened"])
        return s | set(self.port_choices["locked"])

    def ports_state(self):
        locked_set = self._demo_lock_set()
        found = [ports._row(p, reach, progs, self.port_choices, locked_set) for p, reach, progs in self.DEMO_LISTENING]
        found.sort(key=lambda r: (ports.LEVEL_ORDER[r["level"]], r["port"]))
        counts = {lvl: sum(1 for r in found if r["level"] == lvl) for lvl in ports.LEVEL_ORDER}
        return {"supported": True, "ports": found, "counts": counts, "firewall": "", "trusted": len(self.trusted), "message": ""}

    def ports_lock(self, port, caller_ip, confirmed):
        row = next((r for r in self.ports_state()["ports"] if r["port"] == port), None)
        if row is None:
            return Result(False, "Nothing is listening on port %s." % port, "not_listening")
        if port in ports.PROTECTED:
            return Result(False, row["cannot_lock_reason"], "protected")
        if row["locked_by"]:
            return Result(False, "Port %d is already locked." % port, "already")
        if row["warn"] and not confirmed:
            return Result(False, row["warn"], "needs_confirm")
        if port in config.ADMIN_PORTS:
            self.port_choices["opened"] = [p for p in self.port_choices["opened"] if p != port]
        else:
            self.port_choices["locked"] = sorted(set(self.port_choices["locked"]) | {port})
        return Result(True, "Port %d is now locked: only your trusted addresses can reach it." % port)

    def ports_unlock(self, port, confirmed):
        if port in self.port_choices["locked"]:
            self.port_choices["locked"] = [p for p in self.port_choices["locked"] if p != port]
            return Result(True, "Port %d is open to everybody again." % port)
        if port in config.ADMIN_PORTS and port not in self.port_choices["opened"]:
            if not confirmed:
                return Result(False, "This admin page will be reachable by anybody on the internet.", "needs_confirm")
            self.port_choices["opened"] = sorted(set(self.port_choices["opened"]) | {port})
            return Result(True, "Port %d is open to everybody. The lock will not close it again until you lock it." % port)
        return Result(False, "Port %d is not locked." % port, "not_locked")

    def ports_accept(self, port, accepted):
        have = set(self.port_choices["accepted"])
        (have.add if accepted else have.discard)(port)
        self.port_choices["accepted"] = sorted(have)
        return Result(True, "Noted. CP-Security will stop warning you about port %d." % port if accepted
                      else "CP-Security will mention port %d again if it stays open." % port)

    # ------------------------------------------------------------------ server firewall (made-up server)
    FW_SUGGEST = [("Websites HTTP", "tcp", "", "80", "In use right now by litespeed"),
                  ("Websites HTTPS", "tcp", "", "443", "In use right now by litespeed"),
                  ("Program node", "tcp", "", "5000", "In use right now by node"),
                  ("pdns_server UDP", "udp", "", "53", "In use right now by pdns_server"),
                  ("litespeed UDP", "udp", "", "443", "In use right now by litespeed"),
                  ("tunnel test", "tcp", "198.51.100.46", "2053", "Another program already allows this in the firewall")]
    FW_CYBERPANEL = [("http", "tcp", "0.0.0.0/0", "80"), ("https", "tcp", "0.0.0.0/0", "443"), ("ftp", "tcp", "0.0.0.0/0", "21"),
                     ("smtp", "tcp", "0.0.0.0/0", "25"), ("dns", "udp", "0.0.0.0/0", "53"), ("ftptls", "tcp", "0.0.0.0/0", "40110-40210"),
                     ("web-tunnel", "tcp", "0.0.0.0/0", "8440")]

    def _fw_has(self, clean):
        return any((r["proto"], r["address"], r["port"]) == (clean["proto"], clean["address"], clean["port"]) for r in self.fw_rules)

    def _fw_put(self, clean, source):
        if self._fw_has(clean):
            return False
        self.fw_rules.append(dict(clean, id=self.fw_next, source=source))
        self.fw_next += 1
        return True

    def _fw_suggestions(self):
        out = []
        for name, proto, address, port, why in self.FW_SUGGEST:
            clean, _ = serverfw.check_rule(name, proto, address, port)
            if not self._fw_has(clean):
                out.append(dict(clean, key="%s:%s:%s" % (clean["proto"], clean["address"], clean["port"]), why=why))
        return out

    def serverfw_state(self):
        pending = None
        if self.fw_pending_until:
            left = int(self.fw_pending_until - time.time())
            if left <= 0:
                self.serverfw_undo()
            else:
                pending = {"seconds_left": left, "action": "on"}
        page_on = True
        verdict = ("ok", "The CP-Security firewall is ON. Only the ports on the list are open.") if self.fw_enabled else \
            ("bad", "No firewall is running. Every port that has a program behind it can be reached from the internet, "
                    "except the admin pages that the admin lock protects.")
        truth = {"protected": self.fw_enabled, "verdict": {"level": verdict[0], "text": verdict[1]},
                 "cyberpanel": {"present": True, "page_says_on": page_on, "firewalld_installed": False, "firewalld_running": False,
                                "rules_listed": len(self.FW_CYBERPANEL), "level": "bad",
                                "text": "CyberPanel's Firewall page says ON, but the program behind it (firewalld) is not installed. "
                                        "The rules on that page are only a list: nothing is enforced."},
                 "ours": {"enabled": self.fw_enabled, "loaded": self.fw_enabled}, "others": []}
        rules = [dict(r, in_use=r["port"] in ("80", "443", "5000"), used_by=[], text=serverfw.describe(r)) for r in self.fw_rules]
        refused = [{"proto": "tcp", "port": 23, "packets": 240, "programs": []}, {"proto": "tcp", "port": 4445, "packets": 12, "programs": []},
                   {"proto": "udp", "port": 5060, "packets": 31, "programs": []}] if self.fw_enabled else None
        refused = [r for r in refused if not any(x["proto"] == r["proto"] and x["port"] == str(r["port"]) for x in rules)] if refused is not None else None
        return {"truth": truth, "enabled": self.fw_enabled, "loaded": self.fw_enabled, "rules": rules, "refused": refused,
                "builtin": [
                    {"name": "Replies to connections the server started", "what": "Updates, mail it sends, anything the server asks for.", "port": ""},
                    {"name": "The server talking to itself", "what": "Websites, databases and caches reach each other inside the server.", "port": ""},
                    {"name": "Ping and network messages", "what": "Needed for the network to work (and for you to test it).", "port": ""},
                    {"name": "Server login (SSH)", "what": "Always open so you can never lock yourself out.", "port": "22"},
                    {"name": "Admin pages and this panel", "what": "Always open here; the admin lock decides who may use them.", "port": "7080, 8090, 8888, 9443"}],
                "suggestions": self._fw_suggestions(), "cyberpanel_rules": len(self.FW_CYBERPANEL),
                "pending": pending, "confirm_seconds": serverfw.CONFIRM_SECONDS, "max_rules": serverfw.MAX_RULES}

    def serverfw_add(self, name, proto, address, port):
        clean, err = serverfw.check_rule(name, proto, address, port)
        if err:
            return Result(False, err, "invalid")
        if not self._fw_put(clean, "you"):
            return Result(False, "That rule is already on the list.", "exists")
        return Result(True, "%s is open." % serverfw.describe(clean) if self.fw_enabled
                      else "Saved: %s. The firewall is off, so this applies when you turn it on." % serverfw.describe(clean))

    def serverfw_remove(self, rule_id, confirmed):
        rule = next((r for r in self.fw_rules if r["id"] == rule_id), None)
        if rule is None:
            return Result(False, "That rule does not exist.", "missing")
        if self.fw_enabled and not confirmed and rule["port"] in ("80", "443", "5000"):
            return Result(False, "%s is in use right now. If you remove this rule, nobody outside can reach it any more." % serverfw.describe(rule), "needs_confirm")
        self.fw_rules = [r for r in self.fw_rules if r["id"] != rule_id]
        return Result(True, "%s is closed." % serverfw.describe(rule) if self.fw_enabled else "Removed: %s." % serverfw.describe(rule))

    def serverfw_power(self, action, add_in_use, confirmed):
        if action == "on":
            if not confirmed:
                return Result(False, "Please confirm that you want to switch the firewall on.", "needs_confirm")
            if self.fw_pending_until:
                return Result(False, "A change is waiting for your answer. Press 'Keep it' or 'Undo' first.", "pending")
            self.fw_previous = {"enabled": self.fw_enabled, "rules": [dict(r) for r in self.fw_rules]}
            if add_in_use:
                for s in self._fw_suggestions():
                    clean, _ = serverfw.check_rule(s["name"], s["proto"], s["address"], s["port"])
                    self._fw_put(clean, "in use")
            self.fw_enabled = True
            self.fw_pending_until = time.time() + serverfw.CONFIRM_SECONDS
            return Result(True, "The firewall is ON. Press 'Keep it' within 2 minutes, or it switches itself off again.", "pending")
        if action == "off":
            self.fw_enabled, self.fw_pending_until = False, 0.0
            return Result(True, "The firewall is OFF. Every port with a program behind it can be reached again (the admin lock still works).")
        if action == "reload":
            if not self.fw_enabled:
                return Result(False, "The firewall is off, so there is nothing to reload. Turn it on first.", "off")
            return Result(True, "The firewall was reloaded from your list (%d rules)." % len(self.fw_rules))
        return Result(False, "Unknown action.", "invalid")

    def serverfw_keep(self):
        if not self.fw_pending_until:
            return Result(False, "Nothing is waiting for an answer.", "none")
        self.fw_pending_until = 0.0
        return Result(True, "Kept. The firewall stays on, also after a restart of the server.")

    def serverfw_undo(self):
        if not self.fw_pending_until or not self.fw_previous:
            return Result(True, "Nothing to undo.")
        self.fw_enabled, self.fw_rules = self.fw_previous["enabled"], self.fw_previous["rules"]
        self.fw_pending_until, self.fw_previous = 0.0, None
        return Result(True, "The change was undone; the firewall is off again." if not self.fw_enabled
                      else "The change was undone; the firewall is back to its earlier list.")

    def serverfw_import(self):
        added = 0
        for name, proto, address, port in self.FW_CYBERPANEL:
            clean, _ = serverfw.check_rule(name, proto, address, port)
            added += 1 if self._fw_put(clean, "cyberpanel") else 0
        return Result(True, "Copied %d rule%s from CyberPanel's list (%d were already here or always open)." % (
            added, "" if added == 1 else "s", len(self.FW_CYBERPANEL) - added))

    def serverfw_add_suggested(self, keys):
        added = 0
        for s in self._fw_suggestions():
            if keys is None or s["key"] in keys:
                clean, _ = serverfw.check_rule(s["name"], s["proto"], s["address"], s["port"])
                added += 1 if self._fw_put(clean, "other firewall" if s["why"].startswith("Another") else "in use") else 0
        return Result(True, "Added %d rule%s." % (added, "" if added == 1 else "s")) if added else Result(False, "There is nothing to add.", "none")

    # ------------------------------------------------------------------ security headers (made-up websites)
    def _demo_block(self, domain):
        eff = headers.effective(self.h_cfg, domain)
        return headers.build_block(eff, set(self.h_sites[domain]["own"]))[0] or ""

    def headers_state(self):
        rows = []
        for domain, s in self.h_sites.items():
            block = s["block"]
            info = {"exists": True, "has_block": bool(block), "block": block, "damaged": False,
                    "site_names": sorted(s["own"]), "taken": len(s["taken"]), "error": s["error"]}
            sent = (htfile.header_names(block) - {"x-powered-by"}) | set(s["own"])
            if "x-powered-by" not in htfile.header_names(block):
                sent.add("x-powered-by")
            live = {"status": "200", "headers": {n: "x" for n in sent}, "at": time.time()}
            rows.append(headers.build_row(domain, self.h_cfg, info, live))
        return headers.assemble(self.h_cfg, rows, False, time.time())

    def headers_defaults(self, changes):
        clean, err = headers._clean(changes, False)
        if err:
            return Result(False, err, "invalid")
        self.h_cfg["defaults"].update(clean)
        return Result(True, "Saved. Press Apply to put the new choices on your websites.")

    def headers_check(self):
        return Result(True, "Asked %d websites what they send." % len(self.h_sites))

    def _demo_change(self, domains, take_over, remove):
        targets = [d for d in self.h_sites if domains is None or d in domains]
        if domains is not None and len(targets) != len(set(domains)):
            return Result(False, "Not a website on this server.", "unknown_site")
        done = failed = 0
        for d in targets:
            s = self.h_sites[d]
            if s["error"]:
                failed += 1
                continue
            if remove:
                s["block"] = ""
                s["own"] = sorted(set(s["own"]) | set(s["taken"]))
                s["taken"] = []
            elif not headers.effective(self.h_cfg, d).get("exclude"):
                if take_over:
                    wanted = {i["name"].lower() for i in headers.ITEMS if headers.enabled(i["id"], headers.effective(self.h_cfg, d))}
                    mine = sorted(set(s["own"]) & wanted)
                    s["taken"] = sorted(set(s["taken"]) | set(mine))
                    s["own"] = [n for n in s["own"] if n not in mine]
                s["block"] = self._demo_block(d)
            done += 1
        if len(targets) == 1:
            return Result(not failed, "%s: %s" % (targets[0], "Done." if not failed else "The CP-Security lines in this website's .htaccess are damaged. Nothing was changed."),
                          "" if not failed else "failed")
        text = "%s %d website%s." % ("Removed from" if remove else "Applied to", done, "" if done == 1 else "s")
        return Result(not failed, text + (" %d could not be changed." % failed if failed else ""), "failed" if failed else "")

    def headers_apply(self, domains, take_over):
        return self._demo_change(domains, take_over, False)

    def headers_remove(self, domains):
        return self._demo_change(domains, False, True)

    def headers_site(self, domain, changes, apply_now, take_over=False):
        if domain not in self.h_sites:
            return Result(False, "That website is not on this server.", "unknown_site")
        wanted = {k: v for k, v in changes.items() if v is not None}
        clean, err = headers._clean(wanted, True)
        if err:
            return Result(False, err, "invalid")
        mine = self.h_cfg["sites"].setdefault(domain, {})
        for k, v in changes.items():
            if v is None:
                mine.pop(k, None)
        mine.update(clean)
        if not mine:
            self.h_cfg["sites"].pop(domain, None)
        if changes.get("exclude") is True:
            self._demo_change([domain], False, True)
            return Result(True, "%s is left alone from now on." % domain)
        return self._demo_change([domain], take_over, False) if apply_now else Result(True, "Saved for %s." % domain)

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

    # ------------------------------------------------------------------ manual updates (made-up)
    WP_DEMO_SECONDS = 1.2

    def wpupdate_start(self, items):
        if self.wp_job and not self.wp_job.get("finished"):
            return Result(False, "Updates are already running. Wait for them to finish.", "busy")
        if not isinstance(items, list) or not items:
            return Result(False, "Choose what to update.", "invalid")
        known = {(s["site"], i["kind"], i.get("slug", "")): i for s in self.updates["sites"] for i in s["items"]}
        rows = []
        for it in items:
            key = (it.get("site"), it.get("kind"), it.get("slug"))
            if key not in known or it.get("kind") not in ("plugin", "theme"):
                return Result(False, "That is not something that is waiting for an update.", "invalid")
            rows.append(dict(site=key[0], kind=key[1], slug=key[2], title=known[key]["what"], status="waiting", message="",
                             **{"from": known[key]["from"], "to": known[key]["to"]}))
        self.wp_job = {"items": rows, "started": time.time(), "stop": False, "stop_at": None, "finished": ""}
        return Result(True, "Started: %d update%s." % (len(rows), "" if len(rows) == 1 else "s"))

    def wpupdate_stop(self):
        if not self.wp_job or self.wp_job.get("finished"):
            return Result(False, "Nothing is running.", "none")
        self.wp_job["stop_at"] = time.time() - self.wp_job["started"]
        return Result(True, "It stops after the update that is running now. The rest are skipped.")

    def wpupdate_state(self):
        job = self.wp_job
        if not job:
            return {"status": "idle", "items": [], "started": "", "finished": "", "stop": False,
                    "counts": {k: 0 for k in ("waiting", "working", "done", "failed", "restored", "skipped")}}
        elapsed = time.time() - job["started"]
        for n, it in enumerate(job["items"]):
            if it["status"] in ("done", "failed", "restored", "skipped"):
                continue
            if job["stop_at"] is not None and n * self.WP_DEMO_SECONDS >= job["stop_at"]:
                it.update(status="skipped", message="Skipped, because you stopped the updates.")
            elif elapsed >= (n + 1) * self.WP_DEMO_SECONDS:
                if it["slug"] == "bricks":
                    it.update(status="restored", message="After the update the home page now answers 500, so the old version %s was put back." % it["from"], to=it["from"])
                elif it["slug"] == "old-gallery":
                    it.update(status="failed", message="The update failed (Download failed. Invalid license). The website stays on version %s." % it["from"])
                else:
                    it.update(status="done", message="Updated from %s to %s. The website still answers normally." % (it["from"], it["to"]))
            elif elapsed >= n * self.WP_DEMO_SECONDS:
                it.update(status="working", message="Updating…")
        if all(i["status"] in ("done", "failed", "restored", "skipped") for i in job["items"]) and not job["finished"]:
            job["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
            done = {(i["site"], i["kind"], i["slug"]) for i in job["items"] if i["status"] == "done"}
            for s in self.updates["sites"]:
                s["items"] = [i for i in s["items"] if (s["site"], i["kind"], i.get("slug", "")) not in done]
        out = copy.deepcopy(job)
        out["stop"] = job["stop_at"] is not None
        out["status"] = "done" if job["finished"] else "running"
        out["counts"] = {k: sum(1 for i in out["items"] if i["status"] == k) for k in ("waiting", "working", "done", "failed", "restored", "skipped")}
        return out

    def updates_state(self):
        return copy.deepcopy(self.updates)

    def updates_refresh(self):
        def item(what, slug, kind, now, to, status="active"):
            return {"what": what, "slug": slug, "from": now, "to": to, "kind": kind, "status": status,
                    "careful": updates.is_careful(slug, what)}
        self.updates = {"status": "done", "finished": time.strftime("%Y-%m-%d %H:%M:%S"), "sites": [
            {"site": "shop.example.com", "checked": True, "items": [
                item("WooCommerce", "woocommerce", "plugin", "10.0.4", "11.2.1"),
                item("Yoast SEO", "wordpress-seo", "plugin", "28.2", "28.7"),
                item("Bricks", "bricks", "theme", "1.9.8", "1.12.4")]},
            {"site": "blog.example.com", "checked": True, "items": [
                item("WordPress itself", "", "core-minor", "", "6.8.11"),
                item("WooCommerce", "woocommerce", "plugin", "10.1.0", "11.2.1"),
                item("Old gallery plugin", "old-gallery", "plugin", "2.1", "2.4", "inactive")]},
            {"site": "staging.example.com", "checked": True, "items": [
                item("Bricks", "bricks", "theme", "1.9.8", "1.12.4", "inactive")]},
            {"site": "example.org", "checked": False, "items": []}]}
        return Result(True, "Started looking for updates.")
