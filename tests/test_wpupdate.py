import os
import time

from cpsec import config, wpupdate
from tests.helpers import EnvTestCase

DOMAIN = "shop.example.com"


class FakeWordPress:
    """Stands in for WP-CLI (through `su`) and for the website's answers (through curl)."""

    def __init__(self, case):
        self.case = case
        self.versions = {"plugin:woo": "1.0", "theme:blocksy": "2.0", "plugin:other": "3.0"}
        self.update_to = {"plugin:woo": "1.1", "theme:blocksy": "2.1", "plugin:other": "3.1"}
        self.update_mode = {}               # key -> 'fail' | 'nochange'
        self.db_fails = False
        self.broken = set()                 # keys that break the website once updated
        self.fatal = set()                  # keys that make the website show a PHP crash text
        self.files_differ = False
        self.script_log = []
        self.login_code = "200"
        self.home_down_before = False
        self.saved = {}                     # copy path -> version when it was saved
        self.admin = ""                     # the administrator's number, as WP-CLI would print it
        self.own_server = set()             # keys WordPress.org knows nothing about: only found when plugins are loaded
        self.admin_area_only = set()        # keys that only update when WordPress believes it is inside wp-admin
        self.area_crashes = False           # loading plugins inside wp-admin makes WP-CLI fail

    def key_in(self, script):
        for kind in ("plugin", "theme"):
            for k in self.versions:
                if k.startswith(kind + ":") and (" %s get %s " % (kind, k.split(":")[1]) in script + " " or
                                                 " %s update %s " % (kind, k.split(":")[1]) in script + " "):
                    return k
        return None

    def su(self, cmd):
        script = cmd[5]
        self.script_log.append(script)
        if "core version" in script:
            return 0, "6.5.2\n"
        if "user list" in script:
            return 0, self.admin
        if "db export" in script:
            return (1, "Error: mysqldump missing") if self.db_fails else (0, "Success: Exported to file.")
        if " path" in script and ("plugin path" in script or "theme path" in script):
            kind = "plugins" if "plugin path" in script else "themes"
            return 0, "%s/wp-content/%s\n" % (self.case.docroot, kind)
        if "test -d" in script:
            return 0, "dir\n"
        if "litespeed-purge" in script:
            return 1, "Error: 'litespeed-purge' is not a registered wp command.\n"
        if "diff -rq" in script:
            return 0, "different\n" if self.files_differ else "same\n"
        if "mkdir -p -m 700" in script and "cp -a" in script:
            kind_slug = script.split("cps-backups/")[-1].split(" ")[0].strip("'")
            self.saved[kind_slug] = dict(self.versions)
            return 0, ""
        if script.startswith("export") and "rm -rf" in script and "cp -a" in script and "cps-backups" in script:
            for name, snapshot in self.saved.items():
                if name in script:
                    self.versions.update(snapshot)
            return 0, ""
        if "ls -1" in script:
            return 0, ""
        if "rm -rf" in script and "cp -a" in script:
            for name, snapshot in self.saved.items():
                if name in script:
                    self.versions.update(snapshot)
            return 0, ""
        key = self.key_in(script)
        if key and " get " in script and "--field=version" in script:
            return 0, "Warning: something noisy\n" + self.versions[key] + "\n"
        if key and " update " in script:
            mode = self.update_mode.get(key)
            if key in self.own_server and "--skip-plugins" in script:
                mode = "nochange"
            if key in self.admin_area_only and "WP_ADMIN" not in script:
                mode = "nochange"
            if self.area_crashes and "WP_ADMIN" in script:
                return 255, "PHP Fatal error:  Uncaught Error in some-plugin.php\n"
            if mode == "fail":
                return 1, "Error: Download failed. Invalid license.\n"
            if mode != "nochange":
                self.versions[key] = self.update_to[key]
            return 0, "Success: Updated 1 of 1 %ss.\n" % key.split(":")[0]
        return 0, ""

    def curl(self, cmd):
        url = cmd[-1]
        updated = {k for k, v in self.versions.items() if v == self.update_to[k]}
        code, body = "200", "<html>hello</html>"
        if "/wp-login.php" in url:
            code = self.login_code
            if updated & self.broken:
                code = "500"
        else:
            if self.home_down_before and not updated:
                code = "503"
            if updated & self.broken:
                code = "500"
            if updated & self.fatal:
                body = "<b>There has been a critical error on this website.</b>"
        return 0, body + "\n" + code


class UpdateCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.docroot = "%s/%s/public_html" % (config.P.home_dir, DOMAIN)
        os.makedirs(self.docroot)
        self.write(config.P.lsws_root + "/lsphp81/bin/php", "")
        self.wp = FakeWordPress(self)
        self.fake.table += [(["su"], self.wp.su), (["curl"], self.wp.curl)]
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", DOMAIN)])
        self.patch("cpsec.wpupdate._sleep")
        wpupdate._php_cache.clear()
        self.reset_job()
        self.addCleanup(self.reset_job)

    def reset_job(self):
        with wpupdate._lock:
            wpupdate._job.update(status="idle", items=[], started="", finished="", stop=False)

    def wait(self):
        for _ in range(300):
            if wpupdate.state()["status"] != "running":
                return
            time.sleep(0.02)
        self.fail("the updates did not finish")

    def calls(self, word):
        return [s for s in self.wp.script_log if word in s]


class OneUpdate(UpdateCase):
    def test_a_good_update_saves_a_copy_first_then_updates_and_checks(self):
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["from"], r["to"]), ("1.0", "1.1"))
        self.assertIn("Updated from 1.0 to 1.1", r["message"])
        order = [("copy" if "mkdir -p -m 700" in s and "cp -a" in s else "db" if "db export" in s else "update" if " update " in s else None)
                 for s in self.wp.script_log]
        order = [o for o in order if o]
        self.assertEqual(order, ["copy", "db", "update"], "a copy of the files and the database come before the update")
        self.assertTrue(all(s.startswith("export HOME=") or "mkdir" in s or "test " in s or "diff" in s or "ls -1" in s
                            for s in self.wp.script_log), "everything runs as the website's user through su")

    def test_everything_runs_as_the_websites_own_user_never_as_root(self):
        wpupdate.update_one(DOMAIN, "plugin", "woo")
        sus = [c for c in self.fake.calls if c[:1] == ["su"]]
        self.assertTrue(sus)
        self.assertTrue(all(c[1:4] == ["-s", "/bin/bash", "shopuser"] for c in sus))

    def test_the_database_is_saved_once_per_website_when_asked_to_skip_it(self):
        wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertEqual(len(self.calls("db export")), 1)
        wpupdate.update_one(DOMAIN, "theme", "blocksy", db_saved=True)
        self.assertEqual(len(self.calls("db export")), 1)

    def test_a_database_copy_that_fails_is_reported_but_does_not_stop_the_update(self):
        self.wp.db_fails = True
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"])
        self.assertIn("the database copy could not be made", r["notes"])

    def test_an_update_the_tool_refuses_leaves_the_website_alone_and_says_why(self):
        self.wp.update_mode["plugin:woo"] = "fail"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertFalse(r["restored"])
        self.assertIn("Invalid license", r["message"])
        self.assertIn("stays on version 1.0", r["message"])
        self.assertEqual(self.wp.versions["plugin:woo"], "1.0")

    def test_if_a_failed_update_left_the_files_changed_the_saved_copy_goes_back(self):
        self.wp.update_mode["plugin:woo"] = "fail"
        self.wp.files_differ = True
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["restored"])
        self.assertIn("saved copy was put back", r["message"])

    def test_an_update_that_changes_nothing_is_not_called_a_success(self):
        self.wp.update_mode["plugin:woo"] = "nochange"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertIn("Nothing changed", r["message"])
        self.assertIn("licence", r["message"])

    def test_a_website_that_breaks_gets_the_old_version_back(self):
        self.wp.broken.add("plugin:woo")
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertTrue(r["restored"])
        self.assertIn("the home page now answers 500", r["message"])
        self.assertIn("old version 1.0 was put back", r["message"])
        self.assertEqual(self.wp.versions["plugin:woo"], "1.0", "the files are really back")
        self.assertNotIn("still does not look right", r["message"])

    def test_a_php_crash_shown_in_the_page_is_caught_even_when_the_answer_is_200(self):
        self.wp.fatal.add("theme:blocksy")
        r = wpupdate.update_one(DOMAIN, "theme", "blocksy")
        self.assertTrue(r["restored"])
        self.assertIn("PHP error", r["message"])
        self.assertEqual(self.wp.versions["theme:blocksy"], "2.0")

    def test_the_check_uses_a_fresh_address_so_a_cached_page_cannot_hide_a_crash(self):
        wpupdate.update_one(DOMAIN, "plugin", "woo")
        urls = [c[-1] for c in self.fake.calls if c[:1] == ["curl"]]
        self.assertTrue(any("/?cpsu=" in u for u in urls))
        self.assertTrue(any(u.endswith("/wp-login.php") for u in urls))
        fresh = [u for u in urls if "/?cpsu=" in u]
        self.assertGreaterEqual(len(fresh), 2, "once before and once after")
        self.assertEqual(len(set(fresh)), len(fresh), "a different address every time")

    def test_a_website_that_is_already_broken_is_not_touched(self):
        self.wp.home_down_before = True
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertIn("not answering normally", r["message"])
        self.assertEqual(self.calls(" update "), [])
        self.assertEqual(self.calls("cp -a"), [])

    def test_a_hidden_login_page_does_not_stop_updates(self):
        self.wp.login_code = "404"                    # a "hide login" plugin: the login address does not exist
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"], r)

    def test_odd_names_are_refused_before_anything_runs(self):
        for kind, slug in (("plugin", "woo; rm -rf /"), ("plugin", "$(id)"), ("plugin", "../x"), ("core", "woo"), ("plugin", ""), ("theme", "a b")):
            r = wpupdate.update_one(DOMAIN, kind, slug)
            self.assertFalse(r["ok"], (kind, slug))
        self.assertEqual(self.wp.script_log, [])

    def test_a_website_that_is_not_wordpress_here_is_refused(self):
        r = wpupdate.update_one("nowhere.example.com", "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertEqual(self.wp.script_log, [])

    def test_an_item_that_is_not_installed_is_reported(self):
        r = wpupdate.update_one(DOMAIN, "plugin", "ghost")
        self.assertFalse(r["ok"])

    def test_versions_are_read_even_with_noise_around_them(self):
        self.assertEqual(wpupdate._version("Warning: x\n6.5.2\n"), "6.5.2")
        self.assertEqual(wpupdate._version("Warning: x\n"), "")
        self.assertEqual(wpupdate._version("1.2.3-beta+4\n"), "1.2.3-beta+4")

    def test_shops_and_page_builders_are_marked_careful(self):
        self.assertTrue(wpupdate.is_careful("woocommerce", "WooCommerce"))
        self.assertTrue(wpupdate.is_careful("bricks", "Bricks"))
        self.assertTrue(wpupdate.is_careful("woo-zarinpal-gateway", ""))
        self.assertFalse(wpupdate.is_careful("akismet", "Akismet Anti-spam"))


class TheJob(UpdateCase):
    def items(self, *pairs):
        return [{"site": DOMAIN, "kind": k, "slug": s} for k, s in pairs]

    def test_items_are_checked_before_anything_starts(self):
        for bad in (None, [], "x", [5], [{"site": "nope", "kind": "plugin", "slug": "woo"}],
                    [{"site": DOMAIN, "kind": "core", "slug": "woo"}], [{"site": DOMAIN, "kind": "plugin", "slug": "a;b"}],
                    [{"site": DOMAIN, "kind": "plugin", "slug": "woo"}] * 1 + [{"site": DOMAIN, "kind": "plugin", "slug": "x"}] * 101):
            res = wpupdate.start(bad)
            self.assertEqual((res.ok, res.code), (False, "invalid"), bad if not isinstance(bad, list) or len(bad) < 5 else "too many")
        self.assertEqual(wpupdate.state()["status"], "idle")

    def test_a_job_does_every_item_in_order_and_reports_each_result(self):
        done = []
        finished = []
        res = wpupdate.start(self.items(("plugin", "woo"), ("theme", "blocksy"), ("plugin", "other")),
                             titles={(DOMAIN, "plugin", "woo"): "WooCommerce"}, on_item=done.append, on_done=finished.append)
        self.assertTrue(res.ok)
        self.wait()
        st = wpupdate.state()
        self.assertEqual(st["status"], "done")
        self.assertEqual([i["status"] for i in st["items"]], ["done", "done", "done"])
        self.assertEqual(st["items"][0]["title"], "WooCommerce")
        self.assertEqual((st["items"][0]["from"], st["items"][0]["to"]), ("1.0", "1.1"))
        self.assertEqual(st["counts"]["done"], 3)
        self.assertEqual(len(self.calls("db export")), 1, "the database is saved once for the website, not once per item")
        self.assertEqual([d["slug"] for d in done], ["woo", "blocksy", "other"])
        self.assertEqual(finished, [[DOMAIN]])

    def test_one_failure_does_not_stop_the_others_and_is_labelled(self):
        self.wp.update_mode["theme:blocksy"] = "fail"
        self.wp.broken.add("plugin:other")
        wpupdate.start(self.items(("plugin", "woo"), ("theme", "blocksy"), ("plugin", "other")))
        self.wait()
        st = wpupdate.state()
        self.assertEqual([i["status"] for i in st["items"]], ["done", "failed", "restored"])
        self.assertIn("Invalid license", st["items"][1]["message"])
        self.assertIn("old version", st["items"][2]["message"])
        self.assertEqual(st["counts"], {"waiting": 0, "working": 0, "done": 1, "failed": 1, "restored": 1, "skipped": 0})

    def test_a_second_job_cannot_start_while_one_runs(self):
        calls = []
        orig = wpupdate.update_one

        def slow(*args, **kwargs):
            calls.append(1)
            for _ in range(50):
                if len(calls) > 1:
                    break
                time.sleep(0.01)
            return orig(*args, **kwargs)
        self.patch("cpsec.wpupdate.update_one", side_effect=slow)
        wpupdate.start(self.items(("plugin", "woo")))
        again = wpupdate.start(self.items(("plugin", "other")))
        self.assertEqual((again.ok, again.code), (False, "busy"))
        calls.append(1)
        self.wait()

    def test_stopping_skips_what_has_not_started(self):
        orig = wpupdate.update_one

        def stop_after_first(*args, **kwargs):
            res = orig(*args, **kwargs)
            wpupdate.stop()
            return res
        self.patch("cpsec.wpupdate.update_one", side_effect=stop_after_first)
        wpupdate.start(self.items(("plugin", "woo"), ("theme", "blocksy"), ("plugin", "other")))
        self.wait()
        st = wpupdate.state()
        self.assertEqual([i["status"] for i in st["items"]], ["done", "skipped", "skipped"])
        self.assertEqual(wpupdate.stop().code, "none")

    def test_an_unexpected_crash_in_one_item_is_caught(self):
        self.patch("cpsec.wpupdate.update_one", side_effect=RuntimeError("boom"))
        wpupdate.start(self.items(("plugin", "woo")))
        self.wait()
        st = wpupdate.state()
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["items"][0]["status"], "failed")
        self.assertIn("Unexpected problem", st["items"][0]["message"])


class OldCopies(UpdateCase):
    """Found on the real server: `cp -a` keeps the plugin's old modified time, so the cleanup must go by the time stamp in the name."""

    def run_prune(self, listing, kind="plugin", slug="woo"):
        removed = []

        def su(cmd):
            script = cmd[5]
            if script.startswith("ls -1"):
                return 0, "\n".join(listing) + "\n"
            if "rm -rf --" in script:
                removed.append(script)
            return 0, ""
        self.fake.table.insert(0, (["su"], su))
        wpupdate._clean_old_copies({"home": "/home/x", "user": "u", "docroot": "/home/x/public_html"}, kind, slug)
        return removed

    def test_the_three_newest_copies_by_name_are_kept(self):
        names = ["plugin-woo-2026101%d-120000" % d for d in range(1, 6)]
        removed = self.run_prune(names)
        self.assertEqual(len(removed), 1)
        self.assertIn("plugin-woo-20261011-120000", removed[0])
        self.assertIn("plugin-woo-20261012-120000", removed[0])
        for kept in names[2:]:
            self.assertNotIn(kept, removed[0])

    def test_another_plugin_with_a_longer_name_is_never_touched(self):
        names = ["plugin-woo-20261011-120000", "plugin-woo-20261012-120000", "plugin-woo-20261013-120000", "plugin-woo-20261014-120000",
                 "plugin-woo-bar-20260101-120000", "theme-woo-20260101-120000", "db-20260101-120000.sql"]
        removed = self.run_prune(names)
        self.assertEqual(len(removed), 1)
        self.assertIn("plugin-woo-20261011-120000", removed[0])
        self.assertNotIn("woo-bar", removed[0])
        self.assertNotIn("theme-woo", removed[0])
        self.assertNotIn("db-2026", removed[0])

    def test_nothing_is_removed_when_there_are_three_or_fewer(self):
        self.assertEqual(self.run_prune(["plugin-woo-20261011-120000", "plugin-woo-20261012-120000"]), [])


class UpdatesFromTheMakersOwnServer(UpdateCase):
    """Plugins that are not on WordPress.org (WPCodeBox, BricksExtras...) only update when loaded and asked by an administrator."""

    def update_scripts(self):
        return [x for x in self.wp.script_log if " plugin update woo " in x + " "]

    def test_it_is_tried_again_the_way_the_dashboard_does_and_that_works(self):
        self.wp.own_server = {"plugin:woo"}
        self.wp.admin = "5\n"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["from"], r["to"]), ("1.0", "1.1"))
        self.assertIn("maker's own server", r["message"])
        first, second = self.update_scripts()
        self.assertIn("--skip-plugins", first)
        self.assertNotIn("--skip-plugins", second)
        self.assertIn("--user=5", second)

    def test_a_plugin_that_only_starts_inside_wp_admin_is_updated_that_way(self):
        self.wp.admin_area_only = {"plugin:woo"}
        self.wp.own_server = {"plugin:woo"}
        self.wp.admin = "5\n"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"], r)
        self.assertIn("WP_ADMIN", self.update_scripts()[-1])
        self.assertEqual(len(self.update_scripts()), 2, "plain first, then once inside wp-admin; no third try")

    def test_if_wp_admin_mode_crashes_the_plain_loaded_way_is_tried(self):
        self.wp.own_server = {"plugin:woo"}
        self.wp.area_crashes = True
        self.wp.admin = "5\n"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"], r)
        scripts = self.update_scripts()
        self.assertEqual(len(scripts), 3)
        self.assertIn("WP_ADMIN", scripts[1])
        self.assertNotIn("WP_ADMIN", scripts[2])

    def test_a_normal_update_is_not_tried_twice(self):
        self.wp.admin = "5\n"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertTrue(r["ok"])
        self.assertEqual(len(self.update_scripts()), 1)
        self.assertNotIn("maker's own server", r["message"])

    def test_a_failure_is_not_tried_again(self):
        self.wp.admin = "5\n"
        self.wp.update_mode["plugin:woo"] = "fail"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertEqual(len(self.update_scripts()), 1)

    def test_without_an_administrator_it_says_nothing_changed(self):
        self.wp.own_server = {"plugin:woo"}
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertIn("Nothing changed", r["message"])
        self.assertEqual(len(self.update_scripts()), 1)


class TheListIsReadAgainBeforeTheJobIsFinished(UpdateCase):
    """Reported by the owner: after an update the page still showed it. The page fetched the list the moment the job
    said "finished", but the list was only read again after that."""

    def test_the_job_is_not_finished_while_the_list_is_being_read_again(self):
        seen = []
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo"}],
                       on_done=lambda touched: seen.append((wpupdate.state()["status"], wpupdate.state()["phase"], touched)))
        self.wait()
        self.assertEqual(seen, [("running", "checking", [DOMAIN])])
        st = wpupdate.state()
        self.assertEqual((st["status"], st["phase"]), ("done", ""))

    def test_the_list_is_up_to_date_the_moment_the_job_is_finished(self):
        waiting = {"woo": True}

        def read_again(touched):
            time.sleep(0.15)                  # reading again takes a while
            waiting["woo"] = False
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo"}], on_done=read_again)
        for _ in range(500):
            if wpupdate.state()["status"] == "done":
                break
            time.sleep(0.01)
        self.assertFalse(waiting["woo"], "the page fetches the list as soon as it sees 'done'")

    def test_a_crash_while_reading_again_still_finishes_the_job(self):
        def boom(touched):
            raise RuntimeError("boom")
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo"}], on_done=boom)
        self.wait()
        self.assertEqual(wpupdate.state()["status"], "done")


class WhyAnUpdateFailed(UpdateCase):
    """Found on the real server: the cause is on a 'Warning:' line, the 'Error:' line only says 'No plugins updated'."""

    def test_the_warning_with_the_cause_wins_over_the_generic_error(self):
        out = ('Enabling Maintenance mode...\nDownloading update from https://example.com/package/...\n'
               'Warning: Download failed. "Unauthorized"\nDisabling Maintenance mode...\n'
               'name\told_version\tnew_version\tstatus\nbricksextras\t1.5.3\t1.7.6\tError\nError: No plugins updated (1 failed).\n')
        text = wpupdate.reason(out)
        self.assertIn('Download failed. "Unauthorized"', text)
        self.assertNotIn("No plugins updated", text)
        self.assertIn("licence is not active", text, "an 'Unauthorized' answer is explained in plain words")

    def test_only_an_error_line_is_used_when_there_is_no_warning(self):
        self.assertEqual(wpupdate.reason("Error: Could not create directory."), "Could not create directory.")

    def test_something_is_always_said(self):
        self.assertEqual(wpupdate.reason(""), "the update tool reported a failure")

    def test_a_failed_update_shows_the_reason_and_clears_a_leftover_upgrade_marker(self):
        self.wp.update_mode["plugin:woo"] = "fail"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertIn("Invalid license", r["message"])
        self.assertTrue(any(".maintenance" in s for s in self.wp.script_log), "a marker left by a killed update would keep the site in maintenance mode")
        self.assertTrue(all(".maintenance" not in s or s.startswith("test -f") for s in self.wp.script_log))
