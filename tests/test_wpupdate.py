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
        self.install_key = "plugin:woo"     # what an uploaded file installs
        self.install_version = "2.0"
        self.install_mode = None            # 'fail' | 'nochange'
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
        if " install " in script and "--force" in script:
            if self.install_mode == "fail":
                return 1, "Error: Could not create directory.\n"
            if self.install_mode != "nochange":
                self.versions[self.install_key] = self.install_version
            return 0, "Success: Installed 1 of 1 plugins.\n"
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
        self.assertTrue(all(s.startswith("export HOME=") or "mkdir" in s or "test " in s or "diff" in s or "ls -1" in s or s.startswith("chmod 600 --")
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


class SomethingIsVisiblyHappening(UpdateCase):
    """The page shows a spinner, the current step and how long it has been going, so a slow update does not look stuck."""

    def test_each_step_is_announced_in_order(self):
        steps = []
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", progress=steps.append)
        self.assertTrue(r["ok"], r)
        wanted = ["Checking that the website answers normally", "Saving a copy of the plugin files", "Saving a copy of the database",
                  "Installing the new version", "Checking the website again", "Clearing the cache"]
        positions = [next(i for i, s in enumerate(steps) if s.startswith(w)) for w in wanted]
        self.assertEqual(positions, sorted(positions))

    def test_the_database_copy_is_only_announced_when_it_is_made(self):
        steps = []
        wpupdate.update_one(DOMAIN, "plugin", "woo", db_saved=True, progress=steps.append)
        self.assertFalse([s for s in steps if "database" in s])

    def test_putting_the_old_version_back_is_announced(self):
        self.wp.broken = {"plugin:woo"}
        steps = []
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", progress=steps.append)
        self.assertTrue(r["restored"])
        self.assertTrue(any("putting the old version back" in s for s in steps), steps)

    def test_a_missing_progress_function_is_fine(self):
        self.assertTrue(wpupdate.update_one(DOMAIN, "plugin", "woo")["ok"])

    def test_the_job_shows_the_step_and_the_seconds_while_it_works(self):
        import threading
        release, reached = threading.Event(), threading.Event()
        real = wpupdate.update_one

        def slow(domain, kind, slug, db_saved=False, stamp=None, progress=None, upload=None):
            progress("Installing the new version")
            reached.set()
            release.wait(5)
            return real(domain, kind, slug, db_saved=db_saved, stamp=stamp, progress=progress, upload=upload)
        self.patch("cpsec.wpupdate.update_one", side_effect=slow)
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo"}, {"site": DOMAIN, "kind": "theme", "slug": "blocksy"}])
        self.assertTrue(reached.wait(5))
        time.sleep(1.1)
        st = wpupdate.state()
        first, second = st["items"]
        self.assertEqual(first["status"], "working")
        self.assertEqual(first["step"], "Installing the new version")
        self.assertGreaterEqual(first["seconds"], 1)
        self.assertEqual((second["status"], second["seconds"], second["step"]), ("waiting", 0, ""))
        self.assertNotIn("since", first, "the raw clock value stays inside")
        release.set()
        self.wait()
        done = wpupdate.state()["items"]
        self.assertTrue(all(i["step"] == "" and i["seconds"] == 0 for i in done), "nothing is shown as busy afterwards")


ENTRY = {"id": "0123456789abcdef", "kind": "plugin", "slug": "woo", "name": "Woo", "version": "2.0", "sha256": "0" * 64}
SENT = "/home/%s/cps-backups/upload-0123456789abcdef.zip" % DOMAIN


class UpdatingFromAnUploadedFile(UpdateCase):
    """The owner uploaded the maker's zip; the website's plugin is replaced with it, with the same safety as any other update."""

    def setUp(self):
        super().setUp()
        self.discarded = []
        self.patch("cpsec.wpupdate.library.deliver", return_value=(SENT, ""))
        self.patch("cpsec.wpupdate.library.discard", side_effect=lambda site, path: self.discarded.append(path))
        self.patch("cpsec.wpupdate.library.get", side_effect=lambda zid: dict(ENTRY) if zid == ENTRY["id"] else None)

    def installs(self):
        return [s for s in self.wp.script_log if " install " in s]

    def test_the_plugin_is_replaced_with_the_uploaded_file_and_checked(self):
        steps = []
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY), progress=steps.append)
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["from"], r["to"]), ("1.0", "2.0"))
        self.assertIn("with the file you uploaded", r["message"])
        self.assertEqual(len(self.installs()), 1)
        self.assertIn("plugin install", self.installs()[0])
        self.assertIn(SENT, self.installs()[0])
        self.assertIn("--force", self.installs()[0])
        self.assertFalse(self.calls(" plugin update "), "WordPress.org is not asked at all")
        self.assertIn("Installing the uploaded version", steps)
        self.assertIn("Sending the uploaded file to the website", steps)

    def test_the_copy_and_the_database_are_saved_first_like_for_any_update(self):
        wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        order = [("copy" if "mkdir -p -m 700" in s and "cp -a" in s else "db" if "db export" in s else "install" if " install " in s else None)
                 for s in self.wp.script_log]
        self.assertEqual([o for o in order if o], ["copy", "db", "install"])

    def test_the_websites_copy_of_the_file_never_stays_behind(self):
        wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertEqual(self.discarded, [SENT])
        self.wp.install_mode = "fail"
        self.wp.versions["plugin:woo"] = "1.0"
        self.discarded.clear()
        wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertEqual(self.discarded, [SENT], "also when the install fails")

    def test_the_same_version_or_a_newer_one_on_the_website_is_left_alone(self):
        for have in ("2.0", "2.5"):
            self.wp.versions["plugin:woo"] = have
            before = len(self.wp.script_log)
            r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
            self.assertFalse(r["ok"])
            self.assertTrue(r["skipped"])
            self.assertIn("nothing was changed", r["message"])
            self.assertEqual(self.installs(), [])
            self.assertFalse([s for s in self.wp.script_log[before:] if "cp -a" in s], "no copy is even made")

    def test_a_file_that_cannot_be_sent_changes_nothing(self):
        self.patch("cpsec.wpupdate.library.deliver", return_value=("", "The file could not be sent to the website (no space)."))
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertFalse(r["ok"])
        self.assertIn("could not be sent", r["message"])
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.wp.versions["plugin:woo"], "1.0")

    def test_if_the_website_breaks_the_old_version_is_put_back(self):
        self.wp.broken = {"plugin:woo"}
        self.wp.update_to["plugin:woo"] = "2.0"                # the fake website breaks once this version is on it
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertTrue(r["restored"])
        self.assertFalse(r["ok"])
        self.assertEqual(self.wp.versions["plugin:woo"], "1.0")
        self.assertIn("old version 1.0 was put back", r["message"])

    def test_a_failed_install_says_why_and_leaves_the_old_version(self):
        self.wp.install_mode = "fail"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertFalse(r["ok"])
        self.assertIn("Could not create directory", r["message"])
        self.assertIn("stays on version 1.0", r["message"])

    def test_an_install_that_changes_nothing_is_reported_plainly(self):
        self.wp.install_mode = "nochange"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertFalse(r["ok"])
        self.assertIn("did not replace the files with the uploaded ones", r["message"])

    def test_a_different_version_than_the_file_says_is_noted(self):
        self.wp.install_version = "2.0.1"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo", upload=dict(ENTRY))
        self.assertTrue(r["ok"])
        self.assertTrue([n for n in r["notes"] if "2.0.1" in n and "2.0" in n])


class PointingToTheUploadedFile(UpdateCase):
    """Found with the owner: the normal Update button asked the maker's server (which refused); the uploaded file would have worked."""

    def test_a_refused_update_points_to_the_file_already_uploaded(self):
        self.patch("cpsec.wpupdate.library.list_zips", return_value=[dict(ENTRY, version="2.0")])
        self.wp.update_mode["plugin:woo"] = "fail"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertFalse(r["ok"])
        self.assertIn("You have already uploaded version 2.0", r["message"])
        self.assertIn("Update from your upload", r["message"])

    def test_nothing_is_added_when_there_is_no_newer_upload(self):
        self.wp.update_mode["plugin:woo"] = "fail"
        self.assertNotIn("uploaded", wpupdate.update_one(DOMAIN, "plugin", "woo")["message"].split("Download failed")[-1])
        self.patch("cpsec.wpupdate.library.list_zips", return_value=[dict(ENTRY, version="1.0")])
        self.assertNotIn("already uploaded", wpupdate.update_one(DOMAIN, "plugin", "woo")["message"])
        self.patch("cpsec.wpupdate.library.list_zips", return_value=[dict(ENTRY, slug="other", version="9.0")])
        self.assertNotIn("already uploaded", wpupdate.update_one(DOMAIN, "plugin", "woo")["message"])

    def test_a_do_nothing_update_points_there_too(self):
        self.patch("cpsec.wpupdate.library.list_zips", return_value=[dict(ENTRY, version="2.0")])
        self.wp.update_mode["plugin:woo"] = "nochange"
        r = wpupdate.update_one(DOMAIN, "plugin", "woo")
        self.assertIn("Nothing changed", r["message"])
        self.assertIn("already uploaded version 2.0", r["message"])


class UploadedFilesInTheJob(UpdateCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.wpupdate.library.deliver", return_value=(SENT, ""))
        self.patch("cpsec.wpupdate.library.discard")
        self.entries = {ENTRY["id"]: dict(ENTRY)}
        self.patch("cpsec.wpupdate.library.get", side_effect=lambda zid: dict(self.entries[zid]) if isinstance(zid, str) and zid in self.entries else None)

    def test_the_list_from_the_page_may_carry_the_file(self):
        clean, err = wpupdate.check_items([{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ENTRY["id"]}])
        self.assertEqual(err, "")
        self.assertEqual(clean, [{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ENTRY["id"]}])

    def test_a_file_that_is_not_there_or_not_for_that_plugin_is_refused(self):
        clean, err = wpupdate.check_items([{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": "ffffffffffffffff"}])
        self.assertIsNone(clean)
        self.assertIn("no longer on the server", err)
        clean, err = wpupdate.check_items([{"site": DOMAIN, "kind": "plugin", "slug": "other", "zip": ENTRY["id"]}])
        self.assertIsNone(clean)
        self.assertIn("not the plugin you chose", err)
        clean, err = wpupdate.check_items([{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ["x"]}])
        self.assertIsNone(clean)

    def test_the_job_updates_from_the_file_and_the_row_says_updated(self):
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ENTRY["id"]}])
        self.wait()
        st = wpupdate.state()
        self.assertEqual([i["status"] for i in st["items"]], ["done"])
        self.assertEqual((st["items"][0]["from"], st["items"][0]["to"]), ("1.0", "2.0"))

    def test_a_site_that_already_has_it_is_shown_as_skipped_not_failed(self):
        self.wp.versions["plugin:woo"] = "2.0"
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ENTRY["id"]}])
        self.wait()
        st = wpupdate.state()
        self.assertEqual(st["items"][0]["status"], "skipped")
        self.assertEqual(st["counts"]["skipped"], 1)
        self.assertEqual(st["counts"]["failed"], 0)

    def test_a_file_deleted_while_the_job_waits_changes_nothing(self):
        calls = []

        def first_item_deletes_the_file(domain, kind, slug, **kwargs):
            calls.append(slug)
            self.entries.clear()                                  # the owner deletes the upload while the first item is running
            return {"ok": True, "restored": False, "skipped": False, "from": "1", "to": "2", "message": "ok", "notes": [], "db_attempted": True}
        self.patch("cpsec.wpupdate.update_one", side_effect=first_item_deletes_the_file)
        wpupdate.start([{"site": DOMAIN, "kind": "plugin", "slug": "other"}, {"site": DOMAIN, "kind": "plugin", "slug": "woo", "zip": ENTRY["id"]}])
        self.wait()
        st = wpupdate.state()
        self.assertEqual(calls, ["other"], "the second item never reached the update")
        self.assertEqual([i["status"] for i in st["items"]], ["done", "failed"])
        self.assertIn("deleted from the server before its turn", st["items"][1]["message"])
