"""The copies saved before each update: listing them, choosing how many to keep, and deleting them on request."""
import shlex

from cpsec import config, settings, wpupdate
from tests.helpers import EnvTestCase

SHOP, BLOG = "shop.example.com", "blog.example.com"

PLUGIN_OLD = "plugin-woocommerce-20261012-081500"
PLUGIN_NEW = "plugin-woocommerce-20261019-093000"
THEME = "theme-bricks-20261012-081500"
DB_OLD = "db-20261012-081500.sql"
DB_NEW = "db-20261019-093000.sql"
OWN_FILES = ["notes.txt", "my-own-backup", "plugin-x-20261019.bak", "db-20261019-093000.sql.old", "plugin-x-20261019-093000; rm -rf ~"]


class FakeBackupFolders:
    """Stands in for `su`: the backup folder of each website is a dict {name: size in KB}."""

    def __init__(self):
        self.folders = {"shopuser": {PLUGIN_OLD: 30000, PLUGIN_NEW: 31200, THEME: 9800, DB_OLD: 18000, DB_NEW: 18400, **{n: 5 for n in OWN_FILES}},
                        "bloguser": {"plugin-yoast-seo-20261017-141000": 14200, DB_NEW: 4100}}
        self.remove_fails = set()               # users whose files cannot be removed
        self.scripts = []

    def su(self, cmd):
        user, script = cmd[3], cmd[5]
        self.scripts.append(script)
        folder = self.folders.setdefault(user, {})
        if script.startswith("cd ") and "for n in *" in script:
            return 0, "".join("%d\t%s\n" % (kb, name) for name, kb in folder.items())
        if " rm -rf -- " in script:
            if user in self.remove_fails:
                return 1, "rm: cannot remove: Operation not permitted\n"
            for name in shlex.split(script.split(" rm -rf -- ", 1)[1]):
                folder.pop(name, None)
            return 0, ""
        if script.startswith("ls -1"):
            return 0, "".join(n + "\n" for n in folder)
        return 0, ""


class CopiesCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.folders = FakeBackupFolders()
        self.fake.table += [(["su"], self.folders.su)]
        sites = [("%s/%s/public_html" % (config.P.home_dir, SHOP), "shopuser", SHOP), ("%s/%s/public_html" % (config.P.home_dir, BLOG), "bloguser", BLOG)]
        self.patch("cpsec.updates._wordpress_sites", return_value=sites)
        self.reset_job()
        self.addCleanup(self.reset_job)

    def reset_job(self):
        with wpupdate._lock:
            wpupdate._job.update(status="idle", items=[], started="", finished="", stop=False)

    def mine(self, user):
        return sorted(n for n in self.folders.folders[user] if n not in OWN_FILES)


class Listing(CopiesCase):
    def test_only_the_copies_the_panel_made_are_listed_newest_first(self):
        items = wpupdate.copies({"home": "/home/%s" % SHOP, "user": "shopuser", "docroot": "/home/%s/public_html" % SHOP})
        self.assertEqual({i["name"] for i in items}, {PLUGIN_OLD, PLUGIN_NEW, THEME, DB_OLD, DB_NEW})
        whens = [i["when"] for i in items]
        self.assertEqual(whens, sorted(whens, reverse=True))
        by_name = {i["name"]: i for i in items}
        first = by_name[PLUGIN_NEW]
        self.assertEqual((first["kind"], first["what"], first["when"], first["kb"]), ("plugin", "woocommerce", "2026-10-19 09:30", 31200))
        self.assertEqual((by_name[DB_NEW]["kind"], by_name[DB_NEW]["what"]), ("database", "Database"))
        self.assertEqual(by_name[THEME]["kind"], "theme")
        for own in OWN_FILES:
            self.assertNotIn(own, by_name)

    def test_the_page_gets_each_website_with_its_totals(self):
        data = wpupdate.copies_state()
        self.assertEqual(data["keep"], 3)
        self.assertEqual([s["site"] for s in data["sites"]], [BLOG, SHOP])
        shop = data["sites"][1]
        self.assertEqual((shop["count"], shop["kb"], shop["newest"]), (5, 30000 + 31200 + 9800 + 18000 + 18400, "2026-10-19 09:30"))
        self.assertEqual(data["count"], 7)
        self.assertEqual(data["kb"], sum(s["kb"] for s in data["sites"]))

    def test_a_website_without_copies_is_not_listed(self):
        self.folders.folders["bloguser"] = {}
        self.assertEqual([s["site"] for s in wpupdate.copies_state()["sites"]], [SHOP])

    def test_a_server_without_websites_gives_an_empty_list(self):
        self.patch("cpsec.updates._wordpress_sites", return_value=[])
        data = wpupdate.copies_state()
        self.assertEqual((data["sites"], data["count"], data["kb"]), ([], 0, 0))

    def test_sizes_are_written_for_people(self):
        self.assertEqual(wpupdate.size_text(0), "1 KB")
        self.assertEqual(wpupdate.size_text(800), "800 KB")
        self.assertEqual(wpupdate.size_text(1536), "1.5 MB")


class HowManyAreKept(CopiesCase):
    SITE = {"home": "/home/x", "user": "shopuser", "docroot": "/home/x/public_html"}

    def test_three_is_the_start_and_the_owner_can_choose_one_to_five(self):
        self.assertEqual(wpupdate.keep_copies(), 3)
        for n in (1, 2, 4, 5):
            self.assertTrue(wpupdate.set_keep(n).ok)
            self.assertEqual(wpupdate.keep_copies(), n)
            self.assertEqual(settings.load()["copies_keep"], n)

    def test_other_choices_are_refused_and_change_nothing(self):
        wpupdate.set_keep(2)
        for bad in (0, 6, -1, 2.5, "3", None, True, [3]):
            res = wpupdate.set_keep(bad)
            self.assertEqual((res.ok, res.code), (False, "invalid"), bad)
        self.assertEqual(wpupdate.keep_copies(), 2)

    def test_a_damaged_setting_falls_back_to_three(self):
        settings.save({"copies_keep": "lots"})
        self.assertEqual(wpupdate.keep_copies(), 3)
        settings.save({"copies_keep": 99})
        self.assertEqual(wpupdate.keep_copies(), 5)

    def test_after_an_update_only_the_chosen_number_of_the_newest_are_kept(self):
        names = ["plugin-woo-2026101%d-120000" % d for d in range(1, 6)]
        self.folders.folders["shopuser"] = {n: 10 for n in names}
        wpupdate.set_keep(1)
        wpupdate._clean_old_copies(self.SITE, "plugin", "woo")
        self.assertEqual(sorted(self.folders.folders["shopuser"]), [names[-1]])

    def test_the_message_says_what_happens_to_the_copies_already_there(self):
        self.assertIn("newest copy of each", wpupdate.set_keep(1).message)
        self.assertIn("newest 4 copies of each", wpupdate.set_keep(4).message)
        self.assertIn("stay until you delete them", wpupdate.set_keep(4).message)


class DatabaseCopiesArePrivate(CopiesCase):
    SITE = {"home": "/home/x", "user": "shopuser", "docroot": "/home/x/public_html"}

    def run_save(self, export_ok):
        def su(cmd):
            self.folders.scripts.append(cmd[5])
            return (0, "Success") if (export_ok or "db export" not in cmd[5]) else (1, "Error: mysqldump missing")
        self.fake.table.insert(0, (["su"], su))
        return wpupdate.save_database(self.SITE, "/php", "20261020-120000")

    def test_a_new_database_copy_can_only_be_read_by_the_websites_own_user(self):
        ok, note = self.run_save(True)
        self.assertTrue(ok)
        chmods = [s for s in self.folders.scripts if s.startswith("chmod 600 --")]
        self.assertEqual(len(chmods), 1)
        self.assertIn("/home/x/cps-backups/db-20261020-120000.sql", chmods[0])

    def test_nothing_is_changed_when_the_copy_could_not_be_made(self):
        ok, note = self.run_save(False)
        self.assertFalse(ok)
        self.assertFalse([s for s in self.folders.scripts if s.startswith("chmod")])


class Deleting(CopiesCase):
    def test_all_the_copies_go_and_the_owners_own_files_stay(self):
        res = wpupdate.copies_remove(None)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.mine("shopuser"), [])
        self.assertEqual(self.mine("bloguser"), [])
        for own in OWN_FILES:
            self.assertIn(own, self.folders.folders["shopuser"])
        self.assertIn("Deleted 7 saved copies", res.message)
        self.assertIn("from 2 websites", res.message)
        self.assertEqual(wpupdate.copies_state()["count"], 0)

    def test_one_website_can_be_chosen(self):
        res = wpupdate.copies_remove([BLOG])
        self.assertTrue(res.ok, res.message)
        self.assertEqual(self.mine("bloguser"), [])
        self.assertEqual(len(self.mine("shopuser")), 5)
        self.assertIn("from 1 website.", res.message)

    def test_nothing_to_delete_is_said_plainly(self):
        wpupdate.copies_remove(None)
        res = wpupdate.copies_remove(None)
        self.assertEqual((res.ok, res.code), (False, "none"))

    def test_websites_that_are_not_on_the_server_are_refused(self):
        for names in ([], ["nope.example.com"], [SHOP, "nope.example.com"]):
            res = wpupdate.copies_remove(names)
            self.assertEqual((res.ok, res.code), (False, "invalid"), names)
        self.assertEqual(len(self.mine("shopuser")), 5)

    def test_nothing_is_deleted_while_updates_are_running(self):
        with wpupdate._lock:
            wpupdate._job["status"] = "running"
        res = wpupdate.copies_remove(None)
        self.assertEqual((res.ok, res.code), (False, "busy"))
        self.assertEqual(len(self.mine("shopuser")), 5)

    def test_only_names_the_panel_makes_are_ever_given_to_the_delete_command(self):
        wpupdate.copies_remove(None)
        removals = [s for s in self.folders.scripts if " rm -rf -- " in s]
        self.assertEqual(len(removals), 2)
        for script in removals:
            for own in OWN_FILES:
                self.assertNotIn(own, script)
            self.assertNotIn("~", script)

    def test_it_runs_as_the_websites_own_user_inside_its_backup_folder(self):
        seen = []

        def su(cmd):
            seen.append((cmd[3], cmd[5]))
            return self.folders.su(cmd)
        self.fake.table.insert(0, (["su"], su))
        wpupdate.copies_remove([SHOP])
        users = {u for u, s in seen if " rm -rf -- " in s}
        self.assertEqual(users, {"shopuser"})
        for _u, script in seen:
            if " rm -rf -- " in script:
                self.assertTrue(script.startswith("cd %s && rm -rf --" % shlex.quote("%s/%s/cps-backups" % (config.P.home_dir, SHOP))), script)

    def test_a_website_where_deleting_fails_is_named(self):
        self.folders.remove_fails.add("shopuser")
        res = wpupdate.copies_remove(None)
        self.assertEqual((res.ok, res.code), (False, "partial"))
        self.assertIn(SHOP, res.message)
        self.assertEqual(self.mine("bloguser"), [])
        self.assertIn("Deleted 2 saved copies", res.message)


if __name__ == "__main__":
    import unittest
    unittest.main()
