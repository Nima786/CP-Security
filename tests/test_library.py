"""Plugin and theme zips the owner uploads: checking them, keeping them, and sending one to a website."""
import hashlib
import os
import stat
import time
import zipfile

from cpsec import config, library
from tests.helpers import EnvTestCase

PLUGIN_HEAD = "<?php\n/*\nPlugin Name: Bricks Extras\nVersion: 1.7.6\nDescription: Test\n*/\n"
THEME_HEAD = "/*\nTheme Name: Test Theme\nVersion: 3.2\n*/\n"


def make_zip(path, files, folder_flags=None):
    """files: {name inside the zip: text}. Returns the path."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():
            z.writestr(name, text)
    return path


class LibraryCase(EnvTestCase):
    def zip(self, name="plugin.zip", files=None):
        files = files if files is not None else {"bricksextras/bricksextras.php": PLUGIN_HEAD, "bricksextras/readme.txt": "hello"}
        path = os.path.join(self.root, name)
        return make_zip(path, files)


class LookingInside(LibraryCase):
    def test_a_plugin_is_recognised_with_its_name_and_version(self):
        info, err = library.inspect_zip(self.zip())
        self.assertIsNone(err)
        self.assertEqual((info["kind"], info["slug"], info["name"], info["version"]), ("plugin", "bricksextras", "Bricks Extras", "1.7.6"))
        self.assertFalse(info["renamed"])

    def test_a_theme_is_recognised(self):
        info, err = library.inspect_zip(self.zip(files={"mytheme/style.css": THEME_HEAD, "mytheme/index.php": "<?php"}))
        self.assertIsNone(err)
        self.assertEqual((info["kind"], info["slug"], info["name"], info["version"]), ("theme", "mytheme", "Test Theme", "3.2"))

    def test_a_folder_packed_with_the_version_in_its_name_is_given_its_real_name(self):
        info, err = library.inspect_zip(self.zip(files={"bricksextras-1.7.6/bricksextras.php": PLUGIN_HEAD}))
        self.assertIsNone(err)
        self.assertEqual((info["slug"], info["folder"], info["renamed"]), ("bricksextras", "bricksextras-1.7.6", True))
        info, err = library.inspect_zip(self.zip(files={"bricksextras (1)/bricksextras.php": PLUGIN_HEAD}))
        self.assertEqual(info["slug"], "bricksextras")

    def test_names_that_only_look_like_a_version_are_kept(self):
        info, err = library.inspect_zip(self.zip(files={"ac-addon-woocommerce/x.php": PLUGIN_HEAD}))
        self.assertEqual(info["slug"], "ac-addon-woocommerce")
        self.assertFalse(info["renamed"])

    def test_mac_leftovers_are_ignored(self):
        info, err = library.inspect_zip(self.zip(files={"bricksextras/bricksextras.php": PLUGIN_HEAD, "__MACOSX/bricksextras/._x.php": "junk",
                                                        "bricksextras/.DS_Store": "x"}))
        self.assertIsNone(err)
        self.assertEqual(info["files"], 1)

    def refused(self, files=None, path=None, word=""):
        info, err = library.inspect_zip(path or self.zip(files=files))
        self.assertIsNone(info)
        self.assertTrue(err, "a sentence saying what is wrong")
        self.assertIn(word.lower(), err.lower())
        return err

    def test_things_that_are_not_a_plugin_or_theme_zip_are_refused(self):
        bad = os.path.join(self.root, "x.zip")
        with open(bad, "wb") as f:
            f.write(b"this is not a zip")
        self.refused(path=bad, word="not a zip")
        empty = os.path.join(self.root, "empty.zip")
        open(empty, "wb").close()
        self.refused(path=empty, word="empty")
        self.refused(path=os.path.join(self.root, "missing.zip"), word="could not be read")

    def test_files_must_be_inside_one_folder(self):
        self.refused({"bricksextras.php": PLUGIN_HEAD}, word="inside one folder")
        self.refused({"a/a.php": PLUGIN_HEAD, "b/b.php": PLUGIN_HEAD}, word="2 folders")

    def test_a_zip_without_a_plugin_or_theme_header_is_refused(self):
        self.refused({"stuff/readme.txt": "just text", "stuff/code.php": "<?php echo 1;"}, word="plugin or a theme")

    def test_a_zip_without_a_version_is_refused(self):
        self.refused({"p/p.php": "<?php\n/*\nPlugin Name: No Version\n*/"}, word="version")

    def test_paths_that_could_write_outside_the_folder_are_refused(self):
        self.refused({"p/p.php": PLUGIN_HEAD, "p/../../evil.php": "x"}, word="unsafe")
        self.refused({"p/p.php": PLUGIN_HEAD, "/etc/cron.d/evil": "x"}, word="unsafe")
        self.refused({"p/p.php": PLUGIN_HEAD, "p\\..\\evil.php": "x"}, word="unsafe")
        self.refused({"p/p.php": PLUGIN_HEAD, "C:/evil.php": "x"}, word="unsafe")

    def test_a_link_inside_the_zip_is_refused(self):
        path = os.path.join(self.root, "link.zip")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("p/p.php", PLUGIN_HEAD)
            link = zipfile.ZipInfo("p/passwd")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(link, "/etc/passwd")
        self.refused(path=path, word="link")

    def test_a_password_protected_zip_is_refused(self):
        path = self.zip("locked.zip", {"p/p.php": PLUGIN_HEAD})
        with open(path, "rb") as f:
            data = bytearray(f.read())
        data[data.index(b"PK\x01\x02") + 8] |= 0x1              # the "encrypted" flag in the zip's own table of contents
        with open(path, "wb") as f:
            f.write(bytes(data))
        self.refused(path=path, word="password")

    def test_size_and_count_limits_stop_a_zip_bomb(self):
        saved = (library.MAX_FILES, library.MAX_UNPACKED, library.MAX_ZIP)
        self.addCleanup(lambda: (setattr(library, "MAX_FILES", saved[0]), setattr(library, "MAX_UNPACKED", saved[1]), setattr(library, "MAX_ZIP", saved[2])))
        library.MAX_FILES = 2
        self.refused({"p/p.php": PLUGIN_HEAD, "p/a": "1", "p/b": "2"}, word="too many files")
        library.MAX_FILES = saved[0]
        library.MAX_UNPACKED = 100
        self.refused({"p/p.php": PLUGIN_HEAD + "x" * 500}, word="unpack")
        library.MAX_UNPACKED = saved[1]
        library.MAX_ZIP = 10
        self.refused({"p/p.php": PLUGIN_HEAD}, word="bigger than")


class Keeping(LibraryCase):
    def test_a_good_upload_is_kept_privately_and_listed(self):
        res, entry = library.add(self.zip(), "Bricks Extras 1.7.6.zip")
        self.assertTrue(res.ok, res.message)
        self.assertIn("Bricks Extras 1.7.6 is ready", res.message)
        listed = library.list_zips()
        self.assertEqual([(z["name"], z["version"], z["kind"], z["slug"]) for z in listed], [("Bricks Extras", "1.7.6", "plugin", "bricksextras")])
        self.assertEqual(listed[0]["filename"], "Bricks Extras 1.7.6.zip")
        kept = library.zip_path(entry["id"])
        self.assertTrue(zipfile.is_zipfile(kept))
        with open(kept, "rb") as f:
            self.assertEqual(entry["sha256"], hashlib.sha256(f.read()).hexdigest())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(kept).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(library.base_dir()).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(library.incoming_dir()).st_mode), 0o700)

    def test_a_bad_file_is_not_kept(self):
        bad = os.path.join(self.root, "bad.zip")
        with open(bad, "wb") as f:
            f.write(b"nope")
        res, entry = library.add(bad, "bad.zip")
        self.assertFalse(res.ok)
        self.assertIsNone(entry)
        self.assertEqual(library.list_zips(), [])

    def test_a_newer_upload_of_the_same_plugin_replaces_the_older_one(self):
        res1, first = library.add(self.zip(), "a.zip")
        newer = self.zip("b.zip", {"bricksextras/bricksextras.php": PLUGIN_HEAD.replace("1.7.6", "1.8.0")})
        res2, second = library.add(newer, "b.zip")
        self.assertIn("replaces the earlier upload of version 1.7.6", res2.message)
        self.assertEqual([z["version"] for z in library.list_zips()], ["1.8.0"])
        self.assertFalse(os.path.exists(library.zip_path(first["id"])), "the old file is gone from the server")

    def test_a_different_plugin_does_not_replace_it(self):
        library.add(self.zip(), "a.zip")
        other = self.zip("c.zip", {"other/other.php": PLUGIN_HEAD.replace("Bricks Extras", "Other")})
        library.add(other, "c.zip")
        self.assertEqual(sorted(z["slug"] for z in library.list_zips()), ["bricksextras", "other"])

    def test_a_renamed_folder_is_stored_under_the_real_name(self):
        res, entry = library.add(self.zip(files={"bricksextras-1.7.6/bricksextras.php": PLUGIN_HEAD, "bricksextras-1.7.6/inc/a.php": "x"}), "p.zip")
        self.assertTrue(res.ok)
        self.assertIn("renamed to bricksextras", res.message)
        with zipfile.ZipFile(library.zip_path(entry["id"])) as z:
            self.assertEqual(sorted(z.namelist()), ["bricksextras/bricksextras.php", "bricksextras/inc/a.php"])
        info, err = library.inspect_zip(library.zip_path(entry["id"]))
        self.assertFalse(info["renamed"], "the stored file is already right")
        self.assertEqual(entry["sha256"], library._sha256(library.zip_path(entry["id"])), "the fingerprint is of the stored file")
        self.assertEqual(entry["renamed_from"], "bricksextras-1.7.6")

    def test_deleting_removes_the_file_and_only_that(self):
        _, a = library.add(self.zip(), "a.zip")
        _, b = library.add(self.zip("o.zip", {"other/other.php": PLUGIN_HEAD.replace("Bricks Extras", "Other")}), "o.zip")
        res = library.delete(a["id"])
        self.assertTrue(res.ok, res.message)
        self.assertIn("websites keep what was installed", res.message)
        self.assertFalse(os.path.exists(library.zip_path(a["id"])))
        self.assertTrue(os.path.exists(library.zip_path(b["id"])))
        self.assertEqual([z["slug"] for z in library.list_zips()], ["other"])
        self.assertEqual(library.delete(a["id"]).code, "missing")

    def test_odd_ids_find_nothing(self):
        for bad in (None, "", "../../etc/passwd", "zzzz", 5, "0123456789abcdef0"):
            self.assertIsNone(library.get(bad))

    def test_an_entry_whose_file_has_gone_is_not_listed(self):
        _, a = library.add(self.zip(), "a.zip")
        os.remove(library.zip_path(a["id"]))
        self.assertEqual(library.list_zips(), [])


class Versions(EnvTestCase):
    def test_numbers_are_compared_as_numbers(self):
        for a, b, want in [("7.1.10", "7.1.9", 1), ("1.0", "1.0.0", 0), ("2.0", "10.0", -1), ("1.2.3", "1.2.3", 0),
                           ("1.0.0-beta", "1.0.0", -1), ("1.0.0", "1.0.0-rc1", 1), ("1.0.0-rc1", "1.0.0-beta2", 1), ("v2.1", "2.0.9", 1),
                           ("6.4.18", "7.1.7", -1), ("3.5", "3.5.0.0", 0), ("1.0.0-pl1", "1.0.0", 1)]:
            self.assertEqual(library.version_cmp(a, b), want, (a, b))

    def test_it_is_symmetric(self):
        self.assertEqual(library.version_cmp("1.5.3", "1.7.6"), -library.version_cmp("1.7.6", "1.5.3"))


class WhatEachWebsiteHas(EnvTestCase):
    ENTRY = {"kind": "plugin", "slug": "bricksextras", "version": "1.7.6"}

    def test_each_state_is_told_apart(self):
        sites = {
            "old.example.com": {"checked": True, "plugin": {"bricksextras": {"version": "1.5.3", "status": "active"}}, "theme": {}},
            "same.example.com": {"checked": True, "plugin": {"bricksextras": {"version": "1.7.6", "status": "active"}}, "theme": {}},
            "ahead.example.com": {"checked": True, "plugin": {"bricksextras": {"version": "2.0", "status": "inactive"}}, "theme": {}},
            "none.example.com": {"checked": True, "plugin": {}, "theme": {}},
            "broken.example.com": {"checked": False},
        }
        names = ["ahead.example.com", "broken.example.com", "none.example.com", "old.example.com", "same.example.com", "not-read-yet.example.com"]
        rows = library.rows_for(self.ENTRY, sites, names)
        by = {r["site"]: r for r in rows}
        self.assertEqual(by["old.example.com"]["state"], "update")
        self.assertTrue(by["old.example.com"]["can_update"])
        self.assertEqual((by["same.example.com"]["state"], by["same.example.com"]["can_update"]), ("same", False))
        self.assertEqual((by["ahead.example.com"]["state"], by["ahead.example.com"]["status"], by["ahead.example.com"]["can_update"]), ("newer", "inactive", False))
        self.assertEqual(by["none.example.com"]["state"], "missing")
        self.assertEqual(by["broken.example.com"]["state"], "unknown")
        self.assertEqual(by["not-read-yet.example.com"]["state"], "unknown")
        self.assertEqual(rows[0]["site"], "old.example.com", "what can be updated comes first")

    def test_a_theme_is_matched_among_themes_not_plugins(self):
        sites = {"a.example.com": {"checked": True, "plugin": {"mytheme": {"version": "1", "status": "active"}}, "theme": {"mytheme": {"version": "1.0", "status": "active"}}}}
        rows = library.rows_for({"kind": "theme", "slug": "mytheme", "version": "2.0"}, sites, ["a.example.com"])
        self.assertEqual(rows[0]["installed"], "1.0")


class SendingToAWebsite(LibraryCase):
    SITE = {"user": "shopuser", "home": "/home/shop.example.com", "docroot": "/home/shop.example.com/public_html"}

    def setUp(self):
        super().setUp()
        _, self.entry = library.add(self.zip(), "a.zip")
        self.sent = []
        self.patch("cpsec.library.util.run_with_file", side_effect=lambda cmd, path, timeout=0: self.sent.append((cmd, path)) or (0, ""))

    def sha_answers(self, digest):
        self.fake.table.insert(0, (["su"], lambda cmd: (0, "%s  file\n" % digest) if "sha256sum" in cmd[5] else (0, "")))

    def test_the_website_receives_its_copy_written_by_its_own_user(self):
        self.sha_answers(self.entry["sha256"])
        path, err = library.deliver(self.entry["id"], self.SITE)
        self.assertEqual((path, err), ("/home/shop.example.com/cps-backups/upload-%s.zip" % self.entry["id"], ""))
        cmd, source = self.sent[0]
        self.assertEqual(cmd[:4], ["su", "-s", "/bin/bash", "shopuser"], "never written by root")
        self.assertIn("umask 077", cmd[5])
        self.assertIn("mkdir -p -m 700 /home/shop.example.com/cps-backups", cmd[5])
        self.assertEqual(source, library.zip_path(self.entry["id"]))

    def test_a_copy_that_does_not_match_is_thrown_away(self):
        self.sha_answers("0" * 64)
        path, err = library.deliver(self.entry["id"], self.SITE)
        self.assertEqual(path, "")
        self.assertIn("did not match", err)
        self.assertTrue(self.fake.called("su", "-s", "/bin/bash", "shopuser"))
        self.assertTrue([c for c in self.fake.calls if c[:1] == ["su"] and "rm -f" in c[5]], "the bad copy was removed")

    def test_a_failed_send_says_so(self):
        self.patch("cpsec.library.util.run_with_file", return_value=(1, "No space left on device"))
        path, err = library.deliver(self.entry["id"], self.SITE)
        self.assertEqual(path, "")
        self.assertIn("could not be sent", err)
        self.assertIn("No space left", err)

    def test_a_file_that_was_deleted_cannot_be_sent(self):
        library.delete(self.entry["id"])
        path, err = library.deliver(self.entry["id"], self.SITE)
        self.assertEqual(path, "")
        self.assertIn("no longer on the server", err)

    def test_only_a_copy_made_for_this_purpose_is_removed(self):
        library.discard(self.SITE, "/home/shop.example.com/public_html/wp-config.php")
        self.assertFalse([c for c in self.fake.calls if "rm -f" in " ".join(c)])
        library.discard(self.SITE, "/home/shop.example.com/cps-backups/upload-abc.zip")
        self.assertTrue([c for c in self.fake.calls if c[:1] == ["su"] and "rm -f" in c[5] and "upload-abc.zip" in c[5]])


class ReadingTheWebsites(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.docroot = "%s/shop.example.com/public_html" % config.P.home_dir
        os.makedirs(self.docroot)
        self.write(config.P.lsws_root + "/lsphp81/bin/php", "")
        self.patch("cpsec.updates._wordpress_sites", return_value=[(self.docroot, "shopuser", "shop.example.com")])
        from cpsec import wpupdate
        wpupdate._php_cache.clear()
        self.fail_themes = False

        def su(cmd):
            script = cmd[5]
            if "core version" in script:
                return 0, "6.5.2\n"
            if "plugin list" in script:
                return 0, "Notice: noise\nname,status,version\nbricksextras,active,1.5.3\nhello,inactive,1.0\nobject-cache.php,dropin,\nsecurity,must-use,2\nnet,active-network,3\n"
            if "theme list" in script:
                return (1, "Error") if self.fail_themes else (0, "name,status,version\ntwentytwentyfive,inactive,1.2\n")
            return 0, ""
        self.fake.table.append((["su"], su))
        with library._lock:
            library._inv.update(status="idle", started="", finished="", sites={})

    def test_plugins_and_themes_are_read_and_odd_entries_are_left_out(self):
        library.inventory_refresh(["shop.example.com"])
        site = library.inventory_state()["sites"]["shop.example.com"]
        self.assertEqual(site["plugin"], {"bricksextras": {"version": "1.5.3", "status": "active"}, "hello": {"version": "1.0", "status": "inactive"},
                                          "net": {"version": "3", "status": "active"}})
        self.assertEqual(site["theme"], {"twentytwentyfive": {"version": "1.2", "status": "inactive"}})

    def test_a_website_that_cannot_be_read_is_marked_so_not_guessed(self):
        self.fail_themes = True
        library.inventory_refresh(["shop.example.com"])
        self.assertEqual(library.inventory_state()["sites"]["shop.example.com"], {"checked": False})

    def test_the_background_look_finishes_and_says_when(self):
        self.assertTrue(library.inventory_start().ok)
        for _ in range(200):
            if library.inventory_state()["status"] == "done":
                break
            time.sleep(0.02)
        st = library.inventory_state()
        self.assertEqual(st["status"], "done")
        self.assertTrue(st["finished"])
        self.assertTrue(st["sites"]["shop.example.com"]["checked"])
