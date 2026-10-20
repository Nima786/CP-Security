import os

from cpsec import config, crs_convert, sites, updates, util
from tests.helpers import EnvTestCase


class Sites(EnvTestCase):
    def make_sites(self, *names):
        for n in names:
            os.makedirs(os.path.join(config.P.home_dir, n, "public_html"))

    def test_sites_are_the_folders_with_a_public_html(self):
        self.make_sites("b.example.com", "a.example.com")
        os.makedirs(os.path.join(config.P.home_dir, "vmail"))
        self.assertEqual(sites.list_sites(), ["a.example.com", "b.example.com"])

    def test_old_problems_are_told_apart_from_new_ones(self):
        util.write_json(config.P.baseline, {"a.example.com": "200", "b.example.com": "500", "c.example.com": "200"})
        results = [("a.example.com", "200"), ("b.example.com", "500"), ("c.example.com", "503"), ("d.example.com", "301")]
        s = sites.summarize(results)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["normal"], 2)
        self.assertEqual(s["new_problems"], [{"domain": "c.example.com", "code": "503"}])
        self.assertEqual(s["old_problems"], [{"domain": "b.example.com", "code": "500"}])

    def test_check_asks_the_local_server_directly(self):
        self.fake.table.append((("curl",), (0, "200")))
        self.assertEqual(sites.check_site("a.example.com"), ("a.example.com", "200"))
        call = self.fake.called("curl")[0]
        self.assertIn("a.example.com:443:127.0.0.1", call)

    def test_unreachable_is_000(self):
        self.fake.table.append((("curl",), (7, "")))
        self.assertEqual(sites.check_site("a.example.com")[1], "000")

    def test_sample_prefers_sites_that_normally_work(self):
        util.write_json(config.P.baseline, {"a": "200", "b": "500", "c": "301"})
        self.assertEqual(sites.sample_for_check(), ["a", "c"])


class UpdatesParsing(EnvTestCase):
    def test_plugins_and_core_are_listed(self):
        plugins = "title,version,update_version\nYoast SEO,28.2,28.7\n\"WooCommerce, Legacy\",1.0,1.1\n"
        core = "version,update_type\n6.8.11,minor\n7.1.3,major\n"
        s = updates.parse_site("a.example.com", plugins, core)
        self.assertTrue(s["checked"])
        what = [(i["what"], i["to"], i["kind"]) for i in s["items"]]
        self.assertIn(("Yoast SEO", "28.7", "plugin"), what)
        self.assertIn(("WooCommerce, Legacy", "1.1", "plugin"), what)
        self.assertIn(("WordPress itself", "6.8.11", "core-minor"), what)

    def test_themes_come_with_their_name_and_whether_they_are_switched_on(self):
        plugins = "name,title,status,version,update_version\nwoocommerce,WooCommerce,active,10.0.4,11.2.1\nold-gallery,Old gallery,inactive,2.1,2.4\n"
        themes = "name,title,status,version,update_version\nbricks,Bricks,active,1.9.8,1.12.4\n"
        s = updates.parse_site("a.example.com", plugins, "", themes)
        rows = {(i["kind"], i["slug"]): i for i in s["items"]}
        self.assertEqual(rows[("plugin", "woocommerce")]["what"], "WooCommerce")
        self.assertEqual(rows[("plugin", "old-gallery")]["status"], "inactive")
        self.assertEqual((rows[("theme", "bricks")]["from"], rows[("theme", "bricks")]["to"]), ("1.9.8", "1.12.4"))
        self.assertEqual(len(s["items"]), 3)

    def test_a_site_with_only_theme_updates_is_still_checked(self):
        s = updates.parse_site("a.example.com", None, None, "name,title,status,version,update_version\nbricks,Bricks,active,1,2\n")
        self.assertTrue(s["checked"])
        self.assertEqual([i["kind"] for i in s["items"]], ["theme"])

    def test_a_site_that_could_not_be_read_is_marked_unchecked(self):
        self.assertEqual(updates.parse_site("a.example.com", None, None), {"site": "a.example.com", "items": [], "checked": False})


class FakeWordPressLook:
    """Stands in for WP-CLI as the website's user. Remembers every command."""
    HEADER = "name,title,status,version,update_version\n"

    def __init__(self):
        self.log = []
        self.admin = "7\n"
        self.loaded_works = True
        self.area_works = True               # plugins also load when WordPress believes it is inside wp-admin
        self.admin_only_plugins = ""          # extra rows that only appear inside wp-admin (plugins that start with "if (!is_admin()) return;")
        self.vendor_plugins = self.HEADER + "bricksextras,BricksExtras,active,1.5.3,1.7.6\n"
        self.repo_plugins = self.HEADER
        self.core = "version,update_type\n7.1.3,major\n"

    def su(self, cmd):
        script = cmd[5]
        self.log.append(script)
        loaded = "--skip-plugins" not in script
        if "core version" in script:
            return 0, "6.8.1\n"
        if "user list" in script:
            return 0, self.admin
        if "load-update-core.php" in script:
            return 0, "" if self.loaded_works else (255, "")[1]
        in_admin = "WP_ADMIN" in script
        if loaded and in_admin and not self.area_works:
            return 255, ""
        if "plugin list" in script:
            if loaded:
                extra = self.admin_only_plugins if in_admin else ""
                return (0, "PHP Notice:  Undefined variable in some-plugin.php on line 3\n" + self.vendor_plugins + extra) if self.loaded_works else (255, "")
            return 0, self.repo_plugins
        if "theme list" in script:
            return (0, self.HEADER) if (not loaded or self.loaded_works) else (255, "")
        if "core check-update" in script:
            return 0, self.core
        return 0, ""

    def asked(self, word):
        return [i for i, s in enumerate(self.log) if word in s]


class UpdatesLook(EnvTestCase):
    SITE = ("/home/a.example.com/public_html", "auser", "a.example.com")

    def setUp(self):
        super().setUp()
        self.write(config.P.lsws_root + "/lsphp81/bin/php", "")
        self.wp = FakeWordPressLook()
        self.fake.table.append((["su"], self.wp.su))

    def test_the_scan_asks_for_plugins_themes_and_wordpress(self):
        updates._look(self.SITE)
        joined = " | ".join(self.wp.log)
        self.assertIn("plugin list", joined)
        self.assertIn("theme list", joined)
        self.assertIn("core check-update", joined)

    def test_updates_from_a_plugin_makers_own_server_are_found(self):
        """Found on the real server: a plugin that is not on WordPress.org only speaks when it is loaded and an administrator asks."""
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        self.assertTrue(vendors)
        entry = updates.parse_site(name, plugins, core, themes, vendors)
        self.assertEqual([(i["slug"], i["from"], i["to"]) for i in entry["items"] if i["kind"] == "plugin"], [("bricksextras", "1.5.3", "1.7.6")])
        self.assertTrue(entry["vendors"])
        loaded = [self.wp.log[i] for i in self.wp.asked("plugin list")]
        self.assertEqual(len(loaded), 1)
        self.assertNotIn("--skip-plugins", loaded[0])
        self.assertIn("--user=7", loaded[0], "asked as an administrator")

    def test_the_websites_own_update_check_is_asked_first_then_the_lists_are_read(self):
        updates._look(self.SITE)
        order = [self.wp.asked(w)[0] for w in ("load-update-core.php", "plugin list", "theme list", "core check-update")]
        self.assertEqual(order, sorted(order), "refresh, then plugins, themes, then WordPress itself")

    def test_the_refresh_can_be_left_out(self):
        updates._look(self.SITE, nudge=False)
        self.assertEqual(self.wp.asked("load-update-core.php"), [])

    def test_everything_runs_as_the_websites_own_user_with_its_home_for_wpcli_files(self):
        updates._look(self.SITE)
        for c in self.fake.called("su"):
            self.assertEqual(c[:4], ["su", "-s", "/bin/bash", "auser"])
            self.assertIn("export HOME=/home/a.example.com;", c[5], "WP-CLI's cache goes next to the site, never into the web folder")

    def test_notices_printed_by_a_plugin_before_the_list_are_ignored(self):
        _n, plugins, _c, _t, _v = updates._look(self.SITE)
        self.assertTrue(plugins.startswith("name,title"))

    def test_an_invisible_byte_order_mark_in_front_of_the_list_is_ignored(self):
        """Found on the real server: one website printed U+FEFF before the header, so its list was thrown away."""
        self.wp.vendor_plugins = "\ufeff" + self.wp.vendor_plugins
        _n, plugins, _c, _t, vendors = updates._look(self.SITE)
        self.assertTrue(vendors)
        self.assertTrue(plugins.startswith("name,title"))
        self.assertEqual(updates._csv("\ufeffname,title,status,version,update_version\n"), "name,title,status,version,update_version")

    def test_a_plugin_that_only_starts_inside_wp_admin_is_found(self):
        """Found on the real server: Admin Columns Pro begins with 'if (!is_admin()) return;', so from the command line it never speaks."""
        self.wp.admin_only_plugins = "admin-columns-pro,Admin Columns Pro,active,6.4.18,7.1.7\n"
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        entry = updates.parse_site(name, plugins, core, themes, vendors)
        self.assertEqual(sorted(i["slug"] for i in entry["items"] if i["kind"] == "plugin"), ["admin-columns-pro", "bricksextras"])
        self.assertTrue(vendors)

    def test_the_admin_area_way_is_the_first_one_tried_and_the_refresh_uses_it_too(self):
        updates._look(self.SITE)
        for word in ("load-update-core.php", "plugin list", "theme list"):
            first = self.wp.log[self.wp.asked(word)[0]]
            self.assertIn("WP_ADMIN", first, word)
        self.assertNotIn("WP_ADMIN", self.wp.log[self.wp.asked("core check-update")[0]], "WordPress itself is asked the plain way")

    def test_if_a_plugin_cannot_cope_with_wp_admin_the_plain_loaded_way_is_used(self):
        self.wp.area_works = False
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        self.assertTrue(vendors, "plugins were still loaded, just not inside wp-admin")
        self.assertIn("bricksextras", plugins)
        last = self.wp.log[self.wp.asked("plugin list")[-1]]
        self.assertNotIn("WP_ADMIN", last)

    def test_if_the_plugins_cannot_be_loaded_the_wordpress_org_list_is_used_and_it_is_said(self):
        self.wp.loaded_works = False
        self.wp.repo_plugins = self.wp.HEADER + "woocommerce,WooCommerce,active,10.0,11.0\n"
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        self.assertFalse(vendors)
        entry = updates.parse_site(name, plugins, core, themes, vendors)
        self.assertTrue(entry["checked"])
        self.assertFalse(entry["vendors"])
        self.assertIn("woocommerce", [i.get("slug") for i in entry["items"]])

    def test_a_website_without_an_administrator_still_gets_the_wordpress_org_list(self):
        self.wp.admin = ""
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        self.assertFalse(vendors)
        self.assertIsNotNone(plugins)
        self.assertEqual(self.wp.asked("load-update-core.php"), [])

    def test_a_website_that_cannot_start_is_unchecked(self):
        self.fake.table.insert(0, (["su"], lambda cmd: (1, "")))
        name, plugins, core, themes, vendors = updates._look(self.SITE)
        self.assertEqual(updates.parse_site(name, plugins, core, themes, vendors), {"site": "a.example.com", "items": [], "checked": False})

    def test_looking_at_one_website_stamps_when(self):
        self.patch("cpsec.updates._wordpress_sites", return_value=[self.SITE])
        entry = updates.look_one("a.example.com")
        self.assertRegex(entry["looked"], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertIsNone(updates.look_one("nope.example.com"))


class RuleConverter(EnvTestCase):
    SAMPLE = '''SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" "id:942012,phase:2,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
# level 1 rules
SecRule ARGS "@detectSQLi" \\
    "id:942100,\\
    phase:2,\\
    block"
SecRule ARGS "@rx foo" "id:942101,phase:2,block"
# level 2
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:942013,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
SecRule ARGS "@rx strict" "id:942200,phase:2,block"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 3" "id:942015,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
SecRule ARGS "@rx stricter" "id:942300,phase:2,block"
SecMarker "END-REQUEST-942-APPLICATION-ATTACK-SQLI"
'''

    def test_only_level_one_survives_and_no_skips_are_left(self):
        new, cut = crs_convert.convert(self.SAMPLE)
        self.assertIn("id:942100", new)
        self.assertIn("id:942101", new)
        self.assertNotIn("942200", new)
        self.assertNotIn("942300", new)
        self.assertNotIn("skipAfter", new)
        self.assertNotIn("SecMarker", new)
        self.assertEqual(cut, 4, "two gates and two rules were cut")

    def test_multiline_rules_are_kept_whole(self):
        new, _ = crs_convert.convert(self.SAMPLE)
        self.assertIn('SecRule ARGS "@detectSQLi" \\\n    "id:942100,\\\n    phase:2,\\\n    block"', new)

    def test_the_startup_file_keeps_its_own_skip(self):
        text = 'SecRule TX:X "@eq 100" "id:901450,phase:1,pass,nolog,skipAfter:END-SAMPLING"\nSecMarker "END-SAMPLING"\n'
        new, _ = crs_convert.convert(text, keep_skips=True)
        self.assertIn("skipAfter:END-SAMPLING", new)
        self.assertIn('SecMarker "END-SAMPLING"', new)

    def test_a_whole_folder_is_converted_and_data_files_copied(self):
        src, dst = os.path.join(self.root, "src"), os.path.join(self.root, "dst")
        self.write(os.path.join(src, "REQUEST-942-X.conf"), self.SAMPLE)
        self.write(os.path.join(src, "words.data"), "a\nb\n")
        self.write(os.path.join(src, "RESPONSE-950-Y.conf"), "SecRule A B\n")
        report = crs_convert.convert_dir(src, dst)
        self.assertEqual(list(report), ["REQUEST-942-X.conf"])
        self.assertTrue(os.path.exists(os.path.join(dst, "words.data")))
        self.assertFalse(os.path.exists(os.path.join(dst, "RESPONSE-950-Y.conf")))


class FileHelpers(EnvTestCase):
    def test_atomic_write_and_snapshot_restore(self):
        path = os.path.join(self.root, "x", "y.txt")
        util.atomic_write(path, "one\n")
        snap = util.snapshot([path, path + ".missing"])
        util.atomic_write(path, "two\n")
        util.atomic_write(path + ".missing", "new\n")
        util.restore(snap)
        self.assertEqual(self.read(path), "one\n")
        self.assertFalse(os.path.exists(path + ".missing"))
        self.assertFalse(os.path.exists(path + ".tmp"))

    def test_read_json_falls_back(self):
        self.assertEqual(util.read_json(os.path.join(self.root, "nope.json"), {"a": 1}), {"a": 1})
        self.write(os.path.join(self.root, "bad.json"), "{not json")
        self.assertEqual(util.read_json(os.path.join(self.root, "bad.json"), []), [])
