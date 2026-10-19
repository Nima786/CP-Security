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

    def test_a_site_that_could_not_be_read_is_marked_unchecked(self):
        self.assertEqual(updates.parse_site("a.example.com", None, None), {"site": "a.example.com", "items": [], "checked": False})


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
